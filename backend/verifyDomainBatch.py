#!/usr/bin/env python3
"""
UNIROUTE - verifyDomainBatch.py

Verifies a batch of manually-researched university domains before they are
trusted. Reads a TSV of "university_id <TAB> url".

    python verifyDomainBatch.py batch.tsv [--apply]

Each row is checked for:
  * the value actually being a URL
  * DNS resolution (apex and www)
  * an HTTP response
  * whether it redirects off to a different registered domain
  * whether the page identifies the expected institution, by comparing the
    university's name against the page title and visible text
  * whether the domain's country TLD contradicts the country we hold

Verdicts:
  ok            responds and the page identifies the right institution
  review        responds, but the page does not clearly confirm the name
  wrong-site    lands on a different institution or an unrelated domain
  unreachable   DNS or connection failure
  invalid       the cell is not a URL

Only 'ok' rows are written by --apply.
"""

import argparse
import csv
import os
import re
import socket
import ssl
import sys
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

import psycopg2

UA = "Mozilla/5.0 (compatible; UnirouteDomainVerify/1.0)"
socket.setdefaulttimeout(20)

STOP = {"university", "universite", "universitat", "universita", "universidad",
        "universidade", "universiteit", "of", "the", "de", "di", "del", "la",
        "el", "and", "for", "at", "in", "college", "institute", "school",
        "national", "state", "technology", "technical", "science", "sciences",
        "study", "home", "welcome", "official", "site", "website"}

CC_HINT = {
    "germany": "de", "france": "fr", "italy": "it", "spain": "es", "portugal": "pt",
    "netherlands": "nl", "belgium": "be", "switzerland": "ch", "austria": "at",
    "poland": "pl", "czechia": "cz", "sweden": "se", "denmark": "dk", "norway": "no",
    "finland": "fi", "ireland": "ie", "greece": "gr", "romania": "ro", "ukraine": "ua",
    "russia": "ru", "turkiye": "tr", "turkey": "tr", "india": "in", "pakistan": "pk",
    "china": "cn", "taiwan": "tw", "japan": "jp", "south korea": "kr", "malaysia": "my",
    "indonesia": "id", "vietnam": "vn", "australia": "au", "canada": "ca",
    "brazil": "br", "mexico": "mx", "chile": "cl", "argentina": "ar", "colombia": "co",
    "venezuela": "ve", "egypt": "eg", "saudi arabia": "sa", "jordan": "jo",
    "lebanon": "lb", "bahrain": "bh", "luxembourg": "lu", "hong kong": "hk",
    "singapore": "sg", "kazakhstan": "kz", "uzbekistan": "uz", "brunei darussalam": "bn",
    "united kingdom": "uk", "united arab emirates": "ae", "bosnia and herzegovina": "ba",
}

MULTI_TLD = {"ac.uk","co.uk","ac.jp","co.jp","ac.nz","ac.za","edu.au","com.au",
             "edu.cn","edu.in","ac.in","edu.sg","edu.my","edu.pk","edu.br","edu.mx",
             "edu.tr","edu.ar","ac.kr","ac.th","edu.hk","edu.tw","ac.ir","edu.eg",
             "edu.sa","edu.co","edu.pe","edu.ph","ac.id","ac.be","ac.at","ac.il",
             "edu.pl","edu.gr","edu.ua","edu.ru","edu.jo","edu.bh","edu.bn","edu.lb",
             "edu.kz","edu.uz","edu.ve","edu.ba","ac.ae","edu.ae","edu.vn"}


def strip_accents(s):
    return "".join(c for c in unicodedata.normalize("NFKD", str(s or ""))
                   if not unicodedata.combining(c))


def toks(s):
    s = strip_accents(s).lower()
    s = re.sub(r"[^a-z0-9\s]", " ", s)
    return {t for t in s.split() if len(t) > 2 and t not in STOP}


def reg_domain(host):
    h = str(host or "").lower().strip()
    if h.startswith(("http://", "https://")):
        h = urllib.parse.urlparse(h).netloc
    h = h.split("/")[0].split(":")[0].rstrip(".")
    if h.startswith("www."):
        h = h[4:]
    p = [x for x in h.split(".") if x]
    if len(p) <= 2:
        return ".".join(p)
    if ".".join(p[-2:]) in MULTI_TLD and len(p) >= 3:
        return ".".join(p[-3:])
    return ".".join(p[-2:])


def text_of(html):
    html = re.sub(r"(?is)<(script|style|noscript).*?</\1>", " ", html)
    title = ""
    m = re.search(r"(?is)<title[^>]*>(.*?)</title>", html)
    if m:
        title = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", "", m.group(1))).strip()
    body = re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", html))
    return title[:110], body[:6000]


def verify(row):
    uid, name, country, url = row
    rec = {"id": uid, "name": name, "country": country, "url": url,
           "verdict": "", "http": "", "final_domain": "", "title": "", "note": ""}

    if not url or not url.lower().startswith(("http://", "https://")):
        rec["verdict"] = "invalid"; rec["note"] = "cell is not a URL"
        return rec

    host = urllib.parse.urlparse(url).netloc
    cands = [host] if host.startswith("www.") else [host, "www." + host]
    if not any(_resolves(c) for c in cands):
        rec["verdict"] = "unreachable"; rec["note"] = "DNS does not resolve"
        return rec

    ctx = ssl.create_default_context(); ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
    html = ""
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=25, context=ctx) as r:
            raw = r.read(300000); rec["http"] = r.status
            rec["final_domain"] = reg_domain(r.geturl())
            html = raw.decode(r.headers.get_content_charset() or "utf-8", "replace")
    except urllib.error.HTTPError as e:
        rec["http"] = e.code
        rec["final_domain"] = reg_domain(url)
        try:
            html = e.read(200000).decode("utf-8", "replace")
        except Exception:
            pass
        if e.code not in (401, 403):
            rec["verdict"] = "unreachable"; rec["note"] = f"HTTP {e.code}"
            return rec
    except Exception as e:
        rec["verdict"] = "unreachable"; rec["note"] = type(e).__name__
        return rec

    title, body = text_of(html)
    rec["title"] = title

    if rec["final_domain"] and rec["final_domain"] != reg_domain(url):
        rec["verdict"] = "wrong-site"
        rec["note"] = f"redirects to {rec['final_domain']}"
        return rec

    nt = toks(name)
    hit = nt & (toks(title) | toks(body))
    if nt and hit:
        rec["verdict"] = "ok"
        rec["note"] = "page names: " + ", ".join(sorted(hit)[:4])
    else:
        rec["verdict"] = "review"
        rec["note"] = "page does not mention the university name"

    cc = CC_HINT.get(strip_accents(country).lower())
    tld = rec["final_domain"].rsplit(".", 1)[-1] if rec["final_domain"] else ""
    if cc and tld and tld != cc and tld not in ("edu", "org", "com", "net", "eu", "university", "int"):
        rec["note"] += f" | country mismatch: {country} but .{tld}"
        if rec["verdict"] == "ok":
            rec["verdict"] = "review"
    return rec


def _resolves(h):
    try:
        socket.getaddrinfo(h, None); return True
    except Exception:
        return False


def load_env(p):
    e = {}
    if os.path.exists(p):
        for line in open(p, encoding="utf-8"):
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                e[k.strip()] = v.strip().strip('"').strip("'")
    return e


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("tsv")
    ap.add_argument("--apply", action="store_true")
    ap.add_argument("--workers", type=int, default=12)
    ap.add_argument("--out", default="../data/imports/domain_batch_verified.csv")
    a = ap.parse_args()

    pairs = []
    for line in open(a.tsv, encoding="utf-8"):
        line = line.rstrip("\n")
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) >= 2 and parts[0].strip().isdigit():
            pairs.append((int(parts[0]), parts[1].strip()))
    print(f"{len(pairs)} rows to verify")

    env = load_env(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
    conn = psycopg2.connect(host=env["DB_HOST"], port=env["DB_PORT"], dbname=env["DB_NAME"],
                            user=env["DB_USER"], password=env["DB_PASSWORD"])
    cur = conn.cursor()
    cur.execute("SELECT id, name, country FROM universities WHERE id = ANY(%s)",
                ([p[0] for p in pairs],))
    meta = {i: (n, c) for i, n, c in cur.fetchall()}

    rows = []
    for uid, url in pairs:
        if uid not in meta:
            print(f"  !! id {uid} not in database - skipped")
            continue
        rows.append((uid, meta[uid][0], meta[uid][1], url))

    results = []
    with ThreadPoolExecutor(max_workers=a.workers) as ex:
        futs = [ex.submit(verify, r) for r in rows]
        for i, f in enumerate(as_completed(futs), 1):
            results.append(f.result())
            if i % 25 == 0:
                print(f"  {i}/{len(rows)}", flush=True)

    order = {"wrong-site": 0, "invalid": 1, "unreachable": 2, "review": 3, "ok": 4}
    results.sort(key=lambda r: (order.get(r["verdict"], 9), r["name"]))
    out = os.path.abspath(a.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=["id", "name", "country", "url", "verdict",
                                           "http", "final_domain", "title", "note"])
        w.writeheader(); w.writerows(results)

    from collections import Counter
    c = Counter(r["verdict"] for r in results)
    print(f"\n{len(results)} verified -> {out}\n")
    for k in ["ok", "review", "wrong-site", "unreachable", "invalid"]:
        if c.get(k):
            print(f"  {k:12} {c[k]}")

    problems = [r for r in results if r["verdict"] != "ok"]
    if problems:
        print("\n---- NEEDS ATTENTION ----")
        for r in problems:
            print(f"  [{r['verdict']}] {r['name'][:46]}")
            print(f"      {r['url']}")
            print(f"      {r['note']}")

    if a.apply:
        good = [r for r in results if r["verdict"] == "ok"]
        cur.executemany("UPDATE universities SET web=%s, domain=%s WHERE id=%s",
                        [(r["url"], reg_domain(r["url"]), r["id"]) for r in good])
        conn.commit()
        print(f"\napplied {len(good)} verified domains")
    cur.close(); conn.close()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""R1.3 benign FP: replay the benign corpora through CRS 4.29.0 (Host: localhost). 403 = false positive.
   SQLi benign -> clean customapp routes (same endpoints attacks used); XSS benign -> search.php/calc.php."""
import urllib.request, urllib.parse, urllib.error, os, csv, collections
from concurrent.futures import ThreadPoolExecutor, as_completed

SQLI = "http://127.0.0.1:8081"; XSS = "http://127.0.0.1:8086"; HOST = "localhost"
ROOT = "/home/vahid/Projects/GenWebSec"
OUT  = f"{ROOT}/paper-frontiers/results/V2/RevisionNewResults/R1.3/benign"
os.makedirs(OUT, exist_ok=True)

def get(base, route, raw_query):
    url = f"{base}/{route}?{raw_query}" if raw_query else f"{base}/{route}"
    try:
        req = urllib.request.Request(url, headers={"Host": HOST})
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return -1

tasks = []   # (family, page, route, raw_query, base)
for line in open(f"{ROOT}/data/benignurls.txt", encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line: continue
    pr = urllib.parse.urlparse(line)
    page = pr.path.rsplit("/", 1)[-1].replace(".php", "")      # login/search/product/filter
    tasks.append(("sqli", page, page, pr.query, SQLI))
for line in open(f"{ROOT}/data/benignurls_xss.txt", encoding="utf-8", errors="replace"):
    line = line.strip()
    if not line: continue
    pr = urllib.parse.urlparse(line)
    pfile = pr.path.rsplit("/", 1)[-1]                         # search.php/calc.php
    tasks.append(("xss", pfile.replace(".php", ""), pfile, pr.query, XSS))

print(f"benign corpus: sqli={sum(1 for t in tasks if t[0]=='sqli')}  xss={sum(1 for t in tasks if t[0]=='xss')}")

def work(t):
    fam, page, route, q, base = t
    return (fam, page, q, get(base, route, q))

results = []
with ThreadPoolExecutor(max_workers=12) as ex:
    futs = [ex.submit(work, t) for t in tasks]
    for fu in as_completed(futs):
        results.append(fu.result())

per = f"{OUT}/benign_through_crs429_perrequest.csv"
with open(per, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh); w.writerow(["family", "page", "status", "is_false_positive", "query"])
    for fam, page, q, st in sorted(results, key=lambda r: (r[0], r[1])):
        w.writerow([fam, page, st, int(st == 403), q])

summ = f"{OUT}/benign_through_crs429_summary.csv"
with open(summ, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh); w.writerow(["scope", "n", "fp_403", "fp_rate_pct", "n_200", "n_404", "n_other", "status_dist"])
    def emit(label, rows):
        n = len(rows); fp = sum(1 for r in rows if r[3] == 403)
        n200 = sum(1 for r in rows if r[3] == 200); n404 = sum(1 for r in rows if r[3] == 404)
        other = n - fp - n200 - n404
        dist = dict(collections.Counter(r[3] for r in rows))
        w.writerow([label, n, fp, f"{100.0*fp/n if n else 0:.2f}", n200, n404, other, dist])
        print(f"  {label:<16} n={n:<5} FP(403)={fp:<4} fp%={100.0*fp/n if n else 0:5.2f}  200={n200:<5} 404={n404:<4} other={other}")
    for fam in ("sqli", "xss"):
        emit(f"{fam} (all)", [r for r in results if r[0] == fam])
        for page in sorted({r[1] for r in results if r[0] == fam}):
            emit(f"{fam}:{page}", [r for r in results if r[0] == fam and r[1] == page])
print("per-request ->", per); print("summary ->", summ); print("== benign done ==")

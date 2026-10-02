#!/usr/bin/env python3
"""R1.3 benign FP (extended): replay the bwApp, juice, and CSIC benign corpora through CRS 4.29.0.
   403 = false positive. FP is decided by CRS at the inbound phase BEFORE proxying, so it is
   backend-independent; all corpora are routed through one CRS 4.29.0 container with Host: localhost,
   preserving method/body/content-type. Passed requests may 404 at the stand-in backend (not an FP)."""
import urllib.request, urllib.parse, urllib.error, os, csv, json, collections
from concurrent.futures import ThreadPoolExecutor, as_completed

ROOT = "/home/vahid/Projects/GenWebSec"
DATA = f"{ROOT}/Data"
OUT = f"{ROOT}/paper-frontiers/results/V2/RevisionNewResults/R1.3/benign"
os.makedirs(OUT, exist_ok=True)
CRS = "http://127.0.0.1:8081"
HOST = "localhost"

def to_container(url):
    pr = urllib.parse.urlparse(url)
    pq = pr.path + (("?" + pr.query) if pr.query else "")
    if not pq.startswith("/"):
        pq = "/" + pq
    return CRS + pq

recs = []   # (corpus, method, url, body, content_type)
JSONL = {
    "bwapp_login":  "benign_sqli_bwapp_login.jsonl",
    "bwapp_search": "benign_sqli_bwapp_search.jsonl",
    "bwapp_calc":   "benign_xss_bwapp_calc.jsonl",
    "juice_login":  "benign_sqli_juice_login.jsonl",
    "juice_search": "benign_sqli_juice_search.jsonl",
}
for ck, fn in JSONL.items():
    for line in open(f"{DATA}/{fn}", encoding="utf-8", errors="replace"):
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        recs.append((ck, r["method"], to_container(r["url"]), r.get("body"), r.get("content_type")))

with open(f"{DATA}/all.csv", encoding="utf-8") as f:
    for row in csv.DictReader(f):
        method = str(row["method"]).upper()
        path = str(row["path"])
        q = row.get("query")
        q = None if (q is None or q == "" or str(q).lower() == "nan") else str(q)
        if method == "GET":
            url = CRS + "/" + path.lstrip("/") + (f"?{q}" if q else "")
            recs.append(("csic", "GET", url, None, None))
        else:
            url = CRS + "/" + path.lstrip("/")
            recs.append(("csic", "POST", url, (q or ""), "application/x-www-form-urlencoded"))

print("extra benign records:", dict(collections.Counter(r[0] for r in recs)), " total:", len(recs))

def send(rec):
    ck, method, url, body, ct = rec
    hdr = {"Host": HOST}
    pr = urllib.parse.urlparse(url)
    path = pr.path
    detail = pr.query if method == "GET" else (body or "")
    try:
        if method == "GET":
            req = urllib.request.Request(url, headers=hdr)
        else:
            if ct:
                hdr["Content-Type"] = ct
            req = urllib.request.Request(url, data=(body or "").encode("utf-8", "replace"), method="POST", headers=hdr)
        with urllib.request.urlopen(req, timeout=15) as r:
            st = r.status
    except urllib.error.HTTPError as e:
        st = e.code
    except Exception:
        st = -1
    return (ck, method, path, detail, st)

results = []; done = 0
with ThreadPoolExecutor(max_workers=12) as ex:
    futs = [ex.submit(send, r) for r in recs]
    for fu in as_completed(futs):
        results.append(fu.result()); done += 1
        if done % 2000 == 0:
            print(f"  ...{done}/{len(recs)}")

# per-request CSV (benign corpora are publishable; kept in the clear)
per = f"{OUT}/benign_extra_through_crs429_perrequest.csv"
with open(per, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["corpus", "method", "path", "query_or_body", "status", "is_false_positive"])
    for ck, method, path, detail, st in sorted(results, key=lambda r: (r[0], r[4])):
        w.writerow([ck, method, path, detail, st, int(st == 403)])

# FP detail (the benign requests CRS 4.29.0 wrongly blocked)
fpdet = f"{OUT}/benign_extra_false_positives.csv"
with open(fpdet, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["corpus", "method", "path", "query_or_body"])
    for ck, method, path, detail, st in results:
        if st == 403:
            w.writerow([ck, method, path, detail])

summ = f"{OUT}/benign_extra_through_crs429_summary.csv"
with open(summ, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["corpus", "n", "fp_403", "fp_rate_pct", "errors_neg1", "status_dist"])
    def emit(label, rows):
        n = len(rows); fp = sum(1 for r in rows if r[4] == 403); err = sum(1 for r in rows if r[4] == -1)
        dist = dict(collections.Counter(r[4] for r in rows))
        w.writerow([label, n, fp, f"{100.0*fp/n if n else 0:.3f}", err, dist])
        print(f"  {label:<14} n={n:<6} FP(403)={fp:<4} fp%={100.0*fp/n if n else 0:6.3f}  err={err}  dist={dist}")
    for ck in ["bwapp_login", "bwapp_search", "bwapp_calc", "juice_login", "juice_search", "csic"]:
        emit(ck, [r for r in results if r[0] == ck])
    emit("ALL-extra", results)
print("summary ->", summ)
print("== extra benign done ==")

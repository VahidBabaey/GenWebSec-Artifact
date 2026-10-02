#!/usr/bin/env python3
"""R1.3 (extension): replay the RQ4 held-out attacks for bwApp + Juice (valid + CRS-3.3.2-bypassing)
   through CRS 4.29.0, status-only. Reproduces the EXACT request shapes + URIs the study sent (so CRS
   4.29.0 inspects byte-identical requests); 403 = blocked by updated CRS, non-403 = still bypasses.
   403 is an inbound (ARGS/body) decision, so it is backend-independent; all go through one CRS container."""
import urllib.request, urllib.parse, urllib.error, json, os, csv, re, glob, hashlib, collections
from concurrent.futures import ThreadPoolExecutor, as_completed

CRS = "http://127.0.0.1:8081"           # CRS 4.29.0 container (backend-independent for the 403 decision)
HOST = "localhost"
ROOT = "/home/vahid/Projects/GenWebSec"
OUT = f"{ROOT}/paper-frontiers/results/V2/RevisionNewResults/R1.3/rq4_bwapp_juice"
os.makedirs(OUT, exist_ok=True)

def build(target, page, payload):
    """Return (method, url, body_bytes_or_None, content_type) exactly as pilot_A1_sqli_attack_only_v2."""
    if target == "bwapp":
        if page == "login":
            body = urllib.parse.urlencode({"login": payload, "password": "wrongpw", "form": "submit"}).encode()
            return "POST", f"{CRS}/bwapp/sqli_3.php", body, "application/x-www-form-urlencoded"
        qs = urllib.parse.urlencode({"title": payload, "action": "search"})
        return "GET", f"{CRS}/bwapp/sqli_1.php?{qs}", None, None
    # juice
    if page == "login":
        body = json.dumps({"email": payload, "password": "x"}).encode()
        return "POST", f"{CRS}/juice/rest/user/login", body, "application/json"
    return "GET", f"{CRS}/juice/rest/products/search?q=" + urllib.parse.quote(payload, safe=""), None, None

def status(target, page, payload):
    method, url, body, ct = build(target, page, payload)
    hdr = {"Host": HOST}
    if ct:
        hdr["Content-Type"] = ct
    try:
        req = urllib.request.Request(url, data=body, method=method, headers=hdr)
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return -1

# load distinct held-out attacks per (target, page) across seeds 1..5
tasks = []       # (target, page, payload)
counts = {}
for target in ("bwapp", "juice"):
    for page in ("login", "search"):
        seen = set(); lines = 0
        for f in sorted(glob.glob(f"{ROOT}/results/V2/A1_HeldOut/A1_{target}_heldout_seed*/A1_{target}_{page}_winners.txt")):
            for line in open(f, encoding="utf-8", errors="replace"):
                s = line.rstrip("\n")
                if s and not s.startswith("#"):
                    lines += 1
                    if s not in seen:
                        seen.add(s)
        counts[(target, page)] = (lines, len(seen))
        for p in seen:
            tasks.append((target, page, p))

print("held-out corpus (lines / distinct):")
for k, v in counts.items():
    print(f"  {k[0]}/{k[1]}: lines={v[0]}  distinct={v[1]}")
print("total distinct tasks:", len(tasks))

def work(t):
    target, page, payload = t
    return (target, page, payload, status(target, page, payload))

results = []; done = 0
with ThreadPoolExecutor(max_workers=12) as ex:
    futs = [ex.submit(work, t) for t in tasks]
    for fu in as_completed(futs):
        results.append(fu.result()); done += 1
        if done % 500 == 0:
            print(f"  ...{done}/{len(tasks)}")

# per-request CSV (payload hashed)
per = f"{OUT}/rq4_bwapp_juice_through_crs429_perrequest.csv"
with open(per, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["target", "page", "payload_sha1", "status", "blocked_by_crs429"])
    for target, page, payload, st in sorted(results, key=lambda r: (r[0], r[1])):
        w.writerow([target, page, hashlib.sha1(payload.encode("utf-8", "replace")).hexdigest()[:16], st, int(st == 403)])

with open(f"{OUT}/rq4_still_bypassing_raw_PRIVATE.txt", "w", encoding="utf-8") as fh:
    for target, page, payload, st in results:
        if st != 403:
            fh.write(f"{target}\t{page}\t{st}\t{payload}\n")

# summary
summ = f"{OUT}/rq4_bwapp_juice_through_crs429_summary.csv"
with open(summ, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["scope", "n_distinct", "blocked_crs429", "still_bypassing", "block_rate_pct", "persistence_pct", "status_dist"])
    def emit(label, rows):
        n = len(rows); blk = sum(1 for r in rows if r[3] == 403); byp = n - blk
        dist = dict(collections.Counter(r[3] for r in rows))
        br = 100.0 * blk / n if n else 0.0
        w.writerow([label, n, blk, byp, f"{br:.2f}", f"{100.0*byp/n if n else 0:.2f}", dist])
        print(f"  {label:<16} n={n:<5} blocked={blk:<5} bypass={byp:<4} block%={br:6.2f}  dist={dist}")
    for target in ("bwapp", "juice"):
        emit(f"{target} (all)", [r for r in results if r[0] == target])
        for page in ("login", "search"):
            emit(f"{target}:{page}", [r for r in results if r[0] == target and r[1] == page])
print("per-request ->", per)
print("summary     ->", summ)
print("== RQ4 bwapp/juice replay done ==")

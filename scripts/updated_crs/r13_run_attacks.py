#!/usr/bin/env python3
"""R1.3 attack replay: send EVERY RQ1 (CRS-3.3.2-bypassing) attack through CRS 4.29.0, status-only.
   403 = blocked by updated CRS ; non-403 = still bypasses. Host: localhost (baseline-faithful).
   Writes a per-request CSV (payloads hashed) + per-context summary; reconciles counts to RQ1."""
import urllib.request, urllib.parse, urllib.error, glob, os, csv, re, hashlib
from concurrent.futures import ThreadPoolExecutor, as_completed

SQLI = "http://127.0.0.1:8081"   # crs-sqli -> customapp
XSS  = "http://127.0.0.1:8086"   # crs-xss  -> customxss
HOST = "localhost"
ROOT = "/home/vahid/Projects/GenWebSec"
OUT  = f"{ROOT}/paper-frontiers/results/V2/RevisionNewResults/R1.3/attack_replay"
os.makedirs(OUT, exist_ok=True)

SQLI_CFG = {"login": ("login", "username", "POST", {"password": "x"}), "search": ("search", "q", "GET", {}),
            "product": ("product", "id", "GET", {}), "filter": ("filter", "category", "GET", {})}
XSS_CFG  = {"search": ("search.php", "q", "GET", {}), "calc": ("calc.php", "expr", "GET", {})}

def status(base, path, param, payload, method, extra):
    params = dict(extra); params[param] = payload
    data = urllib.parse.urlencode(params)
    hdr = {"Host": HOST}
    try:
        if method == "GET":
            req = urllib.request.Request(f"{base}/{path}?{data}", headers=hdr)
        else:
            hdr["Content-Type"] = "application/x-www-form-urlencoded"
            req = urllib.request.Request(f"{base}/{path}", data=data.encode(), method="POST", headers=hdr)
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception as e:
        return -1

def seed_of(path):
    m = re.search(r"seed(\d+)", path)
    return int(m.group(1)) if m else -1

# build the task list from the winners files (one task per winner line = RQ1's denominator basis)
tasks = []   # (family, page, seed, idx, payload, base, path, param, method, extra)
for page, (path, param, method, extra) in SQLI_CFG.items():
    for f in sorted(glob.glob(f"{ROOT}/results/V2/CustomApp_A1/*A1_CRSonly_seed*/A1_customapp_{page}_winners.txt")):
        s = seed_of(f); idx = 0
        for line in open(f, encoding="utf-8", errors="replace"):
            line = line.rstrip("\n")
            if line.strip() and not line.startswith("#"):
                tasks.append(("sqli", page, s, idx, line, SQLI, path, param, method, extra)); idx += 1
for page, (path, param, method, extra) in XSS_CFG.items():
    for f in sorted(glob.glob(f"{ROOT}/results/V2/CustomApp_A2/*A2_CRSonly_seed*/A2_customxss_{page}_winners.txt")):
        s = seed_of(f); idx = 0
        for line in open(f, encoding="utf-8", errors="replace"):
            line = line.rstrip("\n")
            if line.strip() and not line.startswith("#"):
                tasks.append(("xss", page, s, idx, line, XSS, path, param, method, extra)); idx += 1

n_sqli = sum(1 for t in tasks if t[0] == "sqli")
n_xss  = sum(1 for t in tasks if t[0] == "xss")
print(f"corpus: SQLi winner-lines = {n_sqli}  (RQ1 reported 9159)   XSS winner-lines = {n_xss}  (RQ1 reported 2892)")

def work(t):
    fam, page, s, idx, payload, base, path, param, method, extra = t
    st = status(base, path, param, payload, method, extra)
    return (fam, page, s, idx, payload, st)

results = []
done = 0
with ThreadPoolExecutor(max_workers=12) as ex:
    futs = [ex.submit(work, t) for t in tasks]
    for fu in as_completed(futs):
        results.append(fu.result()); done += 1
        if done % 1000 == 0:
            print(f"  ...{done}/{len(tasks)}")

# per-request CSV (payload hashed, publishable)
per = f"{OUT}/rq1_through_crs429_perrequest.csv"
with open(per, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["family", "page", "cg_attack_seed", "idx", "payload_sha1", "status", "blocked_by_crs429"])
    for fam, page, s, idx, payload, st in sorted(results, key=lambda r: (r[0], r[1], r[2], r[3])):
        h = hashlib.sha1(payload.encode("utf-8", "replace")).hexdigest()[:16]
        w.writerow([fam, page, s, idx, h, st, int(st == 403)])

# private raw list of attacks that STILL bypass (for our analysis; excluded from the public artifact)
with open(f"{OUT}/still_bypassing_raw_PRIVATE.txt", "w", encoding="utf-8") as fh:
    for fam, page, s, idx, payload, st in results:
        if st != 403:
            fh.write(f"{fam}\t{page}\tseed{s}\t{st}\t{payload}\n")

# summaries (per family, per page); line-basis and distinct-payload basis
def summarize(rows):
    n = len(rows)
    blk = sum(1 for r in rows if r[5] == 403)
    byp = n - blk
    neg = sum(1 for r in rows if r[5] == -1)
    # distinct payloads
    seen = {}
    for r in rows:
        seen.setdefault(r[4], r[5])  # payload -> status (deterministic)
    dn = len(seen); dblk = sum(1 for v in seen.values() if v == 403)
    return n, blk, byp, neg, dn, dblk

summ = f"{OUT}/rq1_through_crs429_summary.csv"
with open(summ, "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["scope", "n_requests", "blocked_crs429", "still_bypassing", "errors_neg1",
                "block_rate_pct", "persistence_pct", "distinct_payloads", "distinct_blocked", "distinct_block_rate_pct"])
    def emit(label, rows):
        n, blk, byp, neg, dn, dblk = summarize(rows)
        br = 100.0 * blk / n if n else 0.0
        pr = 100.0 * byp / n if n else 0.0
        dbr = 100.0 * dblk / dn if dn else 0.0
        w.writerow([label, n, blk, byp, neg, f"{br:.2f}", f"{pr:.2f}", dn, dblk, f"{dbr:.2f}"])
        print(f"  {label:<22} n={n:<6} blocked={blk:<6} bypass={byp:<5} err={neg:<3} block%={br:5.2f} persist%={pr:5.2f}  (distinct {dblk}/{dn} = {dbr:.2f}%)")
    for fam in ("sqli", "xss"):
        emit(f"{fam} (all)", [r for r in results if r[0] == fam])
        for page in sorted({r[1] for r in results if r[0] == fam}):
            emit(f"{fam}:{page}", [r for r in results if r[0] == fam and r[1] == page])

print("per-request ->", per)
print("summary     ->", summ)
print("== attack replay done ==")

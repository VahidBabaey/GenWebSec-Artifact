#!/usr/bin/env python3
"""R2.3 PL2 benign false-positive sweep -- one unit = (FAM, TECH, SEED) via env, like benign_fp_sweep.py,
   but (1) the replay session sends browser-like headers so PL2 913101/920300 score the client, not the
   benign content; (2) outputs go under results/V2/RevisionNewResults/R2.3/PL2/benign/ (PL1 benign
   results untouched). Run only while host CRS PL2 is active.

   FP here = benign request blocked (HTTP 403) at PL2. CRS-only gives PL2's own benign FP (expected to
   rise, since the corpora were built to pass PL1); CG adds the generated-rule FP on top. Env: FAM, TECH, SEED."""
import os, sys, csv
sys.argv = sys.argv[:1]
ROOT = "/home/vahid/Projects/GenWebSec"
sys.path.insert(0, os.path.join(ROOT, "WorkFlowV2"))
import benign_fp_sweep as b   # reuse corpus loaders, ruleset build, measure_fp, set_waf

BROWSER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

FAM = b.FAM; TECH = b.TECH; EPS = b.EPS; SEED = b.SEED
OUT = os.path.join(ROOT, "results", "V2", "RevisionNewResults", "R2.3", "PL2", "benign",
                   "A1" if FAM == "sqli" else "A2")
os.makedirs(OUT, exist_ok=True)
stem = f"r23pl2_benign_{FAM}_{TECH}" + ("" if TECH == "CRS-only" else f"_seed{SEED}")

import requests
rules, missing = b.build_ruleset(FAM, TECH, SEED)
if missing:
    print(f"[warn] missing {missing}", flush=True)
corpora = {ck: b.load_corpus(paths) for ck, paths in b.CORPORA[FAM].items()}
session = requests.Session()
session.headers.update(BROWSER)   # <-- the only behavioral change vs benign_fp_sweep
session.mount("http://", requests.adapters.HTTPAdapter(pool_connections=b.FP_WORKERS,
              pool_maxsize=b.FP_WORKERS, max_retries=0))
print(f"[pl2-fp] {FAM} {TECH} seed{SEED} rules={len(rules)} "
      f"corpora={{{', '.join(f'{k}:{len(v)}' for k,v in corpora.items())}}}", flush=True)

ok, cfgout = b.set_waf([r for _, r in rules])
rows = []
if ok:
    for ck, recs in corpora.items():
        blocked, err, total, rate, _ = b.measure_fp(recs, session)
        rows.append((FAM, TECH, SEED, len(rules), ck, blocked, err, total, f"{rate:.4f}", "ok"))
        print(f"    {ck:13}: FP {blocked:>4}/{total:<5} = {rate:6.3f}%  (errors={err})", flush=True)
else:
    print(f"[pl2-fp] CONFIGTEST FAILED: {cfgout[:200]}", flush=True)
    for ck in b.CORPORA[FAM]:
        rows.append((FAM, TECH, SEED, len(rules), ck, "", "", len(corpora[ck]), "", "configtest_fail"))
b.set_waf([])

with open(os.path.join(OUT, f"{stem}.csv"), "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["family", "technique", "seed", "n_rules", "corpus", "blocked", "errors", "total", "fp_pct", "status"])
    w.writerows(rows)
print(f"[pl2-fp] wrote {os.path.join(OUT, stem)}.csv", flush=True)

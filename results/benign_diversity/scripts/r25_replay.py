#!/usr/bin/env python3
"""R2.5 benign-diversity FP replay. One unit = (CORP, TECH, SEED) via env.
   CORP=nested_json -> SQLi co-evolved rules (Juice sign-ups); CORP=rich_text -> XSS rules (customxss search).
   Reuses benign_fp_sweep (same PL1 methodology): build per-seed union ruleset, deploy, replay the
   backend-validated corpus through the WAF, FP = HTTP 403. Output under R2.5/. Run at PL1, eps=0.3."""
import os, sys, csv, json
ROOT = "/home/vahid/Projects/GenWebSec"
sys.path.insert(0, os.path.join(ROOT, "WorkFlowV2"))
import benign_fp_sweep as b
import requests

CORP = os.environ.get("CORP", "nested_json")        # nested_json | rich_text
TECH = os.environ.get("TECH", "CRS-only")
SEED = os.environ.get("SEED", "1")
FAM = "sqli" if CORP == "nested_json" else "xss"     # rule family deployed at that backend
CDIR = f"{ROOT}/results/V2/RevisionNewResults/R2.5/corpora"
path = f"{CDIR}/benign_{CORP}.jsonl"
recs = [json.loads(l) for l in open(path, encoding="utf-8") if l.strip()]
OUT = f"{ROOT}/results/V2/RevisionNewResults/R2.5/replay"
os.makedirs(OUT, exist_ok=True)
stem = f"r25_fp_{CORP}_{TECH}" + ("" if TECH == "CRS-only" else f"_seed{SEED}")

rules, missing = b.build_ruleset(FAM, TECH, SEED)
if missing:
    print(f"[warn] missing {missing}", flush=True)
session = requests.Session()
session.mount("http://", requests.adapters.HTTPAdapter(pool_connections=b.FP_WORKERS, pool_maxsize=b.FP_WORKERS, max_retries=0))
print(f"[r25] {CORP} ({FAM} rules) {TECH} seed{SEED} rules={len(rules)} corpus={len(recs)}", flush=True)
ok, cfgout = b.set_waf([r for _, r in rules])
rows = []
if ok:
    blocked, err, total, rate, samples = b.measure_fp(recs, session)
    rows.append((CORP, FAM, TECH, SEED, len(rules), blocked, err, total, f"{rate:.4f}", "ok"))
    print(f"    FP {blocked}/{total} = {rate:.3f}%  (errors={err})", flush=True)
    if blocked:
        with open(f"{OUT}/{stem}_BLOCKED.txt", "w", encoding="utf-8") as f:
            for m, u, body in samples:
                f.write(f"{m} {u}" + (f"  body={body}" if body else "") + "\n")
else:
    print(f"[r25] CONFIGTEST FAIL: {cfgout[:160]}", flush=True)
    rows.append((CORP, FAM, TECH, SEED, len(rules), "", "", len(recs), "", "configtest_fail"))
b.set_waf([])
with open(f"{OUT}/{stem}.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["corpus", "family", "technique", "seed", "n_rules", "blocked", "errors", "total", "fp_pct", "status"])
    w.writerows(rows)
print(f"[r25] wrote {OUT}/{stem}.csv", flush=True)

#!/usr/bin/env python3
"""R2.3 PL2 benign FP on the CUSTOM APP (the app the rules were trained on; admission benign corpus).
   FAM sqli|xss, TECH, SEED via env. GET each benign URL through the WAF with browser headers; FP = HTTP 403.
   Output under results/V2/RevisionNewResults/R2.3/PL2/benign/customapp/. Run while PL2 active."""
import os, sys, csv, re
ROOT = "/home/vahid/Projects/GenWebSec"
sys.path.insert(0, os.path.join(ROOT, "WorkFlowV2"))
import benign_fp_sweep as b
import requests

BROWSER = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
                  "(KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}
FAM = os.environ.get("FAM", "sqli"); TECH = os.environ.get("TECH", "CRS-only"); SEED = os.environ.get("SEED", "1")
URLFILE = f"{ROOT}/data/benignurls.txt" if FAM == "sqli" else f"{ROOT}/data/benignurls_xss.txt"
urls = [l.strip() for l in open(URLFILE, encoding="utf-8", errors="replace") if l.strip()]
# SQLi custom app is Python (serves /customapp/<page>, not .php); strip .php so benign hits the SAME
# endpoint as the attack replay. The XSS custom app is PHP (customxss/*.php) and is left as-is.
if FAM == "sqli":
    urls = [re.sub(r"(/customapp/[a-z]+)\.php", r"\1", u) for u in urls]
recs = [{"method": "GET", "url": u, "body": None, "content_type": None} for u in urls]
OUT = f"{ROOT}/results/V2/RevisionNewResults/R2.3/PL2/benign/customapp"
os.makedirs(OUT, exist_ok=True)
stem = f"r23pl2_benign_customapp_{FAM}_{TECH}" + ("" if TECH == "CRS-only" else f"_seed{SEED}")

rules, missing = b.build_ruleset(FAM, TECH, SEED)
if missing:
    print(f"[warn] missing {missing}", flush=True)
session = requests.Session(); session.headers.update(BROWSER)
session.mount("http://", requests.adapters.HTTPAdapter(pool_connections=b.FP_WORKERS, pool_maxsize=b.FP_WORKERS, max_retries=0))
print(f"[ca-fp] customapp {FAM} {TECH} seed{SEED} rules={len(rules)} urls={len(recs)}", flush=True)
ok, cfgout = b.set_waf([r for _, r in rules])
rows = []
if ok:
    blocked, err, total, rate, _ = b.measure_fp(recs, session)
    rows.append((FAM, TECH, SEED, len(rules), "customapp", blocked, err, total, f"{rate:.4f}", "ok"))
    print(f"    customapp {FAM}: FP {blocked}/{total} = {rate:.3f}%  (errors={err})", flush=True)
else:
    print(f"[ca-fp] CONFIGTEST FAILED: {cfgout[:160]}", flush=True)
    rows.append((FAM, TECH, SEED, len(rules), "customapp", "", "", len(recs), "", "configtest_fail"))
b.set_waf([])
with open(f"{OUT}/{stem}.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["family", "technique", "seed", "n_rules", "corpus", "blocked", "errors", "total", "fp_pct", "status"])
    w.writerows(rows)
print(f"[ca-fp] wrote {OUT}/{stem}.csv", flush=True)

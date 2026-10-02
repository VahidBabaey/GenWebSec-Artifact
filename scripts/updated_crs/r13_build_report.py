#!/usr/bin/env python3
"""R1.3: build the consolidated comparison tables + README by READING the summary CSVs (provenance)."""
import csv, os

R13 = "/home/vahid/Projects/GenWebSec/paper-frontiers/results/V2/RevisionNewResults/R1.3"

def rows(path):
    with open(path, encoding="utf-8") as f:
        return list(csv.DictReader(f))

atk = {r["scope"]: r for r in rows(f"{R13}/attack_replay/rq1_through_crs429_summary.csv")}
ben = {r["scope"]: r for r in rows(f"{R13}/benign/benign_through_crs429_summary.csv")}
bex = {r["corpus"]: r for r in rows(f"{R13}/benign/benign_extra_through_crs429_summary.csv")}

# ---- Table A: attack-surface persistence under CRS 4.29.0 (per context) ----
tabA = f"{R13}/R13_attack_persistence.csv"
with open(tabA, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["context", "attacks_observed_bypassed_CRS332", "blocked_by_CRS429",
                "still_bypassing_CRS429", "CRS429_block_rate_pct", "persistence_pct"])
    for ctx, key in [("SQLi (customapp)", "sqli (all)"), ("XSS (customxss)", "xss (all)")]:
        r = atk[key]
        w.writerow([ctx, r["n_requests"], r["blocked_crs429"], r["still_bypassing"],
                    r["block_rate_pct"], r["persistence_pct"]])
    # per-page detail
    for key in ["sqli:login", "sqli:search", "sqli:product", "sqli:filter", "xss:search", "xss:calc"]:
        r = atk[key]
        w.writerow([f"  {key}", r["n_requests"], r["blocked_crs429"], r["still_bypassing"],
                    r["block_rate_pct"], r["persistence_pct"]])

# ---- Table B: benign false positives under CRS 4.29.0 (all corpora) ----
tabB = f"{R13}/R13_benign_fp.csv"
with open(tabB, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["benign_corpus", "n", "false_positives_403", "fp_rate_pct"])
    w.writerow(["customapp (SQLi contexts)", ben["sqli (all)"]["n"], ben["sqli (all)"]["fp_403"], ben["sqli (all)"]["fp_rate_pct"]])
    w.writerow(["customxss (XSS contexts)", ben["xss (all)"]["n"], ben["xss (all)"]["fp_403"], ben["xss (all)"]["fp_rate_pct"]])
    for ck in ["bwapp_login", "bwapp_search", "bwapp_calc", "juice_login", "juice_search", "csic"]:
        r = bex[ck]
        w.writerow([ck, r["n"], r["fp_403"], r["fp_rate_pct"]])

# ---- Table C: RQ4 held-out attacks (bwApp, Juice) under CRS 4.29.0 ----
rq4 = {r["scope"]: r for r in rows(f"{R13}/rq4_bwapp_juice/rq4_bwapp_juice_through_crs429_summary.csv")}
rqx = {r["scope"]: r for r in rows(f"{R13}/rq4_bwapp_juice/rq4_bwapp_xss_through_crs429_summary.csv")}
tabC = f"{R13}/R13_rq4_bwapp_juice_persistence.csv"
with open(tabC, "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f)
    w.writerow(["scope", "family", "attacks_distinct", "blocked_by_CRS429", "still_bypassing",
                "CRS429_block_rate_pct", "persistence_pct"])
    for key in ["bwapp (all)", "bwapp:login", "bwapp:search"]:
        r = rq4[key]
        w.writerow([key, "SQLi", r["n_distinct"], r["blocked_crs429"], r["still_bypassing"],
                    r["block_rate_pct"], r["persistence_pct"]])
    rx = rqx["bwapp:xss_eval"]
    w.writerow(["bwapp:xss_eval", "XSS", rx["n_distinct"], rx["blocked_crs429"], rx["still_bypassing"],
                rx["block_rate_pct"], rx["persistence_pct"]])
    for key in ["juice (all)", "juice:login", "juice:search"]:
        r = rq4[key]
        w.writerow([key, "SQLi", r["n_distinct"], r["blocked_crs429"], r["still_bypassing"],
                    r["block_rate_pct"], r["persistence_pct"]])

# totals
tot_ben_n = int(ben["sqli (all)"]["n"]) + int(ben["xss (all)"]["n"]) + int(bex["ALL-extra"]["n"])
tot_ben_fp = int(ben["sqli (all)"]["fp_403"]) + int(ben["xss (all)"]["fp_403"]) + int(bex["ALL-extra"]["fp_403"])

def g(d, k):  # pretty getter
    return d[k]

print("=== Table A: attack-surface persistence under CRS 4.29.0 ===")
for ctx, key in [("SQLi (customapp)", "sqli (all)"), ("XSS (customxss)", "xss (all)")]:
    r = atk[key]
    print(f"  {ctx:<18} observed={r['n_requests']:>5}  blocked={r['blocked_crs429']:>5}  still_bypass={r['still_bypassing']:>4}  block%={r['block_rate_pct']}  persist%={r['persistence_pct']}")
print("=== Table B: benign FP under CRS 4.29.0 ===")
for label, d, n, fp, pc in [("customapp", ben, ben['sqli (all)']['n'], ben['sqli (all)']['fp_403'], ben['sqli (all)']['fp_rate_pct'])]:
    pass
print(f"  customapp   n={ben['sqli (all)']['n']:>5} FP={ben['sqli (all)']['fp_403']}  ({ben['sqli (all)']['fp_rate_pct']}%)")
print(f"  customxss   n={ben['xss (all)']['n']:>5} FP={ben['xss (all)']['fp_403']}  ({ben['xss (all)']['fp_rate_pct']}%)")
for ck in ["bwapp_login", "bwapp_search", "bwapp_calc", "juice_login", "juice_search", "csic"]:
    r = bex[ck]
    print(f"  {ck:<12} n={r['n']:>5} FP={r['fp_403']}  ({r['fp_rate_pct']}%)")
print(f"  TOTAL benign n={tot_ben_n}  FP={tot_ben_fp}")
print("=== Table C: RQ4 held-out attacks (bwApp, Juice) under CRS 4.29.0 ===")
for key in ["bwapp (all)", "bwapp:login", "bwapp:search"]:
    r = rq4[key]
    print(f"  {key:<16}(SQLi) distinct={r['n_distinct']:>5}  blocked={r['blocked_crs429']:>5}  still_bypass={r['still_bypassing']:>5}  block%={r['block_rate_pct']}")
rx = rqx["bwapp:xss_eval"]
print(f"  {'bwapp:xss_eval':<16}(XSS)  distinct={rx['n_distinct']:>5}  blocked={rx['blocked_crs429']:>5}  still_bypass={rx['still_bypassing']:>5}  block%={rx['block_rate_pct']}")
for key in ["juice (all)", "juice:login", "juice:search"]:
    r = rq4[key]
    print(f"  {key:<16}(SQLi) distinct={r['n_distinct']:>5}  blocked={r['blocked_crs429']:>5}  still_bypass={r['still_bypassing']:>5}  block%={r['block_rate_pct']}")

# ---- README ----
readme = f"""# R1.3 - Attack-surface persistence under an UPDATED OWASP CRS (+ benign FP + audit)

Reviewer R1.3 asks how much of the attack surface that bypassed the paper's baseline (OWASP CRS 3.3.2)
persists under an updated CRS, with benign false-positive rates reported alongside, plus representative
audit logs showing which request fields were inspected. The paper's main experiments remain on CRS 3.3.2;
this is an added comparison.

## Setup (host unchanged; updated CRS in a container beside it)
- Updated WAF: official `owasp/modsecurity-crs:apache` -> **OWASP CRS 4.29.0** on **ModSecurity 2.9.15**,
  Apache httpd 2.4.68. Image digest `sha256:d70df2e6fecd94ad38ba815e28782c5f7c88a17bf9472576a66dfdeacada67f8`.
- Configuration pinned to the baseline: paranoia level 1, inbound anomaly threshold 5, outbound 4,
  rule engine on. See `metadata/crs429_container_metadata.md` for the exact `docker run` commands.
- The container reverse-proxies to the same backends used in the study; all requests carry `Host: localhost`
  to match the baseline (so CRS rule 920350 "numeric-IP Host" does not add a spurious +3 anomaly).
- Measurement is status-only: HTTP 403 = blocked by the updated CRS; any non-403 = still bypasses.

## What was replayed
- Attacks: EVERY RQ1 attack that bypassed CRS 3.3.2 (9,159 SQLi + 2,892 XSS; reconciled exactly to the
  RQ1 totals). Status-only through CRS 4.29.0.
- Benign (false positives): the customapp/customxss benign corpora (2,000 + 2,000) and, additionally,
  the bwApp, juice, and CSIC-2012 benign corpora (14,363). FP is decided by CRS at the inbound phase
  before proxying, so it is backend-independent.

## Headline results (computed from the CSVs in this directory)
Attack-surface persistence under CRS 4.29.0 (see `R13_attack_persistence.csv`):
- SQLi (customapp): {atk['sqli (all)']['blocked_crs429']}/{atk['sqli (all)']['n_requests']} blocked = {atk['sqli (all)']['block_rate_pct']}%  ({atk['sqli (all)']['still_bypassing']} still bypass = {atk['sqli (all)']['persistence_pct']}%)
- XSS  (customxss): {atk['xss (all)']['blocked_crs429']}/{atk['xss (all)']['n_requests']} blocked = {atk['xss (all)']['block_rate_pct']}%  ({atk['xss (all)']['still_bypassing']} still bypass = {atk['xss (all)']['persistence_pct']}%)
- The residual concentrates in inline-comment SQLi (login) and the JS eval-sink XSS (calc.php).

Benign false positives under CRS 4.29.0 (see `R13_benign_fp.csv`):
- customapp {ben['sqli (all)']['fp_403']}/{ben['sqli (all)']['n']}, customxss {ben['xss (all)']['fp_403']}/{ben['xss (all)']['n']}, bwApp 0/4000, juice 0/2000,
  CSIC {bex['csic']['fp_403']}/{bex['csic']['n']} = {bex['csic']['fp_rate_pct']}% (6 Spanish-language POSTs with Latin-1-encoded accents).
- Total benign tested = {tot_ben_n}; total false positives = {tot_ben_fp}.

RQ4 held-out attacks (bwApp, Juice; valid + CRS-3.3.2-bypassing) under CRS 4.29.0 (see `R13_rq4_bwapp_juice_persistence.csv`):
- bwApp SQLi: {rq4['bwapp (all)']['blocked_crs429']}/{rq4['bwapp (all)']['n_distinct']} blocked = {rq4['bwapp (all)']['block_rate_pct']}% (login 100%, search {rq4['bwapp:search']['block_rate_pct']}%).
- bwApp XSS (xss_eval, eval sink): {rqx['bwapp:xss_eval']['blocked_crs429']}/{rqx['bwapp:xss_eval']['n_distinct']} blocked = {rqx['bwapp:xss_eval']['block_rate_pct']}% ({rqx['bwapp:xss_eval']['still_bypassing']} still bypass) - routed through the real bwApp backend with a bee/bug session so inbound AND outbound CRS both apply.
- Juice SQLi: {rq4['juice (all)']['blocked_crs429']}/{rq4['juice (all)']['n_distinct']} blocked = {rq4['juice (all)']['block_rate_pct']}% (login {rq4['juice:login']['block_rate_pct']}%, search {rq4['juice:search']['block_rate_pct']}% - the context breakouts contain no classic SQLi tokens and evade generic CRS entirely). Juice has no XSS context (JSON API).
- Status-only, Host: localhost, exact study request shapes reproduced; SQLi 403 is an inbound (ARGS/body) decision (backend-independent); bwApp XSS used the live backend+session for outbound coverage.

## Files
- `attack_replay/rq1_through_crs429_perrequest.csv` - per-request outcome (payload hashed), one row per RQ1 bypass.
- `attack_replay/rq1_through_crs429_summary.csv`    - block rate / persistence per context and per page.
- `attack_replay/still_bypassing_raw_PRIVATE.txt`   - raw residual payloads (NOT for publication).
- `benign/benign_through_crs429_*.csv`              - customapp/customxss benign FP (per-request + summary).
- `benign/benign_extra_through_crs429_*.csv`        - bwApp/juice/CSIC benign FP (per-request + summary).
- `benign/benign_extra_false_positives.csv`        - the 6 CSIC benign requests CRS 4.29.0 blocked.
- `audit/audit_summary.csv`                          - matched rules, anomaly score, inspected fields (blocked vs passed).
- `audit/audit_sample_redacted.jsonl`               - representative JSON audit records (payloads redacted).
- `metadata/crs429_container_metadata.md`           - image digest, versions, applied config, run commands.
- `rq4_bwapp_juice/rq4_bwapp_juice_through_crs429_*.csv` - RQ4 bwApp/Juice held-out attacks vs CRS 4.29.0 (per-request hashed + summary).
- `R13_rq4_bwapp_juice_persistence.csv`             - consolidated bwApp/Juice persistence table.

## Reproduce
Deploy: `r13_deploy.py` (in ~/); replay: `r13_run_attacks.py`, `r13_run_benign.py`, `r13_run_benign_extra.py`,
`r13_run_rq4_bwapp_juice.py`; audit: `r13_capture_audit.py`; metadata: `r13_metadata.py`; this report: `r13_build_report.py`.
"""
with open(f"{R13}/README.md", "w", encoding="utf-8") as f:
    f.write(readme)
print("\nwrote", tabA, "\n      ", tabB, "\n      ", f"{R13}/README.md")

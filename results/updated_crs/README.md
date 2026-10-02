# R1.3 - Attack-surface persistence under an UPDATED OWASP CRS (+ benign FP + audit)

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
- SQLi (customapp): 9119/9159 blocked = 99.56%  (40 still bypass = 0.44%)
- XSS  (customxss): 2448/2892 blocked = 84.65%  (444 still bypass = 15.35%)
- The residual concentrates in inline-comment SQLi (login) and the JS eval-sink XSS (calc.php).

Benign false positives under CRS 4.29.0 (see `R13_benign_fp.csv`):
- customapp 0/2000, customxss 0/2000, bwApp 0/4000, juice 0/2000,
  CSIC 6/8363 = 0.072% (6 Spanish-language POSTs with Latin-1-encoded accents).
- Total benign tested = 18363; total false positives = 6.

RQ4 held-out attacks (bwApp, Juice; valid + CRS-3.3.2-bypassing) under CRS 4.29.0 (see `R13_rq4_bwapp_juice_persistence.csv`):
- bwApp SQLi: 3562/3763 blocked = 94.66% (login 100%, search 88.87%).
- bwApp XSS (xss_eval, eval sink): 780/1278 blocked = 61.03% (498 still bypass) - routed through the real bwApp backend with a bee/bug session so inbound AND outbound CRS both apply.
- Juice SQLi: 1416/4280 blocked = 33.08% (login 71.99%, search 0.00% - the context breakouts contain no classic SQLi tokens and evade generic CRS entirely). Juice has no XSS context (JSON API).
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

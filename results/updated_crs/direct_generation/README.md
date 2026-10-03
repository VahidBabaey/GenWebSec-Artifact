# Direct generation against the updated OWASP CRS (4.29.0)

A complement to the persistence replay in the parent directory. Instead of replaying attacks that
bypassed the study baseline (OWASP CRS 3.3.2), here the co-evolutionary attack agent is pointed
directly at the latest CRS (4.29.0): from a single confirmed seed per context it generates new,
re-confirmed bypasses round by round. Supports reviewer comment R1.3 of the Frontiers revision (the
"even the latest CRS is bypassable" strand).

## Setup
- WAF: OWASP CRS 4.29.0 container (same image, digest, and configuration as the replay; paranoia
  level 1, inbound anomaly 5, outbound 4; `Host: localhost`). Route B (WAF) is the 4.29 container;
  Route A is the direct backend.
- Attack agent: new CRS-4.29 attack-prompt modules (one 4.29-confirmed seed plus an updated account of
  the evasion methods, per context). The prompt modules are WITHHELD (see `../../prompts/attack/README.md`
  and `manifests/provenance_checksums.csv`); only the structured outcomes (counts) and the drivers are
  released.
- Model: `openai/gpt-4.1-mini`. Five rounds of about 50 candidates (47 to 51 parsed per round), each
  round seeded from the previous round's confirmed winners.
- Three-step check per candidate: (1) backend-valid (the exploit works with the WAF removed),
  (2) not blocked by CRS 4.29.0 (a non-403 response through the WAF), (3) the exploit is re-confirmed on
  the WAF response (SQLi: target rows returned or admin login; XSS: a JavaScript dialog fires in a real
  browser). "distinct" means distinct payload strings.

## Headline results (computed from the CSVs in this directory)
Distinct three-step-confirmed bypasses of CRS 4.29.0, from one seed, over five rounds
(new per round -> cumulative):
- Custom app SQLi (login):      29, 25, 37, 35, 44  -> 170
- Juice Shop SQLi (login):      17, 31, 34, 35, 32  -> 149
- Custom XSS (calc, eval sink): 30, 35, 42, 41, 45  -> 193
- bWAPP XSS (xss_eval sink):    38, 33, 39, 33, 46  -> 189

False bypasses (passed the WAF but failed step three) were zero in every context. The canonical form of
each attack (the tautology `' OR '1'='1'`, and `<script>alert(1)</script>`) is blocked (HTTP 403),
confirming the ruleset is active. The two SQLi contexts are the primary evidence (an injection is
exactly what a WAF should catch); the two eval-sink XSS contexts corroborate but are permissive sinks
that execute attacker JavaScript directly, where a WAF has little purchase.

## Files
- `{customapp_login,juice_login,customxss_calc,bwapp_xss_eval}_rounds.csv` - per-round funnel counts
  (generated, validated_step1, waf_bypass_non403_step2, false_bypass, confirmed_3step, new_distinct,
  cumulative_distinct_confirmed).
- `_SUMMARY_attack429.csv` - per-context per-round new counts plus cumulative and totals.
- Raw confirmed-bypass strings (`*_confirmed_bypasses_PRIVATE.txt`) are withheld; their hashes are in
  `manifests/provenance_checksums.csv`.

## Reproduce
Drivers in `scripts/updated_crs/`: `r_attack429_newprompts_sqli.py` (`TGT=customapp|juice`, `PG=login`)
and `r_attack429_newprompts_xss.py` (`TGT=customxss|bwapp`); aggregate with
`r13_crs429_attack_summary.py`. They reuse the A1/A2 pilots and the withheld CRS-4.29 attack-prompt
modules, and route Route B at the CRS 4.29.0 container.

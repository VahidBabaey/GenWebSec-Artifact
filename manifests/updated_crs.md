# Updated-CRS evaluation (OWASP CRS 4.29.0)

Maps the "persistence under an updated CRS" evaluation to its files. Every attack that bypassed the study
baseline (OWASP CRS 3.3.2) is replayed through the current CRS (4.29.0); benign false positives are reported
alongside; container/configuration metadata and representative audit logs are included. Supports the response
to reviewer comment R1.3 of the Frontiers revision.

## Updated-CRS replay (per request; attack payloads hashed)
`results/updated_crs/`
- `attack_replay/rq1_through_crs429_perrequest.csv` (12,051) + `_summary.csv` -- custom-application attacks
  (RQ1 CRS-only winners) through CRS 4.29.0: SQLi 9,119/9,159 blocked (99.56%), XSS 2,448/2,892 (84.65%).
- `rq4_bwapp_juice/rq4_bwapp_juice_through_crs429_*.csv` -- bWAPP + Juice SQLi held-out attacks (RQ4):
  bWAPP 3,562/3,763 blocked (94.66%), Juice 1,416/4,280 (33.08%; Juice search 0%).
- `rq4_bwapp_juice/rq4_bwapp_xss_through_crs429_*.csv` -- bWAPP XSS (xss_eval) via the live bWAPP backend
  with a bee/bug session (inbound+outbound): 780/1,278 blocked (61.03%).
- `R13_attack_persistence.csv`, `R13_rq4_bwapp_juice_persistence.csv` -- consolidated persistence tables.
- `README.md` -- overview + reproduction.

## Benign results (false positives under CRS 4.29.0)
`results/updated_crs/benign/`
- `benign_through_crs429_*.csv` -- custom-application + custom-XSS corpora (0/2,000 each).
- `benign_extra_through_crs429_*.csv` -- bWAPP, Juice, CSIC-2012 (0/4,000, 0/2,000, 6/8,363 = 0.072%).
- `benign_extra_false_positives.csv` -- the six CSIC requests blocked (Latin-1 encoded accents).
- `R13_benign_fp.csv` -- consolidated FP table.

## Configuration / container metadata
`configs/updated_crs/crs429_container_metadata.md` -- image reference and digest, CRS/ModSecurity/Apache
versions, applied paranoia and anomaly configuration, exact docker run commands, reverse-proxy wiring.

## Audit logs
`logs/updated_crs/` -- `audit_summary.csv` (matched rule IDs, anomaly score, inspected fields; blocked vs
passed) and `audit_sample_redacted.jsonl` (representative JSON audit records; payloads redacted).

## Generating scripts
`scripts/updated_crs/` -- deploy, replay, benign, audit, metadata, and report drivers (`r13_*.py`).

## Direct generation against CRS 4.29.0 (attack agent vs the latest ruleset)
`results/updated_crs/direct_generation/`
A complement to the replay: the co-evolutionary attack agent is pointed directly at CRS 4.29.0 and, from a
single confirmed seed per context, generates new re-confirmed bypasses round by round. Five rounds of about
50 candidates; three-step check (backend-valid; non-403 through the WAF; exploit re-confirmed on the WAF
response). Distinct three-step-confirmed bypasses: custom-app SQLi 170, Juice SQLi 149, custom-XSS calc 193,
bWAPP xss_eval 189; zero false bypasses; canonical attacks blocked (403). Supports the "even the latest CRS
is bypassable" strand of reviewer comment R1.3.
- `direct_generation/{customapp_login,juice_login,customxss_calc,bwapp_xss_eval}_rounds.csv` -- per-round
  funnel counts; `direct_generation/_SUMMARY_attack429.csv` -- consolidated; `direct_generation/README.md`.
- Drivers: `scripts/updated_crs/r_attack429_newprompts_sqli.py`, `r_attack429_newprompts_xss.py`, aggregator
  `r13_crs429_attack_summary.py`.
- WITHHELD (dual-use): the four CRS-4.29 attack-prompt modules (`*_crs429.py`) and the raw confirmed-bypass
  lists (`*_confirmed_bypasses_PRIVATE.txt`); hashes recorded in `manifests/provenance_checksums.csv`, per
  the `prompts/attack/` policy. Only counts and drivers are released.

## Notes
- The updated CRS runs in a container (OWASP CRS 4.29.0, ModSecurity 2.9.15, Apache 2.4.68) beside the
  unchanged study host (Apache 2.4.52 + ModSecurity 2.9.5 + CRS 3.3.2), at matched configuration
  (paranoia 1, inbound anomaly 5, outbound 4). All requests use `Host: localhost`.
- Raw attack payloads are not published: per-request files identify payloads only by `payload_sha1`;
  residual-attack lists (`*_PRIVATE`) are withheld. Benign corpora are retained in the clear.
- A few scripts carry canonical textbook probes (`alert(1)`, `' OR '1'='1`) used as sanity checks; these
  are not from the generated corpus.

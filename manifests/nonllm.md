# Independent non-LLM attack sources (sqlmap, CSIC/Torpeda 2012, FuzzDB, WAF-A-MoLE, Dalfox)

Maps the independent, non-LLM attack-source evaluation to its files. Four SQL-injection sources
(sqlmap, CSIC/Torpeda 2012, FuzzDB, WAF-A-MoLE) and one XSS source (Dalfox) are run through the same
execution-validation funnel as the LLM attacks, and the frozen family-specific rule sets are replayed
against the attacks that both execute and bypass baseline CRS. Supports the response to reviewer comments
R2.1 (independent attack-search strategy) and R2.4 (independent attacker for the budget-dependent-stopping
concern); FuzzDB and WAF-A-MoLE were added in the second revision round. XSStrike is not used; the XSS
source is Dalfox.

## Validation funnel
`results/nonllm/`
- `nonllm_funnel.csv` -- per source: candidates -> distinct -> execution-valid -> CRS-bypassing
  (sqlmap 1,316/329/31/0; CSIC/Torpeda 57,812/15,796/224/0; FuzzDB 2,640/660/67/2;
  WAF-A-MoLE 400,000/100,000/2,457/0; Dalfox 117/39/59/45).
- `nonllm_funnel_detail.csv` -- the same, broken down per page and per technique.

## Frozen-ruleset replay
`results/nonllm/`
- `nonllm_dalfox_replay.csv` -- the 45 Dalfox CRS-bypassing winners replayed against each per-seed
  frozen rule set (eps=0.3, seeds 1-10): CRS-only 0%, CG-Static 95.3+/-3.2% (median 93.3), CG-Adaptive
  96.0+/-3.4%.
- `results/denominators/dalfox_perseed.csv` and `dalfox_summary.csv` -- per-seed and summary, with the
  exact binomial interval (worst seed 42/45 -> 95% lower bound 81.7%).
- `nonllm_fuzzdb_replay.csv` -- the 2 FuzzDB CRS-bypassing SQLi winners replayed against each per-seed
  frozen rule set (eps=0.3, seeds 1-10): CRS-only 0%, CG-Static 95.0+/-15.8% (9 seeds block 2/2, 1 blocks
  1/2), CG-Adaptive 100.0+/-0.0%. WAF-A-MoLE produced no CRS-bypassing attacks, so it has no replay.

## Per-payload outcomes (payloads hashed)
`results/nonllm/`
- `nonllm_sqlmap_crs_outcomes.csv` (31), `nonllm_csic_crs_outcomes.csv` (224),
  `nonllm_fuzzdb_crs_outcomes.csv` (67), `nonllm_wafamole_crs_outcomes.csv` (2,457),
  `nonllm_dalfox_crs_outcomes.csv` (59) -- per-payload Route A (execution) and Route B (CRS) outcome;
  `nonllm_dalfox_replay_perattack.csv` (945) -- per-(payload, configuration) frozen-rule replay outcome
  (CRS-only plus CG-Static and CG-Adaptive, seeds 1-10). Every attack-string column is removed; the
  payload is identified only by `payload_sha1`, so these are outcome records, not payloads.

## Tool versions, method, budgets, commands
`results/nonllm/README.md` -- pinned versions (sqlmap commit `a184c89...`; Dalfox commit `ad28887...`),
the static-extraction method, the deterministic fixed budgets (the complete shipped payload set of each
tool), the frozen-ruleset replay configuration, and the script run order.

## Generating scripts
`results/nonllm/scripts/` -- extraction, Route A (backend execution) validators, Route B (CRS) checks,
and the Dalfox replay (sqlmap 01-03, CSIC 11-13, Dalfox 21-24). Payload-free; breakout templates and
smoke-test payloads redacted.

## Notes
- Raw tool payloads are not redistributed (dual-use policy); only funnel counts and replay outcomes are
  released. The CSIC/Torpeda 2012, FuzzDB (pinned commit `5656ab2...`), and WAF-A-MoLE (100,000-statement
  random sample) sources are third-party; their preprocessed corpora are hashed in
  `manifests/provenance_checksums.csv` (see `data/third-party/`).
- Of the four SQL-injection sources, sqlmap, CSIC/Torpeda, and WAF-A-MoLE are a floor: baseline CRS with
  libinjection blocks every execution-valid injection from them. Only FuzzDB (2 bypasses) and Dalfox (45
  bypasses) produce attacks that reach and test the frozen rules.

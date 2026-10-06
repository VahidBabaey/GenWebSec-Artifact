# Benign-traffic diversity supplement (nested JSON, rich text)

Maps the R2.5 benign-diversity supplement to its machine-readable artifacts. Two benign corpora in the
formats the reviewer named (nested JSON, rich text) are backend-validated, then replayed through the
frozen co-evolved rules to measure any false positive beyond the CRS baseline. Supports reviewer
comment **R2.5** (benign-traffic diversity; shadow-mode and tuning). All files are under
`results/benign_diversity/`.

GraphQL is not covered: no evaluated application exposes a GraphQL endpoint, so it is reported as an
untested format rather than probed against an endpoint that would ignore the body.

## Benign corpora (backend-validated)
`results/benign_diversity/`
- `benign_nested_json.jsonl` -- 500 Juice Shop account sign-ups (`POST /api/Users`, nested
  `securityQuestion` object); kept only when the Juice backend returns HTTP 201.
- `benign_rich_text.jsonl` -- 500 review-style search queries (`GET search.php?q=`); kept only when the
  custom-XSS backend returns HTTP 200 **and** the request passes the CRS baseline (not 403). Built from
  518 backend-valid candidates; 18 were rejected by the CRS baseline and excluded (518 = 500 + 18).

## Per-seed false-positive outcomes
`results/benign_diversity/per_seed_fp.csv` -- one row per (corpus x configuration x seed): CRS-only,
CRS+CG-Static (seeds 1-10), CRS+CG-Adaptive (seeds 1-10), for each corpus. `blocked` is HTTP 403
(false positive); every value is 0 (0/500 on both formats, every seed, both strategies).

## Rule / audit matches
`results/benign_diversity/crs_baseline_rejections.csv` -- the 18 legitimate rich-text candidates the
CRS baseline rejected during construction, each with the triggering rule from the Apache error log
(`benign_rich_text`, `crs_rule_id`, `crs_rule_msg`). All 18 carry a `<link in bio>` fragment and fire
CRS rule **941100** (XSS via libinjection); a CRS-baseline false positive, not the co-evolved rules'.

## Versions, seeds, configuration
- Apache 2.4.52, ModSecurity 2.9.5 (blocking), OWASP CRS 3.3.2, paranoia level 1, thresholds 5/4,
  JSON body processor on; full list in `environment/software-versions.txt`, CRS/ModSecurity config in
  `configs/crs/` and `configs/modsecurity/`.
- Applications: Juice Shop `bkimminich/juice-shop` 20.2.0; the custom PHP XSS application. Python 3.10.12.
- Rules: frozen per-seed co-evolved sets at eps = 0.3, seeds 1-10 (CG-Static and CG-Adaptive), from
  `rules/final_rulesets/`; nested JSON uses the SQLi family, rich text the XSS family. No new synthesis.
- Deterministic generation: `random.seed(20261006)` in both builders.

## Generating scripts
`results/benign_diversity/scripts/` -- `r25_build_corpora.py` (nested JSON + backend validation),
`r25_build_richtext500.py` (rich text + backend and CRS-baseline validation, rejection capture),
`r25_replay.py` (per-seed FP replay), `r25_agg.py` (summary), and `benign_fp_sweep.py` (the reused
false-positive engine). Scripts carry their original WSL paths.

## Notes
- Both corpora are benign and released in full, like `data/benign/`; nothing here is a withheld attack
  artifact.
- This supplement is additional to the main benign false-positive evaluation (`results/rq4_fp/`,
  `data/benign/`; `tab:fp-incidents`); it does not repeat it.

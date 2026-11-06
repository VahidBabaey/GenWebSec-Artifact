# Attack diversity (baseline CRS 3.3.2 and CRS 4.29.0)

Maps the attack-diversity appendix tables to their file. Confirms that the large attack counts reflect
genuine variety rather than near-duplicates. Supports manuscript tables `tab:div-baseline` (B7) and
`tab:div-crs429` (B8).

## Data and script
`results/diversity/attack_diversity.csv` -- one row per (attack_set, family, entry point) for the six
custom-application pages, with:
- `distinct_pct` -- the share of generated attacks whose exact text appears only once.
- `n_techniques` -- the number of distinct evasion methods a rule-based tagger marks across the set
  (out of 15 SQLi / 12 XSS methods).
- `techniques` -- the per-method `tag:count` breakdown (method NAMES only, e.g. quote_breakout, case_when,
  sink_call; these are allowed technique names, not payloads).

`analysis/attack_diversity.py` prints both tables.

## Key numbers
- Baseline (`tab:div-baseline`): distinct 97.8-100%, 7-11 techniques.
- Direct against CRS 4.29.0 (`tab:div-crs429`): distinct 90.5-100%, 3-12 techniques.

## Notes
- Only aggregate diversity metrics and method names are released; no attack strings. Derived by the
  diversity tagger over the baseline (T4) and CRS-4.29 (T10) generated-attack sets.

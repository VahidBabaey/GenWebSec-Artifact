# Rule-set economy and pipeline analysis (RQ2: PP vs CG vs RG)

Maps the analysis of why grouped pipelines produce fewer rules, and of rule length/complexity, to its
files. Tabulated from the saved fixed-corpus rulesets and clustering logs (three strategies x six contexts
x ten seeds); no new runs or model calls. Supports the response to reviewer comment R1.5 of the Frontiers
revision.

## Rule length / complexity
`results/rule_economy/`
- `rule_complexity_perseed.csv` -- per strategy/family/context/seed: rule count, distinct regexes, per-rule
  and total regex length, alternations, groups, transform chains.
- `rule_complexity_percontext.csv` -- per-context medians over seeds (the manuscript-table source).
- `rule_complexity_summary.csv` -- per strategy x family rollup.
  Finding: CG per-rule regex length is not larger than PP (CG-Static SQLi 20-59, XSS 87-344; PP 112-164,
  344-350); CG total regex length is ~250-630x shorter; every rule is a single-line `@rx` rule, phase 2,
  `deny`, no chaining (complexity is not relocated).

## Cluster / singleton statistics (group size under identical instructions)
- `cluster_singleton_perseed.csv` -- per family/context/eps/seed: round-0 clusters, singleton %, rules.
- `cluster_singleton_sweep_summary.csv` -- the eps sweep: clusters from a median of 254 (89% singletons)
  at eps=0.1 to 1 (0%) at eps=0.5, with the rule count ~1 throughout (group size does not change it).
- `rq2_cluster_coverage_perseed.txt` -- clusters formed vs sent to the defender, coverage (reconciled).

## Pipeline differences
- `pipeline_differences.csv` -- coverage recheck (CG/RG yes, PP no), rules per file, distinct/total,
  transform chains per strategy (including the earlier two-transform PP-SQLi revision in 16 runs).

## Generating scripts
`scripts/rule_economy/` -- `r15_tables.py` (this artifact's generator) and `r15_rules.py` (per-rule cross-check).

## Notes
- The published tables report rule lengths and counts only; raw rule regex text and attack payloads are not
  published.

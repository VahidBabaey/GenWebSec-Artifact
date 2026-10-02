# R1.5 - Why grouped pipelines produce fewer rules; rule length and complexity

Derived tables and per-seed measurements for reviewer comment R1.5. No new experiment and no new model
calls: everything is tabulated from the saved fixed-corpus rulesets and clustering logs (three strategies
x six injection contexts x ten seeds). Supports the response to R1.5 of the Frontiers revision.

## Headline findings (all computed from the files in this directory)
- **Rule count does not depend on group size, under identical grouped (CG) instructions.** Across the eps
  sweep the round-0 partition goes from a median of 254 clusters (89% singletons) at eps=0.1 to a single
  whole-corpus cluster (0% singletons) at eps=0.5, yet the median accepted-rule count stays at 1 at every
  eps. Group size changes synthesis effort, not the rule count. (`cluster_singleton_sweep_summary.csv`)
- **The reduction comes from the coverage step, not from "joint presentation".** CG rechecks coverage
  before each synthesis and admits a candidate only if it adds coverage; a general rule accepted early
  makes the remaining units unnecessary. At eps=0.3 the round-0 partition holds 6-32 clusters per context,
  but a median of one cluster per context (four on Login) is sent to the defender; the rest are already
  covered when reached. Coverage reaches ~100%. (`rq2_cluster_coverage_perseed.txt`)
- **PP, as implemented, issues one rule per listed bypass with no in-round coverage recheck.** Median
  accepted rules per context: PP 93-217 (SQLi) and 289-297 (XSS) against CG/RG 1-2. PP rulesets contain
  many exact-duplicate regexes; CG and RG rulesets are essentially all distinct (CG-Static SQLi 50/50).
  (`pipeline_differences.csv`, `rule_complexity_percontext.csv`)
- **Complexity is not relocated into fewer, larger expressions.** Per-rule regex length (per-context
  median range): CG-Static 20-59 (SQLi) / 87-344 (XSS) versus PP-Static 112-164 / 344-350; CG rules are
  not longer than PP rules. Total regex characters per ruleset: CG 43-61 (SQLi) / 289-370 (XSS) versus PP
  10,691-35,950 / 97,778-104,278, so CG rulesets are roughly 250-630x shorter in total. Every saved rule
  is a single-line `@rx` rule on the same target set (`ARGS|REQUEST_URI|QUERY_STRING`), phase 2, `deny`,
  no chaining. (`rule_complexity_percontext.csv`, `rule_complexity_perseed.csv`)
- **Normalization provenance disclosed.** PP-Static SQLi rulesets carry two transform chains: a two-step
  chain (urlDecodeUni, lowercase) in the 16 earlier-revision runs (2,989 rules) and the four-step chain
  (urlDecodeUni, replaceComments, compressWhitespace, lowercase) in the rest (3,898 rules). All CG, RG,
  adaptive, and PP XSS runs use the four-step chain. (`pipeline_differences.csv`)

## Files
- `rule_complexity_perseed.csv` - per (strategy, family, context, seed): n_rules, n_distinct, median and
  total regex length, median alternations/groups, transform chains.
- `rule_complexity_percontext.csv` - per-context medians over seeds (matches the manuscript table framing).
- `rule_complexity_summary.csv` - per strategy x family rollup.
- `cluster_singleton_perseed.csv` - per (family, context, eps, seed): round-0 clusters, singleton %, rules.
- `cluster_singleton_sweep_summary.csv` - the group-size comparison under identical CG instructions.
- `rq2_cluster_coverage_perseed.txt` - per-seed clusters formed vs sent to the defender, coverage (reconciled).
- `pipeline_differences.csv` - coverage-recheck, rules/file, distinct/total, transform chains per strategy.

## Reproduce
`r15_tables.py` (this directory's generator) and `r15_rules.py` (per-rule complexity cross-check), in the
WSL home. Sources under `results/V2/CustomApp_D1{,-PP}`, `CustomApp_D2{,-PP}`, `Random-Groups`,
`CustomApp_C1{,-PP}`, `CustomApp_C2{,-PP}`.

## Note
Rule regex text is a structural measurement input here; the derived tables report lengths and counts only.
The separate contributions of the PP prompt wording and of the coverage step to the PP rule count were not
isolated by a dedicated controlled run (none is planned; see the response).

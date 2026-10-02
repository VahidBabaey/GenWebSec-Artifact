# R1.6 - Qualifying-attack denominators and uncertainty for Tables 6-8 and Dalfox

Per-seed numerator/denominator data behind the blocking percentages, with attacker-seed and defense-seed
kept separate, and exact Clopper-Pearson binomial 95% confidence intervals. No new experiment or model
calls: tabulated from the saved RQ3 held-out funnel, the RQ4 per-ruleset replays, and the Dalfox replay.
Supports the response to reviewer comment R1.6 of the Frontiers revision.

## Why this matters
A reported percentage is only interpretable with its denominator (a 300-candidate set yields far fewer
*qualifying* attacks) and the right uncertainty. The current "+/-" in Tables 7-8 is the SD across the five
attack-set averages, not across defense seeds, which can hide large defense variation.

## Headline (computed from the files here)
- Clopper-Pearson self-test: 39/39 lower bound 91.0%, 250/250 lower bound 98.5% (matches the plan).
- RQ3 (Table 6), CG-Adaptive eps=0.3, eligible = CRS-bypassing valid attacks (NOT 300): per context the
  range is Login 123-253, Product-search 229-277, URL-parameter 246-283, Product-filter 221-269,
  XSS-search 57-99, XSS-calculator 39-125; rule block rate 97.4-100%. (PP-Adaptive ranges, from the
  verified plan: Login 182-225, Search 245-275, URL 258-287, Filter 215-271, XSS-search 60-98,
  XSS-calc 45-77; per-run CSV available on request.)
- RQ4 (Tables 7-8): each defense seed faces the five frozen attack sets pooled (eligible ~1,310-2,333 per
  context; per-attack-set 228-483). The misleading "90.0 +/- 0.0%" for CG-Static Juice-search is resolved:
  defense-seed range [0-100] (nine seeds block all, one blocks none); pooled 90.0%. bwApp-login CG-Adaptive
  defense-seed range [57-100].
- Dalfox: 45 eligible instances, outcome two-valued (42 or 45 blocked), median 93.33%, worst-seed exact
  binomial 95% lower bound 81.73%; 10 replays of the same 45 are not 450 independent samples.

## Files
- `rq4_perseed.csv` - per (family, context, strategy, attacker_seed, defense_seed): eligible, blocked, rate.
  THE per-seed numerator/denominator table with attacker-seed and defense-seed kept separate.
- `rq4_summary.csv` - per (context, strategy): pooled rate with blocked/eligible; defense-seed spread
  (median, min, max); attack-set spread (min, max); worst-defense-seed rate with its Clopper-Pearson 95%
  lower bound; the median defense seed's 95% interval.
- `rq3_cg_adaptive_perseed.csv` - per (family, context, seed): generated (300), backend-valid,
  CRS-bypasses (eligible), blocked-by-rules (numerator), residual, rate, Clopper-Pearson 95% interval.
- `dalfox_perseed.csv` / `dalfox_summary.csv` - per defense seed blocked/45 and the per-technique summary
  with the two-valued outcome and binomial interval.

## Notes
- Uncertainty is reported three ways, as the reviewer asked: spread across defense seeds (generated
  defenses), spread across attack sets, and the exact binomial interval over the attack sample. SD is never
  presented as a confidence interval, and the ten replays of one fixed set are not treated as independent.
- Table 6 is variation across complete adaptive runs (each run has its own defense AND its own held-out
  attack set), so its median/range mixes both sources; per-run binomial intervals are in the CSV.
- Consistency with R1.1: of the RQ4 qualifying attacks, seven Juice Shop requests returned HTTP 502 and are
  non-exploits; they remain eligible only where the R1.1 two-stage replay confirms the exploit.

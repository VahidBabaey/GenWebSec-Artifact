# RQ4: frozen-rule generalization

**Question.** After hardening is complete and the rules are frozen, do the defenses
generalize across shifts in attacker model, application and backend, and benign
traffic?

This directory holds the full RQ4 held-out block-rate artifacts, **payload-free**.
No rule generation happens in RQ4: frozen CG-Adaptive and CG-Static rulesets are
replayed against held-out attacks. The raw replay logs reference attack payloads,
so they are not released; the released matrices are counts only.

## Contents

```
rq4/
├── rq4_per_ruleset.csv           finest: one row per (family,source_application,target,page,eps,attack_seed,defense_seed,technique)
├── rq4_blockrate_matrix.csv      aggregated: per (family,target,page,eps,technique), across attack sets
├── rq4_heldout_attack_funnel.csv held-out attack generation funnel per (family,target,page,attack_seed)
└── README.md
```

## Shifts and attack sources

| Target | Backend | Held-out attacker | Shift |
| --- | --- | --- | --- |
| customapp | Python/SQLite | Claude Opus 4.7 | model shift (same app) |
| customxss | PHP | Claude Opus 4.7 | model shift (same app) |
| bwapp | PHP/MySQL | Llama-4 Maverick | cross-backend |
| juice | Node.js/SQLite | Llama-4 Maverick | cross-backend |

Both are recorded as `attack_source_model` and `shift_type` columns.

## `rq4_per_ruleset.csv` (per frozen ruleset)

One row per frozen ruleset (defense seed) replayed against one held-out attack set:

| Column | Meaning |
| --- | --- |
| `family`, `source_application`, `target`, `page`, `backend`, `attack_source_model`, `shift_type`, `eps` | context (`source_application` = the app the frozen family rules were learned on) |
| `technique` | CRS-only, CG-Adaptive, or CG-Static (static/adaptive origin) |
| `attack_seed`, `defense_seed` | the held-out attack set and the frozen ruleset |
| `n_rules` | rules in the frozen set |
| `crs_bypass_count` | distinct held-out winners replayed (valid AND CRS-bypassing) -- the replay denominator |
| `blocked`, `bypassed` | blocked / still bypassing after the rules |
| `block_rate_pct` | `blocked / crs_bypass_count` |

`crs_bypass_count` is the replay denominator (distinct CRS-bypassing winners),
matching the paper's block-rate definition. Benign false positives are a separate
measurement, in repository section 12 (`rq4_fp`), and the rule-level incident
annotations are `rq4_fp/rq4_fp_incidents.csv`; the RQ4 replays here are attacks only.

## `rq4_heldout_attack_funnel.csv` (held-out attack generation funnel)

The upstream generation funnel of each held-out attack set, per
(family, source_application, target, page, attack_seed):

| Column | Meaning |
| --- | --- |
| `generated_raw` | attack candidates generated |
| `backend_valid_raw` | of those, confirmed to exploit the target application |
| `crs_bypassing_raw` | of the valid, those that bypass baseline CRS |

These are generation-instance counts (they include duplicates). The RQ4 block rate
is computed over the **distinct** CRS-bypassing winners actually replayed, which is
`crs_bypass_count` in `rq4_per_ruleset.csv`; that distinct count is slightly smaller
than `crs_bypassing_raw` here because duplicate winners are removed before replay
(for example bWAPP login seed 1: 414 raw vs 409 distinct). This file supplies the
per-set backend-valid count; the block-rate denominator remains the distinct count
in `rq4_per_ruleset.csv`.

## `rq4_blockrate_matrix.csv` (aggregated)

Per (family, target, page, eps, technique): `mean_of_means` +/- `sd`, `median`,
`min`, `max` over the held-out attack sets, plus `pooled_block_rate`, `blocked_sum`,
and `total_sum` for the pooled (micro) average.

## Reproducing the paper's RQ4 tables

From a clean checkout:

```
python analysis/rq4_primary.py        # per-context tables at eps=0.3, micro/macro (rq4-heldout-sqli/xss)
python analysis/rq4_eps_sweep.py      # block rate per context x epsilon (rq4-heldout-*-eps)
python analysis/rq4_significance.py   # paired adaptive-vs-static: Wilcoxon + bootstrap 95% CI
```

Verified against the paper:

- Custom application: CG-Adaptive blocks 100% of held-out SQLi and ~96-100% of XSS.
- Cross-backend (pooled micro): SQLi 94.9% adaptive vs 89.4% static (+5.5); XSS
  97.6% vs 97.7%. Every per-context cell and every micro/macro average matches,
  including the hard bWAPP Login (78.5 +/- 13.6 adaptive vs 69.9 +/- 19.1 static).
- Epsilon sweep overall (micro): adaptive 98.5/97.9/97.4/91.2/98.5 and static
  98.0/95.9/94.7/92.9/93.2 across 0.1-0.5, matching the paper; eps=0.3 is robust.

## Notes

- The significance script uses a normal-approximation Wilcoxon signed-rank test
  (no scipy dependency); for the RQ4 comparisons it gives the same significance
  verdict as the exact test (the cross-backend adaptive edge is not significant at
  n=10: the bootstrap CI includes zero). The bootstrap RNG is seeded for
  reproducibility, so CI bounds are stable; the point estimates and p-values are
  exact functions of the released counts.
- A couple of standard deviations and one macro cell differ from the paper by 0.1
  through display rounding; all block-rate point values and averages match.

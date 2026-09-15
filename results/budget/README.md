# Synthesis-cost and budget accounting

Per-run cost and effort for every hardening run, and the code that turns it into the
paper's budget tables. Payload-free (counts, tokens, times, cost).

## Contents

```
budget/
├── budget_matrix.csv   one row per run (static RQ2 + adaptive RQ3)
└── README.md
```

## `budget_matrix.csv`

One row per run, 780 rows. Per-payload (PP) and random-group (RG) have no clustering
threshold and appear only at the operating point eps=0.3; the clustered strategy
(CG-Static and CG-Adaptive) is swept over the full range eps in {0.1,0.2,0.3,0.4,0.5}.
So the one file backs both the operating-point budget tables and the per-epsilon
budget tables:

| Regime | Strategy | eps | Rows |
| --- | --- | --- | --- |
| static | PP-Static | 0.3 | 60 |
| static | RG | 0.3 | 60 |
| static | CG-Static | 0.1-0.5 | 300 |
| adaptive | PP-Adaptive | 0.3 | 60 |
| adaptive | CG-Adaptive | 0.1-0.5 | 300 |

| Column | Meaning |
| --- | --- |
| `family`, `context`, `strategy`, `regime`, `eps`, `seed` | which run |
| `bypasses_B` | validated CRS bypasses hardened against (300 fixed for static; total generated for adaptive) |
| `accepted_rules` | final rule count `\|R\|` |
| `rules_per_100` | `100 * \|R\| / bypasses_B` |
| `defense_calls` | defense-model calls |
| `attacker_calls` | attacker-model calls (0 for static; `total - defense` for adaptive) |
| `calls_per_rule` | `defense_calls / \|R\|` |
| `candidates`, `rejected` | candidate rules proposed / not accepted (rejection reason breakdown in `rules/rejected_summary.csv`) |
| `input_tokens`, `output_tokens` | token totals (attacker + defender for adaptive) |
| `gen_time_s` | model-generation latency |
| `rule_eval_time_s` | rule-validation wall-time (config test, reload, replay), for every run (static and adaptive) |
| `wall_time_s` | end-to-end offline hardening time (not deployed request latency) |
| `est_cost_usd` | estimated API cost, at gpt-4.1-mini rates (0.40 in / 1.60 out per 1M tokens) |

`gen_time_s`, `rule_eval_time_s`, and `wall_time_s` are offline hardening times, not
deployed WAF request latency (which is a separate measurement, `results/latency`).

## Reproducing the paper's budget tables

```
python analysis/budget_aggregate.py
```

This prints all four budget tables from `budget_matrix.csv` alone:

1. **RQ2 static budget at eps=0.3** (paper tables rq2-budget-compare and
   rq2-budget-cost): rules/100, rejected, LLM calls, calls/rule, tokens in/out,
   validation time, generation time, cost.
2. **RQ3 adaptive budget at eps=0.3** (paper table rq3-adaptive-budget): rules/100,
   rejected, LLM calls, calls/rule, validation time, cost.
3. **CG-Static budget swept over eps** (paper table rq2-eps-budget): rules/100,
   calls/rule, validation time, rejected, cost.
4. **CG-Adaptive budget swept over eps** (paper table rq3-budget): |R|, calls/rule,
   rule-eval time, rejected, cost.

Counts (rules/100, rejected, LLM calls, |R|) are the median [min-max]; the skewed
columns (calls/rule, tokens, validation and generation time, cost) are the median
[IQR], matching the paper. The values reproduce the paper cell for cell, e.g.:

- SQLi Login PP-Static: rules/100 31.17 [27.67-46.33], rejected 668 [577-690],
  759.5 [716-773] calls, 8.2 [6.5-8.3] calls/rule, validation 551 [524-632] s,
  generation 1888 [1773-2033] s.
- SQLi Login CG-Static (eps=0.3): |R| median 0.67/100, validation 21 [14-39] s.
- SQLi Login CG-Adaptive rule-eval over eps: 14.9, 27.2, 42.0, 32.5, 13.2 s.
- CG synthesizes one or two rules for the whole 300-attack corpus against 31-99 per
  100 for per-payload, at well under one cent versus tens of cents.

Small residual differences from the printed paper cells are display rounding: cost
recomputed from the released token totals can differ by 0.01 cent, and the paper's
per-page adaptive table floor-rounds a few count medians that fall between two seeds
(for example a rejected median of 72.5 shown as 72). The matrix values are the exact
medians.

Two columns the paper puts in its per-epsilon budget tables are **not** in this file
because they are not synthesis-budget quantities: the RQ2 `Time` column of the
random-group control table is the end-to-end wall-time (`wall_time_s` here), and the
RQ3 `Blocked / 1k def-tok` column is an effectiveness ratio (held-out attacks blocked
per 1000 defense tokens) reproduced from the RQ3 effectiveness data, not from the
budget accounting.

## Rejection categories

Per-run candidate and rejected counts are here; the reason breakdown (almost
entirely no-coverage) is in `rules/rejected_summary.csv` (repository section 13).

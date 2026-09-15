# Analysis and table-generation scripts

Deterministic command-line scripts that regenerate every main-paper and appendix
result from the released, payload-free structured data. Each reads only files under
`results/`, `rules/`, and `data/`, resolves paths relative to the repository, and
takes no arguments (a few accept optional overrides). From a clean checkout:

```
python analysis/run_all.py        # runs every script below
python analysis/<script>.py       # or run one
```

Python 3.10+, standard library only (no numpy/scipy/pandas required).

## Scripts and the results they reproduce

| Script | Reproduces | Reads |
| --- | --- | --- |
| `rq1_aggregate.py` | RQ1 summary, dedup stats, per-round trajectory | `results/rq1/` |
| `rq1_confidence_intervals.py` | RQ1 bypass-rate 95% Student-t CIs | `results/rq1/` |
| `rq2_aggregate.py` | RQ2 effectiveness + budget (PP/RG/CG) | `results/rq2/` |
| `rq2_rg_paired.py` | RQ2 random-group control: paired Wilcoxon + rank-biserial | `results/rq2/` |
| `rq2_eps_sweep.py` | RQ2 per-page CG sensitivity over epsilon | `results/rq2/` |
| `rq3_aggregate.py` | RQ3 adaptive effectiveness + budget, convergence | `results/rq3/` |
| `rq3_eps_sweep.py` | RQ3 CG-Adaptive outcome over epsilon | `results/rq3/` |
| `rq3_round_trace.py` | RQ3 round-by-round trace (the "login journey") | `results/rq3/` |
| `rq4_primary.py` | RQ4 per-context tables, micro/macro averages | `results/rq4/` |
| `rq4_eps_sweep.py` | RQ4 held-out block rate over epsilon | `results/rq4/` |
| `rq4_significance.py` | RQ4 paired Wilcoxon + bootstrap 95% CI | `results/rq4/` |
| `rq4_fp.py` | RQ4 benign FP matrix + incident detail | `results/rq4_fp/` |
| `budget_aggregate.py` | all budget tables: operating-point + per-epsilon, static + adaptive | `results/budget/` |
| `nonllm_funnel.py` | non-LLM funnel + Dalfox replay | `results/nonllm/` |
| `latency_table.py` | deployed WAF request latency | `results/latency/` |

## Coverage of the specification's required scripts

| Required (repository-materials.md section 17) | Script |
| --- | --- |
| RQ1 summary statistics and trajectory | `rq1_aggregate.py` |
| RQ2 PP/RG/CG comparisons | `rq2_aggregate.py` |
| paired statistical tests | `rq2_rg_paired.py`, `rq4_significance.py` |
| rule-count summaries | `rq2_aggregate.py`, `rq3_aggregate.py` |
| model-call and token comparisons | `budget_aggregate.py` |
| RQ3 convergence statistics | `rq3_aggregate.py` |
| held-out block-rate summaries | `rq4_primary.py` |
| RQ4 micro- and macro-averages | `rq4_primary.py` |
| bootstrap confidence intervals | `rq4_significance.py` |
| Wilcoxon tests | `rq2_rg_paired.py`, `rq4_significance.py` |
| false-positive incident summaries | `rq4_fp.py` |
| latency tables | `latency_table.py` |
| appendix sensitivity tables | `rq2_eps_sweep.py`, `rq3_eps_sweep.py`, `rq4_eps_sweep.py` (outcomes); `budget_aggregate.py` (per-epsilon budget) |

## Verification against the paper

Every script was checked to reproduce its paper table. The values match the
published tables (a handful of standard deviations and one macro cell differ by 0.1
through display rounding, noted in the relevant `results/*/README.md`). Notable
exact matches: RQ1 bypass 97.7-99.6% / 74.3-80.8%; RQ2 CG 1-3 rules vs PP 93.5-297;
RQ2 RG-vs-CG 38/60 ties, Wilcoxon p=0.495, r=+0.17; RQ4 cross-backend 94.9/89.4;
the login-journey retries 3/9/6/36/9; latency +0.0% overhead at one client.

## Note on statistics without scipy

`rq2_rg_paired.py` and `rq4_significance.py` implement the Wilcoxon signed-rank test
with a normal approximation and a seeded percentile bootstrap, so the repository
needs no scientific-Python stack. For the reported comparisons this gives the same
significance verdicts as the exact test; the paper's own pipeline used scipy, and the
point estimates and effect sizes match.

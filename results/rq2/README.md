# RQ2: fixed-corpus rule synthesis (PP, RG, CG)

**Question.** On a fixed corpus of 300 validated CRS bypasses per context, how does
presenting bypasses individually (PP), in random groups (RG), or in structural
clusters (CG) affect the number, cost, and safety of the synthesized rules?

This directory holds the complete per-run RQ2 matrices, **payload-free**. The raw
run logs contain the attack payloads (the cluster listings), so they are not
released; every number the paper reports is regenerated from them here.

## Contents

```
rq2/
├── rq2_static_matrix.csv   one row per (family, page, strategy, seed) at eps=0.3
│                           PP + RG + CG  ->  6 pages x 3 strategies x 10 seeds = 180 rows
├── rq2_eps_sweep.csv       one row per (family, page, seed, epsilon) for CG
│                           6 pages x 5 eps x 10 seeds = 300 rows
└── README.md
```

## `rq2_static_matrix.csv`

| Column | Meaning |
| --- | --- |
| `family`, `page`, `strategy`, `seed` | condition and run (`strategy` in {PP, RG, CG}) |
| `corpus_size` | fixed bypass corpus (300) |
| `block_pct`, `blocked` | observed-corpus coverage |
| `accepted_rules` | final rule count, `|R|` |
| `rounds` | synthesize-and-test iterations |
| `candidates`, `rejected` | candidate rules proposed / not accepted |
| `defense_calls` | defense-model calls |
| `input_tokens`, `output_tokens`, `est_cost_usd` | token and cost accounting (cost at gpt-4.1-mini rates 0.40/1.60 per 1M in/out) |
| `rule_eval_time_s`, `wall_time_s` | offline validation and end-to-end hardening time (not deployed latency) |
| `added_fp_pct` | benign false-positive rate added over CRS |
| `clusters`, `singleton_pct`, `mean/median/max_cluster_size` | the group-size distribution (CG and RG; blank for PP) |

## `rq2_eps_sweep.csv`

The complete DBSCAN epsilon sweep for CG: `epsilon` in {0.1, 0.2, 0.3, 0.4, 0.5},
with `clusters`, `singleton_pct`, `median/max_cluster_size`, `accepted_rules`,
`defense_calls`, token counts, `added_fp_pct`, and `block_pct` per (page, seed, eps).

## Reproducing the paper's RQ2 tables

From a clean checkout:

```
python analysis/rq2_aggregate.py     # effectiveness + budget (PP/RG/CG, eps=0.3)
python analysis/rq2_rg_paired.py     # paired RG-vs-CG control (ratios + Wilcoxon, rank-biserial)
python analysis/rq2_eps_sweep.py     # per-page CG sensitivity over epsilon
```

These read only the payload-free matrices here and reproduce the paper exactly.
Spot checks against the paper:

- CG blocks the 300-attack corpus with a median of 1-3 rules where PP needs
  93.5-297 (a 50-300x difference at matched coverage).
- RG and CG are statistically indistinguishable in rule count: pooled median
  difference 0, 38/60 ties, Wilcoxon p=0.495, rank-biserial r=+0.17. Clustering's
  only efficiency edge is on the login form (calls ratio 4.99, p=0.053, r=+0.71),
  the one structurally diverse context.
- Across epsilon, block rate, rule count, and added false positives stay flat
  while the partition collapses from ~250 near-singletons at 0.1 to a single
  cluster at 0.5.

## Group assignments and the size multiset

The group-size distribution of each run is released as summary statistics
(`clusters`, `singleton_pct`, `median_cluster_size`, `max_cluster_size`), which is
the payload-free characterization of the CG and RG partitions. Exact per-cluster
membership is a deterministic function of the 300-payload corpus and epsilon;
reconstructing it requires that corpus, which is withheld because it is attack
data. The RG partition matches the CG cluster-size multiset per seed with random
membership, seeded by the run seed (see `configs/experiment/rq2-static.yaml`).

## Rules

The synthesized rules themselves (accepted and rejected, per seed) are defensive
artifacts and are released under `rules/` (repository section 13), not here.

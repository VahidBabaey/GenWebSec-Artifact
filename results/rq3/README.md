# RQ3: adaptive co-evolution

**Question.** When attack generation resumes after each defensive update, does
grouped hardening keep producing compact defenses while suppressing newly found
bypasses?

This directory holds the complete RQ3 artifacts, **payload-free**: the full
round-by-round trace of every PP-Adaptive and CG-Adaptive run, plus run-level
summaries. The raw run logs contain the attack payloads (per-round bypass listings
and confirmation batches), so they are not released; the round trace comes from
each run's payload-free per-round `metrics.csv`, and the run-level summary lines
are parsed out of the logs.

## Contents

```
rq3/
├── rq3_round_traces.csv     every hardening round of every run (PP + CG, all eps)
├── rq3_adaptive_matrix.csv  run-level summary at eps=0.3 (PP + CG), one row per (page, strategy, seed)
├── rq3_eps_sweep.csv        run-level summary for CG-Adaptive across eps 0.1..0.5
└── README.md
```

## `rq3_round_traces.csv` (the round-by-round trace)

One row per hardening round of every run. Columns:

| Column | Meaning |
| --- | --- |
| `family`, `page`, `strategy`, `epsilon`, `seed` | which run |
| `iter` | outer-loop round index from the pilot; it can skip values (rounds with no new bypasses, and confirmation rounds, are not logged), so per run the number of trace rows is the count of active hardening rounds (at most 10, the iteration cap), not `max(iter)+1` |
| `generated`, `valid_n`, `bypassed_n` | newly generated candidates, backend-valid, CRS-bypassing that round |
| `num_clusters` | synthesis units that round |
| `retries` | synthesis attempts that round (defense-model calls) |
| `rules_added`, `num_rules` | rules accepted that round / cumulative |
| `num_hard` | carried residual bypasses to the next round |
| `block_after_pct_byp` | fraction of the round's bypasses blocked after the round |
| `added_fp_pct`, `uniqueness_pct` | added FP over CRS; near-dup diversity |
| `attack_/defense_in_/out_tokens`, `rule_eval_s` | per-round token and validation-time accounting |

## `rq3_adaptive_matrix.csv` and `rq3_eps_sweep.csv`

Run-level summaries: `converged` (0/1), `heldout_block_pct`, `heldout_valid`,
`heldout_residual`, `added_fp_pct`, `accepted_rules`, `rounds`, `candidates`,
`rejected`, `defense_calls`, `total_calls`, token counts, `est_cost_usd`
(attacker + defender, at gpt-4.1-mini rates), and `wall_s`.

## Reproducing the paper's RQ3 tables

From a clean checkout:

```
python analysis/rq3_aggregate.py     # effectiveness + budget (PP vs CG, eps=0.3)
python analysis/rq3_eps_sweep.py     # CG-Adaptive outcome across epsilon
python analysis/rq3_round_trace.py   # the "login journey" round-by-round trace
```

These read only the payload-free files here and reproduce the paper:

- CG-Adaptive converges on 10/10 seeds for every context, blocking a median of
  99.6-100% of held-out attacks with 1-2 rules; PP-Adaptive needs 7-33.
- Two of the ten PP-Adaptive SQLi Filter runs do not converge (8/10).
- The login-journey trace (SQLi Login, CG, eps=0.3, slowest seed = 5 rounds)
  reproduces exactly: Bypassing 27/45/18/39/50, Retries 3/9/6/36/9, one rule at
  round 0 then a second at round 4 that closes the whole family (block 0% -> 100%).

`rq3_round_trace.py` defaults to that run; pass
`<family> <page> <strategy> <eps> <seed>` to view any other.

## A note on held-out block %

The `heldout_block_pct` column is the final stress test's block rate over
backend-valid held-out attacks (`(valid - residual) / valid`). The paper's RQ3
table uses the same quantity but over the valid *and* CRS-bypassing subset; the two
differ by at most 0.1 in two bracket minima (e.g. URL parameter 97.5 here vs 97.4),
because a few held-out attacks are blocked by CRS alone and are excluded from the
paper's denominator. `heldout_valid` and `heldout_residual` are released so either
denominator can be computed. All medians and rule/round/converged counts match the
paper exactly.

## Coverage and limitations (repository section 10)

The round-by-round trace and run-level matrices cover every field the specification
asks for except the following, which follow from the no-payloads policy and from
what the pilots logged:

- **Representative payload identifiers** are not released. The per-round
  representatives are a subset of the round's bypass payloads, shown to the model in
  the prompt; they appear in the raw logs only as payload text, and no stable
  payload-id registry was recorded, so there is no payload-free identifier to
  release. The number of synthesis units per round is given (`num_clusters`), and
  the count of representatives shown per attempt follows the cap `N_rep = 15`.
- **Synthesis-unit (cluster) membership** is released as the per-round unit count
  (`num_clusters`), not as an exact payload-to-unit assignment, which would require
  the withheld corpus.
- **Confirmation-batch outcome** is released as the convergence result
  (`converged`: 3 consecutive clean fresh batches vs reaching the round cap) and the
  final held-out stress result (`heldout_*`); the per-batch bypass counts of the
  three confirmation batches are in the withheld raw logs, not in the released trace.

Everything else in section 10 is present: per-round generated/valid/bypass/residual
counts, clusters, retries, rules added and cumulative, block rate, tokens, and
validation time in `rq3_round_traces.csv`; and stopping decision, held-out results,
call counts, cost, and convergence status in `rq3_adaptive_matrix.csv`. The
CG-Adaptive epsilon sweep in `rq3_eps_sweep.csv` includes the runs that reached the
hardening-round cap (the non-converged rows).

## Rules

The synthesized rules are released under `rules/` (repository section 13).

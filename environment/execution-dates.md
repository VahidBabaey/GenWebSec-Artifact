# Execution dates

All reported experiments ran between **2026-07-30 and 2026-09-01**.

The dates below are filesystem modification times of the result files themselves,
read from the experiment host on 2026-09-14. They are evidence of when each run
wrote its output, not a hand-kept lab diary. Where a run family was repeated, the
range covers all of its attempts.

## Per experiment family

| Result directory | First | Last | Files | What it is |
| --- | --- | --- | --- | --- |
| `CustomApp_C1_Token` | 2026-07-30 | 2026-07-30 | 3 | token-accounting probe, SQLi |
| `_item1_runlog` | 2026-08-03 | 2026-08-04 | 33 | seeded attack-generation run logs |
| `CustomApp_A1` | 2026-08-03 | 2026-08-03 | 173 | RQ1 SQLi attack baseline |
| `CustomApp_A2` | 2026-08-03 | 2026-08-03 | 80 | RQ1 XSS attack baseline |
| `_item1_corpus` | 2026-08-04 | 2026-08-04 | 6 | fixed bypass corpora construction |
| `CustomApp_D1-PP` | 2026-08-04 | 2026-08-11 | 119 | RQ2 per-payload synthesis, SQLi |
| `CustomApp_D2-PP` | 2026-08-12 | 2026-08-12 | 60 | RQ2 per-payload synthesis, XSS |
| `CustomApp_D1` | 2026-08-06 | 2026-08-10 | 600 | RQ2 cluster-guided synthesis, SQLi |
| `CustomApp_D2` | 2026-08-07 | 2026-08-07 | 300 | RQ2 cluster-guided synthesis, XSS |
| `Random-Groups` | 2026-08-31 | 2026-08-31 | 122 | RQ2 matched random-grouping control |
| `CustomApp_C1` | 2026-08-06 | 2026-08-14 | 804 | RQ3 adaptive hardening, SQLi |
| `CustomApp_C2` | 2026-08-06 | 2026-08-10 | 404 | RQ3 adaptive hardening, XSS |
| `CustomApp_C1-PP` | 2026-08-13 | 2026-08-14 | 161 | RQ3 per-payload adaptive, SQLi |
| `CustomApp_C2-PP` | 2026-08-14 | 2026-08-14 | 80 | RQ3 per-payload adaptive, XSS |
| `rules` | 2026-08-17 | 2026-08-17 | 2 | frozen rulesets used for RQ4 |
| `A1_HeldOut` | 2026-08-17 | 2026-08-18 | 2639 | RQ4 held-out replay, SQLi |
| `A2_HeldOut` | 2026-08-17 | 2026-08-18 | 1420 | RQ4 held-out replay, XSS |
| `A1-A2_BenignTest` | 2026-08-18 | 2026-09-01 | 669 | benign false-positive sweep |
| `WAF_Latency` | 2026-08-19 | 2026-08-19 | 183 | deployed request-processing overhead |
| `NonLLM_Results` | 2026-08-24 | 2026-08-24 | 51 | sqlmap, CSIC/Torpeda, Dalfox funnel |

Total: 9,924 files under `results/V2`.

## Ordering

The dates confirm the intended experimental order. Attack baselines (RQ1) run
first, fixed-corpus synthesis (RQ2) next, adaptive hardening (RQ3) alongside it,
then the rules are frozen on 2026-08-17 and every generalization measurement
(RQ4, benign sweep, latency, non-LLM funnel) runs after that freeze. No RQ4 or
benign-evaluation artifact predates the freeze, which is what the paper's claim
of a genuine freeze-then-replay protocol requires.

The random-grouping control ran last, on 2026-08-31, against the same stored
seed-specific corpora used by the earlier RQ2 conditions.

## One file dated outside this window

```
2021-02-26   results/V2/NonLLM_Results/PublicDataset/allsample.csv
```

This is a third-party public dataset, not an experimental output. Its timestamp
is the dataset's own, preserved on copy. It is not redistributed in this
repository; see `data/` for its citation, retrieval instructions, and checksum.

## Repeated and superseded runs

Several directories hold superseded attempts and are retained for audit rather
than cited by the paper:

| Directory | Why it exists |
| --- | --- |
| `CustomApp_D1__before_promptfix`, `CustomApp_D2__before_promptfix` | runs predating a defense-prompt correction |
| `CustomApp_D1 - Copy`, `CustomApp_D2 - Copy` | working copies of the same |
| `_contaminated_backup` | runs set aside after a corpus contamination check |

These are excluded from every reported number. The manifests added in a later
step record which run directories each paper table draws on, so the distinction
does not rest on directory naming.

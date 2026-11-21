# CRS-4.29.0 attack generation

The co-evolutionary attack agent run against OWASP Core Rule Set 4.29.0 on the
six controlled custom-application injection contexts. This is the data behind the
paper's CRS-4.29 attack-generation table (`tab:crs429-gen`): for each context, how
many attacks the agent generates, how many are execution-valid, and what fraction
of the execution-valid attacks evade CRS 4.29.0, over five independent runs of ten
rounds each. Payload-free: counts, rates, means, SDs, and confidence intervals
only; the confirmed bypass payloads themselves are withheld (dual-use policy).

## Contents

```
crs429_generation/
├── crs429_generation_summary.csv   per-page mean/SD/CI, plus the five per-run values
├── crs429_generation_rounds.csv    every page x 5 runs x 10 rounds of per-round counts
└── README.md
```

## Reproduced result (`analysis/crs429_generation.py`)

| Family | Context | Generated | Execution-valid | CRS-4.29 bypass % | 95% CI | False bypasses |
| --- | --- | --- | --- | --- | --- | --- |
| SQLi | Login | 500 +/- 3 | 480 +/- 7 | 78.0 +/- 6.1 | [70.3, 85.6] | 0 |
| SQLi | Search | 500 +/- 0 | 460 +/- 8 | 87.8 +/- 1.0 | [86.6, 89.0] | 0 |
| SQLi | URL parameter | 500 +/- 1 | 461 +/- 7 | 85.7 +/- 4.1 | [80.6, 90.8] | 0 |
| SQLi | Filter | 500 +/- 0 | 458 +/- 12 | 87.4 +/- 2.0 | [84.9, 89.9] | 0 |
| XSS | Search | 481 +/- 6 | 476 +/- 7 | 99.6 +/- 0.9 | [98.5, 100.0] | 0 |
| XSS | Calculator | 499 +/- 1 | 426 +/- 29 | 93.8 +/- 2.2 | [91.1, 96.6] | 0 |

Six custom-application pages, five independent runs each (30 runs, 300 rounds in
all), zero false bypasses throughout. Pooled over all runs: 14,902 attacks
generated, 13,805 execution-valid, 12,237 confirmed CRS-4.29 bypasses. The attack
agent still finds genuine, execution-valid bypasses against the current CRS on every
context, most readily on the JavaScript-context XSS search page (99.6%).

## Columns

**`crs429_generation_summary.csv`** -- one row per context (the paper table).

| Column | Meaning |
| --- | --- |
| `app`, `family`, `entry_point` | context labels (`Custom app`; `SQLi`/`XSS`; the injection point) |
| `generated_mean`, `generated_sd` | mean and sample SD (across the 5 runs) of attacks generated |
| `valid_mean`, `valid_sd` | mean and sample SD of execution-valid attacks (step 1 of the oracle) |
| `bypass_pct_mean`, `bypass_pct_sd` | mean and sample SD of the CRS-4.29 bypass rate, as a percentage of the execution-valid attacks |
| `ci_lo`, `ci_hi` | 95% confidence interval for the bypass-rate mean (Student-t, 4 degrees of freedom, n = 5) |
| `false_bypass_total` | total false bypasses across all 5 runs (0 everywhere) |
| `generated_per_seed`, `valid_per_seed`, `bypass_pct_per_seed` | the five per-run values, semicolon-separated |

The semicolons in the three `*_per_seed` columns are the only semicolons in the file;
they delimit a five-element numeric list (one value per run) and are not payload
characters.

**`crs429_generation_rounds.csv`** -- one row per (page, run, round).

| Column | Meaning |
| --- | --- |
| `page`, `family`, `entry_point`, `seed` | the run (page key, family, context, run 1-5) |
| `round` | round index, 0-9 |
| `generated` | attacks generated in this round |
| `validated_step1` | of those, execution-valid (3-step oracle, step 1) |
| `waf_bypass_non403_step2` | of the execution-valid, those CRS 4.29.0 did not block, i.e. non-403 (step 2) |
| `false_bypass` | candidates that passed step 2 but failed 3-step confirmation (0 throughout) |
| `confirmed_3step` | attacks confirmed by all three steps (equals `waf_bypass_non403_step2` here, since `false_bypass` is 0) |
| `new_distinct` | newly distinct confirmed bypasses added this round |
| `cumulative_distinct_confirmed` | running total of distinct confirmed bypasses within the run |

The per-run bypass rate is `sum(waf_bypass_non403_step2) / sum(validated_step1)` over
the ten rounds; the per-page figure is the mean over the five runs. The analysis
script recomputes every per-page rate from this file as an independent check that the
summary means follow from the raw counts.

## Reproduce

```
python analysis/crs429_generation.py
```

prints the per-page table above and the per-round cross-check (every per-page bypass
rate, recomputed from the raw counts, matches the summary to one decimal).

## What is withheld

The raw confirmed-bypass payloads (the attack strings the agent found against CRS
4.29.0) are **not** released; in the source run tree they live in separate
per-run files that are not redistributed. This folder reports only derived
quantities: counts, execution-validity and bypass outcomes, per-round and
per-run aggregates, means, SDs, and confidence intervals. See `SECURITY.md` and
the repository README for the artifact's dual-use position on attack payloads.

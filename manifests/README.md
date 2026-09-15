# Reproducibility manifests

A machine-readable record of every reported run, and a map from the submitted
paper's tables to the runs behind them.

## Contents

```
manifests/
├── run_manifests.csv          one row per reported run (identity + provenance)
├── paper_runs.csv             top-level map: each submitted-paper table -> its backing runs
├── provenance_checksums.csv   checksums of the withheld and third-party inputs
└── README.md
```

## `run_manifests.csv`

One row per reported run (1,085 rows), with:

| Column | Meaning |
| --- | --- |
| `run_id` | unique id: `<experiment>_<family>_<strategy>_<context>_eps<eps>_seed<seed>` |
| `experiment` | RQ1, RQ2, RQ3, or RQ4 |
| `family`, `strategy`, `context`, `seed`, `epsilon` | the run's identity |
| `model` | defense/attack model (`openai/gpt-4.1-mini`) |
| `attacker_model` | held-out attacker for RQ4 (Claude Opus 4.7 for custom apps, Llama-4 Maverick cross-backend); same as `model` otherwise |
| `config_version`, `prompt_version` | pipeline/prompt version (`v2`) |
| `config_hash` | SHA-256 of the config files that govern the run (see note below); one value per experiment |
| `corpus_id` | the input corpus (`generated`, `fixed-300 seed<n>`, `co-evolved`, `held-out attack-seed <n>`) |
| `output_dir` | the run's output directory under `results/V2/` |
| `start_ts`, `end_ts` | earliest / latest file mtime in the output directory |
| `status` | completion status |
| `code_commit` | see note below |

Run counts: RQ1 30, RQ2 420, RQ3 360, RQ4 275. Every output directory was resolved
on disk (`status` never `dir-missing`).

## Which runs back the paper (`paper_runs.csv`)

`paper_runs.csv` is the top-level manifest that identifies the exact runs behind each
table of the submitted (Frontiers) manuscript. One row per paper table, with:

| Column | Meaning |
| --- | --- |
| `paper_table` | the manuscript label (`tab:rq2`, `tab:rq3`, `tab:rq4-sqli`, ...) |
| `section` | `main` or `appendix` |
| `description` | what the table reports |
| `backing` | the `run_manifests.csv` filter that selects its runs, or the `results/` artifact for evaluations that are not synthesis runs (latency, non-LLM funnel, external FP) |
| `n_runs` | number of matching manifest runs (blank for the non-run evaluations) |

The headline tables are the **operating point eps = 0.3, seeds 1-10** (`tab:rq2` 180
runs, `tab:rq3` 120, `tab:rq4-sqli` 40, `tab:rq4-xss` 15); the epsilon sweeps
(`tab:rq2-eps`, `tab:rq3-coevolution`, `tab:rq4-eps-summary`) add the other four
thresholds and back the sensitivity appendix only. The representative trace
`tab:rq3-trace` is a single identifiable run, `RQ3_SQLi_CG-Adaptive_login_eps0.3_seed7`.
`tab:latency`, `tab:nonllm`, and `tab:fp-incidents` are separate evaluations (deployed
benchmark, non-LLM sources, frozen-rule benign replay), not synthesis runs, so they
point to their `results/` artifact rather than a manifest filter.

Every synthesis run also maps to a released result row under `results/`.

## A note on `config_hash`

The pipeline was driven by environment variables and stored no per-run configuration
hash, so (as with `code_commit`) none exists from run time. `config_hash` is derived
from the released configuration record instead: for each experiment it is the SHA-256
of the raw bytes of the config files that govern it, concatenated in order, namely
`common.yaml` plus that experiment's file (and `epsilon-sweep.yaml` for RQ2/RQ3/RQ4).
It is therefore one value per experiment (all reported runs share pipeline version
`v2`; the per-run variation is the seed, epsilon, page, and strategy columns). A
reviewer can recompute it directly, for example for RQ2:

```
cat configs/experiment/common.yaml configs/experiment/rq2-static.yaml \
    configs/experiment/epsilon-sweep.yaml | sha256sum
```

## A note on `code_commit`

The experiment code was not under version control when the runs were executed, so no
per-run commit hash exists. This is recorded honestly in the `code_commit` column
rather than fabricated. The reference point for the code is the tagged release of
this artifact repository (see `CITATION.cff` `version`); the released defensive code
is in `scripts/`, and the exact parameters of each run are in
`configs/experiment/`.

## Timestamps

`start_ts`/`end_ts` are filesystem modification times of the run's output files
(evidence of when the run wrote its output), in the host's local time. The
per-experiment date ranges and the freeze ordering are summarized in
`environment/execution-dates.md`; all reported runs fall between 2026-07-30 and
2026-09-01.

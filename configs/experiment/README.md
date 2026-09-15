# Experiment configuration

These files record the exact parameters of every reported experiment. Each value
was read from the experiment code and, where possible, cross-checked against the
on-disk result directories. The `source` comments give the file:line each value
comes from.

## How the experiments were actually driven

The pilots are parameterized by **environment variables**, not by a YAML file.
There was no native config file that drove the runs. So these YAMLs are a faithful
machine-readable record of the values used, with the environment variable named
for each one. To re-run, set the environment variables to the values here and
invoke the corresponding pilot; per-run specifics (which seed, which page) are in
the run manifests (repository section 18).

## Files

| File | Covers | Question |
| --- | --- | --- |
| `common.yaml` | shared parameters | (all) |
| `rq1-baseline.yaml` | attack discovery against CRS-only | RQ1 |
| `rq2-static.yaml` | fixed-corpus synthesis: PP, RG, CG | RQ2 |
| `rq3-adaptive.yaml` | adaptive co-evolution: PP, CG | RQ3 |
| `rq4-generalization.yaml` | frozen-rule replay under shift | RQ4 |
| `epsilon-sweep.yaml` | DBSCAN epsilon 0.1..0.5 | RQ2/RQ3/RQ4 |

Read `common.yaml` first; the per-experiment files add to or override it.

## Parameter coverage

Every parameter that `repository-materials.md` section 6 asks for is recorded:

| Required parameter | Where |
| --- | --- |
| attack batch size | rq1, rq3 (`batch_size: 50`) |
| temperature allocation | rq1, rq3 (`[0.7,1.0,1.3]` x `[17,17,16]`) |
| number of seeds | common (`10`, values 1..10) |
| number of rounds | rq1/rq2/rq3 (`max_iterations: 10`) |
| hardening budgets | rq2, rq3 (iterations, attempts, confirmation batches) |
| confirmation-batch logic | rq3 (`confirmation_batches: 3`, size 50) |
| held-out evaluation size | rq3 (stress 300), rq4 (all frozen winners) |
| representative-prompt cap N_rep | common (`representative_prompt_cap: 15`) |
| synthesis-attempt budget | common (`synthesis_attempts_per_unit: 3`) |
| benign false-positive threshold | common (`benign_fp_threshold: 0.01`) |
| clustering metric | common (`1 - Levenshtein.ratio`, precomputed) |
| DBSCAN epsilon values | epsilon-sweep (`0.1..0.5`), operating point 0.3 |
| min_samples | common (`min_samples: 1`) |
| grouping strategy | rq2 (PP / RG / CG), rq3 (PP / CG) |
| random-group construction | rq2 (sizes matched to DBSCAN clusters, membership randomised, seeded RNG) |
| model parameters | common (model, temperature, max_tokens, top_p, provider-seed formula) |
| target context | common (`target_contexts`) |
| random seed | common (`seeds`, provider-seed formula) |
| output paths | every per-experiment file |

## A note on the clustering metric

The paper describes clustering as "DBSCAN over a normalized Levenshtein distance
matrix". In the code the distance is `1.0 - Levenshtein.ratio(a, b)` and, because
`min_samples = 1`, DBSCAN reduces exactly to connected components. The pilots
therefore compute the distance matrix and label connected components directly;
the code records that this is label-identical to
`sklearn.cluster.DBSCAN(metric='precomputed')` for every epsilon in the sweep. A
legacy `helpers/clustering.py` exists but is not the code path used by the reported
runs; the canonical clustering is inline in the pilots.

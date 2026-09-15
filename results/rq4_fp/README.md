# RQ4: external false-positive incidents

Benign false-positive behavior of the frozen rules on external and cross-backend
corpora, and the full detail of every nonzero incident.

## Contents

```
rq4_fp/
├── rq4_fp_matrix.csv      FP rate per family, corpus, technique, epsilon (CG-Adaptive, CG-Static, RG)
├── rq4_fp_incidents.csv   the nonzero incidents, with offending rule and cause
└── README.md
```

## The headline result

- **CRS-only** blocks zero benign requests on every corpus.
- **CG-Adaptive** blocks zero on every corpus, at every epsilon, in every one of the
  ten seeds.
- **CG-Static** is clean at the operating point (eps=0.3) and on all four
  per-backend corpora, but at the two finest thresholds a single seed occasionally
  emits an over-broad rule (four nonzero cells).
- **RG** (random grouping) has one seed whose rule blocks 100% of CSIC at the
  operating point eps=0.3.

## `rq4_fp_matrix.csv`

Per (family, technique, eps, corpus): `mean_fp`, `sd_fp`, `max_fp` over the seeds,
and `blocked_sum` / `total_sum`. Corpus sizes: bWAPP and Juice Shop 1,000 each
(SQLi), bWAPP Calculator 2,000 (XSS), CSIC 2012 8,363. RG was run at eps=0.3 only
(it is the RQ2 control); CG-Adaptive and CG-Static span all five thresholds.

## `rq4_fp_incidents.csv`

One row per nonzero incident, with every field the specification asks for:
`strategy`, `family`, `corpus`, `eps`, `defense_seed`, `benign_blocked`,
`benign_total`, `own_fp_pct`, `offending_rule_id`, `offending_rule_rx`,
`matched_variables`, `example_benign`, `why_passed_admission`,
`at_operating_point`. The offending rules are defensive ModSecurity rules and are
also in `rules/` (repository section 13); the example benign requests are described
by pattern (e.g. `8-F` address fields, `/tienda1/` paths) rather than dumping the
third-party CSIC rows.

### The five incidents

| Strategy | Family | Corpus | eps | Seed | Blocked | Cause |
| --- | --- | --- | --- | --- | --- | --- |
| CG-Static | XSS | bWAPP eval sink | 0.2 | 9 | 2000/2000 (100%) | rule matches bare token `eval`; page URL is `xss_eval.php` |
| CG-Static | SQLi | CSIC | 0.1 | 4 | 125/8363 (1.49%) | rule matches a digit then `-`, e.g. `8-F` |
| CG-Static | XSS | CSIC | 0.2 | 9 | 9/8363 (0.11%) | same seed-9 bare-`eval` rule |
| CG-Static | XSS | CSIC | 0.1 | 1,10 | 6/8363 (0.07%) | same bare-`eval` overreach |
| RG | SQLi | CSIC | 0.3 | 4 | 8363/8363 (100%) | terminator branch includes a bare `/`, matching digit-then-slash in URL paths |

The four CG-Static incidents are **not** at the operating point (all at eps 0.1/0.2;
eps=0.3 is clean). The RG incident **is** at eps=0.3, which is the decisive safety
difference between random grouping and cluster-guided synthesis: on the same page
and the same 300 attacks, the cluster-guided rule keyed on a real comment opener
`/*` rather than a bare `/`.

## Why the rules passed admission but over-blocked

Every rule is admitted under the same gate: the full benign corpus is replayed
after each candidate, and any rule that raises the benign block rate is rejected.
That gate runs on the **custom application's own benign traffic**, not on these
external corpora. Each incident is an over-broad rule that passed the gate on the
custom corpus (0 FP there) yet over-blocks an unseen corpus. This is a property of
the rule a strategy produced, not of how rules were admitted: at the fine
thresholds the static runs happened to emit such rules and the co-evolved runs did
not.

## Reproduction

`rq4_fp_incidents.csv` carries a per-incident `reproduction_command` column with the
concrete steps for that row (which ruleset to assemble from `rules/accepted_rules.csv`,
which benign corpus to replay, and the expected 403 count). The general recipe is:

```
# general recipe (fill in strategy, family, page, eps, seed, corpus from the incident row)
#  1. load CRS + the frozen ruleset for <strategy>/<family>/eps<eps>/seed<seed>  (rules/)
#  2. replay the benign corpus <corpus>  (data/benign/ for bWAPP/Juice; CSIC per data/third-party/)
#  3. FP count = number of requests returning HTTP 403
```

The bWAPP and Juice Shop benign corpora are in `data/benign/external/`; CSIC 2012
is third-party (see `data/third-party/csic-torpeda-2012.md` for retrieval and
checksums). The frozen rulesets are in `rules/`.

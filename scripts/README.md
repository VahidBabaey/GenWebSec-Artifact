# Experiment-running code

The defensive and evaluation code that produced the results: rule synthesis and
admission, frozen-rule replay, the benign and latency benchmarks, and the
aggregators. The attack-generation and co-evolution drivers are withheld; see
`attack/`.

```
scripts/
├── pilots/        defense pilots: rule synthesis + admission (RQ2 static, and the RG control)
├── helpers/       the two helper modules the defensive code needs
├── aggregators/   the log/CSV aggregators that produce the paper's numbers
├── evaluation/    RQ4 frozen-rule replay, the benign FP sweep, the deployed-latency benchmark
├── attack/        statement only -- attack and co-evolution drivers are withheld
└── README.md
```

## What is released

| Directory | Files | Role |
| --- | --- | --- |
| `pilots/` | `pilot_D1_customapp_defense_v2.py`, `pilot_D2_customxss_defense_v2.py`, `pilot_RG_D1_customapp_defense.py`, `pilot_RG_D2_customxss_defense.py` | the defense agent: cluster / random-group / per-payload rule synthesis, the cumulative-FP admission gate, config test and reload. These do not generate attacks; they harden against a fixed corpus of confirmed bypasses. |
| `helpers/` | `llm_client.py`, `modsec_helpers.py`, `__init__.py` | the only two helpers the released code imports: the OpenRouter client wrapper and the ModSecurity interface (write rules, config test, reload, FPR replay). |
| `aggregators/` | `agg_*.py` (11) | parse the run logs into the per-run numbers; these are the origin of the values that `analysis/` reads from the released CSVs. |
| `evaluation/` | `rq4_replay_heldout.py`, `rq4_replay_xss.py`, `benign_fp_sweep.py`, `benign_fp_sweep_rg.py`, `waf_latency_bench.py` | frozen-rule replay (RQ4), the benign false-positive sweep, and the deployed-latency benchmark. |

## What is withheld

The attack-only pilots (`pilot_A1_*`, `pilot_A2_*`) and the co-evolution pilots
(`pilot_C1_*`, `pilot_C2_*`) are not released: they drive attack generation and
import the withheld attack-agent prompts. See `attack/README.md`. This mirrors the
prompt policy: the defensive half is released, the offensive half is not.

## Credentials and safety

`helpers/llm_client.py` reads `OPENROUTER_API_KEY` from the environment (via a
`.env` file); no key is embedded. Every file here was scanned for credentials and
for attack payloads before release; none contains either. The defense pilots import
only the redacted defense prompts (`prompts/defense/`), never the attack prompts.

## Scope of runnability

This code is released for inspection and audit, and to document exactly how the
defensive results were produced. It is not turnkey: the original runs used a
specific module layout and environment (`environment/`), and a full end-to-end
reproduction of the loop also needs the withheld attack drivers. The defensive
mechanisms, the admission gate, and the aggregation are fully readable and
re-usable here, and every reported number is regenerable from the released data via
`analysis/` without running any of this code.

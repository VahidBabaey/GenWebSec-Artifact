# Attack and co-evolution drivers (withheld)

**The attack-generation and co-evolution pilots are intentionally not included, and
will not be added.**

Withheld:

- `pilot_A1_*` and `pilot_A2_*` -- the attack-only drivers (RQ1 baseline and the
  held-out attack generation), and
- `pilot_C1_*` and `pilot_C2_*` -- the co-evolution drivers (RQ3), which run the
  full attack-generate / validate / harden loop.

## Why

These drivers generate SQL-injection and cross-site-scripting payloads that exploit
the target and evade the WAF, and they import the withheld attack-agent prompts
(`prompts/attack/`). Releasing them would publish an operational attack generator.
This is the same dual-use safeguard applied to the attack prompts and the raw
payloads; it is a deliberate omission, not missing documentation.

## What is provided instead

- The **defensive half** of the pipeline is released under `scripts/` (rule
  synthesis, admission, replay, benchmarks, aggregators).
- The attack agent's **role, parameters, and validation procedure** are described in
  the paper and recorded machine-readably in `configs/experiment/` (batch size,
  temperature allocation, seeds, dedup, oracle).
- The **outcomes** of attack generation are released as data: per-context and
  per-seed counts, validity and CRS-bypass rates, and the sanitized per-candidate
  event log (`results/rq1/`, `logs/`), without the payloads.

A full end-to-end re-run of attack generation is therefore not possible from this
repository by design. Every reported result is still reproducible from the released
structured data via `analysis/`.

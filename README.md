# GenWebSec Artifact Repository

Reproducibility artifacts for the paper *Adaptive Web Application Firewall Hardening with
Co-Evolving LLM Attack and Defense Agents* (Vahid Babaey and Arun Ravindran, University of North
Carolina at Charlotte).

> **Artifact version:** `v0-unreleased`. This repository is under construction and has not yet been
> tagged against a submitted or published version of the paper. The release identifier that
> corresponds to the paper will be recorded here and in `CITATION.cff` at tagging time.

---

## 1. What GenWebSec is

GenWebSec is an execution-grounded framework for hardening a web application firewall (WAF) against
injection attacks. It couples two large-language-model agents in a loop:

- an **attack agent** that searches for SQL-injection (SQLi) and cross-site-scripting (XSS) payloads
  which both exploit the target application and evade the WAF currently deployed, and
- a **defense agent** that reads the confirmed bypasses and writes new ModSecurity rules.

Nothing is accepted on a model's own say-so. A candidate attack counts only when the application is
observed to execute the intended exploit and the request is then observed to pass the WAF. A
candidate rule is accepted only when ModSecurity loads it, it blocks at least one bypass that was not
already blocked, and the accumulated ruleset still stays under a cumulative false-positive budget on
a held-apart corpus of benign requests.

The experiments run on ModSecurity with the OWASP Core Rule Set across six controlled injection
contexts:

| Family | Context  | Injection point        |
| ------ | -------- | ---------------------- |
| SQLi   | Login    | `username='<input>'`   |
| SQLi   | Search   | `LIKE '%<input>%'`     |
| SQLi   | Product  | `id=<input>`           |
| SQLi   | Filter   | `category='<input>'`   |
| XSS    | Search   | JS string `'<input>'`  |
| XSS    | Calculator | `eval(<input>)`      |

Generalization is evaluated on independently implemented applications, namely bWAPP (PHP/MySQL) and
OWASP Juice Shop (Node.js/SQLite).

## 2. How this repository relates to the paper

The paper appendix and this repository are meant to be read together, and they deliberately do not
contain the same things.

| | Paper appendix | This repository |
| --- | --- | --- |
| Purpose | Judge the claims | Reproduce and audit the work |
| Contents | A short configuration summary, summarized sensitivity results, the external false-positive incident summary, one representative hardening trace, the compact non-LLM validation funnel | The exhaustive per-seed, per-context, per-round, per-threshold data behind every one of those summaries |

If a number appears in the paper, the data and the script that produce it should be findable here. If
you find a number in the paper that you cannot reconstruct from this repository, that is a defect;
please open an issue.

## 3. Directory structure

```text
genwebsec-artifact/
├── README.md            this file
├── LICENSE              license terms
├── CITATION.cff         how to cite the paper and the artifact
├── SECURITY.md          authorized use and responsible disclosure
├── environment/         exact software, hardware, and execution-date records
├── prompts/             redacted defense-agent prompts; attack prompts are withheld
├── configs/             ModSecurity, CRS, and per-experiment configuration
├── data/                released corpora and dataset provenance
├── results/             structured per-run results for RQ1 through RQ4
├── rules/               generated rules, admission outcomes, final rulesets
├── logs/                sanitized structured run logs
├── scripts/             experiment-running code
├── analysis/            scripts that regenerate the paper's tables (and figure data)
└── docs/                supplementary documentation
```

## 4. Software and hardware requirements

These are the exact versions used for the reported runs. `environment/` holds the machine-readable
records and the configuration files themselves.

**WAF and server**

| Component | Version |
| --- | --- |
| Apache | 2.4.52 |
| ModSecurity | 2.9.5, blocking mode |
| OWASP CRS | 3.3.2, paranoia level 1, no rule exclusions |
| CRS anomaly thresholds | inbound 5, outbound 4 |

**Runtime**

| Component | Version |
| --- | --- |
| OS | Ubuntu 22.04.5 under WSL2, kernel 6.6.87.2 |
| Python | 3.10.12 |
| SQLite | 3.37.2 |
| MySQL | 8.0.45 |
| Selenium | 4.39.0 |
| Chromium | 150.0.7871.128, with the matching ChromeDriver |

**Models.** All language-model requests go through the OpenRouter v1 chat-completions interface using
the OpenAI Python SDK 2.8.0. The hardening attacker, the hardening defender, and the baseline attack
generator use `openai/gpt-4.1-mini`. Held-out evaluation on the controlled applications uses
`anthropic/claude-opus-4.7`, and cross-application evaluation uses `meta-llama/llama-4-maverick`.
These are provider routing identifiers; immutable provider snapshot hashes were not exposed by the
provider and are therefore not recorded.

**Hardware.** One host with an Intel Core i9-14900K, 32 logical processors allocated to WSL, 26 GB of
RAM, and 8 GB of swap. bWAPP and OWASP Juice Shop run as Docker containers behind the Apache reverse
proxy (image digests in `environment/software-versions.txt`).

## 5. Reproducing the experiments

The experiments were driven by environment variables over the pilot scripts. The exact parameters of
every reported run are recorded, machine-readably, in `configs/experiment/` (with the environment
variable and source-file line for each value), and the corpus-construction and non-LLM processing
code is in `data/scripts/` and `results/nonllm/scripts/`. To re-run:

1. Recreate the environment from `environment/requirements.txt` (Python 3.10 virtualenv) and the
   software versions in `environment/software-versions.txt`.
2. Bring up ModSecurity + CRS with the configuration in `configs/`, and the targets described in
   `environment/`.
3. Set the environment variables for the experiment family (see `configs/experiment/README.md`) and
   run the corresponding pilot.

The attack-agent prompts are withheld, so an exact reproduction of our specific attack payloads is
not possible by design; the paper and `configs/experiment/` document the generation parameters.

## 6. Reconstructing the paper's tables and figures

Every table in the main paper and the appendix is regenerable from the released, payload-free data in
`results/` by a script in `analysis/`, from a clean checkout, with no manually edited spreadsheets:

```
python analysis/run_all.py
```

runs all fifteen scripts. `analysis/README.md` maps each script to the paper table(s) it reproduces
and records the verification. The scripts use only the Python standard library.

The scripts regenerate the tables and the data behind the paper's one data-driven figure (the RQ1
bypasses-per-round trajectory, printed by `rq1_aggregate.py`). The schematic figures (the architecture
and workflow diagrams) are drawn illustrations, not results, so they are not regenerated from data.

## 7. Prompts: what is released and what is not

### Attack-agent prompts are withheld

**The prompts used to generate WAF-bypassing SQLi and XSS payloads are not in this repository and
will not be added.** They provide direct operational guidance for evading a deployed web application
firewall.

This is an intentional dual-use safeguard, not an oversight or an incomplete artifact. The paper
describes the attack agent's role, its generation parameters, and its validation procedure in enough
detail to interpret every reported result. The same statement is recorded in `prompts/attack/`, in
place of the withheld material, so that its absence is not mistaken for an incomplete artifact.

We have also excluded prompt fragments, template variables, backup copies, and any log fields that
would let the withheld prompts be reconstructed.

### Defense-agent prompts are released, redacted

The defense-agent prompt materials are released, with worked attack examples removed and marked as
redacted. What is included:

- the system prompt,
- the user prompt templates, including the separate variant used for the random-group control,
- the response schema and expected output format,
- the parsing logic and any repair prompt used after malformed model output,
- the generation parameters, and
- notes recording exactly which fields were redacted and why.

### Attack payloads

Raw generated bypass payloads are **not** released. The repository reports derived quantities:
counts, rates, identifiers, and aggregate statistics. This keeps the public artifact consistent with
the paper's position on dual-use material. See `SECURITY.md`.

## 8. Third-party datasets

Some datasets used in the evaluation are third-party and are not redistributed here. For those, the
repository provides the source citation, retrieval instructions, a checksum of the exact version
used, the preprocessing script, and the expected record counts, so that the processed inputs can be
reconstructed exactly. See `data/` for per-dataset provenance.

## 9. Citing this work

See `CITATION.cff`.

## 10. Reporting problems

For defects in the artifact, open an issue. For security concerns about the artifact itself, follow
`SECURITY.md` instead of opening a public issue.

## 11. License

This repository is released under the MIT License (SPDX: `MIT`); see `LICENSE`. Copyright (c) 2026
Vahid Babaey and Arun Ravindran, The University of North Carolina at Charlotte.

The MIT terms cover the material authored for this artifact (code, configurations, derived results,
generated rules, and documentation). Third-party datasets referenced by this repository (for example
CSIC/Torpeda 2012) are not redistributed here and keep their own terms; see `data/` for retrieval
instructions and provenance.

# Checksums and provenance

## `SHA256SUMS` (every released file)

`SHA256SUMS` at the repository root lists a SHA-256 hash for every released file
(209 files), in the standard `<hash>  <path>` format. Verify the whole artifact
from the repository root with:

```
sha256sum -c SHA256SUMS
```

This covers all the categories the artifact specification asks to checksum that are
released here:

| Category | Location under `SHA256SUMS` |
| --- | --- |
| benign corpora | `data/benign/` (7 files) |
| final per-seed rulesets | `rules/final_rulesets/` (40 files) |
| experiment configuration files | `configs/` (15 files) |
| released result tables | `results/` (66 files) |

Regenerating `SHA256SUMS` after any change and re-running the check is how a
reviewer confirms a repository copy matches the artifact used in the paper. The file
excludes only itself.

## `manifests/provenance_checksums.csv` (withheld and third-party inputs)

Two categories the specification asks to checksum are inputs we do not redistribute:
the fixed bypass corpora (attack data) and the external attack datasets after
preprocessing (they contain payloads). Their SHA-256 hashes are still recorded (13
entries), so a reviewer who reconstructs those inputs can confirm they match the
versions we used, without the payloads themselves being released.

| Category | Files |
| --- | --- |
| fixed bypass corpora (withheld) | the six pooled winner sets the per-seed 300-attack samples are drawn from |
| external attack datasets after preprocessing (withheld) | the deduplicated, page-instantiated candidate corpora that feed the non-LLM funnel: `sqlmap_candidates.tsv`, `csic_candidates.tsv`, `dalfox_candidates.tsv` |
| third-party benign after preprocessing (not redistributed) | CSIC normal replayed through baseline CRS (`csic_normal_crs_baseline.csv`, 8,363) |
| third-party source datasets (raw, not redistributed) | the Torpeda CSIC 2012 partitions (`SQLi.csv`, `XSS.csv`, `allsample.csv`) |

The three preprocessed candidate corpora are the external attack datasets *after*
extraction and page instantiation (repository section 15); hashing them lets a
reviewer confirm a byte-identical reconstruction from the pinned tool commits without
the payloads being released. The CSIC/Torpeda source hashes match those in
`data/third-party/csic-torpeda-2012.md`, which also gives the retrieval instructions
and expected record counts.

## Scope

A hash of a withheld corpus is provenance, not a release: it lets a reviewer verify
they rebuilt the same input, but it discloses nothing about the payloads. The
released benign corpora, rulesets, configs, and result tables are hashed in
`SHA256SUMS` and are present in the repository.

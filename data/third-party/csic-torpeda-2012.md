# CSIC / Torpeda 2012 dataset (not redistributed)

The Torpeda CSIC 2012 HTTP dataset is used in two places in this study:

- its **normal (benign) requests** form the external benign corpus for the
  false-positive evaluation, and
- its **anomalous SQLi and XSS requests** are one of the non-LLM attack sources
  in the RQ4 generalization funnel.

**This dataset is not redistributed here.** It is third-party data, and its
anomalous partition is attack data. Instead, this file gives everything needed to
obtain and reproduce the exact inputs we used: the citation, retrieval steps, the
checksums of the versions we processed, the record counts, and the preprocessing
script.

## Source citation

The dataset was obtained from the public repository the paper cites:

> DuckDuckBug. *cnn_waf: Web Attacks Detection Based on CNN (Torpeda CSIC 2012
> dataset).* GitHub repository. Repository snapshot accessed 2026-07-02.
> https://github.com/DuckDuckBug/cnn_waf

The Torpeda CSIC 2012 dataset itself derives from the HTTP DATASET CSIC 2010,
produced by the Information Security Institute of the Spanish National Research
Council (CSIC).

## Retrieval

1. Clone the repository above at (or after) the accessed snapshot.
2. Locate its Torpeda CSIC 2012 CSV export. It has the columns
   `file, id, label, method, path, query, url`, where `label` marks each request
   as normal or anomalous.
3. This is the file we refer to below as `allsample.csv`; its SQLi-only and
   XSS-only partitions are `SQLi.csv` and `XSS.csv`.

## Versions we processed (checksums and counts)

These are the exact files we used, so a reviewer can confirm they reconstructed
the same inputs.

| File | Rows (excl. header) | sha256 |
| --- | --- | --- |
| `allsample.csv` (full Torpeda export) | 74,147 | `22e27264c43d18adc6fbb643158815dfea8e35dc83db7daeedf918ada7cba72d` |
| `SQLi.csv` (SQLi partition) | 43,213 | `aa54b6b4ab8c68d40354d06e078baac696e333f120e0259146ae0b101dbe17fc` |
| `XSS.csv` (XSS partition) | 7,295 | `576b0f37650830f542b6d441724a672a6d2ba9463a5c99524e8ae1f416f73cd6` |

## Derived benign corpus we used

The external benign evaluation uses the **8,363 normal requests** from this
dataset, replayed through baseline ModSecurity + CRS. Replaying adds a `blocked`
column recording the CRS decision per request.

| Derived file (not redistributed) | Rows | sha256 |
| --- | --- | --- |
| `csic_normal_crs_baseline.csv` | 8,363 | `1ab87ba9ca661c0bd4fde03c7099fe12b18a6c8de23622b3364a54ab6ccf05a9` |

To reproduce it, run the preprocessing script on the normal partition:

```
python data/scripts/csic_preprocess_replay.py --input <torpeda normal CSV> \
       --base-url http://localhost/ --output csic_normal_crs_baseline.csv
```

(The script expects the `id, label, method, path, query, url` schema and preserves
GET/POST semantics exactly; see its header for details.)

## How the attack partition was used

The SQLi and XSS anomalous partitions feed the non-LLM validation funnel described
in `results/` (repository section 15): each distinct payload is sent as-is through
the same execution-validity and CRS-bypass checks as the LLM attacks, and only
those that both execute and bypass baseline CRS are replayed against the frozen
rules. We release the **counts and outcomes** of that funnel, not the payloads.
See `data/attack-corpora.md`.

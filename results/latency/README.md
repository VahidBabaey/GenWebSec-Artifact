# Deployed WAF request latency

The per-request latency the WAF adds when deployed, and in particular the marginal
latency the generated rules add on top of the CRS baseline.

## Contents

```
latency/
├── latency_summary.csv   median-of-5 percentiles, throughput, CPU, overhead per config x workload x concurrency
├── latency_raw.csv       every repeat (5 per cell): p50/p95/p99, avg, req/s, CPU
└── README.md
```

## Method

The running server is benchmarked with the `hey` HTTP load generator against the
custom application through the WAF (a sub-millisecond backend, so the measured time
is WAF processing). Each measurement issues 10,000 requests and is repeated 5 times;
the median of the 5 is reported. Three concurrency levels (1, 10, 50 clients) and six
configurations: the backend reached directly (floor), CRS alone, and CRS plus each of
the four frozen rule sets (CG-Adaptive/CG-Static x SQLi/XSS, eps=0.3, one
representative seed). Two benign workloads: `plain` (a numeric product lookup) and
`token` (a benign request carrying SQL/JS-like characters, `a<b and c>d`). Both
return HTTP 200, so the timing is request processing, not blocking.

## Fields (`latency_summary.csv`)

`config`, `workload`, `concurrency`, `p50_ms`, `p95_ms`, `p99_ms`, `req_per_sec`,
`cpu_pct` (Apache+ModSecurity CPU as % of one core), `overhead_vs_crs_pct`,
`overhead_vs_direct_pct`.

## Reproduce

```
python analysis/latency_table.py
```

reproduces the paper's latency table (plain workload) exactly, e.g. at one client
CRS and every rule set sit at p50 = 1.00 ms (overhead +0.0% over CRS), against
0.40 ms for the direct backend.

## Result

The generated rules impose no measurable latency: a handful of accepted rules add a
negligible number of regex evaluations on top of the hundreds in CRS. The WAF layer
itself adds a small fixed cost (about 0.6 ms/request at one client), which shrinks in
relative terms as concurrency rises. The large, variable p99 at 50 clients is a
single-host queuing artifact (worst for the direct backend with no WAF), not a WAF
property; the median is the stable signal. All measurements are localhost, without
network transport.

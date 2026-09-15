#!/usr/bin/env python3
"""RQ1 aggregator: attack generation vs the CRS-only baseline (A1 SQLi, A2 XSS).

Reads the released, payload-free per-run metrics under results/rq1/metrics/ and
reports, per (family, page), across the 5 seeds:
  - payloads generated (unique, after exact within-round dedup)
  - backend-valid attacks
  - CRS block % and CRS bypass % of valid  (mean +/- SD over seeds)
  - the per-round bypass trajectory (mean +/- SD)
  - exact-dedup statistics (requested vs unique)

Every number is read from a results file; nothing is hard-coded. Paths are
relative to this file, so it runs from a clean checkout.

Adapted from the original WorkFlowV2/agg_rq1_attackgen.py (absolute paths ->
repo-relative; reads only the payload-free metrics).
"""
import csv, os, statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MBASE = ROOT / "results" / "rq1" / "metrics"
SEEDS = [1, 2, 3, 4, 5]

FAMS = [
    {"family": "SQLi", "key": "A1_customapp",
     "pages": [("login", "Login (username, POST)"), ("search", "Search (q)"),
               ("product", "Product (id)"), ("filter", "Filter (category)")]},
    {"family": "XSS", "key": "A2_customxss",
     "pages": [("search", "Search (JS-string)"), ("calc", "Calculator (eval sink)")]},
]


def load(key, page):
    per_seed = []
    for s in SEEDS:
        path = MBASE / key / ("seed%d" % s) / ("%s_metrics.csv" % page)
        rows = list(csv.DictReader(open(path)))
        per_seed.append([{k: (float(v) if v not in ("", None) else 0.0)
                          for k, v in r.items()} for r in rows])
    return per_seed


def ms(vals):
    return st.mean(vals), (st.stdev(vals) if len(vals) > 1 else 0.0)


def summarize(fam):
    print("\n================= %s (5 seeds) =================" % fam["family"])
    print("%-26s %14s %14s %14s %14s" %
          ("Page", "Generated", "Valid", "CRS Block %", "CRS Bypass %"))
    for page, label in fam["pages"]:
        ps = load(fam["key"], page)
        gen, val, blk, byp = [], [], [], []
        for rows in ps:
            g = sum(r["generated"] for r in rows)
            v = sum(r["backend_valid_n"] for r in rows)
            b = sum(r["waf_blocked_n"] for r in rows)
            y = sum(r["waf_bypassed_n"] for r in rows)
            gen.append(g); val.append(v)
            blk.append(100.0 * b / v if v else 0.0)
            byp.append(100.0 * y / v if v else 0.0)
        gm, gs = ms(gen); vm, vs = ms(val); bm, bs = ms(blk); ym, ys = ms(byp)
        print("%-26s %6.0f +/- %-4.0f %6.0f +/- %-4.0f %6.1f +/- %-4.1f %6.1f +/- %-4.1f"
              % (label, gm, gs, vm, vs, bm, bs, ym, ys))


def dedup_stats(fam):
    # `generated` is the unique count after exact within-round dedup. Pooled
    # exact-string duplicate counts (generated vs unique, valid, bypasses) are in
    # results/rq1/rq1_uniqueness.csv, computed from the raw records and matching the
    # paper. `uniqueness_pct` here is the near-duplicate diversity of the confirmed
    # bypassers (threshold 0.3), a different measure, and IS in the metrics.
    print("\n----- deduplication statistics (payload-free): %s -----" % fam["family"])
    for page, label in fam["pages"]:
        ps = load(fam["key"], page)
        uniq, div = [], []
        for rows in ps:
            uniq.append(sum(r["generated"] for r in rows))       # unique after exact dedup
            div.append(st.mean([r["uniqueness_pct"] for r in rows]))  # bypasser diversity
        um, _ = ms(uniq); dm, _ = ms(div)
        print("  %-26s unique candidates ~%5.0f   bypasser near-dup diversity ~%4.1f%%"
              % (label, um, dm))


def trajectory(fam, page):
    ps = load(fam["key"], page)
    nr = min(len(rows) for rows in ps)
    xs, means, sds = [], [], []
    for r in range(nr):
        vals = [rows[r]["waf_bypassed_n"] for rows in ps]
        m, sd = ms(vals); xs.append(r); means.append(m); sds.append(sd)
    return xs, means, sds


def main():
    for fam in FAMS:
        summarize(fam)
    for fam in FAMS:
        dedup_stats(fam)
    print("\n================= TRAJECTORY (bypasses/round, mean +/- SD over 5 seeds) =================")
    for fam, page, tag in [(FAMS[0], "login", "SQLi Login"),
                           (FAMS[1], "search", "XSS Search")]:
        xs, m, sd = trajectory(fam, page)
        print("%s: %s" % (tag, "  ".join("r%d=%.0f+/-%.0f" % (r, mm, ss)
                                          for r, mm, ss in zip(xs, m, sd))))


if __name__ == "__main__":
    main()

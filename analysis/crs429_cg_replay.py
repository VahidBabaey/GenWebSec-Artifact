#!/usr/bin/env python3
"""Co-evolved rules vs CRS-4.29 held-out bypasses (tab:crs429-cg-sqli and
tab:crs429-cg-xss). Reproduces the two block-rate tables from the released
payload-free matrices.

The held-out attack sets are the generated SQLi/XSS winners that bypass OWASP
CRS 4.29.0 (5 attack seeds per page). Each frozen CG-Adaptive and CG-Static
ruleset (10 defense seeds) is replayed against them. For SQLi the rules run with
CRS 4.29 deployed (tab:crs429-cg-sqli); for XSS the rules run in isolation with
CRS disabled (tab:crs429-cg-xss).

Cell aggregation (matching the manuscript): for each attack seed, average the
block rate over the 10 defense seeds -> one value per attack seed; then report
mean +/- SD across the 5 attack-seed values. The SQLi cross-backend summary is a
count-pooled micro-average; the XSS summary is a macro-average over the pages.

Reads results/crs429_cg/crs429_cg_sqli_matrix.csv and
results/crs429_cg/crs429_cg_xss_matrix.csv. Paths relative. Standard library only.
"""
import csv, statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SQLI = ROOT / "results" / "crs429_cg" / "crs429_cg_sqli_matrix.csv"
XSS = ROOT / "results" / "crs429_cg" / "crs429_cg_xss_matrix.csv"
TECHS = ["CG-Adaptive", "CG-Static"]

# (target, page) -> display label, in table order
SQLI_PAGES = [
    ("customapp", "login",   "Custom Login"),
    ("customapp", "search",  "Custom Search"),
    ("customapp", "product", "Custom URL parameter"),
    ("customapp", "filter",  "Custom Filter"),
    ("bwapp",     "login",   "bWAPP Login"),
    ("bwapp",     "search",  "bWAPP Search"),
    ("juice",     "login",   "Juice Login"),
    ("juice",     "search",  "Juice Search"),
]
XSS_PAGES = [
    ("customxss", "search",   "Custom Search"),
    ("customxss", "calc",     "Custom Calculator"),
    ("bwapp",     "xss_eval", "bWAPP eval sink"),
]


def load(path):
    """Per-seed rows only (attack_seed 1..5); aggregate rows are skipped and
    recomputed here from the per-seed values."""
    rows = []
    with open(path, newline="") as f:
        for r in csv.DictReader(f):
            if r["attack_seed"].isdigit():
                rows.append(r)
    return rows


def cell(rows, target, page, tech):
    """mean +/- SD over the 5 per-seed averaged block rates, plus pooled counts."""
    sel = [r for r in rows if r["target"] == target and r["page"] == page
           and r["strategy"] == tech]
    vals = [float(r["mean_block_rate_over_defense_seeds"]) for r in sel]
    blocked = sum(int(r["blocked_sum"]) for r in sel)
    total = sum(int(r["total_attacks"]) for r in sel)
    return st.mean(vals), st.stdev(vals), blocked, total


def main():
    srows = load(SQLI)
    print("=" * 78)
    print("Co-evolved rules vs CRS-4.29 held-out bypasses -- SQLi (CRS 4.29 deployed)")
    print("Block % = mean +/- SD over 5 held-out attack seeds (each averaged over 10 defense seeds)")
    print("=" * 78)
    print("%-26s %16s %16s" % ("Target page", "CG-Adaptive", "CG-Static"))
    groups = [("Custom application (model shift, Claude Opus 4.7)", SQLI_PAGES[:4]),
              ("Cross-backend transfer (Llama-4 Maverick)", SQLI_PAGES[4:])]
    for name, pages in groups:
        print("-- %s" % name)
        for target, page, label in pages:
            a = cell(srows, target, page, "CG-Adaptive")
            s = cell(srows, target, page, "CG-Static")
            print("   %-23s %7.1f+/-%-6.1f %7.1f+/-%-6.1f" % (label, a[0], a[1], s[0], s[1]))
    cb = SQLI_PAGES[4:]
    for tech in TECHS:
        b = sum(cell(srows, t, p, tech)[2] for t, p, _ in cb)
        n = sum(cell(srows, t, p, tech)[3] for t, p, _ in cb)
        print("   %-23s %16.1f" % ("cross-backend micro-avg " + tech, 100.0 * b / n))

    xrows = load(XSS)
    print("\n" + "=" * 78)
    print("Co-evolved rules vs CRS-4.29 held-out bypasses -- XSS (rules in isolation, CRS disabled)")
    print("Block % = mean +/- SD over 5 held-out attack seeds (each averaged over 10 defense seeds)")
    print("=" * 78)
    print("%-26s %16s %16s" % ("Target page", "CG-Adaptive", "CG-Static"))
    macro = {t: [] for t in TECHS}
    for target, page, label in XSS_PAGES:
        a = cell(xrows, target, page, "CG-Adaptive")
        s = cell(xrows, target, page, "CG-Static")
        macro["CG-Adaptive"].append(a[0]); macro["CG-Static"].append(s[0])
        print("   %-23s %7.1f+/-%-6.1f %7.1f+/-%-6.1f" % (label, a[0], a[1], s[0], s[1]))
    print("   %-23s %16.1f %16.1f" % ("macro-average",
          st.mean(macro["CG-Adaptive"]), st.mean(macro["CG-Static"])))


if __name__ == "__main__":
    main()

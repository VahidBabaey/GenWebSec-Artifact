#!/usr/bin/env python3
"""RQ2 random-group control: paired RG-vs-CG comparison per page and pooled.

RG and CG-Static share the same 300-attack corpus per seed, so the comparison is
paired. Reports the per-seed RG-CG accepted-rule difference (median, range, ties),
the RG/CG effort ratios, and a paired Wilcoxon signed-rank test with rank-biserial
effect size on the call counts. Ports WorkFlowV2/agg_full.py PART B to the released
payload-free matrix. Paths relative to this file.
"""
import csv, math, statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "results" / "rq2" / "rq2_static_matrix.csv"
SQLI = ["login", "search", "product", "filter"]
XSS = ["search", "calc"]
LABEL = {"login": "Login form", "search": "Search", "product": "URL parameter",
         "filter": "Product filter", "calc": "Calculator (eval sink)"}


def wilcoxon(diffs):
    nz = [d for d in diffs if d != 0]
    n = len(nz)
    if n == 0:
        return dict(n=0, p=1.0, r=0.0)
    aug = sorted(((abs(d), (1 if d > 0 else -1)) for d in nz), key=lambda x: x[0])
    vals = [a for a, _ in aug]
    rank = [0.0] * n
    j = 0
    while j < n:
        k = j
        while k + 1 < n and vals[k + 1] == vals[j]:
            k += 1
        avg = (j + 1 + k + 1) / 2.0
        for m in range(j, k + 1):
            rank[m] = avg
        j = k + 1
    Wpos = sum(rank[m] for m in range(n) if aug[m][1] > 0)
    Wneg = sum(rank[m] for m in range(n) if aug[m][1] < 0)
    W = min(Wpos, Wneg)
    meanW = n * (n + 1) / 4.0
    sdW = math.sqrt(n * (n + 1) * (2 * n + 1) / 24.0)
    z = (W - meanW + 0.5) / sdW if sdW else 0.0
    p = 2 * (1 - 0.5 * (1 + math.erf(abs(z) / math.sqrt(2))))
    r = (Wpos - Wneg) / (Wpos + Wneg) if (Wpos + Wneg) else 0.0
    return dict(n=n, p=min(1.0, max(0.0, p)), r=r)


def med(v):
    return st.median(v)


def load():
    d = {}
    for r in csv.DictReader(open(MATRIX)):
        d[(r["family"], r["page"], r["strategy"], int(r["seed"]))] = r
    return d


def main():
    D = load()
    print("RQ2 control: paired RG vs CG (same 300 attacks/seed; ratios = median RG/CG; r>0 => RG larger)")
    print("%-6s %-16s %10s %6s %7s %7s %7s %14s" %
          ("Family", "Page", "dR[range]", "ties", "Calls", "Tokens", "Time", "calls (p, r)"))
    allR, allC = [], []

    def field(row, num):
        if num == "tokens_total":
            return float(row["input_tokens"]) + float(row["output_tokens"])
        return float(row[num])

    def ratio(fam, page, seeds, num, den="CG"):
        vals = []
        for s in seeds:
            a = field(D[(fam, page, "RG", s)], num); b = field(D[(fam, page, den, s)], num)
            if b:
                vals.append(a / b)
        return med(vals) if vals else float("nan")

    for fam, pages in [("SQLi", SQLI), ("XSS", XSS)]:
        for page in pages:
            seeds = [s for s in range(1, 11)
                     if (fam, page, "RG", s) in D and (fam, page, "CG", s) in D]
            dR = [int(D[(fam, page, "RG", s)]["accepted_rules"]) -
                  int(D[(fam, page, "CG", s)]["accepted_rules"]) for s in seeds]
            dC = [int(D[(fam, page, "RG", s)]["defense_calls"]) -
                  int(D[(fam, page, "CG", s)]["defense_calls"]) for s in seeds]
            allR += dR; allC += dC
            ties = sum(1 for x in dR if x == 0)
            w = wilcoxon(dC)
            rc = ratio(fam, page, seeds, "defense_calls")
            rt = ratio(fam, page, seeds, "tokens_total")
            rw = ratio(fam, page, seeds, "wall_time_s")
            print("%-6s %-16s %10s %6s %7.2f %7.2f %7.2f %14s" %
                  (fam, LABEL.get(page, page),
                   "%d[%d,%d]" % (med(dR), min(dR), max(dR)), "%d/%d" % (ties, len(seeds)),
                   rc, rt, rw, "%.3f, %+.2f" % (w["p"], w["r"])))
    wR = wilcoxon(allR); wC = wilcoxon(allC)
    tiesR = sum(1 for x in allR if x == 0)
    print("-" * 92)
    print("POOLED (60 seed-pairs): dR med=%.0f ties=%d/60  |R| Wilcoxon p=%.3f r=%+.2f  calls p=%.3f r=%+.2f"
          % (med(allR), tiesR, wR["p"], wR["r"], wC["p"], wC["r"]))


if __name__ == "__main__":
    main()

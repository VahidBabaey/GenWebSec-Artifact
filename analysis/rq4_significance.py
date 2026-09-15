#!/usr/bin/env python3
"""RQ4 significance: paired CG-Adaptive vs CG-Static at eps=0.3, by defense seed.

For each context group (Custom, Cross-backend) and family, the per-seed block rate
is pooled over the held-out attack sets in that group; the 10 paired differences
(adaptive - static) get a two-sided Wilcoxon signed-rank test and a percentile
bootstrap 95% CI of the mean paired difference (10,000 resamples).

Reads the released per-ruleset matrix results/rq4/rq4_per_ruleset.csv. Self-contained
(no scipy/numpy); the RNG is seeded for reproducibility. Paths relative.
Ports WorkFlowV2-era _rq4_sig.py.
"""
import csv, math, random
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PER = ROOT / "results" / "rq4" / "rq4_per_ruleset.csv"
EPS = "0.3"
N_BOOT = 10000
random.seed(12345)

CTX = {
    "SQLi": {"Custom": [("customapp", "login"), ("customapp", "search"),
                        ("customapp", "product"), ("customapp", "filter")],
             "Cross-backend": [("bwapp", "login"), ("bwapp", "search"),
                               ("juice", "login"), ("juice", "search")]},
    "XSS": {"Custom": [("customxss", "search"), ("customxss", "calc")],
            "Cross-backend": [("bwapp", "xss_eval")]},
}


def load():
    ps = {}
    for r in csv.DictReader(open(PER)):
        if r["eps"] != EPS or r["technique"] not in ("CG-Adaptive", "CG-Static"):
            continue
        k = (r["family"], r["target"], r["page"], r["technique"], int(r["defense_seed"]))
        d = ps.setdefault(k, [0, 0])
        d[0] += int(r["blocked"]); d[1] += int(r["crs_bypass_count"])
    return ps


def seed_rates(ps, fam, pairs, tech):
    out = []
    for cg in range(1, 11):
        b = sum(ps.get((fam, t, p, tech, cg), [0, 0])[0] for t, p in pairs)
        n = sum(ps.get((fam, t, p, tech, cg), [0, 0])[1] for t, p in pairs)
        out.append(100.0 * b / n if n else float("nan"))
    return out


def wilcoxon(diffs):
    nz = [d for d in diffs if d != 0]
    n = len(nz)
    if n == 0:
        return 1.0
    aug = sorted(((abs(d), (1 if d > 0 else -1)) for d in nz), key=lambda x: x[0])
    vals = [a for a, _ in aug]; rank = [0.0] * n; j = 0
    while j < n:
        k = j
        while k + 1 < n and vals[k + 1] == vals[j]:
            k += 1
        avg = (j + 1 + k + 1) / 2.0
        for m in range(j, k + 1):
            rank[m] = avg
        j = k + 1
    Wp = sum(rank[m] for m in range(n) if aug[m][1] > 0)
    Wn = sum(rank[m] for m in range(n) if aug[m][1] < 0)
    W = min(Wp, Wn); meanW = n * (n + 1) / 4.0
    sdW = math.sqrt(n * (n + 1) * (2 * n + 1) / 24.0)
    z = (W - meanW + 0.5) / sdW if sdW else 0.0
    return min(1.0, 2 * (1 - 0.5 * (1 + math.erf(abs(z) / math.sqrt(2)))))


def bootstrap_ci(diffs, n=N_BOOT):
    m = len(diffs)
    boots = []
    for _ in range(n):
        s = [diffs[random.randrange(m)] for _ in range(m)]
        boots.append(sum(s) / m)
    boots.sort()
    return boots[int(0.025 * n)], boots[int(0.975 * n)]


def main():
    ps = load()
    print("RQ4 paired CG-Adaptive vs CG-Static @ eps=0.3 (by defense seed; 10 pairs)")
    print("%-6s %-14s %10s %10s %8s %10s %22s" %
          ("Family", "Group", "Adapt", "Static", "mean d", "Wilcoxon p", "bootstrap 95% CI"))
    for fam in ["SQLi", "XSS"]:
        for group, pairs in CTX[fam].items():
            A = seed_rates(ps, fam, pairs, "CG-Adaptive")
            S = seed_rates(ps, fam, pairs, "CG-Static")
            d = [a - s for a, s in zip(A, S)]
            md = sum(d) / len(d)
            p = wilcoxon(d)
            lo, hi = bootstrap_ci(d)
            print("%-6s %-14s %10.1f %10.1f %8.2f %10.3f    [%+.2f, %+.2f]" %
                  (fam, group, sum(A) / len(A), sum(S) / len(S), md, p, lo, hi))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""RQ4 primary held-out tables (eps=0.3): per-context block rate of the frozen
CG-Adaptive and CG-Static rules, custom vs cross-backend, with adaptive-minus-static
deltas and micro/macro averages. Reproduces the paper's rq4-heldout-sqli / -xss.

Reads results/rq4/rq4_blockrate_matrix.csv (mean_of_means +/- sd per context;
blocked_sum/total_sum for the pooled micro-average). Paths relative.
"""
import csv, statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "results" / "rq4" / "rq4_blockrate_matrix.csv"
EPS = "0.3"
TECHS = ["CG-Adaptive", "CG-Static"]

CTX = {
    "SQLi": {
        "Custom application": [("customapp", "login", "Login form"), ("customapp", "search", "Product search"),
                               ("customapp", "product", "URL parameter"), ("customapp", "filter", "Product filter")],
        "Cross-backend transfer": [("bwapp", "login", "bWAPP, Login"), ("bwapp", "search", "bWAPP, Search"),
                                   ("juice", "login", "Juice Shop, Login"), ("juice", "search", "Juice Shop, Search")],
    },
    "XSS": {
        "Custom application": [("customxss", "search", "Search (JS-string)"), ("customxss", "calc", "Calculator (eval sink)")],
        "Cross-backend transfer": [("bwapp", "xss_eval", "bWAPP, Calculator (eval sink)")],
    },
}


def load():
    d = {}
    for r in csv.DictReader(open(MATRIX)):
        d[(r["family"], r["target"], r["page"], r["eps"], r["technique"])] = r
    return d


def main():
    D = load()

    def rec(fam, t, p, tech):
        return D.get((fam, t, p, EPS, tech))

    def micro(fam, ctxlist, tech):
        b = sum(int(rec(fam, t, p, tech)["blocked_sum"]) for t, p, _ in ctxlist if rec(fam, t, p, tech))
        n = sum(int(rec(fam, t, p, tech)["total_sum"]) for t, p, _ in ctxlist if rec(fam, t, p, tech))
        return 100.0 * b / n if n else 0.0

    def macro(fam, ctxlist, tech):
        vals = [float(rec(fam, t, p, tech)["mean_of_means"]) for t, p, _ in ctxlist if rec(fam, t, p, tech)]
        return st.mean(vals) if vals else 0.0

    for fam in ["SQLi", "XSS"]:
        print("\n" + "=" * 78)
        print("RQ4 %s held-out block %% at eps=0.3 (mean +/- SD over the 5 held-out attack sets)" % fam)
        print("=" * 78)
        print("%-34s %14s %14s %8s" % ("Context", "CG-Adaptive", "CG-Static", "Delta"))
        for group, ctxlist in CTX[fam].items():
            print("-- %s" % group)
            for t, p, label in ctxlist:
                ra, rs = rec(fam, t, p, "CG-Adaptive"), rec(fam, t, p, "CG-Static")
                if not ra or not rs:
                    print("   %-31s n/a" % label); continue
                a, sa = float(ra["mean_of_means"]), float(ra["sd"])
                s, ss = float(rs["mean_of_means"]), float(rs["sd"])
                print("   %-31s %6.1f+/-%-5.1f %6.1f+/-%-5.1f %+8.1f" % (label, a, sa, s, ss, a - s))
        print("-- Summary")
        for grp, key in [("Custom", "Custom application"), ("Cross-backend", "Cross-backend transfer")]:
            cl = CTX[fam][key]
            for kind, fn in [("micro", micro), ("macro", macro)]:
                a, s = fn(fam, cl, "CG-Adaptive"), fn(fam, cl, "CG-Static")
                print("   %-31s %14.1f %14.1f %+8.1f" % ("%s %s-average" % (grp, kind), a, s, a - s))
        allctx = CTX[fam]["Custom application"] + CTX[fam]["Cross-backend transfer"]
        for kind, fn in [("micro", micro), ("macro", macro)]:
            a, s = fn(fam, allctx, "CG-Adaptive"), fn(fam, allctx, "CG-Static")
            print("   %-31s %14.1f %14.1f %+8.1f" % ("Overall %s-average" % kind, a, s, a - s))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""RQ4 held-out block rate swept over epsilon (0.1..0.5), per context, custom vs
cross-backend, CG-Adaptive vs CG-Static, with overall micro/macro at each epsilon.
Reproduces the paper's rq4-heldout-sqli-eps / rq4-heldout-xss-eps.

Reads results/rq4/rq4_blockrate_matrix.csv. Paths relative.
"""
import csv, statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "results" / "rq4" / "rq4_blockrate_matrix.csv"
EPSES = ["0.1", "0.2", "0.3", "0.4", "0.5"]

CTX = {
    "SQLi": {
        "Custom": [("customapp", "login", "Login form"), ("customapp", "search", "Product search"),
                   ("customapp", "product", "URL parameter"), ("customapp", "filter", "Product filter")],
        "Cross": [("bwapp", "login", "bWAPP, Login"), ("bwapp", "search", "bWAPP, Search"),
                  ("juice", "login", "Juice Shop, Login"), ("juice", "search", "Juice Shop, Search")],
    },
    "XSS": {
        "Custom": [("customxss", "search", "Search (JS-string)"), ("customxss", "calc", "Calculator (eval sink)")],
        "Cross": [("bwapp", "xss_eval", "bWAPP, Calculator (eval sink)")],
    },
}


def load():
    d = {}
    for r in csv.DictReader(open(MATRIX)):
        d[(r["family"], r["target"], r["page"], r["eps"], r["technique"])] = r
    return d


def main():
    D = load()

    def rec(fam, t, p, eps, tech):
        return D.get((fam, t, p, eps, tech))

    def micro(fam, ctxlist, eps, tech):
        b = sum(int(rec(fam, t, p, eps, tech)["blocked_sum"]) for t, p, _ in ctxlist if rec(fam, t, p, eps, tech))
        n = sum(int(rec(fam, t, p, eps, tech)["total_sum"]) for t, p, _ in ctxlist if rec(fam, t, p, eps, tech))
        return 100.0 * b / n if n else float("nan")

    def macro(fam, ctxlist, eps, tech):
        v = [float(rec(fam, t, p, eps, tech)["mean_of_means"]) for t, p, _ in ctxlist if rec(fam, t, p, eps, tech)]
        return st.mean(v) if v else float("nan")

    for fam in ["SQLi", "XSS"]:
        print("\n" + "=" * 96)
        print("RQ4 %s held-out block %% (CG-Adaptive) per context x epsilon; * = operating point" % fam)
        print("=" * 96)
        allctx = CTX[fam]["Custom"] + CTX[fam]["Cross"]
        hdr = "%-32s" % "Context" + "".join("%9s" % (("*" if e == "0.3" else "") + e) for e in EPSES)
        print(hdr)
        for group in ["Custom", "Cross"]:
            print("-- %s" % group)
            for t, p, label in CTX[fam][group]:
                cells = []
                for e in EPSES:
                    r = rec(fam, t, p, e, "CG-Adaptive")
                    cells.append("%9.1f" % float(r["mean_of_means"]) if r else "%9s" % "n/a")
                print("   %-29s%s" % (label, "".join(cells)))
        for kind, fn in [("micro", micro), ("macro", macro)]:
            for tech in ["CG-Adaptive", "CG-Static"]:
                cells = "".join("%9.1f" % fn(fam, allctx, e, tech) for e in EPSES)
                print("   Overall %-21s%s" % ("%s (%s)" % (kind, tech), cells))


if __name__ == "__main__":
    main()

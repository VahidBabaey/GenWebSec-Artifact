#!/usr/bin/env python3
"""RQ4 external false positives: reproduce the benign FP matrix and list the
nonzero incidents. Reads results/rq4_fp/rq4_fp_matrix.csv and rq4_fp_incidents.csv.

The matrix gives the FP rate (%) per family, benign corpus, technique, and epsilon.
CRS blocks zero on every corpus; CG-Adaptive is zero in every cell; the only nonzero
entries are CG-Static (at fine thresholds) and one RG seed. Paths relative.
"""
import csv
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "results" / "rq4_fp" / "rq4_fp_matrix.csv"
INC = ROOT / "results" / "rq4_fp" / "rq4_fp_incidents.csv"
EPSES = ["0.1", "0.2", "0.3", "0.4", "0.5"]


def main():
    rows = list(csv.DictReader(open(MATRIX)))
    print("=" * 82)
    print("RQ4 benign false-positive rate (%) -- mean over seeds; * marks the operating point")
    print("=" * 82)
    fams = ["sqli", "xss"]
    for fam in fams:
        corpora = []
        for r in rows:
            if r["family"] == fam and r["corpus"] not in corpora:
                corpora.append(r["corpus"])
        for corpus in corpora:
            print("\n%s / %s" % (fam.upper(), corpus))
            print("  %-14s %s" % ("technique", "".join("%9s" % (("*" if e == "0.3" else "") + e) for e in EPSES)))
            for tech in ["CG-Adaptive", "CG-Static", "RG"]:
                cells = []
                any_row = False
                for e in EPSES:
                    m = [r for r in rows if r["family"] == fam and r["corpus"] == corpus
                         and r["technique"] == tech and r["eps"] == e]
                    if m:
                        any_row = True
                        cells.append("%9.2f" % float(m[0]["mean_fp"]))
                    else:
                        cells.append("%9s" % "-")
                if any_row:
                    print("  %-14s %s" % (tech, "".join(cells)))

    print("\n" + "=" * 82)
    print("Nonzero FP incidents")
    print("=" * 82)
    for r in csv.DictReader(open(INC)):
        print("\n[%s] %s / %s  eps=%s  seed(s)=%s" %
              (r["strategy"], r["family"], r["corpus"], r["eps"], r["defense_seed"]))
        print("  blocked      : %s/%s benign (%.2f%%)" %
              (r["benign_blocked"], r["benign_total"], float(r["own_fp_pct"])))
        print("  offending id : %s" % r["offending_rule_id"])
        print("  offending rx : %s" % r["offending_rule_rx"])
        print("  matched      : %s" % r["matched_variables"])
        print("  example      : %s" % r["example_benign"])
        print("  passed gate  : %s" % r["why_passed_admission"])
        print("  at eps=0.3?  : %s" % r["at_operating_point"])


if __name__ == "__main__":
    main()

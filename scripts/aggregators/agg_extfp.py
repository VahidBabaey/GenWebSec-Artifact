"""Compare external/cross-backend benign-FP at eps=0.3: RG vs CG-Static vs CG-Adaptive, per corpus.
Reads the per-seed csvs under A1-A2_BenignTest/{A1|A2}/eps0.3/benign_fp_<TECH>_eps0.3_seed*.csv.
FP% = 100*blocked(403)/corpus size. Reports mean+/-SD [max] over the seeds present."""
import os, csv, statistics as st

BT = "/path/to/GenWebSec/results/V2/A1-A2_BenignTest"
CORP = {"sqli": ["bwapp_login", "bwapp_search", "juice_login", "juice_search", "csic"],
        "xss":  ["bwapp_calc", "csic"]}


def load(tech, fam):
    d = "A1" if fam == "sqli" else "A2"
    res = {c: [] for c in CORP[fam]}
    for s in range(1, 11):
        f = f"{BT}/{d}/eps0.3/benign_fp_{tech}_eps0.3_seed{s}.csv"
        if not os.path.exists(f):
            continue
        for row in csv.DictReader(open(f, encoding="utf-8")):
            if row["corpus"] in res and row["status"] == "ok" and row["fp_pct"] != "":
                res[row["corpus"]].append(float(row["fp_pct"]))
    return res


def fmt(d, c):
    v = d.get(c, [])
    if not v:
        return "(none)"
    m = st.mean(v); sd = st.stdev(v) if len(v) > 1 else 0.0
    return f"{m:6.3f}+/-{sd:5.3f} [max {max(v):6.3f}] n={len(v)}"


for fam in ["sqli", "xss"]:
    print(f"\n=== {fam.upper()} external benign-FP @ eps0.3  (FP%% = 403/corpus ; mean+/-SD [max]) ===")
    rg = load("RG", fam); cs = load("CG-Static", fam); ca = load("CG-Adaptive", fam)
    print(f"{'corpus':>13} | {'RG (random)':>30} | {'CG-Static':>30} | {'CG-Adaptive':>30}")
    print("-" * 112)
    for c in CORP[fam]:
        print(f"{c:>13} | {fmt(rg, c):>30} | {fmt(cs, c):>30} | {fmt(ca, c):>30}")

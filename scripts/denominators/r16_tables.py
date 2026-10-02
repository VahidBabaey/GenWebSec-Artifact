#!/usr/bin/env python3
"""R1.6 denominator + uncertainty tables (artifact). Per-seed numerator/denominator data with attacker-seed
   and defense-seed kept separate, plus exact Clopper-Pearson binomial 95% CIs. No new runs: tabulated from
   the saved RQ3 funnel, RQ4 per-ruleset replays, and the Dalfox replay."""
import os, re, glob, csv, math, statistics as st
from collections import defaultdict

V = "/home/vahid/Projects/GenWebSec/results/V2"
OUT = "/home/vahid/Projects/GenWebSec/paper-frontiers/results/V2/RevisionNewResults/R1.6"
os.makedirs(OUT, exist_ok=True)

# ---------------- Clopper-Pearson exact binomial CI (self-contained; no scipy) ----------------
def _betacf(a, b, x):
    FPMIN = 1e-300; qab = a + b; qap = a + 1.0; qam = a - 1.0
    c = 1.0; d = 1.0 - qab * x / qap
    if abs(d) < FPMIN: d = FPMIN
    d = 1.0 / d; h = d
    for m in range(1, 400):
        m2 = 2 * m
        aa = m * (b - m) * x / ((qam + m2) * (a + m2))
        d = 1.0 + aa * d; d = FPMIN if abs(d) < FPMIN else d; c = 1.0 + aa / c
        if abs(c) < FPMIN: c = FPMIN
        d = 1.0 / d; h *= d * c
        aa = -(a + m) * (qab + m) * x / ((a + m2) * (qap + m2))
        d = 1.0 + aa * d; d = FPMIN if abs(d) < FPMIN else d; c = 1.0 + aa / c
        if abs(c) < FPMIN: c = FPMIN
        d = 1.0 / d; de = d * c; h *= de
        if abs(de - 1.0) < 1e-14: break
    return h

def betai(a, b, x):
    if x <= 0: return 0.0
    if x >= 1: return 1.0
    bt = math.exp(math.lgamma(a + b) - math.lgamma(a) - math.lgamma(b) + a * math.log(x) + b * math.log(1.0 - x))
    return bt * _betacf(a, b, x) / a if x < (a + 1.0) / (a + b + 2.0) else 1.0 - bt * _betacf(b, a, 1.0 - x) / b

def beta_ppf(p, a, b):
    lo, hi = 0.0, 1.0
    for _ in range(200):
        mid = 0.5 * (lo + hi)
        if betai(a, b, mid) < p: lo = mid
        else: hi = mid
    return 0.5 * (lo + hi)

def cp(k, n, alpha=0.05):
    if n == 0: return (0.0, 1.0)
    lo = 0.0 if k == 0 else beta_ppf(alpha / 2, k, n - k + 1)
    hi = 1.0 if k == n else beta_ppf(1 - alpha / 2, k + 1, n - k)
    return lo, hi

lo39, _ = cp(39, 39); lo250, _ = cp(250, 250)
print(f"[CP self-test] 39/39 lower={lo39*100:.1f}% (expect ~91.0)   250/250 lower={lo250*100:.1f}% (expect ~98.5)")

def pct(x): return f"{100*x:.2f}"

# ---------------- RQ4 (Tables 7-8): attacker-seed x defense-seed ----------------
def parse_rq4(pat, fam):
    rows = []
    for fp in sorted(glob.glob(pat)):
        m = re.match(r"rq4_replay_(.+?)_seed(\d+)_per_ruleset\.csv", os.path.basename(fp))
        if not m: continue
        context, aseed = m.group(1), int(m.group(2))
        for r in csv.DictReader(open(fp, encoding="utf-8", errors="replace")):
            if r["technique"] == "CRS-only": continue
            rows.append((fam, context, r["technique"], aseed, int(r["cg_seed"]), int(r["blocked"]), int(r["total_attacks"])))
    return rows

rq4 = parse_rq4(f"{V}/A1_HeldOut/*/Defense_results/*_per_ruleset.csv", "SQLi") + \
      parse_rq4(f"{V}/A2_HeldOut/*/Defense_results/*_per_ruleset.csv", "XSS")

with open(f"{OUT}/rq4_perseed.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh); w.writerow(["family", "context", "strategy", "attacker_seed", "defense_seed", "eligible", "blocked", "block_rate_pct"])
    for fam, ctx, tech, a, d, blk, tot in sorted(rq4):
        w.writerow([fam, ctx, tech, a, d, tot, blk, f"{100*blk/tot:.2f}" if tot else ""])

keys = sorted({(r[0], r[1], r[2]) for r in rq4})
with open(f"{OUT}/rq4_summary.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["family", "context", "strategy", "n_attack_sets", "eligible_per_defense", "pooled_blocked", "pooled_eligible",
                "pooled_rate_pct", "defseed_median_rate", "defseed_min_rate", "defseed_max_rate",
                "attackset_min_rate", "attackset_max_rate", "worst_defseed_rate", "worst_defseed_cp95_lo", "median_defseed_cp95"])
    for fam, ctx, tech in keys:
        rs = [r for r in rq4 if r[0] == fam and r[1] == ctx and r[2] == tech]
        aset = sorted({r[3] for r in rs}); dset = sorted({r[4] for r in rs})
        # per defense seed d: blocked_d, eligible_d (sum over attack sets)
        dstat = {}
        for d in dset:
            b = sum(r[5] for r in rs if r[4] == d); e = sum(r[6] for r in rs if r[4] == d)
            dstat[d] = (b, e, b / e if e else 0.0)
        drates = sorted(v[2] for v in dstat.values())
        # per attack set a: mean over defenses of per-cell rate
        arates = []
        for a in aset:
            cells = [r[5] / r[6] for r in rs if r[3] == a and r[6]]
            arates.append(sum(cells) / len(cells) if cells else 0.0)
        pooled_b = sum(r[5] for r in rs); pooled_e = sum(r[6] for r in rs)
        elig_per_def = sum(r[6] for r in rs if r[4] == dset[0])     # eligible one defense faces (= sum of attack-set sizes)
        worst_d = min(dstat, key=lambda d: dstat[d][2]); wb, we, wr = dstat[worst_d]
        wlo, whi = cp(wb, we)
        med_d = sorted(dstat, key=lambda d: dstat[d][2])[len(dstat) // 2]; mb, me, mr = dstat[med_d]
        mlo, mhi = cp(mb, me)
        w.writerow([fam, ctx, tech, len(aset), elig_per_def, pooled_b, pooled_e, f"{100*pooled_b/pooled_e:.2f}",
                    f"{100*st.median(drates):.2f}", f"{100*min(drates):.2f}", f"{100*max(drates):.2f}",
                    f"{100*min(arates):.2f}", f"{100*max(arates):.2f}", f"{100*wr:.2f}",
                    f"{100*wlo:.2f}", f"[{100*mlo:.2f},{100*mhi:.2f}]"])

# ---------------- RQ3 (Table 6) CG-Adaptive, eps=0.3, from the funnel file ----------------
rq3 = []
pat = re.compile(r"(SQLi|XSS) (.+?) eps=([0-9.]+) seed(\d+) \|.*?gen=(\d+) valid=(\d+) crs_byp=(\d+) blk_rules=(\d+) still=(\d+)")
for l in open(f"{V}/_rq3_table1_perrun.txt", encoding="utf-8", errors="replace"):
    m = pat.search(l)
    if m and m.group(3) == "0.3":
        fam, page, seed = m.group(1), m.group(2), int(m.group(4))
        gen, valid, crsb, blk, still = (int(m.group(i)) for i in range(5, 10))
        rq3.append((fam, page, seed, gen, valid, crsb, blk, still))
with open(f"{OUT}/rq3_cg_adaptive_perseed.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh); w.writerow(["family", "context", "seed", "generated", "backend_valid", "crs_bypasses_eligible", "blocked_by_rules", "residual", "block_rate_pct", "cp95_lo", "cp95_hi"])
    for fam, page, seed, gen, valid, crsb, blk, still in sorted(rq3):
        lo, hi = cp(blk, crsb)
        w.writerow([fam, page, seed, gen, valid, crsb, blk, still, f"{100*blk/crsb:.2f}" if crsb else "", f"{100*lo:.2f}", f"{100*hi:.2f}"])

# ---------------- Dalfox ----------------
dal = []
for r in csv.DictReader(open(f"{V}/NonLLM_Results/xss_dalfox/replay/per_ruleset.csv", encoding="utf-8")):
    if r["technique"] == "CRS-only": continue
    dal.append((r["technique"], int(r["cg_seed"]), int(r["blocked"]), int(r["total"])))
with open(f"{OUT}/dalfox_perseed.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh); w.writerow(["technique", "defense_seed", "blocked", "eligible", "block_rate_pct"])
    for tech, d, blk, tot in sorted(dal):
        w.writerow([tech, d, blk, tot, f"{100*blk/tot:.2f}"])
with open(f"{OUT}/dalfox_summary.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh); w.writerow(["technique", "n_defense_seeds", "eligible", "median_blocked", "blocked_range", "median_rate", "worst_rate", "worst_cp95_lo", "median_cp95"])
    for tech in ("CG-Adaptive", "CG-Static"):
        rs = [r for r in dal if r[0] == tech]
        if not rs: continue
        blks = sorted(r[2] for r in rs); tot = rs[0][3]
        worst = min(blks); wlo, _ = cp(worst, tot)
        med = int(st.median(blks)); mlo, mhi = cp(med, tot)
        w.writerow([tech, len(rs), tot, med, f"{min(blks)}-{max(blks)}", f"{100*med/tot:.2f}", f"{100*worst/tot:.2f}", f"{100*wlo:.2f}", f"[{100*mlo:.2f},{100*mhi:.2f}]"])

# ---------------- verification prints ----------------
print("\n== RQ4 denominator (eligible per defense) + spreads, per context/strategy ==")
for fam, ctx, tech in keys:
    with open(f"{OUT}/rq4_summary.csv") as fh:
        pass
print("  (written to rq4_summary.csv; sample below)")
import csv as _c
for row in list(_c.DictReader(open(f"{OUT}/rq4_summary.csv")))[:99]:
    if row["strategy"] in ("CG-Adaptive", "CG-Static"):
        print(f"  {row['family']:4} {row['context']:16} {row['strategy']:12} elig={row['eligible_per_defense']:>4} pooled={row['pooled_rate_pct']:>6}%  defseed[{row['defseed_min_rate']}-{row['defseed_max_rate']}] worst={row['worst_defseed_rate']}% CP95lo={row['worst_defseed_cp95_lo']}")

print("\n== RQ3 CG-Adaptive eps0.3 crs_byp (eligible) range per context ==")
for fam in ("SQLi", "XSS"):
    for page in sorted({r[1] for r in rq3 if r[0] == fam}):
        cb = [r[5] for r in rq3 if r[0] == fam and r[1] == page]
        bl = [100 * r[6] / r[5] for r in rq3 if r[0] == fam and r[1] == page and r[5]]
        print(f"  {fam} {page:18}: crs_byp {min(cb)}-{max(cb)}  block% {min(bl):.1f}-{max(bl):.1f}")

print("\n== Dalfox ==")
for row in _c.DictReader(open(f"{OUT}/dalfox_summary.csv")):
    print(f"  {row['technique']:12} eligible={row['eligible']} blocked_range={row['blocked_range']} median_rate={row['median_rate']}% worst_cp95_lo={row['worst_cp95_lo']}%")
print("\nwrote", OUT)
for f in sorted(os.listdir(OUT)):
    print("  ", f)

#!/usr/bin/env python3
"""RQ1 aggregator: attack generation vs the CRS-only baseline (A1 SQLi, A2 XSS).
Reads every per-page _metrics.csv across the 5 seeds and reports, per (family,page):
  Payloads Generated = sum over rounds of `generated`
  Valid              = sum over rounds of `backend_valid_n`   (SQLi: injection oracle; XSS: executes)
  CRS Block %        = 100 * sum(waf_blocked_n) / sum(backend_valid_n)
each as mean +/- SD across the 5 seeds. Also emits the per-round bypass trajectory
(mean +/- SD across seeds) for one representative page per family, and draws the figure.
Every number is read from a results file; nothing hard-coded.
"""
import csv, statistics as st, os
BASE = "/path/to/GenWebSec/results/V2"
SEEDS = [1, 2, 3, 4, 5]

A1 = {"family": "SQLi", "dirfmt": f"{BASE}/CustomApp_A1/CustomApp_A1_CRSonly_seed%d",
      "filefmt": "A1_customapp_%s_metrics.csv",
      "pages": [("login", "Login (username, POST)"), ("search", "Search (q)"),
                ("product", "Product (id)"), ("filter", "Filter (category)")]}
A2 = {"family": "XSS", "dirfmt": f"{BASE}/CustomApp_A2/CustomXSS_A2_CRSonly_seed%d",
      "filefmt": "A2_customxss_%s_metrics.csv",
      "pages": [("search", "Search (JS-string)"), ("calc", "Calculator (eval sink)")]}

def load(fam, page):
    """return list over seeds of per-round dicts."""
    per_seed = []
    for s in SEEDS:
        path = os.path.join(fam["dirfmt"] % s, fam["filefmt"] % page)
        rows = list(csv.DictReader(open(path)))
        per_seed.append([{k: (float(v) if v not in ("", None) else 0.0) for k, v in r.items()} for r in rows])
    return per_seed

def ms(vals):
    return st.mean(vals), (st.stdev(vals) if len(vals) > 1 else 0.0)

def summarize(fam):
    print(f"\n================= {fam['family']} (5 seeds) =================")
    print(f"{'Page':<26} {'Generated':>14} {'Valid':>14} {'CRS Block %':>14} {'CRS Bypass %':>14}")
    out = []
    for page, label in fam["pages"]:
        ps = load(fam, page)
        gen, val, blkpct, byppct = [], [], [], []
        for rows in ps:
            g = sum(r["generated"] for r in rows)
            v = sum(r["backend_valid_n"] for r in rows)
            b = sum(r["waf_blocked_n"] for r in rows)
            yp = sum(r["waf_bypassed_n"] for r in rows)
            gen.append(g); val.append(v)
            blkpct.append(100.0 * b / v if v else 0.0)
            byppct.append(100.0 * yp / v if v else 0.0)   # from files: bypassed / valid
        gm, gs = ms(gen); vm, vs = ms(val); bm, bs = ms(blkpct); ym, ys = ms(byppct)
        print(f"{label:<26} {gm:6.0f} +/- {gs:<4.0f} {vm:6.0f} +/- {vs:<4.0f} {bm:6.1f} +/- {bs:<4.1f} {ym:6.1f} +/- {ys:<4.1f}")
        out.append((label, gm, gs, vm, vs, bm, bs, ym, ys))
    return out

def trajectory(fam, page):
    ps = load(fam, page)
    nr = min(len(rows) for rows in ps)
    means, sds = [], []
    for r in range(nr):
        byp = [rows[r]["waf_bypassed_n"] for rows in ps]
        m, sd = ms(byp); means.append(m); sds.append(sd)
    return list(range(nr)), means, sds

sumA1 = summarize(A1)
sumA2 = summarize(A2)

print("\n================= TRAJECTORY (bypasses/round, mean +/- SD over 5 seeds) =================")
traj = {}
for fam, page, tag in [(A1, "login", "SQLi Login"), (A2, "search", "XSS Search")]:
    rounds, m, sd = trajectory(fam, page)
    traj[tag] = (rounds, m, sd)
    print(f"{tag}: " + "  ".join(f"r{r}={mm:.0f}±{ss:.0f}" for r, mm, ss in zip(rounds, m, sd)))

# ---- figure ----
try:
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt
    fig, ax = plt.subplots(figsize=(6.4, 3.2))
    colors = {"SQLi Login": "#1f4e79", "XSS Search": "#a23b2c"}
    for tag, (rounds, m, sd) in traj.items():
        m = [float(x) for x in m]; sd = [float(x) for x in sd]
        lo = [a - b for a, b in zip(m, sd)]; hi = [a + b for a, b in zip(m, sd)]
        ax.plot(rounds, m, marker="o", ms=4, lw=1.8, color=colors[tag], label=tag)
        ax.fill_between(rounds, lo, hi, color=colors[tag], alpha=0.15)
    ax.set_xlabel("Round"); ax.set_ylabel("Validated bypasses / round")
    ax.set_xticks(range(0, 10)); ax.set_ylim(bottom=0)
    ax.grid(True, ls=":", alpha=0.5); ax.legend(frameon=False)
    fig.tight_layout()
    outdir = "/path/to/GenWebSec/results/V2/_rq1_fig"
    os.makedirs(outdir, exist_ok=True)
    fig.savefig(f"{outdir}/rq1_bypass_trajectory.pdf")
    fig.savefig(f"{outdir}/rq1_bypass_trajectory.png", dpi=150)
    print(f"\nFIGURE saved: {outdir}/rq1_bypass_trajectory.[pdf|png]")
except Exception as e:
    print(f"\n[figure skipped] {type(e).__name__}: {e}")

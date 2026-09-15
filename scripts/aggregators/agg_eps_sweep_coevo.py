#!/usr/bin/env python3
"""
Item 6 (clustering sensitivity) aggregator for the CO-EVOLUTIONARY cluster-guided pilots (CG-Adaptive):
  C1 = SQLi  (pilot_C1_customapp_coevolution_v2.py)   dirs: results/V2/CustomApp_C1_Token_eps{E}_seed{S}/
  C2 = XSS   (pilot_C2_customxss_coevolution_v2.py)    dirs: results/V2/CustomXSS_C2_Token_eps{E}_seed{S}/

For EACH threshold eps in {0.1,0.2,0.3,0.4,0.5}, RUN SEPARATELY for SQLi and XSS, this reports every
quantity advisor item 6 asks to record, parsed from each run's clustering log (provenance per seed),
with mean/SD/95%CI across seeds (item 1):

  cluster count, singleton %, mean/median/max cluster size (round 0),
  accepted rules |R|, observed(dev) coverage, held-out coverage, FPR, tokens, wall-clock time.

It then SELECTS eps on DEVELOPMENT data only (never the held-out stress test), with the explicit
criterion stated below, and prints the selected eps per family.

Everything is parsed from the real logs; nothing is estimated. Usage:  python3 agg_eps_sweep_coevo.py
"""
import re, sys, math, statistics
from pathlib import Path

V2 = Path("/path/to/GenWebSec/results/V2")
EPSES = ["0.1", "0.2", "0.3", "0.4", "0.5"]
SEEDS = list(range(1, 11))

# item 6: "Select eps using development data only ... minimizing rules subject to at least 99%
# development coverage and FPR below 1%."
DEV_COVERAGE_MIN = 99.0    # percent: observed(development) block-rate of the final ruleset
FPR_MAX = 1.0              # percent: cumulative benign false-positive rate (item 2 budget)

FAMILIES = {
    "C1 (SQLi)": {"parent": "CustomApp_C1", "prefix": "CustomApp_C1_Token", "log": "C1_customapp_{page}_clustering.txt",
                  "pages": ["login", "search", "product", "filter"]},
    "C2 (XSS)":  {"parent": "CustomApp_C2", "prefix": "CustomXSS_C2_Token", "log": "C2_customxss_{page}_clustering.txt",
                  "pages": ["search", "calc"]},
}

def _num(s):
    return float(s.replace(",", "")) if s is not None else None

def first(t, pat, grp=1, cast=float):
    m = re.search(pat, t)
    return cast(m.group(grp)) if m else None

def last(t, pat, grp=1, cast=float):
    ms = re.findall(pat, t)
    if not ms:
        return None
    v = ms[-1]
    if isinstance(v, tuple):
        v = v[grp - 1]
    return cast(v)

def parse_run(text):
    """Every item-6 field for ONE run, from its clustering log. round-0 cluster stats = the FIRST
    [cluster-stats] line (the clustering of the initial bypassing set); |R|/coverage/FPR/time = final."""
    r = {}
    m = re.search(r"cluster-stats eps=[\d.]+\]\s*clusters=(\d+)\s+singleton%=([\d.]+)\s+"
                  r"mean=([\d.]+)\s+median=([\d.]+)\s+max=(\d+)", text)         # round 0 (first)
    if m:
        r["clusters0"] = int(m.group(1)); r["singleton_pct"] = float(m.group(2))
        r["mean_size"] = float(m.group(3)); r["median_size"] = float(m.group(4))
        r["max_size"] = int(m.group(5))
    else:
        r["clusters0"] = r["singleton_pct"] = r["mean_size"] = r["median_size"] = r["max_size"] = None
    r["rules"]      = last(t=text, pat=r"Final rule set:\s*(\d+)\s*rule", cast=int)      # |R|
    r["dev_cov"]    = last(t=text, pat=r"BlockRate\(after\)\s+([\d.]+)% of valid")        # observed/dev coverage
    r["heldout_cov"]= last(t=text, pat=r"HELD-OUT ROBUSTNESS \(stress \d+\):\s*\d+/\d+ valid bypassed\s*=\s*[\d.]+%\s*\(block\s*([\d.]+)%\)")
    if r["heldout_cov"] is None:                                                          # fallback to STRESS RESULT line
        r["heldout_cov"] = last(t=text, pat=r"held-out bypass [\d.]+%\s*\(block\s*([\d.]+)%\)")
    r["fpr"]        = last(t=text, pat=r"FPRate\(t\)\s+([\d.]+)%")                         # final total FPR
    r["in_tok"]     = last(t=text, pat=r"TOTAL input tokens:\s*([\d,]+)", cast=lambda s: int(s.replace(",", "")))
    r["out_tok"]    = last(t=text, pat=r"TOTAL output tokens:\s*([\d,]+)", cast=lambda s: int(s.replace(",", "")))
    r["wall_s"]     = last(t=text, pat=r"wall-clock\s*([\d.]+)s")
    m = re.search(r"HARDENING TERMINATION:\s*(CONVERGED|DID NOT CONVERGE)", text)
    r["converged"]  = (m.group(1) == "CONVERGED") if m else None
    r["rounds"]     = first(text, r"after\s*(\d+)\s*hardening round", cast=int)
    return r

def collect(parent, prefix, logname, page, eps):
    rows = []
    for s in SEEDS:
        f = V2 / parent / f"{prefix}_eps{eps}_seed{s}" / logname.format(page=page)
        if not f.exists():
            continue
        txt = f.read_text(encoding="utf-8", errors="replace")
        row = parse_run(txt); row["seed"] = s
        rows.append(row)
    return rows

def ms(vals):
    vals = [v for v in vals if v is not None]
    if not vals:
        return (float("nan"), 0.0, 0)
    if len(vals) == 1:
        return (vals[0], 0.0, 1)
    return (statistics.mean(vals), statistics.stdev(vals), len(vals))

T95 = {9: 2.262, 8: 2.306, 7: 2.365, 6: 2.447, 5: 2.571, 4: 2.776, 3: 3.182, 2: 4.303, 1: 12.706}

FIELDS = [("clusters0", "clusters(r0)"), ("singleton_pct", "singl%"), ("mean_size", "meanSz"),
          ("median_size", "medSz"), ("max_size", "maxSz"), ("rules", "|R|"),
          ("dev_cov", "devCov%"), ("heldout_cov", "heldCov%"), ("fpr", "FPR%"),
          ("in_tok", "inTok"), ("out_tok", "outTok"), ("wall_s", "wall_s")]

def report_family(name, cfg):
    print("\n" + "=" * 100)
    print(f"ITEM 6 — CLUSTERING SENSITIVITY :: {name}")
    print("=" * 100)
    any_data = False
    # per page: a table of mean(+/-SD, n) for every item-6 field, across eps
    fam_eps_agg = {e: {k: [] for k, _ in FIELDS} for e in EPSES}   # for the family-level selection
    for page in cfg["pages"]:
        print(f"\n--- {name}  page={page}  (mean +/- SD, n seeds) ---")
        header = f"{'eps':>5} | " + " | ".join(f"{lbl:>12}" for _, lbl in FIELDS)
        print(header); print("-" * len(header))
        for e in EPSES:
            rows = collect(cfg["parent"], cfg["prefix"], cfg["log"], page, e)
            if rows:
                any_data = True
            cells = []
            for k, _ in FIELDS:
                m, sd, n = ms([r.get(k) for r in rows])
                fam_eps_agg[e][k].extend([r.get(k) for r in rows if r.get(k) is not None])
                cells.append("n/a" if n == 0 else f"{m:.1f}+/-{sd:.1f}(n{n})")
            print(f"{e:>5} | " + " | ".join(f"{c:>12}" for c in cells))
    # ---- eps SELECTION on DEVELOPMENT data only ----
    print(f"\n--- {name}: eps SELECTION (development data only; held-out stress NOT used) ---")
    print(f"    CRITERION: choose eps* = argmin |R|  subject to  dev coverage >= {DEV_COVERAGE_MIN:.0f}%  "
          f"AND cumulative FPR <= {FPR_MAX:.1f}%  (means across pages+seeds).")
    qualifying = []
    for e in EPSES:
        agg = fam_eps_agg[e]
        rmean = ms(agg["rules"])[0]; dcov = ms(agg["dev_cov"])[0]; fpr = ms(agg["fpr"])[0]
        if any(math.isnan(x) for x in (rmean, dcov, fpr)):
            print(f"    eps={e}: n/a (no runs yet)"); continue
        ok = (dcov >= DEV_COVERAGE_MIN) and (fpr <= FPR_MAX)
        print(f"    eps={e}: |R|={rmean:.2f}  devCov={dcov:.1f}%  FPR={fpr:.2f}%  -> "
              f"{'QUALIFIES' if ok else 'excluded'}")
        if ok:
            qualifying.append((rmean, e))
    if qualifying:
        best = min(qualifying)
        print(f"    => SELECTED eps* = {best[1]}  (smallest |R|={best[0]:.2f} among qualifying thresholds)")
    else:
        print("    => no eps qualifies yet (need completed runs, or relax the criterion)")
    if not any_data:
        print(f"\n    [note] no completed {name} clustering runs found under {V2/cfg['parent']} — "
              f"the aggregator is ready; run the eps sweep to populate it.")

def main():
    print("ITEM 6 clustering-sensitivity aggregator (CG-Adaptive: C1 SQLi + C2 XSS), reported SEPARATELY.")
    print(f"eps in {{{', '.join(EPSES)}}} x seeds {SEEDS[0]}..{SEEDS[-1]}   |   root: {V2}")
    for name, cfg in FAMILIES.items():
        report_family(name, cfg)

if __name__ == "__main__":
    main()

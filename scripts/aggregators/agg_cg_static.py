#!/usr/bin/env python3
"""Aggregate a CG-Static condition across seeds. Every number PARSED from each seed's clustering
log (provenance printed per seed); mean/SD/95%CI computed deterministically (t, df=n-1)."""
import re, sys, math, statistics
from pathlib import Path

PAGE = sys.argv[1] if len(sys.argv) > 1 else "product"
EPS  = sys.argv[2] if len(sys.argv) > 2 else "0.3"
PILOT = sys.argv[3].lower() if len(sys.argv) > 3 else "d1"   # d1 (SQLi) or d2 (XSS)
SEEDS = list(range(1, 11))
V2 = Path("/path/to/GenWebSec/results/V2")
if PILOT == "d2":
    BASE = V2 / "CustomApp_D2"; DIRFMT = "CustomXSS_D2_eps{EPS}_seed{s}"; LOGNAME = f"D2_customxss_{PAGE}_clustering.txt"
else:
    BASE = V2 / "CustomApp_D1"; DIRFMT = "CustomApp_D1_eps{EPS}_seed{s}"; LOGNAME = f"D1_customapp_{PAGE}_clustering.txt"

def one(t, pat, cast=float, last=False):
    m = re.findall(pat, t)
    return cast(m[-1 if last else 0].replace(",", "")) if m else None

rows = []
for s in SEEDS:
    f = BASE / DIRFMT.format(EPS=EPS, s=s) / LOGNAME
    if not f.exists():
        print(f"seed {s}: MISSING {f}"); continue
    t = f.read_text(encoding="utf-8", errors="replace")
    r = {
        "seed": s,
        "blocked": one(t, r"Final:\s*(\d+)/\d+\s+blocked", int),
        "corpus":  one(t, r"Final:\s*\d+/(\d+)\s+blocked", int),
        "rules":   one(t, r"blocked with\s*(\d+)\s*rule", int),
        "rounds":  len(re.findall(r"ITER \d+ SUMMARY", t)),
        "cl0":     one(t, r"cluster-stats eps=[\d.]+\] clusters=(\d+)", int),          # round-0 cluster count
        "fp":      one(t, r"FP=([\d.]+)%", last=True),                                 # final total FP%
        "added":   one(t, r"added\s*([\d.]+)%\s*vs CRS", last=True),
        "calls":   one(t, r"defense LLM calls\s*(\d+)", int),
        "cands":   one(t, r"candidate rules\s*(\d+)", int),
        "accepted":one(t, r"accepted\s*(\d+)\s+rejected", int),
        "rejected":one(t, r"rejected\s*(\d+)\s+failed", int),
        "failcl":  one(t, r"failed clusters\s*(\d+)", int),
        "clproc":  one(t, r"clusters processed\s*(\d+)", int),
        "cl_att":  one(t, r"total cluster attempts\s*(\d+)", int),
        "att_cl":  one(t, r"mean attempts/cluster\s*([\d.]+)"),
        "wall":    one(t, r"wall-clock\s*([\d.]+)s"),
        "in_tok":  one(t, r"TOTAL input tokens:\s*([\d,]+)", int),
        "out_tok": one(t, r"TOTAL output tokens:\s*([\d,]+)", int),
        "cost":    one(t, r"est\. cost \$([\d.]+)"),
        "rp100":   one(t, r"rules per 100 bypasses\s*=\s*([\d.]+)"),
        "cpr":     one(t, r"LLM-calls per accepted rule\s*=\s*([\d.]+)"),
    }
    rows.append(r)

if not rows:
    print("no CG seed logs found"); sys.exit(1)

cols = ["blocked","rules","fp","added","rounds","cl0","calls","cands","accepted","rejected",
        "failcl","att_cl","wall","in_tok","out_tok","cost","rp100","cpr"]
print(f"\n=== CG-Static  page={PAGE}  eps={EPS}  (n={len(rows)} seeds) — per seed (provenance) ===")
print("seed " + " ".join(f"{c:>8}" for c in cols))
for r in rows:
    print(f"{r['seed']:>4} " + " ".join(
        (f"{r[c]:>8.2f}" if isinstance(r[c], float) else f"{str(r[c]):>8}") for c in cols))

T95 = {9:2.262, 8:2.306, 7:2.365, 6:2.447, 5:2.571, 4:2.776, 3:3.182}.get(len(rows)-1, 2.262)
print(f"\n=== mean +/- SD  [95% CI, t(df={len(rows)-1})={T95}] ===")
for c in cols:
    vals = [r[c] for r in rows if r[c] is not None]
    if len(vals) < 2:
        print(f"  {c:>8}: n/a"); continue
    m = statistics.mean(vals); sd = statistics.stdev(vals)
    ci = T95 * sd / math.sqrt(len(vals))
    print(f"  {c:>8}: mean={m:9.3f}  SD={sd:7.3f}  95%CI=[{m-ci:.3f}, {m+ci:.3f}]")

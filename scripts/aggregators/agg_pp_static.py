#!/usr/bin/env python3
"""Aggregate a PP-Static condition across its 5 seeds. Every number is PARSED from each seed's
result log (provenance printed per seed); mean/SD/95%CI computed deterministically (t, df=4)."""
import re, sys, math, statistics
from pathlib import Path

PAGE = sys.argv[1] if len(sys.argv) > 1 else "product"
SEEDS = [1, 2, 3, 4, 5]
V2 = Path("/path/to/GenWebSec/results/V2")
LOGNAME = f"D1_customapp_{PAGE}_per_payload.txt"

def grab(txt, pat, cast=float, group=1):
    m = re.search(pat, txt)
    return cast(m.group(group).replace(",", "")) if m else None

rows = []
for s in SEEDS:
    f = V2 / "CustomApp_D1" / f"CustomApp_D1_seed{s}" / LOGNAME
    if not f.exists():
        print(f"seed {s}: MISSING {f}"); continue
    t = f.read_text(encoding="utf-8", errors="replace")
    r = {
        "seed": s,
        "blocked": grab(t, r"Final:\s*(\d+)/\d+\s+blocked", int),
        "corpus":  grab(t, r"Final:\s*\d+/(\d+)\s+blocked", int),
        "rules":   grab(t, r"blocked with\s*(\d+)\s*rule", int),
        "fp":      grab(t, r"FP=([\d.]+)%\s*\("),                 # total FP% (ITER SUMMARY)
        "added":   grab(t, r"added\s*([\d.]+)%\s*vs CRS"),
        "errors":  grab(t, r"errors\s*(\d+)\s*=", int),
        "calls":   grab(t, r"defense LLM calls\s*(\d+)", int),
        "cands":   grab(t, r"candidate rules\s*(\d+)", int),
        "rej":     grab(t, r"rejected\s*(\d+)", int),
        "wall":    grab(t, r"wall-clock\s*([\d.]+)s"),
        "in_tok":  grab(t, r"TOTAL input tokens:\s*([\d,]+)", int),
        "out_tok": grab(t, r"TOTAL output tokens:\s*([\d,]+)", int),
        "eval_s":  grab(t, r"TOTAL rule-eval time:\s*([\d.]+)s"),
        "lat_s":   grab(t, r"latency=([\d.]+)s"),
        "cost":    grab(t, r"est\. cost \$([\d.]+)"),
        "cpr":     grab(t, r"LLM-calls per accepted rule\s*=\s*([\d.]+)"),
    }
    rows.append(r)

if not rows:
    print("no seed logs found"); sys.exit(1)

cols = [("blocked","%d"),("rules","%d"),("fp","%.2f%%"),("added","%.2f%%"),("errors","%d"),
        ("calls","%d"),("cands","%d"),("rej","%d"),("wall","%.0fs"),("in_tok","%d"),
        ("out_tok","%d"),("eval_s","%.0fs"),("lat_s","%.0fs"),("cost","$%.4f"),("cpr","%.2f")]

print(f"\n=== PP-Static  page={PAGE}  (n={len(rows)} seeds) — per-seed (provenance) ===")
hdr = "seed " + " ".join(f"{k:>9}" for k,_ in cols)
print(hdr)
for r in rows:
    print(f"{r['seed']:>4} " + " ".join(f"{(r[k] if r[k] is not None else float('nan')):>9.2f}" if isinstance(r[k],float) else f"{str(r[k]):>9}" for k,_ in cols))

T95 = {1:12.706,2:4.303,3:3.182,4:2.776,5:2.571}.get(len(rows)-1, 2.776)  # t(0.975, df=n-1)
print(f"\n=== mean +/- SD  [95% CI, t(df={len(rows)-1})={T95}] ===")
for k, fmt in cols:
    vals = [r[k] for r in rows if r[k] is not None]
    if len(vals) < 2:
        print(f"  {k:>8}: n/a"); continue
    m = statistics.mean(vals); sd = statistics.stdev(vals)
    ci = T95 * sd / math.sqrt(len(vals))
    print(f"  {k:>8}: mean={m:10.3f}  SD={sd:8.3f}  95%CI=[{m-ci:.3f}, {m+ci:.3f}]  (half={ci:.3f})")

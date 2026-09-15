#!/usr/bin/env python3
"""Item 6 eps-sensitivity table: |R| (mean±SD, n=10) per page x eps, parsed from each run's log."""
import re, statistics
from pathlib import Path
V2 = Path("/path/to/GenWebSec/results/V2")
EPSES = ["0.1", "0.2", "0.3", "0.4", "0.5"]
PAGES = [("d1", "login"), ("d1", "product"), ("d1", "filter"), ("d1", "search"),
         ("d2", "calc"), ("d2", "search")]

def logpath(pilot, page, eps, s):
    if pilot == "d2":
        return V2 / "CustomApp_D2" / f"CustomXSS_D2_eps{eps}_seed{s}" / f"D2_customxss_{page}_clustering.txt"
    return V2 / "CustomApp_D1" / f"CustomApp_D1_eps{eps}_seed{s}" / f"D1_customapp_{page}_clustering.txt"

def grab(t, pat, cast=int):
    m = re.search(pat, t)
    return cast(m.group(1)) if m else None

def collect(pilot, page, eps):
    rules, blk, cl0 = [], [], []
    for s in range(1, 11):
        f = logpath(pilot, page, eps, s)
        if not f.exists():
            continue
        t = f.read_text(encoding="utf-8", errors="replace")
        r = grab(t, r"blocked with\s*(\d+)\s*rule")
        b = grab(t, r"Final:\s*(\d+)/")
        c = grab(t, r"cluster-stats eps=[\d.]+\] clusters=(\d+)")
        if r is not None: rules.append(r)
        if b is not None: blk.append(b)
        if c is not None: cl0.append(c)
    return rules, blk, cl0

def ms(v):
    if not v: return (float("nan"), 0.0, 0)
    return (statistics.mean(v), (statistics.stdev(v) if len(v) > 1 else 0.0), len(v))

print("\n=== ITEM 6: |R| (mean+/-SD, n) per page x eps ===")
print(f"{'page':12} " + " ".join(f"{'eps='+e:>13}" for e in EPSES))
for pilot, page in PAGES:
    cells = []
    for eps in EPSES:
        r, _, _ = collect(pilot, page, eps)
        m, sd, n = ms(r)
        cells.append(f"{m:.1f}+/-{sd:.1f}(n{n})")
    print(f"{pilot+' '+page:12} " + " ".join(f"{c:>13}" for c in cells))

print("\n=== round-0 cluster count (mean) per page x eps ===")
print(f"{'page':12} " + " ".join(f"{'eps='+e:>13}" for e in EPSES))
for pilot, page in PAGES:
    cells = []
    for eps in EPSES:
        _, _, c = collect(pilot, page, eps)
        m, sd, n = ms(c)
        cells.append(f"{m:.0f}")
    print(f"{pilot+' '+page:12} " + " ".join(f"{c:>13}" for c in cells))

print("\n=== min blocked / 300 across the 10 seeds (worst-case coverage) per page x eps ===")
print(f"{'page':12} " + " ".join(f"{'eps='+e:>13}" for e in EPSES))
for pilot, page in PAGES:
    cells = []
    for eps in EPSES:
        _, b, _ = collect(pilot, page, eps)
        cells.append(f"{min(b) if b else '?'}/300")
    print(f"{pilot+' '+page:12} " + " ".join(f"{c:>13}" for c in cells))

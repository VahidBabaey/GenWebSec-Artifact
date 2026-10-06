import glob, csv, statistics as st
from collections import defaultdict
BASE = "/home/vahid/Projects/GenWebSec/results/V2/RevisionNewResults/R2.5/replay"
agg = defaultdict(list)   # (corpus, tech) -> [(blocked,total,fp%)]
for fp in sorted(glob.glob(f"{BASE}/*.csv")):
    for r in csv.DictReader(open(fp)):
        if r.get("status") != "ok":
            continue
        agg[(r["corpus"], r["technique"])].append((int(r["blocked"]), int(r["total"]), float(r["fp_pct"])))
for corp in ("nested_json", "rich_text"):
    print(f"\n== {corp} ==")
    for tech in ("CRS-only", "CG-Static", "CG-Adaptive"):
        v = agg.get((corp, tech))
        if not v:
            print(f"  {tech:12}: (none)"); continue
        rates = [x[2] for x in v]; tot = v[0][1]
        bl = [x[0] for x in v]
        print(f"  {tech:12}: FP% mean={st.mean(rates):6.3f} min={min(rates):6.3f} max={max(rates):6.3f}  "
              f"blocked_range={min(bl)}-{max(bl)}/{tot}  n_units={len(v)}")

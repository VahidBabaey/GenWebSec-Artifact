#!/usr/bin/env python3
"""RQ2 pattern probe (NOT the final table): parse D1/D2 CG logs and report, per family x eps,
mean+/-SD of the presentation-relevant quantities, so we can discuss structure with real numbers.
Everything is read from each run's log (no CSV exists for D1/D2)."""
import re, glob, statistics as st, os
BASE = "/path/to/GenWebSec/results/V2"
FAMS = {
 "D1 (SQLi)": (f"{BASE}/CustomApp_D1/CustomApp_D1_eps%s_seed%d/D1_customapp_%s_clustering.txt",
               ["login","product","search","filter"]),
 "D2 (XSS)":  (f"{BASE}/CustomApp_D2/CustomXSS_D2_eps%s_seed%d/D2_customxss_%s_clustering.txt",
               ["search","calc"]),
}
EPS = ["0.1","0.2","0.3","0.4","0.5"]; SEEDS = range(1,11)

def parse(path):
    if not os.path.exists(path): return None
    t = open(path, encoding="utf-8", errors="replace").read()
    m_final = re.search(r"Final:\s*(\d+)/300 blocked with (\d+) rule", t)
    if not m_final: return None
    blocked, rules = int(m_final.group(1)), int(m_final.group(2))
    calls = int(re.search(r"defense LLM calls (\d+)", t).group(1)) if re.search(r"defense LLM calls (\d+)", t) else 0
    clusters = int(re.search(r"clusters=(\d+)", t).group(1)) if re.search(r"clusters=(\d+)", t) else 0
    rounds = len(re.findall(r"ITER \d+ SUMMARY", t))
    fp_added = 0.0
    for mm in re.finditer(r"added ([0-9.]+)% vs CRS", t): fp_added = float(mm.group(1))  # last = final ruleset
    cpr = int(re.search(r"clusters processed (\d+)", t).group(1)) if re.search(r"clusters processed (\d+)", t) else 0
    return dict(block=100.0*blocked/300, rules=rules, calls=calls, clusters=clusters,
               rounds=rounds, fp=fp_added, cproc=cpr)

def ms(v): return (st.mean(v), st.stdev(v) if len(v)>1 else 0.0)

for fam,(fmt,pages) in FAMS.items():
    print(f"\n================= {fam} =================")
    print(f"{'eps':>4} {'block%':>13} {'|R|':>10} {'addFP%':>11} {'clusters':>13} {'LLMcalls':>13} {'rounds':>10}  n")
    for e in EPS:
        rows = [parse(fmt%(e,s,p)) for p in pages for s in SEEDS]
        rows = [r for r in rows if r]
        if not rows: continue
        b=ms([r['block'] for r in rows]); R=ms([r['rules'] for r in rows]); f=ms([r['fp'] for r in rows])
        c=ms([r['clusters'] for r in rows]); L=ms([r['calls'] for r in rows]); rd=ms([r['rounds'] for r in rows])
        print(f"{e:>4} {b[0]:6.1f}±{b[1]:<4.1f} {R[0]:5.1f}±{R[1]:<3.1f} {f[0]:5.2f}±{f[1]:<4.2f} "
              f"{c[0]:6.0f}±{c[1]:<5.0f} {L[0]:6.0f}±{L[1]:<5.0f} {rd[0]:4.1f}±{rd[1]:<3.1f}  {len(rows)}")

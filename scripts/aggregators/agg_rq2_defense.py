#!/usr/bin/env python3
"""RQ2 aggregator: defense-only (clustered / CG-Static) on the fixed A1/A2 winners corpus.
Parses every D1/D2 run log (no CSV exists for D1/D2) and emits:
  TABLE 1  per page at eps=0.3 (default): Block%, |R|, Added-FP%, LLM calls, calls/rule
  TABLE 2  per family x eps: Block%, |R|, Added-FP%, Clusters, LLM calls
  PROSE    per family: rounds, tokens, wall-clock, cost
Each value = mean +/- SD over the 10 seeds. Numbers are read from each run's log.
"""
import re, statistics as st, os
BASE = "/path/to/GenWebSec/results/V2"
# (family, log-path template, [(page-key, paper-label)])
FAMS = [
 ("SQLi", f"{BASE}/CustomApp_D1/CustomApp_D1_eps%s_seed%d/D1_customapp_%s_clustering.txt",
   [("login","Login form"),("search","Product search"),("product","URL parameter"),("filter","Product filter")]),
 ("XSS",  f"{BASE}/CustomApp_D2/CustomXSS_D2_eps%s_seed%d/D2_customxss_%s_clustering.txt",
   [("search","Search (JS-string)"),("calc","Calculator (eval sink)")]),
]
EPS = ["0.1","0.2","0.3","0.4","0.5"]; SEEDS = range(1,11)

def parse(path):
    if not os.path.exists(path): return None
    t = open(path, encoding="utf-8", errors="replace").read()
    mf = re.search(r"Final:\s*(\d+)/300 blocked with (\d+) rule", t)
    if not mf: return None
    blocked, rules = int(mf.group(1)), int(mf.group(2))
    g = lambda pat, d=0: (int(re.search(pat, t).group(1)) if re.search(pat, t) else d)
    calls    = g(r"defense LLM calls (\d+)")
    clusters = g(r"clusters=(\d+)")
    rounds   = len(re.findall(r"ITER \d+ SUMMARY", t))
    tin      = g(r"tokens in=([\d,]+)".replace("(\\d+)","([\\d,]+)")) if False else int((re.search(r"tokens in=([\d,]+)",t) or re.search(r"(0)","0")).group(1).replace(",",""))
    tout     = int((re.search(r"out=([\d,]+)\s+est",t) or re.search(r"(0)","0")).group(1).replace(",",""))
    wall     = float((re.search(r"wall-clock ([\d.]+)s",t) or re.search(r"(0)","0")).group(1))
    cost     = float((re.search(r"est\. cost \$([\d.]+)",t) or re.search(r"(0)","0")).group(1))
    fp = 0.0
    for mm in re.finditer(r"added ([0-9.]+)% vs CRS", t): fp = float(mm.group(1))   # last = final ruleset
    return dict(block=100.0*blocked/300, rules=rules, calls=calls, clusters=clusters,
                rounds=rounds, fp=fp, tin=tin, tout=tout, wall=wall, cost=cost,
                cpr=calls/rules if rules else 0.0)

def ms(v): return (st.mean(v), st.stdev(v) if len(v)>1 else 0.0)
def rhu(x, d):  # round-half-up to d decimals (avoids float/banker's ambiguity at .5 boundaries)
    import math; m = 10**d; return math.floor(x*m + 0.5)/m
import math
def mr(v, round_med=False):   # median + [min,max] for discrete COUNT metrics
    m = st.median(v); lo = min(v); hi = max(v)
    if round_med: m = math.floor(m + 0.5)          # large counts (calls, clusters): integer median
    ms_ = f"{m:.0f}" if m == int(m) else f"{m:.1f}"
    return ms_ if lo == hi else f"{ms_} [{lo:.0f}--{hi:.0f}]"
def rows_for(fam_fmt, pages, eps):
    out=[]
    for p in pages:
        for s in SEEDS:
            r = parse(fam_fmt % (eps, s, p))
            if r: out.append(r)
    return out

print("############## TABLE 1: per page @ eps=0.3  (rates=mean+/-SD, counts=median[min-max]) ##############")
print(f"{'Family':>5} {'Page':>22} {'Block%':>12} {'|R|':>10} {'addFP%':>10} {'LLMcalls':>12}")
for fam, fmt, pages in FAMS:
    for pk, lbl in pages:
        rr = rows_for(fmt, [pk], "0.3")
        if not rr: continue
        b=ms([r['block'] for r in rr]); f=ms([r['fp'] for r in rr])
        R=mr([r['rules'] for r in rr]); L=mr([r['calls'] for r in rr], round_med=True)
        print(f"{fam:>5} {lbl:>22} {rhu(b[0],1):6.1f}±{rhu(b[1],1):<4.1f} {R:>10} {rhu(f[0],2):5.2f}±{rhu(f[1],2):<3.2f} {L:>12}")

print("\n############## TABLE 2: per family x eps  (rates=mean+/-SD, counts=median[min-max]) ##############")
print(f"{'Family':>5} {'eps':>4} {'Block%':>12} {'|R|':>10} {'addFP%':>10} {'Clusters':>12} {'LLMcalls':>12}")
for fam, fmt, pages in FAMS:
    for e in EPS:
        rr = rows_for(fmt, [p for p,_ in pages], e)
        b=ms([r['block'] for r in rr]); f=ms([r['fp'] for r in rr])
        R=mr([r['rules'] for r in rr]); cl=mr([r['clusters'] for r in rr], round_med=True); L=mr([r['calls'] for r in rr], round_med=True)
        print(f"{fam:>5} {e:>4} {rhu(b[0],1):6.1f}±{rhu(b[1],1):<4.1f} {R:>10} {rhu(f[0],2):5.2f}±{rhu(f[1],2):<3.2f} {cl:>12} {L:>12}")

print("\n############## PROSE: per family @ eps=0.3 (rounds=median[min-max]; tokens/time/cost=mean) ##############")
for fam, fmt, pages in FAMS:
    rr = rows_for(fmt, [p for p,_ in pages], "0.3")
    rd=mr([r['rounds'] for r in rr]); ti=ms([r['tin'] for r in rr]); to=ms([r['tout'] for r in rr])
    w=ms([r['wall'] for r in rr]); co=ms([r['cost'] for r in rr])
    print(f"{fam}: rounds {rd}  tok_in {ti[0]:.0f}  tok_out {to[0]:.0f}  wall {w[0]:.0f}s  cost ${co[0]:.4f}")

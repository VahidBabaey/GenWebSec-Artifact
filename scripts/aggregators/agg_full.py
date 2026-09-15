#!/usr/bin/env python3
"""Bucket-1 full aggregation: PP vs Random-Group (RG) vs CG on the fixed 300-attack corpus, eps=0.3.
Reads EVERY metric the advisor listed from each run log (robust to the older PP log format), reports
per-page mean+/-SD (rates) and median[min-max] (counts), then the PAIRED RG-vs-CG analysis (same 300
per seed): RG-CG rule count, RG-CG block, RG/CG calls, RG/CG tokens, RG/CG offline time, with a manual
Wilcoxon signed-rank (no scipy) + rank-biserial effect size. Numbers are read from the logs; nothing
is assumed."""
import re, os, math, statistics as st

BASE = "/path/to/GenWebSec/results/V2"
SEEDS = list(range(1, 11))
SQLI = [("login", "Login form"), ("search", "Product search"), ("product", "URL parameter"), ("filter", "Product filter")]
XSS = [("search", "Search (JS-string)"), ("calc", "Calculator (eval sink)")]

def p_cg_sqli(p, s): return f"{BASE}/CustomApp_D1/CustomApp_D1_eps0.3_seed{s}/D1_customapp_{p}_clustering.txt"
def p_cg_xss(p, s):  return f"{BASE}/CustomApp_D2/CustomXSS_D2_eps0.3_seed{s}/D2_customxss_{p}_clustering.txt"
def p_pp_sqli(p, s): return f"{BASE}/CustomApp_D1-PP/CustomApp_D1_seed{s}/D1_customapp_{p}_per_payload.txt"
def p_pp_xss(p, s):  return f"{BASE}/CustomApp_D2-PP/CustomXSS_D2_seed{s}/D2_customxss_{p}_per_payload.txt"
def p_rg_sqli(p, s): return f"{BASE}/Random-Groups/CustomApp_D1_eps0.3_seed{s}/D1_customapp_{p}_random_group.txt"
def p_rg_xss(p, s):  return f"{BASE}/Random-Groups/CustomXSS_D2_eps0.3_seed{s}/D2_customxss_{p}_random_group.txt"

PATHS = {"SQLi": {"PP": p_pp_sqli, "RG": p_rg_sqli, "CG": p_cg_sqli},
         "XSS":  {"PP": p_pp_xss,  "RG": p_rg_xss,  "CG": p_cg_xss}}
FAMS = [("SQLi", SQLI), ("XSS", XSS)]
CONDS = ["PP", "RG", "CG"]


def _num(pat, t, cast=int, d=None):
    m = re.search(pat, t)
    if not m:
        return d
    return cast(m.group(1).replace(",", ""))


def parse(path):
    if not os.path.exists(path):
        return None
    t = open(path, encoding="utf-8", errors="replace").read()
    mf = re.search(r"Final:\s*(\d+)/300 blocked with (\d+) rule", t)
    if not mf:
        return None
    blocked, rules = int(mf.group(1)), int(mf.group(2))
    tin = _num(r"TOTAL input tokens:\s*([\d,]+)", t, int, 0)
    tout = _num(r"TOTAL output tokens:\s*([\d,]+)", t, int, 0)
    fp = 0.0
    for mm in re.finditer(r"added ([0-9.]+)% vs CRS", t):
        fp = float(mm.group(1))
    return dict(
        block=100.0 * blocked / 300, rules=rules,
        calls=_num(r"defense LLM calls (\d+)", t, int, 0),
        cand=_num(r"candidate rules (\d+)", t, int, 0),
        rej=_num(r"rejected (\d+)", t, int, 0),
        tin=tin, tout=tout, ttot=tin + tout,
        ruleeval=_num(r"TOTAL rule-eval time:\s*([\d.]+)s", t, float, 0.0),
        wall=_num(r"wall-clock ([\d.]+)s", t, float, 0.0),
        genlat=_num(r"latency=([\d.]+)s", t, float, 0.0),
        fp=fp,
    )


def by_seed(fam, cond, page):
    out = {}
    for s in SEEDS:
        r = parse(PATHS[fam][cond](page, s))
        if r:
            out[s] = r
    return out


def ms(v): return (st.mean(v), st.stdev(v) if len(v) > 1 else 0.0)
def med(v): return st.median(v)
def pct(v, q):
    v = sorted(v); k = (len(v) - 1) * q; f = math.floor(k); c = math.ceil(k)
    return v[f] if f == c else v[f] + (v[c] - v[f]) * (k - f)
def iqr(v): return (pct(v, 0.25), pct(v, 0.75))
def mrange(v):
    m = med(v); lo, hi = min(v), max(v)
    mm = f"{m:.0f}" if m == int(m) else f"{m:.1f}"
    return mm if lo == hi else f"{mm}[{lo:.0f}-{hi:.0f}]"


def wilcoxon(diffs):
    nz = [d for d in diffs if d != 0]
    n = len(nz)
    if n == 0:
        return dict(n=0, p=1.0, r=0.0, note="all ties")
    aug = sorted(((abs(d), (1 if d > 0 else -1)) for d in nz), key=lambda x: x[0])
    vals = [a for a, _ in aug]
    rank = [0.0] * n
    j = 0
    while j < n:
        k = j
        while k + 1 < n and vals[k + 1] == vals[j]:
            k += 1
        avg = (j + 1 + k + 1) / 2.0
        for m in range(j, k + 1):
            rank[m] = avg
        j = k + 1
    Wpos = sum(rank[m] for m in range(n) if aug[m][1] > 0)
    Wneg = sum(rank[m] for m in range(n) if aug[m][1] < 0)
    W = min(Wpos, Wneg)
    meanW = n * (n + 1) / 4.0
    sdW = math.sqrt(n * (n + 1) * (2 * n + 1) / 24.0)
    z = (W - meanW + 0.5) / sdW if sdW else 0.0
    p = 2 * (1 - 0.5 * (1 + math.erf(abs(z) / math.sqrt(2))))
    r = (Wpos - Wneg) / (Wpos + Wneg) if (Wpos + Wneg) else 0.0
    return dict(n=n, p=min(1.0, max(0.0, p)), r=r)


# ======================= PART A: per-page metric table =======================
print("=" * 118)
print("PART A  RQ2 @ eps=0.3  full metric set  (rates mean+/-SD ; counts median[min-max] over 10 seeds)")
print("  Block%=coverage  |R|=accepted rules  cand=candidates proposed  rej=rejected  calls=defense-model calls")
print("  tokens=in+out (median)  eval_s=validation replay time  wall_s=end-to-end hardening wall-clock  FP%=added-vs-CRS")
print("=" * 118)
hdr = f"{'Family':>4} {'Page':>16} {'C':>2} {'Block%':>11} {'|R|':>10} {'cand':>10} {'rej':>10} {'calls':>10} {'tok(med)':>10} {'eval_s':>8} {'wall_s':>9} {'FP%':>10}"
print(hdr)
for fam, pages in FAMS:
    for pk, lbl in pages:
        for c in CONDS:
            d = by_seed(fam, c, pk); rows = list(d.values())
            if not rows:
                print(f"{fam:>4} {lbl:>16} {c:>2}  NO DATA"); continue
            b = ms([r['block'] for r in rows]); f = ms([r['fp'] for r in rows])
            print(f"{'':>4} {lbl if c=='PP' else '':>16} {c:>2} "
                  f"{b[0]:6.1f}±{b[1]:<4.1f} {mrange([r['rules'] for r in rows]):>10} "
                  f"{mrange([r['cand'] for r in rows]):>10} {mrange([r['rej'] for r in rows]):>10} "
                  f"{mrange([r['calls'] for r in rows]):>10} {med([r['ttot'] for r in rows]):>10.0f} "
                  f"{med([r['ruleeval'] for r in rows]):>8.1f} {med([r['wall'] for r in rows]):>9.1f} "
                  f"{f[0]:5.2f}±{f[1]:<4.2f}")
        print("-" * 118)

# ======================= PART B: paired RG vs CG =======================
print("\n" + "=" * 118)
print("PART B  PAIRED RG vs CG  (same 300 attacks per seed; n pairs per page = seeds in BOTH)")
print("  dR=RG-CG rule count ; dBlock=RG-CG block%% ; ratios=median(RG/CG) with IQR ; Wilcoxon p (approx) + rank-biserial r")
print("  r>0 => RG larger than CG on that metric.  effect size r matters more than p at n=10.")
print("=" * 118)

def pairstats(fam, pk):
    rg = by_seed(fam, "RG", pk); cg = by_seed(fam, "CG", pk)
    seeds = sorted(set(rg) & set(cg))
    dR = [rg[s]['rules'] - cg[s]['rules'] for s in seeds]
    dB = [rg[s]['block'] - cg[s]['block'] for s in seeds]
    rc = [rg[s]['calls'] / cg[s]['calls'] for s in seeds if cg[s]['calls']]
    rt = [rg[s]['ttot'] / cg[s]['ttot'] for s in seeds if cg[s]['ttot']]
    rw = [rg[s]['wall'] / cg[s]['wall'] for s in seeds if cg[s]['wall']]
    dcalls = [rg[s]['calls'] - cg[s]['calls'] for s in seeds]
    return seeds, dR, dB, rc, rt, rw, dcalls

allpairs = {"dR": [], "dB": [], "rc": [], "rt": [], "rw": [], "dcalls": []}
for fam, pages in FAMS:
    for pk, lbl in pages:
        seeds, dR, dB, rc, rt, rw, dcalls = pairstats(fam, pk)
        for k, v in zip(["dR", "dB", "rc", "rt", "rw", "dcalls"], [dR, dB, rc, rt, rw, dcalls]):
            allpairs[k] += v
        wR = wilcoxon(dR); wC = wilcoxon(dcalls)
        npos = sum(1 for x in dR if x > 0); nneg = sum(1 for x in dR if x < 0); nz = sum(1 for x in dR if x == 0)
        print(f"\n{fam} {lbl}  (n={len(seeds)} pairs)")
        print(f"   dR (RG-CG rules)   median {med(dR):+.1f}  range[{min(dR):+.0f},{max(dR):+.0f}]  "
              f"RG>CG:{npos} RG<CG:{nneg} tie:{nz}   Wilcoxon p={wR['p']:.3f}  r={wR['r']:+.2f}")
        print(f"   dBlock (RG-CG %)   median {med(dB):+.2f}  range[{min(dB):+.2f},{max(dB):+.2f}]")
        print(f"   calls RG/CG        median {med(rc):.2f}  IQR[{iqr(rc)[0]:.2f},{iqr(rc)[1]:.2f}]  "
              f"range[{min(rc):.2f},{max(rc):.2f}]   Wilcoxon(dcalls) p={wC['p']:.3f}  r={wC['r']:+.2f}")
        print(f"   tokens RG/CG       median {med(rt):.2f}  IQR[{iqr(rt)[0]:.2f},{iqr(rt)[1]:.2f}]")
        print(f"   walltime RG/CG     median {med(rw):.2f}  IQR[{iqr(rw)[0]:.2f},{iqr(rw)[1]:.2f}]")

print("\n" + "=" * 60)
print("POOLED over all 60 seed-pairs")
print("=" * 60)
wR = wilcoxon(allpairs['dR']); wC = wilcoxon(allpairs['dcalls'])
npos = sum(1 for x in allpairs['dR'] if x > 0); nneg = sum(1 for x in allpairs['dR'] if x < 0); nz = sum(1 for x in allpairs['dR'] if x == 0)
print(f"dR (RG-CG rules)  median {med(allpairs['dR']):+.1f}  RG>CG:{npos} RG<CG:{nneg} tie:{nz}  Wilcoxon p={wR['p']:.3f} r={wR['r']:+.2f}")
print(f"dBlock (RG-CG %)  median {med(allpairs['dB']):+.2f}  range[{min(allpairs['dB']):+.2f},{max(allpairs['dB']):+.2f}]")
print(f"calls  RG/CG      median {med(allpairs['rc']):.2f}  IQR[{iqr(allpairs['rc'])[0]:.2f},{iqr(allpairs['rc'])[1]:.2f}]  Wilcoxon(dcalls) p={wC['p']:.3f} r={wC['r']:+.2f}")
print(f"tokens RG/CG      median {med(allpairs['rt']):.2f}  IQR[{iqr(allpairs['rt'])[0]:.2f},{iqr(allpairs['rt'])[1]:.2f}]")
print(f"wall   RG/CG      median {med(allpairs['rw']):.2f}  IQR[{iqr(allpairs['rw'])[0]:.2f},{iqr(allpairs['rw'])[1]:.2f}]")

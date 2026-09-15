#!/usr/bin/env python3
"""Aggregate RQ2 defense on the fixed 300-attack corpus for THREE conditions at eps=0.3:
   PP-Static (per-payload), Random-Group (RG), CG-Static (clustering).
Parses each run log (same format across conditions). Metrics per run: Block%, |R| (accepted rules),
rules-per-100, defense LLM calls, calls/rule, added benign-FP% vs CRS (in-corpus, during synthesis).
Reports per page (paper labels) and per family, mean+/-SD for rates and median[min-max] for counts,
over the 10 seeds, plus the PP/CG, PP/RG, RG/CG rule-count reduction factors.
Numbers are read from each run's log; missing seeds are reported explicitly (no silent gaps)."""
import re, os, math, statistics as st

BASE = "/path/to/GenWebSec/results/V2"
SEEDS = range(1, 11)

# page-key -> paper label (identical to agg_rq2_defense.py)
SQLI_PAGES = [("login", "Login form"), ("search", "Product search"),
              ("product", "URL parameter"), ("filter", "Product filter")]
XSS_PAGES = [("search", "Search (JS-string)"), ("calc", "Calculator (eval sink)")]

# condition -> {family -> (path_template, needs (eps,seed,page) or (seed,page))}
def cg_sqli(p, s):  return f"{BASE}/CustomApp_D1/CustomApp_D1_eps0.3_seed{s}/D1_customapp_{p}_clustering.txt"
def cg_xss(p, s):   return f"{BASE}/CustomApp_D2/CustomXSS_D2_eps0.3_seed{s}/D2_customxss_{p}_clustering.txt"
def pp_sqli(p, s):  return f"{BASE}/CustomApp_D1-PP/CustomApp_D1_seed{s}/D1_customapp_{p}_per_payload.txt"
def pp_xss(p, s):   return f"{BASE}/CustomApp_D2-PP/CustomXSS_D2_seed{s}/D2_customxss_{p}_per_payload.txt"
def rg_sqli(p, s):  return f"{BASE}/Random-Groups/CustomApp_D1_eps0.3_seed{s}/D1_customapp_{p}_random_group.txt"
def rg_xss(p, s):   return f"{BASE}/Random-Groups/CustomXSS_D2_eps0.3_seed{s}/D2_customxss_{p}_random_group.txt"

CONDS = ["PP", "RG", "CG"]
PATHS = {"SQLi": {"PP": pp_sqli, "RG": rg_sqli, "CG": cg_sqli},
         "XSS":  {"PP": pp_xss,  "RG": rg_xss,  "CG": cg_xss}}
FAMS = [("SQLi", SQLI_PAGES), ("XSS", XSS_PAGES)]


def parse(path):
    if not os.path.exists(path):
        return None
    t = open(path, encoding="utf-8", errors="replace").read()
    mf = re.search(r"Final:\s*(\d+)/300 blocked with (\d+) rule", t)
    if not mf:
        return None
    blocked, rules = int(mf.group(1)), int(mf.group(2))
    def g(pat, d=0):
        m = re.search(pat, t)
        return int(m.group(1)) if m else d
    calls = g(r"defense LLM calls (\d+)")
    groups = g(r"clusters=(\d+)") or g(r"groups=(\d+)")
    fp = 0.0
    for mm in re.finditer(r"added ([0-9.]+)% vs CRS", t):
        fp = float(mm.group(1))   # last occurrence = final ruleset
    return dict(block=100.0 * blocked / 300, rules=rules, calls=calls, groups=groups, fp=fp,
                rpc=100.0 * rules / 300, cpr=(calls / rules if rules else 0.0))


def collect(fam, cond, page):
    rows, missing = [], []
    for s in SEEDS:
        r = parse(PATHS[fam][cond](page, s))
        (rows.append(r) if r else missing.append(s))
    return rows, missing


def ms(v):  return (st.mean(v), st.stdev(v) if len(v) > 1 else 0.0)
def med(v): return st.median(v)
def mr(v):  # median [min-max] for counts
    m = med(v); lo, hi = min(v), max(v)
    mm = f"{m:.0f}" if m == int(m) else f"{m:.1f}"
    return mm if lo == hi else f"{mm} [{lo:.0f}-{hi:.0f}]"


# ---- 1. completeness ----
print("=" * 92)
print("DATA COMPLETENESS  (seeds with a valid Final line, out of 10)")
print("=" * 92)
print(f"{'Family':>5} {'Page':>22} {'PP':>10} {'RG':>10} {'CG':>10}")
complete = True
for fam, pages in FAMS:
    for pk, lbl in pages:
        cells = []
        for c in CONDS:
            rows, missing = collect(fam, c, pk)
            cells.append(f"{len(rows)}/10" + (f" miss{missing}" if missing else ""))
            if len(rows) != 10:
                complete = False
        print(f"{fam:>5} {lbl:>22} {cells[0]:>10} {cells[1]:>10} {cells[2]:>10}")
print(f"\nALL CONDITIONS COMPLETE (10/10 everywhere): {complete}")

# ---- 2. per-page comparison ----
print("\n" + "=" * 92)
print("RQ2 @ eps=0.3 : PP vs RANDOM-GROUP vs CG   (|R|,calls = median[min-max]; Block%,addFP% = mean+/-SD)")
print("=" * 92)
print(f"{'Family':>5} {'Page':>22} {'Cond':>5} {'|R|':>13} {'rules/100':>10} {'Block%':>12} {'LLMcalls':>13} {'calls/rule':>11} {'addFP%':>10}")
for fam, pages in FAMS:
    for pk, lbl in pages:
        for c in CONDS:
            rows, _ = collect(fam, c, pk)
            if not rows:
                print(f"{fam:>5} {lbl:>22} {c:>5}   (no data)")
                continue
            R = mr([r['rules'] for r in rows]); rpc = med([r['rpc'] for r in rows])
            b = ms([r['block'] for r in rows]); L = mr([r['calls'] for r in rows])
            cpr = med([r['cpr'] for r in rows]); f = ms([r['fp'] for r in rows])
            print(f"{'':>5} {lbl if c=='PP' else '':>22} {c:>5} {R:>13} {rpc:>10.2f} "
                  f"{b[0]:6.1f}+/-{b[1]:<4.1f} {L:>13} {cpr:>11.1f} {f[0]:5.2f}+/-{f[1]:<4.2f}")
        print("-" * 92)

# ---- 3. rule-count reduction factors (the reviewer's core question) ----
print("=" * 92)
print("RULE-COUNT REDUCTION  (median |R|)   -- RG/CG near 1 => benefit is joint exposure, not clustering")
print("=" * 92)
print(f"{'Family':>5} {'Page':>22} {'PP':>8} {'RG':>8} {'CG':>8} {'PP/CG':>8} {'PP/RG':>8} {'RG/CG':>8}")
def medrules(fam, c, pk):
    rows, _ = collect(fam, c, pk)
    return med([r['rules'] for r in rows]) if rows else float('nan')
for fam, pages in FAMS:
    for pk, lbl in pages:
        pp, rg, cg = medrules(fam, "PP", pk), medrules(fam, "RG", pk), medrules(fam, "CG", pk)
        rat = lambda a, b: (a / b if b else float('nan'))
        print(f"{fam:>5} {lbl:>22} {pp:>8.1f} {rg:>8.1f} {cg:>8.1f} "
              f"{rat(pp,cg):>8.1f} {rat(pp,rg):>8.1f} {rat(rg,cg):>8.2f}")

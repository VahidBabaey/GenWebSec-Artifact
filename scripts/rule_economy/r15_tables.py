#!/usr/bin/env python3
"""R1.5 derived tables (artifact). Emits clean per-seed CSVs + summaries from the saved rulesets and
   clustering logs (no new runs): rule length/complexity, cluster/singleton statistics across the eps
   sweep (group size under identical CG instructions), and a pipeline-differences summary."""
import os, re, glob, csv, statistics as st
from collections import defaultdict

V = "/home/vahid/Projects/GenWebSec/results/V2"
OUT = "/home/vahid/Projects/GenWebSec/paper-frontiers/results/V2/RevisionNewResults/R1.5"
os.makedirs(OUT, exist_ok=True)
PAGES = {"SQLi": ["login", "search", "product", "filter"], "XSS": ["search", "calc"]}

# ---- SecRule parser (from r15_rules.py) ----
def parse_quoted(s, i):
    j = i + 1; out = []
    while j < len(s):
        c = s[j]
        if c == "\\" and j + 1 < len(s):
            out.append(c + s[j + 1]); j += 2; continue
        if c == '"':
            return "".join(out), j + 1
        out.append(c); j += 1
    raise ValueError("unterminated quote")

def parse_secrule(line):
    rest = line[len("SecRule "):].lstrip()
    m = re.match(r"(\S+)\s+", rest); i = m.end()
    op, i = parse_quoted(rest, i)
    while i < len(rest) and rest[i] == " ":
        i += 1
    actions = ""
    if i < len(rest) and rest[i] == '"':
        actions, _ = parse_quoted(rest, i)
    return m.group(1), op, actions

def rule_info(line):
    _, op, actions = parse_secrule(line)
    op = op.strip()
    pat = op.partition(" ")[2] if op.startswith("@") else op
    alt = pat.count("|"); grp = pat.count("(")
    trans = ",".join(re.findall(r"t:([A-Za-z]+)", actions))
    return pat, len(pat), alt, grp, trans

# strategy -> (family -> ruleset glob with {s} seed and {E} eps placeholders handled below)
STRATS = {
    "PP-Static":   {"SQLi": (f"{V}/CustomApp_D1-PP/CustomApp_D1_seed*/D1_customapp_{{p}}_per_payload_rules.txt", None),
                    "XSS":  (f"{V}/CustomApp_D2-PP/CustomXSS_D2_seed*/D2_customxss_{{p}}_per_payload_rules.txt", None)},
    "CG-Static":   {"SQLi": (f"{V}/CustomApp_D1/CustomApp_D1_eps{{E}}_seed*/D1_customapp_{{p}}_clustering_rules.txt", "0.3"),
                    "XSS":  (f"{V}/CustomApp_D2/CustomXSS_D2_eps{{E}}_seed*/D2_customxss_{{p}}_clustering_rules.txt", "0.3")},
    "RG":          {"SQLi": (f"{V}/Random-Groups/CustomApp_D1_eps0.3_seed*/D1_customapp_{{p}}_random_group_rules.txt", None),
                    "XSS":  (f"{V}/Random-Groups/CustomXSS_D2_eps0.3_seed*/D2_customxss_{{p}}_random_group_rules.txt", None)},
    "CG-Adaptive": {"SQLi": (f"{V}/CustomApp_C1/CustomApp_C1_Token_eps{{E}}_seed*/C1_customapp_{{p}}_clustering_rules.txt", "0.3"),
                    "XSS":  (f"{V}/CustomApp_C2/CustomXSS_C2_Token_eps{{E}}_seed*/C2_customxss_{{p}}_clustering_rules.txt", "0.3")},
    "PP-Adaptive": {"SQLi": (f"{V}/CustomApp_C1-PP/CustomApp_C1_Token_seed*/C1_customapp_{{p}}_per_payload_rules.txt", None),
                    "XSS":  (f"{V}/CustomApp_C2-PP/CustomXSS_C2_Token_seed*/C2_customxss_{{p}}_per_payload_rules.txt", None)},
}

# ============ Table 3: rule length / complexity, per (strategy, family, context, seed) ============
rows = []
for strat, fams in STRATS.items():
    for fam, (gpat, eps) in fams.items():
        for page in PAGES[fam]:
            pat = gpat.format(p=page, E=eps) if eps else gpat.format(p=page)
            for fp in sorted(glob.glob(pat)):
                seed = re.search(r"seed(\d+)", fp).group(1)
                pats, lens, alts, grps, trans = [], [], [], [], set()
                for l in open(fp, encoding="utf-8", errors="replace"):
                    if l.startswith("SecRule "):
                        p_, L, a, g, t = rule_info(l)
                        pats.append(p_); lens.append(L); alts.append(a); grps.append(g); trans.add(t)
                if not pats:
                    continue
                rows.append({"strategy": strat, "family": fam, "context": page, "seed": int(seed),
                             "n_rules": len(pats), "n_distinct": len(set(pats)),
                             "med_regex_len": int(st.median(lens)), "sum_regex_len": sum(lens),
                             "med_alternations": st.median(alts), "med_groups": st.median(grps),
                             "transform_chains": ";".join(sorted(trans))})

with open(f"{OUT}/rule_complexity_perseed.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=list(rows[0].keys())); w.writeheader(); w.writerows(rows)

def rng(vals):
    return f"{min(vals)}-{max(vals)}" if vals else "-"
with open(f"{OUT}/rule_complexity_summary.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["strategy", "family", "n_runs_x_context", "rules_per_file_median", "rules_per_file_range",
                "distinct_over_total", "med_regex_len_median", "med_regex_len_range", "sum_regex_len_median"])
    for strat in STRATS:
        for fam in ("SQLi", "XSS"):
            rs = [r for r in rows if r["strategy"] == strat and r["family"] == fam]
            if not rs:
                continue
            nr = [r["n_rules"] for r in rs]
            tot = sum(r["n_rules"] for r in rs); dist = sum(r["n_distinct"] for r in rs)
            ml = [r["med_regex_len"] for r in rs]; sl = [r["sum_regex_len"] for r in rs]
            w.writerow([strat, fam, len(rs), int(st.median(nr)), rng(nr),
                        f"{dist}/{tot}", int(st.median(ml)), rng(ml), int(st.median(sl))])

print("== Table 3 (rule complexity) per-file medians ==")
for strat in STRATS:
    for fam in ("SQLi", "XSS"):
        rs = [r for r in rows if r["strategy"] == strat and r["family"] == fam]
        if rs:
            nr = [r["n_rules"] for r in rs]; ml = [r["med_regex_len"] for r in rs]
            print(f"  {strat:12s} {fam:4s}: rules/file med={int(st.median(nr))} [{rng(nr)}]  regexlen med={int(st.median(ml))} [{rng(ml)}]  distinct/total={sum(r['n_distinct'] for r in rs)}/{sum(nr)}")

# per-context summary (median over seeds) -> matches the paper table's per-context framing (range over contexts)
pc_len = {}; pc_tot = {}; pc_rul = {}
with open(f"{OUT}/rule_complexity_percontext.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["strategy", "family", "context", "n_seeds", "rules_median", "rules_range",
                "regexlen_median", "total_regexlen_median", "distinct_median", "transform_chains"])
    for strat in STRATS:
        for fam in ("SQLi", "XSS"):
            for page in PAGES[fam]:
                rs = [r for r in rows if r["strategy"] == strat and r["family"] == fam and r["context"] == page]
                if not rs:
                    continue
                chains = sorted({c for r in rs for c in r["transform_chains"].split(";") if c})
                nrm = int(st.median([r["n_rules"] for r in rs]))
                lm = int(st.median([r["med_regex_len"] for r in rs]))
                tm = int(st.median([r["sum_regex_len"] for r in rs]))
                dm = int(st.median([r["n_distinct"] for r in rs]))
                w.writerow([strat, fam, page, len(rs), nrm, rng([r["n_rules"] for r in rs]), lm, tm, dm, " | ".join(chains)])
                pc_len[(strat, fam, page)] = lm; pc_tot[(strat, fam, page)] = tm; pc_rul[(strat, fam, page)] = nrm
print("\n== per-context medians, range OVER contexts (matches plan framing) ==")
for strat in STRATS:
    for fam in ("SQLi", "XSS"):
        L = [pc_len[(strat, fam, p)] for p in PAGES[fam] if (strat, fam, p) in pc_len]
        T = [pc_tot[(strat, fam, p)] for p in PAGES[fam] if (strat, fam, p) in pc_tot]
        R = [pc_rul[(strat, fam, p)] for p in PAGES[fam] if (strat, fam, p) in pc_rul]
        if L:
            print(f"  {strat:12s} {fam:4s}: rules {min(R)}-{max(R)}  per-rule regexlen {min(L)}-{max(L)}  total regexlen {min(T)}-{max(T)}")

# ============ Table 2: cluster/singleton across the eps sweep (CG-Static), per context x eps x seed ============
CS = re.compile(r"cluster-stats eps=[0-9.]+\] clusters=(\d+)\s+singleton%=([0-9.]+)")
cl_rows = []
for fam, (logdir, pfx, pfxp) in {"SQLi": (f"{V}/CustomApp_D1", "D1_customapp", "CustomApp_D1"),
                                 "XSS": (f"{V}/CustomApp_D2", "D2_customxss", "CustomXSS_D2")}.items():
    for page in PAGES[fam]:
        for E in ["0.1", "0.2", "0.3", "0.4", "0.5"]:
            for logf in sorted(glob.glob(f"{logdir}/{pfxp}_eps{E}_seed*/{pfx}_{page}_clustering.txt")):
                seed = re.search(r"seed(\d+)", logf).group(1)
                K = sing = None
                for l in open(logf, encoding="utf-8", errors="replace"):
                    m = CS.search(l)
                    if m:
                        K, sing = int(m.group(1)), float(m.group(2)); break   # round-0 partition
                if K is None:
                    continue
                rf = logf.replace("_clustering.txt", "_clustering_rules.txt")
                nrules = sum(1 for l in open(rf, encoding="utf-8", errors="replace") if l.startswith("SecRule ")) if os.path.exists(rf) else 0
                cl_rows.append({"family": fam, "context": page, "eps": E, "seed": int(seed),
                                "clusters_round0": K, "singleton_pct": sing, "n_rules": nrules})

with open(f"{OUT}/cluster_singleton_perseed.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.DictWriter(fh, fieldnames=list(cl_rows[0].keys())); w.writeheader(); w.writerows(cl_rows)

with open(f"{OUT}/cluster_singleton_sweep_summary.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["eps", "clusters_round0_median_range", "singleton_pct_median_range", "n_rules_median_range"])
    for E in ["0.1", "0.2", "0.3", "0.4", "0.5"]:
        es = [r for r in cl_rows if r["eps"] == E]
        if not es: continue
        K = [r["clusters_round0"] for r in es]; S = [r["singleton_pct"] for r in es]; R = [r["n_rules"] for r in es]
        w.writerow([E, f"{int(st.median(K))} [{rng(K)}]", f"{st.median(S):.0f} [{min(S):.0f}-{max(S):.0f}]", f"{int(st.median(R))} [{rng(R)}]"])

print("\n== Table 2 (CG-Static group-size sweep): median across all contexts/seeds per eps ==")
for E in ["0.1", "0.2", "0.3", "0.4", "0.5"]:
    es = [r for r in cl_rows if r["eps"] == E]
    if es:
        K = [r["clusters_round0"] for r in es]; S = [r["singleton_pct"] for r in es]; R = [r["n_rules"] for r in es]
        print(f"  eps {E}: clusters med={int(st.median(K))} [{rng(K)}]  singleton% med={st.median(S):.0f}  rules med={int(st.median(R))} [{rng(R)}]")

# ============ Table 1: pipeline differences (quantitative provenance) ============
with open(f"{OUT}/pipeline_differences.csv", "w", newline="", encoding="utf-8") as fh:
    w = csv.writer(fh)
    w.writerow(["strategy", "family", "coverage_recheck_in_round", "rules_per_file_median", "distinct_over_total", "transform_chains_observed"])
    meta = {"PP-Static": "no", "PP-Adaptive": "no", "CG-Static": "yes", "CG-Adaptive": "yes", "RG": "yes"}
    for strat in STRATS:
        for fam in ("SQLi", "XSS"):
            rs = [r for r in rows if r["strategy"] == strat and r["family"] == fam]
            if not rs: continue
            nr = [r["n_rules"] for r in rs]
            chains = sorted({c for r in rs for c in r["transform_chains"].split(";") if c})
            w.writerow([strat, fam, meta[strat], int(st.median(nr)),
                        f"{sum(r['n_distinct'] for r in rs)}/{sum(nr)}", " | ".join(chains)])

# copy the authoritative per-seed coverage detail
import shutil
shutil.copy2(f"{V}/_rq2_cluster_coverage.txt", f"{OUT}/rq2_cluster_coverage_perseed.txt")
print("\nwrote:", OUT)
for f in sorted(os.listdir(OUT)):
    print("  ", f)

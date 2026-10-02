#!/usr/bin/env python3
"""r15_rules.py - rule length / complexity measurement for reviewer comment R1.5.

Parses every *accepted* rule (the *_rules.txt files written by the pilots) of
PP-Static, PP-Adaptive, CG-Static, CG-Adaptive and RG at eps = 0.3
(PP has no eps; it never clusters) for all seeds and all pages, and reports
per rule:  total SecRule line length, regex pattern length (the @rx argument),
number of alternations '|', character classes '[...]', quantifiers
(* + ? {n,m}), groups '(', number of variables/targets, number of t: transforms.
Per strategy x family: n runs, n rule files, n rules, rules/run, and
mean / median / max of every metric.  No pattern text is printed.
"""
import os, re, glob, statistics as st
from collections import defaultdict

ROOT = "/home/vahid/Projects/GenWebSec/results/V2"
EPS = "0.3"

# strategy -> list of (family, glob for rule files)
STRATS = {
    "PP-Static":   [("SQLi", f"{ROOT}/CustomApp_D1-PP/CustomApp_D1_seed*/D1_customapp_*_per_payload_rules.txt"),
                    ("XSS",  f"{ROOT}/CustomApp_D2-PP/CustomXSS_D2_seed*/D2_customxss_*_per_payload_rules.txt")],
    "PP-Adaptive": [("SQLi", f"{ROOT}/CustomApp_C1-PP/CustomApp_C1_Token_seed*/C1_customapp_*_per_payload_rules.txt"),
                    ("XSS",  f"{ROOT}/CustomApp_C2-PP/CustomXSS_C2_Token_seed*/C2_customxss_*_per_payload_rules.txt")],
    "CG-Static":   [("SQLi", f"{ROOT}/CustomApp_D1/CustomApp_D1_eps{EPS}_seed*/D1_customapp_*_clustering_rules.txt"),
                    ("XSS",  f"{ROOT}/CustomApp_D2/CustomXSS_D2_eps{EPS}_seed*/D2_customxss_*_clustering_rules.txt")],
    "CG-Adaptive": [("SQLi", f"{ROOT}/CustomApp_C1/CustomApp_C1_Token_eps{EPS}_seed*/C1_customapp_*_clustering_rules.txt"),
                    ("XSS",  f"{ROOT}/CustomApp_C2/CustomXSS_C2_Token_eps{EPS}_seed*/C2_customxss_*_clustering_rules.txt")],
    "RG":          [("SQLi", f"{ROOT}/Random-Groups/CustomApp_D1_eps{EPS}_seed*/D1_customapp_*_random_group_rules.txt"),
                    ("XSS",  f"{ROOT}/Random-Groups/CustomXSS_D2_eps{EPS}_seed*/D2_customxss_*_random_group_rules.txt")],
}
# run directories (to count runs even when a page produced 0 accepted rules -> no file)
RUNDIRS = {
    "PP-Static":   [("SQLi", f"{ROOT}/CustomApp_D1-PP/CustomApp_D1_seed*"), ("XSS", f"{ROOT}/CustomApp_D2-PP/CustomXSS_D2_seed*")],
    "PP-Adaptive": [("SQLi", f"{ROOT}/CustomApp_C1-PP/CustomApp_C1_Token_seed*"), ("XSS", f"{ROOT}/CustomApp_C2-PP/CustomXSS_C2_Token_seed*")],
    "CG-Static":   [("SQLi", f"{ROOT}/CustomApp_D1/CustomApp_D1_eps{EPS}_seed*"), ("XSS", f"{ROOT}/CustomApp_D2/CustomXSS_D2_eps{EPS}_seed*")],
    "CG-Adaptive": [("SQLi", f"{ROOT}/CustomApp_C1/CustomApp_C1_Token_eps{EPS}_seed*"), ("XSS", f"{ROOT}/CustomApp_C2/CustomXSS_C2_Token_eps{EPS}_seed*")],
    "RG":          [("SQLi", f"{ROOT}/Random-Groups/CustomApp_D1_eps{EPS}_seed*"), ("XSS", f"{ROOT}/Random-Groups/CustomXSS_D2_eps{EPS}_seed*")],
}
PAGES = {"SQLi": ["login", "search", "product", "filter"], "XSS": ["search", "calc"]}


def parse_quoted(s, i):
    """s[i] == '"'; return (raw_content, next_index). Backslash escapes are kept raw."""
    assert s[i] == '"', (i, s[:60])
    j = i + 1
    out = []
    while j < len(s):
        c = s[j]
        if c == "\\" and j + 1 < len(s):
            out.append(c + s[j + 1]); j += 2; continue
        if c == '"':
            return "".join(out), j + 1
        out.append(c); j += 1
    raise ValueError("unterminated quote")


def parse_secrule(line):
    assert line.startswith("SecRule "), line[:40]
    rest = line[len("SecRule "):].lstrip()
    m = re.match(r"(\S+)\s+", rest)
    variables = m.group(1)
    i = m.end()
    op, i = parse_quoted(rest, i)
    while i < len(rest) and rest[i] == " ":
        i += 1
    actions = ""
    if i < len(rest) and rest[i] == '"':
        actions, i = parse_quoted(rest, i)
    return variables, op, actions


def regex_metrics(p):
    """Scan a regex once, respecting backslash escapes and [...] classes."""
    alt = cls = quant = grp = 0
    in_cls = False
    i = 0
    n = len(p)
    prev = ""
    while i < n:
        c = p[i]
        if c == "\\":
            prev = "\\x"; i += 2; continue
        if in_cls:
            if c == "]":
                in_cls = False
            prev = c; i += 1; continue
        if c == "[":
            in_cls = True; cls += 1
            # a ']' right after '[' or '[^' is literal
            if i + 1 < n and p[i + 1] == "^":
                i += 1
            if i + 1 < n and p[i + 1] == "]":
                i += 1
        elif c == "|":
            alt += 1
        elif c == "(":
            grp += 1
        elif c in "*+":
            quant += 1
        elif c == "?":
            if prev == "(":
                pass            # (?: (?i) (?= ... group modifier, not a quantifier
            elif prev in "*+?}":
                pass            # lazy modifier of the previous quantifier
            else:
                quant += 1
        elif c == "{":
            mm = re.match(r"\{\d+(,\d*)?\}", p[i:])
            if mm:
                quant += 1
                prev = "}"; i += mm.end(); continue
        prev = c; i += 1
    return alt, cls, quant, grp


def rule_metrics(line):
    variables, op, actions = parse_secrule(line)
    op_s = op.strip()
    if op_s.startswith("@"):
        opname, _, pattern = op_s.partition(" ")
    else:
        opname, pattern = "@rx(implicit)", op_s
    alt, cls, quant, grp = regex_metrics(pattern)
    nvars = len([v for v in variables.split("|") if v])
    ntrans = len(re.findall(r"(?:^|,)\s*t:", actions))
    return dict(line_len=len(line), pat_len=len(pattern), alt=alt, cls=cls, quant=quant, grp=grp,
                nvars=nvars, ntrans=ntrans, op=opname, variables=variables,
                trans=",".join(re.findall(r"t:([A-Za-z]+)", actions)), pattern=pattern)


METRICS = ["line_len", "pat_len", "alt", "cls", "quant", "grp", "nvars", "ntrans"]


def fmt(v):
    return f"{v:.1f}" if isinstance(v, float) else str(v)


def summarize(rows):
    out = {}
    for m in METRICS:
        vals = [r[m] for r in rows]
        out[m] = (st.mean(vals), st.median(vals), max(vals), min(vals)) if vals else (0, 0, 0, 0)
    return out


all_rows = []           # (strategy, family, page, seed, metrics)
files_seen = defaultdict(int)
runs_seen = defaultdict(set)
runs_all = defaultdict(set)
op_kinds = defaultdict(lambda: defaultdict(int))
var_kinds = defaultdict(lambda: defaultdict(int))
trans_kinds = defaultdict(lambda: defaultdict(int))
example = {}

for strat, fams in STRATS.items():
    for fam, pat in fams:
        for rd in glob.glob(RUNDIRS[strat][0][1] if fam == "SQLi" else RUNDIRS[strat][1][1]):
            runs_all[(strat, fam)].add(os.path.basename(rd))
        for fpath in sorted(glob.glob(pat)):
            run = os.path.basename(os.path.dirname(fpath))
            seed = re.search(r"seed(\d+)", run).group(1)
            page = re.search(r"_(login|search|product|filter|calc)_", os.path.basename(fpath)).group(1)
            files_seen[(strat, fam)] += 1
            runs_seen[(strat, fam)].add(run)
            with open(fpath, encoding="utf-8", errors="replace") as f:
                lines = [l.rstrip("\n") for l in f]
            nonrule = [l for l in lines if l.strip() and not l.startswith("SecRule ")]
            if nonrule:
                print(f"WARN non-SecRule content in {fpath}: {len(nonrule)} line(s): {nonrule[0][:60]!r}")
            for l in lines:
                if l.startswith("SecRule "):
                    mtr = rule_metrics(l)
                    op_kinds[(strat, fam)][mtr["op"]] += 1
                    var_kinds[(strat, fam)][mtr["variables"]] += 1
                    trans_kinds[(strat, fam)][mtr["trans"]] += 1
                    all_rows.append((strat, fam, page, seed, mtr))
                    example.setdefault(strat, mtr["pattern"][:40])

print("=" * 100)
print(f"RULE COMPLEXITY, eps={EPS} (PP has no eps), all seeds, all pages.  Source: {ROOT}")
print("Metrics per rule: line_len=chars of whole SecRule line; pat_len=chars of @rx pattern; alt='|' count;")
print("cls='[...]' classes; quant=* + ? {n,m} (excl. (?: modifiers and lazy '?'); grp='(' groups; nvars=targets; ntrans=t: transforms")
print("=" * 100)

hdr = f"{'strategy':12s} {'fam':4s} {'runs':>4s} {'files':>5s} {'rules':>5s} {'r/run':>6s} " + " ".join(f"{m:>22s}" for m in METRICS)
print(hdr)
print("  (each metric column = mean / median / max)")
for strat in STRATS:
    for fam in ("SQLi", "XSS"):
        rows = [r[4] for r in all_rows if r[0] == strat and r[1] == fam]
        nruns = len(runs_all[(strat, fam)])
        s = summarize(rows)
        cells = " ".join(f"{fmt(s[m][0]):>7s}/{fmt(s[m][1]):>6s}/{fmt(s[m][2]):>6s}" for m in METRICS)
        rpr = len(rows) / nruns if nruns else 0
        print(f"{strat:12s} {fam:4s} {nruns:4d} {files_seen[(strat, fam)]:5d} {len(rows):5d} {rpr:6.1f} {cells}")

print("\nRules per run per page (mean over seeds; n = number of rule files found for that page):")
for strat in STRATS:
    for fam in ("SQLi", "XSS"):
        parts = []
        for page in PAGES[fam]:
            per_seed = defaultdict(int)
            for r in all_rows:
                if r[0] == strat and r[1] == fam and r[2] == page:
                    per_seed[r[3]] += 1
            if per_seed:
                v = list(per_seed.values())
                parts.append(f"{page}: mean {st.mean(v):.1f} (min {min(v)}, max {max(v)}, n={len(v)})")
            else:
                parts.append(f"{page}: NO rule files")
        print(f"  {strat:12s} {fam:4s} | " + " | ".join(parts))

print("\nMissing rule files (run dir exists, page file absent -> pilot writes no file when 0 rules accepted):")
for strat in STRATS:
    for fam in ("SQLi", "XSS"):
        missing = []
        for run in sorted(runs_all[(strat, fam)]):
            for page in PAGES[fam]:
                have = any(r[0] == strat and r[1] == fam and r[2] == page and f"seed{r[3]}" == "seed" + re.search(r"seed(\d+)", run).group(1) for r in all_rows)
                if not have:
                    missing.append(f"{run}/{page}")
        print(f"  {strat:12s} {fam:4s}: {len(missing)} missing -> {missing if missing else '-'}")

print("\nOperator kinds per strategy/family:")
for k, d in op_kinds.items():
    print(f"  {k}: {dict(d)}")
print("\nVariable/target strings per strategy/family:")
for k, d in var_kinds.items():
    print(f"  {k}: {dict(d)}")
print("\nTransformation chains per strategy/family (count of rules using each chain):")
for k, d in trans_kinds.items():
    print(f"  {k}: {dict(d)}")

print("\nDistinct patterns (exact string) vs total rules, per strategy/family:")
for strat in STRATS:
    for fam in ("SQLi", "XSS"):
        pats = [r[4]["pattern"] for r in all_rows if r[0] == strat and r[1] == fam]
        print(f"  {strat:12s} {fam:4s}: {len(set(pats))} distinct / {len(pats)} total")

print("\nPer-strategy pattern-length distribution (SQLi+XSS pooled): p10/p25/p50/p75/p90:")
for strat in STRATS:
    vals = sorted(r[4]["pat_len"] for r in all_rows if r[0] == strat)
    if vals:
        q = lambda p: vals[min(len(vals) - 1, int(p * len(vals)))]
        print(f"  {strat:12s}: n={len(vals)} {q(.1)}/{q(.25)}/{q(.5)}/{q(.75)}/{q(.9)}")

print("\nIllustration (first 40 chars of the first pattern seen per strategy):")
for strat, ex in example.items():
    print(f"  {strat:12s}: {ex!r}")

# combined rules/ files
print("\nresults/V2/rules/*.txt (SecRule counts):")
for fp in sorted(glob.glob(f"{ROOT}/rules/*.txt")):
    with open(fp, encoding="utf-8", errors="replace") as f:
        ls = [l.rstrip("\n") for l in f]
    n = sum(1 for l in ls if l.startswith("SecRule "))
    other = [l for l in ls if l.strip() and not l.startswith("SecRule ")]
    print(f"  {os.path.basename(fp)}: {n} SecRule lines, {len(other)} non-SecRule non-empty lines; first non-rule line: {other[0][:100]!r}" if other else f"  {os.path.basename(fp)}: {n} SecRule lines, no non-rule lines")
    pats = set()
    for l in ls:
        if l.startswith("SecRule "):
            pats.add(rule_metrics(l)["pattern"])
    for strat in ("CG-Static", "CG-Adaptive"):
        run_pats = set(r[4]["pattern"] for r in all_rows if r[0] == strat)
        print(f"     overlap with eps{EPS} per-run {strat} patterns: {len(pats & run_pats)} of {len(pats)} file patterns; per-run distinct={len(run_pats)}")

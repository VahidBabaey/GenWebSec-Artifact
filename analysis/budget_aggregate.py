#!/usr/bin/env python3
"""Synthesis-cost / budget aggregation (repository section 14).

Computes every median, range, and IQR of the paper's budget tables from the single
released per-run matrix results/budget/budget_matrix.csv, which holds all 14 budget
items (defense and attacker calls, candidate and rejected increments, accepted rules,
rules per 100 bypasses, calls per rule, input and output tokens, model-generation
time, rule-validation time, estimated API cost, per-run totals). PP and RG have no
clustering threshold and appear only at the operating point eps=0.3; the clustered
strategy is swept over eps in {0.1..0.5}.

Reproduces:
  * static  eps=0.3   -> RQ2 budget-compare and budget-cost tables
  * adaptive eps=0.3  -> RQ3 per-page adaptive budget table
  * CG-Static  sweep  -> RQ2 per-epsilon budget table
  * CG-Adaptive sweep -> RQ3 per-epsilon budget table (budget columns; the
    "blocked / 1k def-tok" efficiency ratio is an effectiveness quantity and is
    reproduced from the RQ3 effectiveness data, not from this budget matrix).

Counts (rules/100, rejected, LLM calls, |R|) are the median with [min-max]; the
skewed columns (calls/rule, tokens, validation and generation time, cost) are the
median with the interquartile range, matching the paper. Standard library only.
"""
import csv, math, statistics as st
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MATRIX = ROOT / "results" / "budget" / "budget_matrix.csv"
SQLI = ["login", "search", "product", "filter"]
XSS = ["search", "calc"]
EPS = ["0.1", "0.2", "0.3", "0.4", "0.5"]
LABEL = {"login": "Login form", "search": "Product search", "product": "URL parameter",
         "filter": "Product filter", "calc": "Calculator (eval sink)"}
XLABEL = {"search": "Search (JS-string)", "calc": "Calculator (eval sink)"}


def load():
    return list(csv.DictReader(open(MATRIX)))


def sel(rows, regime, strat, fam, page, eps=None):
    return [r for r in rows if r["regime"] == regime and r["strategy"] == strat
            and r["family"] == fam and r["context"] == page
            and (eps is None or r["eps"] == eps)]


def vals(rows, col):
    return [float(r[col]) for r in rows if r[col] not in ("", "None")]


def pctl(v, q):
    v = sorted(v); k = (len(v) - 1) * q; f = math.floor(k); c = math.ceil(k)
    return v[f] if f == c else v[f] + (v[c] - v[f]) * (k - f)


def _f(x, dec):
    return "%.*f" % (dec, x)


def _cnt(x):
    # counts: integer, or X.5 for a median between two seeds
    return "%.0f" % x if abs(x - round(x)) < 1e-9 else "%.1f" % x


def mr(v, dec=None):
    """median with [min-max]; dec=None uses the count formatter."""
    if not v:
        return "-"
    fmt = (lambda x: _cnt(x)) if dec is None else (lambda x: _f(x, dec))
    m, lo, hi = st.median(v), min(v), max(v)
    return fmt(m) if lo == hi else "%s [%s-%s]" % (fmt(m), fmt(lo), fmt(hi))


def miqr(v, dec=1):
    """median with [IQR]."""
    if not v:
        return "-"
    m, lo, hi = st.median(v), pctl(v, 0.25), pctl(v, 0.75)
    return _f(m, dec) if lo == hi else "%s [%s-%s]" % (_f(m, dec), _f(lo, dec), _f(hi, dec))


def tok(v):
    if not v:
        return "-"
    m = st.median(v)
    return ("%.1fk" % (m / 1000)) if m >= 1000 else "%.0f" % m


def static_budget(rows):
    print("\n" + "=" * 118)
    print("RQ2 static budget at eps=0.3 (reproduces RQ2 budget-compare + budget-cost tables)")
    print("counts median[min-max]; calls/rule, tokens, times, cost median[IQR]; 10 seeds")
    print("=" * 118)
    h = ("Family", "Page", "Strategy", "Rules/100", "Rejected", "LLM calls",
         "Calls/rule", "Tokens in/out", "Valid.t(s)", "Gen.t(s)", "Cost c")
    print("%-5s %-14s %-10s %-17s %-12s %-14s %-11s %-15s %-11s %-11s %-11s" % h)
    for fam in ["SQLi", "XSS"]:
        for page in (SQLI if fam == "SQLi" else XSS):
            lab = (LABEL if fam == "SQLi" else XLABEL)[page]
            for strat in ["PP-Static", "RG", "CG-Static"]:
                d = sel(rows, "static", strat, fam, page, "0.3")
                if not d:
                    continue
                print("%-5s %-14s %-10s %-17s %-12s %-14s %-11s %-15s %-11s %-11s %-11s" % (
                    fam if strat == "PP-Static" else "",
                    lab if strat == "PP-Static" else "", strat,
                    mr(vals(d, "rules_per_100"), 2), mr(vals(d, "rejected")),
                    mr(vals(d, "defense_calls")), miqr(vals(d, "calls_per_rule"), 1),
                    tok(vals(d, "input_tokens")) + "/" + tok(vals(d, "output_tokens")),
                    miqr(vals(d, "rule_eval_time_s"), 0), miqr(vals(d, "gen_time_s"), 0),
                    miqr([c * 100 for c in vals(d, "est_cost_usd")], 2)))
            print("-" * 118)


def adaptive_budget(rows):
    print("\n" + "=" * 100)
    print("RQ3 adaptive budget at eps=0.3 (reproduces RQ3 per-page adaptive budget table)")
    print("Rules/100, Rejected, LLM calls median[min-max]; Calls/rule, Valid.t, Cost median[IQR]")
    print("=" * 100)
    h = ("Family", "Page", "Strategy", "Rules/100", "Rejected", "LLM calls",
         "Calls/rule", "Valid.t(s)", "Cost c")
    print("%-5s %-14s %-12s %-18s %-12s %-12s %-11s %-16s %-11s" % h)
    for fam in ["SQLi", "XSS"]:
        for page in (SQLI if fam == "SQLi" else XSS):
            lab = (LABEL if fam == "SQLi" else XLABEL)[page]
            for strat in ["PP-Adaptive", "CG-Adaptive"]:
                d = sel(rows, "adaptive", strat, fam, page, "0.3")
                if not d:
                    continue
                print("%-5s %-14s %-12s %-18s %-12s %-12s %-11s %-16s %-11s" % (
                    fam if strat == "PP-Adaptive" else "",
                    lab if strat == "PP-Adaptive" else "", strat,
                    mr(vals(d, "rules_per_100"), 1), mr(vals(d, "rejected")),
                    mr(vals(d, "defense_calls")), miqr(vals(d, "calls_per_rule"), 1),
                    miqr(vals(d, "rule_eval_time_s"), 1),
                    miqr([c * 100 for c in vals(d, "est_cost_usd")], 2)))
            print("-" * 100)


def cg_sweep(rows, regime, strat, title, first="rules_per_100"):
    # first column is rules-per-100 (RQ2 static table) or absolute |R| (RQ3 table)
    fcol = "Rules/100" if first == "rules_per_100" else "|R|"
    print("\n" + "=" * 104)
    print(title)
    print("%s, Rejected median[min-max]; Calls/rule, Valid./Rule-eval time, Cost median[IQR]" % fcol)
    print("=" * 104)
    h = ("Family", "Page", "eps", fcol, "Calls/rule", "Valid.t(s)", "Rejected", "Cost c")
    print("%-5s %-14s %-6s %-17s %-15s %-16s %-13s %-12s" % h)
    for fam in ["SQLi", "XSS"]:
        for page in (SQLI if fam == "SQLi" else XSS):
            lab = (LABEL if fam == "SQLi" else XLABEL)[page]
            for eps in EPS:
                d = sel(rows, regime, strat, fam, page, eps)
                if not d:
                    continue
                mark = "*" if eps == "0.3" else " "
                fval = mr(vals(d, "rules_per_100"), 2) if first == "rules_per_100" \
                    else mr(vals(d, "accepted_rules"))
                print("%-5s %-14s %-6s %-17s %-15s %-16s %-13s %-12s" % (
                    fam if eps == "0.1" else "", lab if eps == "0.1" else "", eps + mark,
                    fval, miqr(vals(d, "calls_per_rule"), 1),
                    miqr(vals(d, "rule_eval_time_s"), 1), mr(vals(d, "rejected")),
                    miqr([c * 100 for c in vals(d, "est_cost_usd")], 2)))
            print("-" * 104)


def main():
    rows = load()
    static_budget(rows)
    adaptive_budget(rows)
    cg_sweep(rows, "static", "CG-Static",
             "RQ2 CG-Static budget swept over epsilon (reproduces RQ2 per-epsilon budget table)")
    cg_sweep(rows, "adaptive", "CG-Adaptive",
             "RQ3 CG-Adaptive budget swept over epsilon (reproduces RQ3 per-epsilon budget table)",
             first="accepted_rules")


if __name__ == "__main__":
    main()

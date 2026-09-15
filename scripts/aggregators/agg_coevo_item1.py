#!/usr/bin/env python3
"""
Item 1 (repeat all stochastic experiments) aggregator for the CO-EVOLUTIONARY pilots, across independent
seeds, for BOTH adaptive conditions:
  PP-Adaptive  = per_payload  (dirs: results/V2/<BASE>/<BASE>_seed{S}/)
  CG-Adaptive  = clustering   (dirs: results/V2/<BASE>/<BASE>_eps{E}_seed{S}/)
where BASE = CustomApp_C1_Token (SQLi, C1) or CustomXSS_C2_Token (XSS, C2).

For the chosen condition it reports EVERY per-run quantity item 1 asks to record -- candidates, valid
attacks, bypasses, rounds-to-termination, accepted rules |R|, false positives, tokens, LLM calls, and
timing -- per seed (provenance), then mean / SD / 95% CI across seeds, and ADDITIONALLY median + IQR
for the skewed timing and token metrics (item 1's explicit ask). Numbers are read from each run's
metrics CSV (per-iteration sums) and its log (run-level summary lines); nothing is estimated.

Usage:  python3 agg_coevo_item1.py <c1|c2> <page> <per_payload|clustering> [eps]
   e.g.  python3 agg_coevo_item1.py c1 login per_payload
         python3 agg_coevo_item1.py c1 login clustering 0.3
         python3 agg_coevo_item1.py c2 calc  clustering 0.3
"""
import csv, re, sys, math, statistics
from pathlib import Path

V2 = Path("/path/to/GenWebSec/results/V2")
SEEDS = list(range(1, 11))

def _fcol(rows, name):
    out = []
    for r in rows:
        v = (r.get(name) or "").replace(",", "").strip()
        if v not in ("", "None"):
            try: out.append(float(v))
            except ValueError: pass
    return out

def parse_csv(path):
    rows = list(csv.DictReader(open(path, encoding="utf-8")))
    if not rows:
        return {}
    return {
        "rounds":      float(len(rows)),                                   # rounds to termination (hardening rounds)
        "candidates":  sum(_fcol(rows, "generated")),                      # attack candidates generated (hardening)
        "valid":       sum(_fcol(rows, "valid_n")),                        # backend-valid attacks
        "bypasses":    sum(_fcol(rows, "bypassed_n")),                     # WAF bypasses
        "atk_tok":     sum(_fcol(rows, "attack_in_tokens")) + sum(_fcol(rows, "attack_out_tokens")),
        "def_tok":     sum(_fcol(rows, "defense_in_tokens")) + sum(_fcol(rows, "defense_out_tokens")),
        "rule_eval_s": sum(_fcol(rows, "rule_eval_s")),                    # validation time (skewed)
    }

def parse_log(t):
    def one(pat, cast=float, last=False):
        m = re.findall(pat, t)
        if not m:
            return None
        v = m[-1 if last else 0]
        try: return cast(str(v).replace(",", ""))
        except ValueError: return None
    return {
        "rules":         one(r"Final rule set:\s*(\d+)\s*rule", int, last=True),
        "fp_final":      one(r"FPRate\(t\)\s+([\d.]+)%", last=True),
        "wall_s":        one(r"wall-clock\s*([\d.]+)s"),
        "calls":         one(r"LLM: calls=(\d+)", int),
        "def_calls":     one(r"defense LLM calls\s*(\d+)", int),
        "heldout_block": one(r"held-out bypass [\d.]+%\s*\(block\s*([\d.]+)%\)", last=True),
        "converged":     1.0 if re.search(r"HARDENING TERMINATION:\s*CONVERGED", t) else 0.0,
    }

# (key, label, skewed?) -- skewed timing/token metrics additionally get median + IQR (item 1)
METRICS = [
    ("candidates", "candidates",     False), ("valid",     "valid_attacks", False),
    ("bypasses",   "bypasses",       False), ("rounds",    "rounds_to_term",False),
    ("rules",      "|R|",            False), ("fp_final",  "final_FP%",     False),
    ("heldout_block","heldout_blk%", False), ("calls",     "LLM_calls",     False),
    ("def_calls",  "defense_calls",  False),
    ("atk_tok",    "attack_tokens",  True),  ("def_tok",   "defense_tokens",True),
    ("rule_eval_s","rule_eval_s",    True),  ("wall_s",    "wall_clock_s",  True),
]

T95 = {9: 2.262, 8: 2.306, 7: 2.365, 6: 2.447, 5: 2.571, 4: 2.776, 3: 3.182, 2: 4.303, 1: 12.706}


def main():
    fam  = (sys.argv[1].lower() if len(sys.argv) > 1 else "c1")
    page = sys.argv[2] if len(sys.argv) > 2 else "login"
    mode = sys.argv[3] if len(sys.argv) > 3 else "clustering"
    eps  = sys.argv[4] if len(sys.argv) > 4 else None
    if fam == "c2":
        parent, prefix, logp = "CustomApp_C2", "CustomXSS_C2_Token", f"C2_customxss_{page}_{mode}"
    else:
        parent, prefix, logp = "CustomApp_C1", "CustomApp_C1_Token", f"C1_customapp_{page}_{mode}"
    def run_dir(s):
        tag = prefix + (f"_eps{eps}" if (mode == "clustering" and eps) else "") + f"_seed{s}"
        return V2 / parent / tag

    rows = []
    for s in SEEDS:
        d = run_dir(s)
        csvf, logf = d / f"{logp}_metrics.csv", d / f"{logp}.txt"
        if not logf.exists():
            continue
        rec = {"seed": s}
        if csvf.exists():
            rec.update(parse_csv(csvf))
        rec.update(parse_log(logf.read_text(encoding="utf-8", errors="replace")))
        rows.append(rec)

    cond = f"{fam.upper()} {page} {mode}" + (f" eps={eps}" if (mode == "clustering" and eps) else "")
    print("=" * 100)
    print(f"ITEM 1 (repeated seeds) :: {cond}")
    print(f"dirs: {V2/parent}/{prefix}" + (f"_eps{eps}" if (mode == 'clustering' and eps) else "") + "_seed<1..10>/")
    print("=" * 100)
    if not rows:
        print("no completed runs found for this condition yet -- run the seeded campaign, then re-run this aggregator.")
        return

    cols = [k for k, _, _ in METRICS]
    print(f"\n{'seed':>4} " + " ".join(f"{lbl:>14}" for _, lbl, _ in METRICS) + f" {'converged':>10}")
    for r in rows:
        cells = []
        for k in cols:
            v = r.get(k)
            cells.append("n/a" if v is None else (f"{int(v)}" if float(v).is_integer() else f"{v:.2f}"))
        print(f"{r['seed']:>4} " + " ".join(f"{c:>14}" for c in cells) + f" {'yes' if r.get('converged') else 'no':>10}")

    n_conv = int(sum(r.get("converged", 0.0) for r in rows))
    print(f"\nn = {len(rows)} seed(s);  converged {n_conv}/{len(rows)}")
    print(f"\n{'metric':>15}  {'mean':>10}  {'SD':>9}  {'95% CI':>22}  {'median':>10}  {'IQR':>10}")
    print("-" * 92)
    for k, lbl, skewed in METRICS:
        vals = [r[k] for r in rows if r.get(k) is not None]
        if not vals:
            print(f"{lbl:>15}  {'n/a':>10}"); continue
        m = statistics.mean(vals)
        sd = statistics.stdev(vals) if len(vals) > 1 else 0.0
        ci = T95.get(len(vals) - 1, 2.262) * sd / math.sqrt(len(vals)) if len(vals) > 1 else 0.0
        med = iqr = ""
        if skewed:                                        # item 1: median + IQR for skewed timing/token metrics
            med = f"{statistics.median(vals):.1f}"
            if len(vals) >= 2:
                q = statistics.quantiles(vals, n=4, method="inclusive")   # [Q1, Q2, Q3]
                iqr = f"{q[2]-q[0]:.1f}"
            else:
                iqr = "0.0"
        print(f"{lbl:>15}  {m:>10.2f}  {sd:>9.2f}  [{m-ci:>9.2f}, {m+ci:>9.2f}]  {med:>10}  {iqr:>10}")
    print("\n(median + IQR are reported for the skewed timing/token metrics, per item 1; the others use mean/SD/95%CI.)")


if __name__ == "__main__":
    main()

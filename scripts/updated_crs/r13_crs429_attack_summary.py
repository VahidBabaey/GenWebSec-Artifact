#!/usr/bin/env python3
"""Aggregate the 4 attack-vs-CRS-4.29 (new-prompt) demonstrations into one summary table."""
import csv, os
D = "/home/vahid/Projects/GenWebSec/paper-frontiers/results/V2/RevisionNewResults/R1.3/crs429_attack_newprompts"
ORDER = [("customapp_login", "Custom app", "SQLi", "login"),
         ("juice_login", "OWASP Juice Shop", "SQLi", "login"),
         ("customxss_calc", "Custom XSS app", "XSS", "calc (eval sink)"),
         ("bwapp_xss_eval", "bWAPP", "XSS", "xss_eval (eval sink)")]

def load(tag):
    rows = []
    with open(f"{D}/{tag}_rounds.csv", encoding="utf-8") as f:
        for r in csv.DictReader(f):
            rows.append(r)
    return rows

summary = []
print("=" * 104)
print("Attack agent vs OWASP CRS 4.29.0 (latest) - NEW *_crs429 prompts, 1 seed each, 3-step check per candidate")
print("=" * 104)
hdr = f"{'target':16} {'fam':4} {'page':18} | " + " ".join(f"R{i}" .rjust(4) for i in range(5)) + " | " + \
      f"{'cum.conf':>8} {'tot.gen':>7} {'tot.val':>7} {'tot.byp':>7} {'false':>5}"
print(hdr); print("-" * len(hdr))
for tag, name, fam, page in ORDER:
    rows = load(tag)
    per_round_new = [int(r["new_distinct"]) for r in rows]
    cum = int(rows[-1]["cumulative_distinct_confirmed"])
    tot_gen = sum(int(r["generated"]) for r in rows)
    tot_val = sum(int(r["validated_step1"]) for r in rows)
    tot_byp = sum(int(r["waf_bypass_non403_step2"]) for r in rows)
    tot_false = sum(int(r["false_bypass"]) for r in rows)
    tot_conf = sum(int(r["confirmed_3step"]) for r in rows)
    cells = " ".join(str(n).rjust(4) for n in per_round_new)
    print(f"{name:16} {fam:4} {page:18} | {cells} | {cum:>8} {tot_gen:>7} {tot_val:>7} {tot_byp:>7} {tot_false:>5}")
    summary.append({"target": name, "family": fam, "page": page,
                    "round0_new": per_round_new[0], "round1_new": per_round_new[1],
                    "round2_new": per_round_new[2], "round3_new": per_round_new[3],
                    "round4_new": per_round_new[4],
                    "cumulative_confirmed": cum, "total_generated": tot_gen,
                    "total_validated": tot_val, "total_waf_bypass_non403": tot_byp,
                    "total_confirmed_3step": tot_conf, "total_false_bypass": tot_false})
print("-" * len(hdr))
print("per-round cells = NEW distinct 3-step-confirmed bypasses added that round (co-evolution signal)")
print("false = candidates that passed WAF (non-403) but FAILED the false-bypass re-check (step 3)")

with open(f"{D}/_SUMMARY_attack429.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.DictWriter(f, fieldnames=list(summary[0].keys()))
    w.writeheader()
    for s in summary:
        w.writerow(s)
print("\nwrote", f"{D}/_SUMMARY_attack429.csv")
print("totals: distinct confirmed CRS-4.29 bypasses across the 4 demos =",
      sum(s["cumulative_confirmed"] for s in summary))

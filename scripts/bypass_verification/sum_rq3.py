import csv, collections
f = "/home/vahid/Projects/GenWebSec/paper-frontiers/results/V2/RevisionNewResults/R1.1/rq3/rq3_sqli_summary.csv"
rows = list(csv.DictReader(open(f)))
print("rows:", len(rows))
byp = collections.Counter()
for r in rows: byp[(r["strategy"], r["page"])] += 1
print("per (strategy,page) seed count:", dict(byp))
unfaithful = [r for r in rows if r["faithful"] != "1"]
print("UNFAITHFUL runs (replay != logged funnel):", len(unfaithful))
for r in unfaithful[:20]:
    print("  ", r["strategy"], r["page"], "seed", r["seed"],
          "log(v/cb/blk/res)=%s/%s/%s/%s"%(r["log_valid"],r["log_crsbyp"],r["log_blocked"],r["log_resid"]),
          "rep=%s/%s/%s/%s"%(r["rep_valid"],r["rep_crsbyp"],r["rep_blocked"],r["rep_resid"]))
tot_fb = sum(int(r["false_bypass"]) for r in rows)
tot_resid_rep = sum(int(r["rep_resid"]) for r in rows)
tot_resid_ver = sum(int(r["ver_resid_exploit"]) for r in rows)
print("TOTAL residuals (reported, 403-only):", tot_resid_rep)
print("TOTAL residuals that are real exploits (two-stage):", tot_resid_ver)
print("TOTAL false bypasses (pass CRS+rules but do NOT exploit):", tot_fb)
diff = [r for r in rows if r["rep_block%"] != r["ver_block%"]]
print("runs where verified block%% != reported block%%:", len(diff))
for r in diff[:20]:
    print("  ", r["strategy"], r["page"], "seed", r["seed"], "rep=%s ver=%s"%(r["rep_block%"],r["ver_block%"]))

#!/bin/bash
# RQ4 re-run WITH per-request logging (advisor artifact: per-request HTTP status + exploit-oracle result).
# Backs up the current summaries, clears the RQ4 CSVs, re-runs all targets. Deterministic: should
# reproduce 16,240 residuals / 0 false / 0 reclassified, and additionally write rq4_*_perrequest.csv.
cd /home/vahid/Projects/GenWebSec/WorkFlowV2 || exit 2
B=/home/vahid/Projects/GenWebSec/paper-frontiers/results/V2/RevisionNewResults/R1.1/rq4
mkdir -p "$B/_prev_summaries"
cp -f "$B/rq4_sqli_summary.csv" "$B/rq4_xss_summary.csv" "$B/_prev_summaries/" 2>/dev/null
rm -f "$B/rq4_sqli_summary.csv" "$B/rq4_sqli_false_bypasses.csv" "$B/rq4_sqli_perrequest.csv"
rm -f "$B/rq4_xss_summary.csv" "$B/rq4_xss_false_bypasses.csv" "$B/rq4_xss_perrequest.csv"
LOG=/home/vahid/rq4_perrequest_run.log
: > "$LOG"
for t in customapp juice bwapp; do
  if [ "$t" = "customapp" ]; then pages="login search product filter"; else pages="login search"; fi
  for pg in $pages; do
    echo "########## SQLi $t $pg ##########" | tee -a "$LOG"
    A1_TARGET="$t" A1_PAGE="$pg" python3 /home/vahid/r11_rq4_reverify_sqli.py 2>>"$LOG" | tee -a "$LOG"
  done
done
for pg in calc search; do
  echo "########## XSS customxss $pg ##########" | tee -a "$LOG"
  C2_PAGE="$pg" python3 /home/vahid/r11_rq4_reverify_xss.py 2>>"$LOG" | tee -a "$LOG"
done
echo "########## XSS bwapp xss_eval ##########" | tee -a "$LOG"
python3 /home/vahid/r11_rq4_reverify_xss_bwapp.py 2>>"$LOG" | tee -a "$LOG"
echo "ALL DONE" | tee -a "$LOG"

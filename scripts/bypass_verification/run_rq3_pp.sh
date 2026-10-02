#!/bin/bash
# PP-Adaptive SQLi RQ3 replay. Appends to the SAME combined CSV (strategy column=PP); no rm.
# Run ONLY after the CG run has finished (both reload Apache; never concurrently).
cd /home/vahid/Projects/GenWebSec/WorkFlowV2 || exit 2
LOG=/home/vahid/rq3_pp_run.log
: > "$LOG"
for pg in login search product filter; do
  echo "########## PAGE=$pg ##########" | tee -a "$LOG"
  RP_STRAT=PP A1_PAGE="$pg" python3 /home/vahid/r11_rq3_replay_sqli.py 2>>"$LOG" | tee -a "$LOG"
done
echo "ALL DONE" | tee -a "$LOG"

#!/bin/bash
cd /home/vahid/Projects/GenWebSec/WorkFlowV2 || exit 2
rm -f /home/vahid/Projects/GenWebSec/paper-frontiers/results/V2/RevisionNewResults/R1.1/rq3/rq3_sqli_*.csv
LOG=/home/vahid/rq3_cg_run.log
: > "$LOG"
for pg in login search product filter; do
  echo "########## PAGE=$pg ##########" | tee -a "$LOG"
  RP_STRAT=CG A1_PAGE="$pg" python3 /home/vahid/r11_rq3_replay_sqli.py 2>>"$LOG" | tee -a "$LOG"
done
echo "ALL DONE" | tee -a "$LOG"

#!/bin/bash
cd /home/vahid/Projects/GenWebSec/WorkFlowV2 || exit 2
LOG=/home/vahid/rq1_sqli_replay.log
: > "$LOG"
for pg in login search product filter; do
  echo "########## RQ1 SQLi $pg ##########" | tee -a "$LOG"
  A1_PAGE="$pg" python3 /home/vahid/r11_rq1_replay_sqli.py 2>>"$LOG" | tee -a "$LOG"
done
echo "ALL DONE" | tee -a "$LOG"

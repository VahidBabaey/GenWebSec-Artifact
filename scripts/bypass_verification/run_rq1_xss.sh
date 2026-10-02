#!/bin/bash
pkill -9 -f chrome-headless-shell 2>/dev/null
sleep 1
cd /home/vahid/Projects/GenWebSec/WorkFlowV2 || exit 2
LOG=/home/vahid/rq1_xss_replay.log
: > "$LOG"
for pg in calc search; do
  echo "########## RQ1 XSS $pg ##########" | tee -a "$LOG"
  C2_PAGE="$pg" python3 /home/vahid/r11_rq1_replay_xss.py 2>>"$LOG" | tee -a "$LOG"
done
echo "ALL DONE" | tee -a "$LOG"

#!/bin/bash
cd /home/vahid/Projects/GenWebSec/WorkFlowV2 || exit 2
LOG=/home/vahid/rq4_bwapp_sqli_run.log
: > "$LOG"
for pg in login search; do
  echo "########## bwapp $pg ##########" | tee -a "$LOG"
  A1_TARGET=bwapp A1_PAGE="$pg" python3 /home/vahid/r11_rq4_reverify_sqli.py 2>>"$LOG" | tee -a "$LOG"
done
echo "ALL DONE" | tee -a "$LOG"

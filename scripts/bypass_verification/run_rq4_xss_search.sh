#!/bin/bash
pkill -9 -f chrome-headless-shell 2>/dev/null
sleep 1
cd /home/vahid/Projects/GenWebSec/WorkFlowV2 || exit 2
LOG=/home/vahid/rq4_xss_search.log
: > "$LOG"
echo "#### customxss search ####" | tee -a "$LOG"
C2_PAGE=search python3 /home/vahid/r11_rq4_reverify_xss.py 2>>"$LOG" | tee -a "$LOG"
echo "ALL DONE" | tee -a "$LOG"

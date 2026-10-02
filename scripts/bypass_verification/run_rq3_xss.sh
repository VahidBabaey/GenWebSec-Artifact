#!/bin/bash
# Full XSS RQ3 held-out replay (valid+bypassed scope), all 4 page x strategy combos, sequential
# (each reloads Apache; never concurrent). Resumable: completed (strategy,page,seed) are skipped.
cd /home/vahid/Projects/GenWebSec/WorkFlowV2 || exit 2
LOG=/home/vahid/rq3_xss_run.log
: > "$LOG"
for strat in CG PP; do
  for page in calc search; do
    mode=clustering; [ "$strat" = "PP" ] && mode=per_payload
    echo "########## STRAT=$strat PAGE=$page ##########" | tee -a "$LOG"
    RP_STRAT="$strat" C2_PAGE="$page" C2_MODE="$mode" python3 /home/vahid/r11_rq3_replay_xss.py 2>>"$LOG" | tee -a "$LOG"
  done
done
echo "ALL DONE" | tee -a "$LOG"

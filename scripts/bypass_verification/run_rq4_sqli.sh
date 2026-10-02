#!/bin/bash
# RQ4 two-stage re-verification (residual bypasses, eps0.3) for the feasible SQLi targets.
# customapp (no docker) + juice (docker, up). bwApp is added separately after `sudo modprobe iptable_raw`.
cd /home/vahid/Projects/GenWebSec/WorkFlowV2 || exit 2
LOG=/home/vahid/rq4_sqli_run.log
: > "$LOG"
for pg in login search product filter; do
  echo "########## customapp $pg ##########" | tee -a "$LOG"
  A1_TARGET=customapp A1_PAGE="$pg" python3 /home/vahid/r11_rq4_reverify_sqli.py 2>>"$LOG" | tee -a "$LOG"
done
for pg in login search; do
  echo "########## juice $pg ##########" | tee -a "$LOG"
  A1_TARGET=juice A1_PAGE="$pg" python3 /home/vahid/r11_rq4_reverify_sqli.py 2>>"$LOG" | tee -a "$LOG"
done
echo "ALL DONE" | tee -a "$LOG"

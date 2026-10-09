#!/usr/bin/env bash
# R2.3 PL2 SQLi replay driver loop. Resumable (skips combos whose per_config.csv exists).
# Env: R23_TARGETS (default "customapp"), R23_SEEDS (default "1 2 3 4 5").
set -u
cd /home/vahid/Projects/GenWebSec || exit 2
PY=.webenv/bin/python3
OUTBASE=results/V2/RevisionNewResults/R2.3/PL2/sqli
declare -A PAGES=( [customapp]="login search product filter" [bwapp]="login search" [juice]="login search" )
TARGETS=(${R23_TARGETS:-customapp})
SEEDS=(${R23_SEEDS:-1 2 3 4 5})
echo "[r23-sqli] START $(date '+%F %T')  targets=(${TARGETS[*]})  seeds=(${SEEDS[*]})"
for target in "${TARGETS[@]}"; do
  for page in ${PAGES[$target]}; do
    for seed in "${SEEDS[@]}"; do
      done="$OUTBASE/${target}_${page}_seed${seed}/r23pl2_${target}_${page}_seed${seed}_per_config.csv"
      if [ -f "$done" ]; then echo "[skip] $target/$page/$seed (done)"; continue; fi
      echo "=== [run] $target/$page/$seed  $(date '+%T') ==="
      A1_TARGET=$target A1_PAGE=$page A1_SEED=$seed $PY -u WorkFlowV2/r23_replay_sqli_pl2.py 2>&1 \
        | grep -E "^\[(r23pl2|CRS|CG|warn)" || true
    done
  done
done
echo "[r23-sqli] ALL DONE $(date '+%F %T')"

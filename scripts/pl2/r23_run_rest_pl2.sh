#!/usr/bin/env bash
# R2.3 PL2 remaining core: full custom-XSS attack matrix + benign (CRS-only + CG seeds 1-5). Resumable.
set -u
cd /home/vahid/Projects/GenWebSec || exit 2
PY=.webenv/bin/python3
B=results/V2/RevisionNewResults/R2.3/PL2
echo "[rest] START $(date '+%F %T')"

echo "[rest] === custom-XSS attacks ==="
for page in search calc; do
  for seed in 1 2 3 4 5; do
    d="$B/xss/customxss_${page}_seed${seed}/r23pl2_xss_customxss_${page}_seed${seed}_per_config.csv"
    if [ -f "$d" ]; then echo "[skip] xss customxss/$page/$seed"; continue; fi
    echo "=== [xss] customxss/$page/$seed $(date '+%T') ==="
    A2_TARGET=customxss CXSS_PAGE=$page A2_SEED=$seed $PY -u WorkFlowV2/r23_replay_xss_pl2.py 2>&1 \
      | grep -E "^\[(r23pl2|CRS|CG|warn)" || true
  done
done

echo "[rest] === benign CRS-only ==="
for fam in sqli xss; do
  sub=$([ "$fam" = sqli ] && echo A1 || echo A2)
  d="$B/benign/$sub/r23pl2_benign_${fam}_CRS-only.csv"
  if [ -f "$d" ]; then echo "[skip] benign $fam CRS-only"; continue; fi
  echo "=== [benign] $fam CRS-only $(date '+%T') ==="
  FAM=$fam TECH=CRS-only SEED=1 $PY -u WorkFlowV2/r23_benign_pl2.py 2>&1 | grep -E "^\[|FP " || true
done

echo "[rest] === benign CG (seeds 1-5) ==="
for fam in sqli xss; do
  sub=$([ "$fam" = sqli ] && echo A1 || echo A2)
  for tech in CG-Adaptive CG-Static; do
    for seed in 1 2 3 4 5; do
      d="$B/benign/$sub/r23pl2_benign_${fam}_${tech}_seed${seed}.csv"
      if [ -f "$d" ]; then echo "[skip] benign $fam $tech $seed"; continue; fi
      echo "=== [benign] $fam $tech seed$seed $(date '+%T') ==="
      FAM=$fam TECH=$tech SEED=$seed $PY -u WorkFlowV2/r23_benign_pl2.py 2>&1 | grep -E "^\[|FP " || true
    done
  done
done
echo "[rest] ALL DONE $(date '+%F %T')"

#!/bin/bash
# Home-turf leaderboard: run keyhog + the three competitors over corpora
# harvested from the competitors' OWN repos (their shipped labeled truth),
# using the single canonical scorer (../scoring/score.py). No new scoring
# logic — just new corpora the existing scorer consumes.
#
#   betterleaks/  — tps/fps from cmd/generate/config/rules/*.go (pos + neg)
#   kingfisher/   — examples/negative_examples from data/rules/*.yml
#
# Reading: a tool scores ~100% on its OWN turf by construction (its regexes
# were tuned to exactly these strings). The decisive numbers are CROSS-tool:
# how close keyhog gets to each competitor on that competitor's own truth,
# and whether keyhog beats the OTHER tools there. keyhog is pinned to the
# deterministic SIMD backend (KEYHOG_NO_GPU=1) so the score is reproducible
# and independent of GPU auto-routing.
set -u
HF="$(cd "$(dirname "$0")" && pwd)"
SCORE="$HF/../scoring/score.py"
REL=/mnt/FlareTraining/santh-archive/cargo-target/release
export PATH="$REL:$PATH"
export KEYHOG_NO_GPU=1

CORPORA=("${@:-betterleaks kingfisher}")
for corpus in ${CORPORA[@]}; do
  cdir="$HF/$corpus/corpus"
  [ -d "$cdir" ] || { echo "skip $corpus (no corpus dir)"; continue; }
  echo "================ home turf: $corpus ================"
  for s in keyhog trufflehog kingfisher betterleaks; do
    python3 "$SCORE" --corpus "$cdir" --scanner "$s" \
        --output "$HF/$corpus/lb-$s.json" >/dev/null 2>&1 \
      && python3 -c "
import json
d=json.load(open('$HF/$corpus/lb-$s.json'))
r=d['report']; o=r['overall']
print('  %-12s F1=%.4f  P=%.4f  R=%.4f  TP=%-5d FP=%-5d FN=%-5d  %.0fms' % (
  '$s', o['f1'],o['precision'],o['recall'],o['tp'],o['fp'],o['fn'], r.get('total_time_ms',0)))" \
      || echo "  $s: FAILED"
  done
done

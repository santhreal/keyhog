#!/usr/bin/env bash
# Full end-to-end: generate the mirror corpus, run every available
# scanner, write the leaderboard JSON, print a one-line summary.
#
# Defaults match the SecretBench paper's scale (~15 k TPs, ~80 k FPs).
# Pass POSITIVES=N / NEGATIVES=N to override.

set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "$here/../.." && pwd)"

POSITIVES="${POSITIVES:-15000}"
NEGATIVES="${NEGATIVES:-80000}"
SEED="${SEED:-0}"
CORPUS_DIR="${CORPUS_DIR:-$here/mirror/corpus}"
OUT_DIR="${OUT_DIR:-$here/results}"
OUT_JSON="$OUT_DIR/leaderboard-$(date -u +%Y%m%dT%H%M%SZ).json"

mkdir -p "$OUT_DIR"

if [[ ! -f "$CORPUS_DIR/manifest.jsonl" ]]; then
    echo "▶ generating mirror corpus ($POSITIVES + $NEGATIVES = $((POSITIVES + NEGATIVES))) at $CORPUS_DIR" >&2
    python3 "$here/mirror/generate.py" \
        --out "$CORPUS_DIR" \
        --positives "$POSITIVES" \
        --negatives "$NEGATIVES" \
        --seed "$SEED"
else
    echo "▶ reusing existing corpus at $CORPUS_DIR" >&2
fi

if [[ ! -x "$repo_root/target/release/keyhog" ]]; then
    echo "▶ building release keyhog binary" >&2
    (cd "$repo_root" && cargo build --release -p keyhog --bin keyhog)
fi

echo "▶ running leaderboard → $OUT_JSON" >&2
PATH="$repo_root/target/release:$PATH" python3 \
    "$here/scoring/leaderboard.py" \
    --corpus "$CORPUS_DIR" \
    --output "$OUT_JSON"

echo
echo "leaderboard written to: $OUT_JSON"

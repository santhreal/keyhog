#!/usr/bin/env bash
# Cross-device benchmark harness: install keyhog on a remote device, generate
# the mirror corpus on its LOCAL disk, run the unified bench leaderboard there,
# and pull the per-host RunResult JSON(s) back into benchmarks/results/<host>/
# so `python -m bench report` aggregates every machine into one matrix.
#
# Nothing here is device-specific: pass the SSH alias + the remote repo path.
# Defaults are read from the environment (Tier A config), never hardcoded.
#
#   DEVICE=tt-macbook REMOTE_REPO='~/Santh/software/keyhog' ./cross_device.sh
#   DEVICE=santhserver POSITIVES=15000 NEGATIVES=80000 ./cross_device.sh
#
# Requirements on the remote: an SSH alias that logs in non-interactively, a
# POSIX shell, python3 (>=3.8), and a Rust toolchain (cargo). The harness
# installs keyhog from the synced current repo on every run; a stale keyhog on
# PATH is never benchmark evidence. The corpus is generated locally on the
# device (NFS is far too slow for a 15k-file scan); only the small result JSON
# crosses the network.
#
# Windows devices are NOT handled here (POSIX-only); use the PowerShell sibling
# flow for the ThinkPad — see benchmarks/README.md.
set -euo pipefail

DEVICE="${DEVICE:?set DEVICE=<ssh-alias>}"
SCANNERS="${SCANNERS:-keyhog}"
CORPUS="${CORPUS:-mirror}"
POSITIVES="${POSITIVES:-3000}"
NEGATIVES="${NEGATIVES:-12000}"
SEED="${SEED:-0}"
# Per-device scratch (LOCAL disk on the remote, never the NFS share).
REMOTE_TMP="${REMOTE_TMP:-/tmp/keyhog-bench}"
# cargo-install feature set. Empty = the device picks per-OS: macOS/Darwin gets
# `--no-default-features --features portable` (keyhog's documented system-lib-free
# build — no Hyperscan/pkg-config/CUDA), Linux gets the default (Hyperscan SIMD).
KEYHOG_INSTALL_FEATURES="${KEYHOG_INSTALL_FEATURES:-}"
# We rsync THIS host's current tree to a device-local scratch copy and build
# there, so a device's stale/absent clone never benches old code. (The repo's
# normal rule is "use the NFS tree"; the user sanctioned rsync for the
# cross-device bench specifically — git clone/NFS-build is too slow.)
REMOTE_REPO="${REMOTE_REPO:-$REMOTE_TMP/keyhog}"
# cargo target stays out of the synced tree.
REMOTE_CARGO_TARGET="${REMOTE_CARGO_TARGET:-$REMOTE_TMP/cargo-target}"

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"          # benchmarks/
LOCAL_REPO="${LOCAL_REPO:-$(cd "$HERE/.." && pwd)}"           # repo root
# Per-device, and OUTSIDE results/ — the README leaderboard report reads
# results/ and `canonical_leaderboard` picks newest-per-scanner across hosts,
# so a remote host's row must never land where it could shadow the canonical
# reference-host numbers. Cross-device data is compared explicitly, not injected.
LOCAL_RESULTS="${LOCAL_RESULTS:-$HERE/results-cross-device/$DEVICE}"
SKIP_SYNC="${SKIP_SYNC:-0}"                                   # 1 = device already current

say() { printf '\033[1m▶ %s\033[0m\n' "$*" >&2; }

# The remote driver. Runs entirely on the device; emits the results dir path on
# its last stdout line so we know what to pull back.
remote_script() {
  cat <<REMOTE
set -eu
REPO="\$(eval echo "$REMOTE_REPO")"
[ -d "\$REPO/benchmarks" ] || { echo "no benchmarks/ under \$REPO" >&2; exit 3; }
cd "\$REPO"
export CARGO_TARGET_DIR="$REMOTE_CARGO_TARGET"
mkdir -p "$REMOTE_TMP" "\$CARGO_TARGET_DIR"

OS="\$(uname -s)"; ARCH="\$(uname -m)"
echo "host: \$OS \$ARCH" >&2

# 1. keyhog: install from the synced current repo via the real install flow
#    (cargo install), not a bare dev build and never PATH.
KH_FEAT="$KEYHOG_INSTALL_FEATURES"
if [ -z "\$KH_FEAT" ]; then
  case "\$OS" in
    Darwin*) KH_FEAT="--no-default-features --features portable" ;;  # no system libs
    *)       KH_FEAT="" ;;                                            # Linux: Hyperscan SIMD
  esac
fi
echo "installing keyhog (cargo install --path crates/cli \$KH_FEAT)..." >&2
cargo install --path crates/cli --root "$REMOTE_TMP/kh" \$KH_FEAT --quiet --locked >&2
KH="$REMOTE_TMP/kh/bin/keyhog"
[ -x "\$KH" ] || { echo "keyhog install failed (no binary at \$KH)" >&2; exit 5; }
KH_VERSION="\$("\$KH" --version)"
echo "keyhog: \$KH (\$KH_VERSION)" >&2

# 2. corpus on LOCAL disk.
export KEYHOG_BENCH_MIRROR="$REMOTE_TMP/corpus-$CORPUS"
( cd benchmarks && python3 -m bench.corpora.$CORPUS --ensure \
    --positives "$POSITIVES" --negatives "$NEGATIVES" --seed "$SEED" ) >&2

# 3. leaderboard into a per-host results dir.
OUT="$REMOTE_TMP/results"
( cd benchmarks && KEYHOG_BIN="\$KH" python3 -m bench leaderboard \
    --corpus "$CORPUS" --scanners "$SCANNERS" --out "\$OUT" ) >&2

# Last line of stdout = the absolute results dir to pull back.
echo "\$OUT"
REMOTE
}

if [ "$SKIP_SYNC" != "1" ]; then
  say "[$DEVICE] rsync $LOCAL_REPO -> $REMOTE_REPO (excludes .git/target/corpora/results)"
  ssh -o BatchMode=yes -o ConnectTimeout=15 "$DEVICE" "mkdir -p '$REMOTE_REPO'"
  rsync -az --delete \
    --exclude '.git' --exclude 'target' --exclude '**/__pycache__' \
    --exclude 'benchmarks/corpora' --exclude 'benchmarks/results' \
    --exclude 'tools/secretbench' --exclude 'tools/diff_bench' --exclude '/pathlib' \
    "$LOCAL_REPO/" "$DEVICE:$REMOTE_REPO/"
fi

say "[$DEVICE] driving install + corpus + leaderboard (repo=$REMOTE_REPO)"
REMOTE_OUT="$(remote_script | ssh -o BatchMode=yes -o ConnectTimeout=15 "$DEVICE" 'bash -lc "$(cat)"' | tail -1)"
[ -n "$REMOTE_OUT" ] || { echo "remote produced no results dir" >&2; exit 4; }

say "[$DEVICE] pulling results from $REMOTE_OUT -> $LOCAL_RESULTS/"
mkdir -p "$LOCAL_RESULTS"
rsync -az "$DEVICE:$REMOTE_OUT/" "$LOCAL_RESULTS/"

say "[$DEVICE] done -> $LOCAL_RESULTS/ . Compare hosts: python3 -m bench.cross_compare"

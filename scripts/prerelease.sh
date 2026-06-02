#!/usr/bin/env bash
# Internal prerelease gate + version bump for keyhog.
#
# This is NOT a publisher: it never tags, pushes, or uploads. It proves a
# candidate is releasable (tests + bench gate + coherence + an install
# smoke-test), and with `--bump X.Y.Z` rolls the workspace version + CHANGELOG
# so a human can do the final tag/push. A failing gate refuses the bump.
#
#   scripts/prerelease.sh                 # gate only (no version change)
#   scripts/prerelease.sh --bump 0.5.38   # gate, then bump if green
#   scripts/prerelease.sh --skip-rust     # skip the slow per-crate cargo gates
#
# Knobs (env or flag): CARGO_TARGET_DIR, PROFILE (release-fast), SKIP_RUST=1.
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO"

BUMP=""
SKIP_RUST="${SKIP_RUST:-0}"
PROFILE="${PROFILE:-release-fast}"
: "${CARGO_TARGET_DIR:=/mnt/FlareTraining/santh-archive/cargo-target}"
export CARGO_TARGET_DIR

while [ $# -gt 0 ]; do
  case "$1" in
    --bump) BUMP="${2:?--bump needs X.Y.Z}"; shift ;;
    --bump=*) BUMP="${1#--bump=}" ;;
    --skip-rust) SKIP_RUST=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
  shift
done

fail=0
declare -a FAILED=()
step() { printf '\n\033[1m== %s ==\033[0m\n' "$*"; }
check() {  # check <label> <cmd...>
  local label="$1"; shift
  if "$@"; then printf '  \033[32mPASS\033[0m %s\n' "$label"
  else printf '  \033[31mFAIL\033[0m %s\n' "$label"; fail=1; FAILED+=("$label"); fi
}

CUR="$(grep -m1 '^version = ' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')"
step "keyhog prerelease — current ${CUR}${BUMP:+ → ${BUMP}} (profile=$PROFILE, skip_rust=$SKIP_RUST)"

# ── 1. bench gates (fast, no cargo) ──────────────────────────────────────────
step "bench: scorer/gate unit tests"
check "bench pytest" bash -c 'cd benchmarks && python3 -m pytest -q bench/tests'

# Regression + differential gate needs a keyhog binary + the mirror corpus; run
# only if both are resolvable, else record SKIP (not a failure on a bare box).
KH_BIN="${KEYHOG_BIN:-$(command -v keyhog || true)}"
[ -n "$KH_BIN" ] || KH_BIN="$REPO/target/release/keyhog"
if [ -x "$KH_BIN" ] && [ -f benchmarks/corpora/mirror/manifest.jsonl ]; then
  step "bench: regression + differential gate (vs committed baseline)"
  check "bench gate" bash -c "cd benchmarks && KEYHOG_BIN='$KH_BIN' python3 -m bench gate \
    --corpus mirror --scanners keyhog --no-beat-competitors \
    --baseline baselines/mirror-keyhog-baseline.json --epsilon 0.005"
else
  echo "  SKIP bench gate (no keyhog binary or mirror corpus on this host)"
fi

# ── 2. coherence gates ───────────────────────────────────────────────────────
# README bench tables must be regenerable-identical (needs a full leaderboard in
# results/); informational on a partial host, so warn instead of hard-fail.
step "coherence: README bench tables fresh (informational)"
if make -C benchmarks report-check >/dev/null 2>&1; then echo "  PASS README tables up to date"
else echo "  WARN README tables differ from results/ (run 'make -C benchmarks report' on a full-scanner host)"; fi

# ── 3. Rust test gates (CI-faithful) ─────────────────────────────────────────
if [ "$SKIP_RUST" != "1" ]; then
  step "rust: per-crate all_tests (matches ci.yml)"
  check "core all_tests"     cargo test -p keyhog-core     --test all_tests --profile "$PROFILE" -- --test-threads=4
  check "scanner all_tests"  cargo test -p keyhog-scanner  --test all_tests --no-default-features --features ci-lean --profile "$PROFILE" -- --test-threads=4
  check "sources all_tests"  cargo test -p keyhog-sources  --test all_tests --profile "$PROFILE" -- --test-threads=4
  check "verifier all_tests" cargo test -p keyhog-verifier --test all_tests --profile "$PROFILE" -- --test-threads=4
  check "cli all_tests"      cargo test -p keyhog          --test all_tests --no-default-features --features ci-lean --profile "$PROFILE" -- --test-threads=4
else
  echo "  SKIP rust gates (--skip-rust)"
fi

# ── 4. install smoke — the install-flow gate ─────────────────────────────────
# Build + install via the system-lib-free `portable` path (the one that works on
# every OS incl. arm64 macOS), then prove the installed binary actually detects.
step "install smoke: cargo install (portable) + version + real detection"
SMOKE="$(mktemp -d)"
if cargo install --path crates/cli --root "$SMOKE/kh" --no-default-features --features portable --locked -q 2>"$SMOKE/build.log"; then
  KHS="$SMOKE/kh/bin/keyhog"
  check "installed --version" bash -c "'$KHS' --version | grep -q KeyHog"
  # A live-shape AWS access-key pair (no checksum class — fires on shape).
  printf 'AWS_ACCESS_KEY_ID=AKIA2E0A8F3B244C9986\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY01\n' > "$SMOKE/leak.env"
  check "installed binary detects a planted secret" bash -c \
    "'$KHS' scan --no-daemon '$SMOKE/leak.env' 2>/dev/null | grep -qiE 'AKIA2E0A8F3B244C9986|aws'"
else
  printf '  \033[31mFAIL\033[0m cargo install (portable) — tail:\n'; tail -5 "$SMOKE/build.log"; fail=1; FAILED+=("install smoke build")
fi
rm -rf "$SMOKE"

# ── 5. version bump (only if every gate passed) ──────────────────────────────
if [ -n "$BUMP" ]; then
  step "bump $CUR → $BUMP"
  if [ "$fail" != "0" ]; then
    echo "  REFUSING to bump: ${#FAILED[@]} gate(s) failed (${FAILED[*]})"; exit 1
  fi
  # Workspace package version + the internal `=X.Y.Z` path-dep pins.
  sed -i "s/^version = \"$CUR\"/version = \"$BUMP\"/" Cargo.toml
  sed -i "s/=$CUR\"/=$BUMP\"/g" Cargo.toml
  # CHANGELOG: rename the top `## Unreleased` to `## $BUMP - <date>`.
  TODAY="$(date -u +%Y-%m-%d)"
  sed -i "0,/^## Unreleased$/s//## $BUMP - $TODAY/" CHANGELOG.md
  echo "  bumped Cargo.toml + rolled CHANGELOG (## $BUMP - $TODAY)"
  echo "  verify: cargo build -p keyhog --bin keyhog && target/$PROFILE/keyhog --version"
fi

# ── 6. verdict ───────────────────────────────────────────────────────────────
step "verdict"
if [ "$fail" = "0" ]; then
  echo "  PRERELEASE OK${BUMP:+ — bumped to $BUMP}"
  echo "  Next (human): review git diff, commit, tag v${BUMP:-$CUR}, push;"
  echo "  watch lanes: ci · bench-nightly · differential-bench · runners-nightly · vendor-vyre"
else
  echo "  PRERELEASE BLOCKED — ${#FAILED[@]} gate(s) failed: ${FAILED[*]}"
fi
exit "$fail"

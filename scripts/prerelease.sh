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
#
# SC2317: the smoke-check functions below (installed_version_smoke, …) are invoked
# INDIRECTLY through the `check` dispatcher (`check <label> <fn> <args>` runs
# `"$@"`), which ShellCheck cannot trace, so it wrongly reports their bodies as
# unreachable. Disable it file-wide (must precede the first command) for this pattern.
# shellcheck disable=SC2317
set -uo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1

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

installed_version_smoke() {
  "$1" --version | grep -q KeyHog
}

installed_detection_smoke() {
  local bin="$1"
  local leak="$2"
  local report="$3"
  local stdout_log="$4"
  local stderr_log="$5"
  local rc

  "$bin" scan --no-daemon --format json --output "$report" "$leak" >"$stdout_log" 2>"$stderr_log"
  rc=$?
  case "$rc" in
    1 | 10) ;;
    *)
      echo "installed scan exited $rc; expected findings exit 1 or live-credential exit 10" >&2
      sed -n '1,40p' "$stderr_log" >&2
      return 1
      ;;
  esac

  python3 - "$report" "$leak" <<'PY'
import json
import pathlib
import sys

report = pathlib.Path(sys.argv[1])
leak = pathlib.Path(sys.argv[2]).name

try:
    data = json.loads(report.read_text())
except Exception as exc:
    print(f"failed to parse scan JSON report {report}: {exc}", file=sys.stderr)
    raise SystemExit(1)

if isinstance(data, list):
    findings = data
elif isinstance(data, dict):
    findings = data.get("findings", [])
else:
    print(
        f"scan JSON report {report} must be an array or object, got {type(data).__name__}",
        file=sys.stderr,
    )
    raise SystemExit(1)
for finding in findings:
    if not isinstance(finding, dict):
        continue
    detector = str(finding.get("detector_id", "")).lower()
    credential = str(finding.get("credential_redacted", "")).lower()
    location = finding.get("location") or {}
    file_path = str(location.get("file_path") or location.get("file") or "")
    if ("aws" in detector or "akia2e0a8f3b244c9986" in credential) and file_path.endswith(leak):
        raise SystemExit(0)

print(f"scan report {report} did not contain the planted AWS finding for {leak}", file=sys.stderr)
raise SystemExit(1)
PY
}

CUR="$(grep -m1 '^version = ' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')"
step "keyhog prerelease — current ${CUR}${BUMP:+ → ${BUMP}} (profile=$PROFILE, skip_rust=$SKIP_RUST)"

# ── 1. candidate + bench gates ───────────────────────────────────────────────
# Bench integration tests must execute the source tree being released. Resolving
# an arbitrary same-semver binary from a shared Cargo target can load an older
# detector schema and turn one stale-artifact error into thousands of recall
# failures. Build once, then pin every benchmark invocation to this artifact.
step "candidate: build benchmark binary"
CANDIDATE="$CARGO_TARGET_DIR/$PROFILE/keyhog"
CANDIDATE_READY=0
if cargo build -p keyhog --bin keyhog --profile "$PROFILE"; then
  export KEYHOG_BIN="$CANDIDATE"
  CANDIDATE_READY=1
  printf '  \033[32mPASS\033[0m candidate build (%s)\n' "$KEYHOG_BIN"
else
  printf '  \033[31mFAIL\033[0m candidate build\n'
  fail=1
  FAILED+=("candidate build")
fi

step "bench: scorer/gate unit tests"
if [ "$CANDIDATE_READY" = "1" ]; then
  check "bench pytest" bash -c "cd benchmarks && python3 -m pytest -q -m 'not target_spec' bench/tests"
else
  echo "  FAIL bench pytest — candidate binary is unavailable"
  fail=1
  FAILED+=("bench pytest prerequisite")
fi

step "bench: mirror corpus"
check "mirror corpus available" make -C benchmarks mirror

step "bench: regression + differential gate (vs committed baseline)"
check "bench gate" bash -c "cd benchmarks && python3 -m bench gate \
  --corpus mirror --scanners keyhog --no-beat-competitors \
  --baseline baselines/mirror-keyhog-baseline.json --epsilon 0.005"

# ── 2. coherence gates ───────────────────────────────────────────────────────
# README bench tables must be regenerable-identical. A prerelease gate with
# stale generated claims is not release evidence.
step "coherence: README bench tables fresh"
check "README bench tables up to date" make -C benchmarks report-check

# ── 3. Rust test gates (CI-faithful) ─────────────────────────────────────────
if [ "$SKIP_RUST" != "1" ]; then
  step "rust: per-crate all_tests (matches ci.yml)"
  check "core all-targets compile" cargo check -p keyhog-core --all-targets
  check "core all_tests"     cargo test -p keyhog-core     --test all_tests --profile "$PROFILE" -- --test-threads=4
  check "scanner all_tests"  cargo test -p keyhog-scanner  --test all_tests --no-default-features --features ci-lean --profile "$PROFILE" -- --test-threads=4
  check "scanner adversarial dead corpus" cargo test -p keyhog-scanner --test adversarial_suite --no-default-features --features ci-lean --profile "$PROFILE" -- --test-threads=4
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
  check "installed --version" installed_version_smoke "$KHS"
  # A live-shape AWS access-key pair (no checksum class — fires on shape).
  printf 'AWS_ACCESS_KEY_ID=AKIA2E0A8F3B244C9986\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY01\n' > "$SMOKE/leak.env"
  check "installed binary detects a planted secret" installed_detection_smoke \
    "$KHS" "$SMOKE/leak.env" "$SMOKE/report.json" "$SMOKE/scan.stdout" "$SMOKE/scan.stderr"
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
  # Portable in-place sed: GNU `sed -i` takes no arg but BSD/macOS `sed -i`
  # requires a backup-suffix arg (`sed -i ''`), so a bare `sed -i "…" file`
  # silently breaks a release cut from macOS. Route both through a temp file
  # (no flavor dependency, no stray .bak litter, preserves the file perms/inode).
  sed_inplace() {
    local script="$1" file="$2" tmp
    tmp="$(mktemp "${TMPDIR:-/tmp}/prerelease-sed.XXXXXX")" || return 1
    if sed "$script" "$file" >"$tmp"; then cat "$tmp" >"$file"; else rm -f "$tmp"; return 1; fi
    rm -f "$tmp"
  }
  # Workspace package version + the internal `=X.Y.Z` path-dep pins.
  sed_inplace "s/^version = \"$CUR\"/version = \"$BUMP\"/" Cargo.toml
  sed_inplace "s/=$CUR\"/=$BUMP\"/g" Cargo.toml
  # CHANGELOG: rename the top `## Unreleased` to `## $BUMP - <date>`.
  TODAY="$(date -u +%Y-%m-%d)"
  sed_inplace "0,/^## Unreleased$/s//## $BUMP - $TODAY/" CHANGELOG.md
  echo "  bumped Cargo.toml + rolled CHANGELOG (## $BUMP - $TODAY)"
  echo "  verify: cargo build -p keyhog --bin keyhog && target/$PROFILE/keyhog --version"
fi

# ── 6. verdict ───────────────────────────────────────────────────────────────
step "verdict"
if [ "$fail" = "0" ]; then
  echo "  PRERELEASE OK${BUMP:+ — bumped to $BUMP}"
  echo "  Next (human): review git diff, commit, tag v${BUMP:-$CUR}, push;"
  echo "  watch lanes: ci · bench-nightly · differential-bench · runners-nightly"
else
  echo "  PRERELEASE BLOCKED — ${#FAILED[@]} gate(s) failed: ${FAILED[*]}"
fi
exit "$fail"

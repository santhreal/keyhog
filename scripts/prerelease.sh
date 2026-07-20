#!/usr/bin/env bash
# Internal prerelease gate + version bump for keyhog.
#
# This is not a publisher: it never tags, pushes, or uploads. It proves a
# candidate is releasable (tests + bench gate + coherence + shipped install
# smoke). `--bump X.Y.Z` rolls every canonical versioned surface, but the
# clean-tree GPU evidence gate remains red until you review and commit the bump,
# then rerun this script against the signed bundle from that exact commit.
#
#   scripts/prerelease.sh --release-candidate PATH
#                                      # gate a signed release bundle
#   scripts/prerelease.sh --bump X.Y.Z  # bump the candidate, then gate it
#   scripts/prerelease.sh --skip-rust   # skip the slow per-crate cargo gates
#
# Knobs: CARGO_TARGET_DIR, PROFILE, SKIP_RUST, KEYHOG_RELEASE_CANDIDATE.
#
# SC2317: the smoke-check functions below (installed_version_smoke, …) are invoked
# INDIRECTLY through the `check` dispatcher (`check <label> <fn> <args>` runs
# `"$@"`), which ShellCheck cannot trace, so it wrongly reports their bodies as
# unreachable. Disable it file-wide (must precede the first command) for this pattern.
# shellcheck disable=SC2317
set -uo pipefail
export PYTHONDONTWRITEBYTECODE=1

REPO="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO" || exit 1

BUMP=""
RELEASE_CANDIDATE="${KEYHOG_RELEASE_CANDIDATE:-}"
SKIP_RUST="${SKIP_RUST:-0}"
PROFILE="${PROFILE:-release-fast}"
: "${CARGO_TARGET_DIR:=/mnt/FlareTraining/santh-archive/cargo-target}"
export CARGO_TARGET_DIR

while [ $# -gt 0 ]; do
  case "$1" in
    --bump) BUMP="${2:?--bump needs X.Y.Z}"; shift ;;
    --bump=*) BUMP="${1#--bump=}" ;;
    --release-candidate) RELEASE_CANDIDATE="${2:?--release-candidate needs PATH}"; shift ;;
    --release-candidate=*) RELEASE_CANDIDATE="${1#--release-candidate=}" ;;
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


release_candidate_bundle_present() {
  local candidate="$1" suffix
  if [ -z "$candidate" ]; then
    echo "provide --release-candidate PATH to the signed release binary" >&2
    return 1
  fi
  for suffix in "" ".sha256" ".minisig" ".gpu-literals.tar.gz" \
    ".gpu-literals.tar.gz.sha256" ".gpu-literals.tar.gz.minisig"; do
    if [ ! -s "$candidate$suffix" ]; then
      echo "signed release bundle is missing or empty: $candidate$suffix" >&2
      return 1
    fi
  done
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

  "$bin" scan --daemon=off --format json --output "$report" "$leak" >"$stdout_log" 2>"$stderr_log"
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
    location = finding.get("location") or {}
    file_path = str(location.get("file_path") or location.get("file") or "")
    if detector == "aws-access-key" and file_path.endswith(leak):
        raise SystemExit(0)

print(f"scan report {report} did not contain the planted AWS finding for {leak}", file=sys.stderr)
raise SystemExit(1)
PY
}

# Portable in-place sed. GNU `sed -i` and BSD/macOS `sed -i` have incompatible
# argument rules, so use a temporary file and preserve the original inode.
sed_inplace() {
  local script="$1" file="$2" tmp
  tmp="$(mktemp "${TMPDIR:-/tmp}/prerelease-sed.XXXXXX")" || return 1
  if sed "$script" "$file" >"$tmp"; then
    cat "$tmp" >"$file"
  else
    rm -f "$tmp"
    return 1
  fi
  rm -f "$tmp"
}

validate_crate_changelogs() {
  python3 - \
    crates/cli/CHANGELOG.md \
    crates/core/CHANGELOG.md \
    crates/scanner/CHANGELOG.md \
    crates/sources/CHANGELOG.md \
    crates/verifier/CHANGELOG.md <<'PY'
import pathlib
import sys

failures = []
for raw in sys.argv[1:]:
    path = pathlib.Path(raw)
    lines = path.read_text().splitlines()
    try:
        start = lines.index("## Unreleased") + 1
    except ValueError:
        failures.append(f"{path}: missing one '## Unreleased' section")
        continue
    end = next(
        (index for index in range(start, len(lines)) if lines[index].startswith("## ")),
        len(lines),
    )
    if not any(line.startswith("- ") for line in lines[start:end]):
        failures.append(f"{path}: Unreleased section has no owned change entry")

if failures:
    print("\n".join(failures), file=sys.stderr)
    raise SystemExit(1)
PY
}

run_gpu_crossover_gate() {
  local source_status artifact head rc
  source_status="$(git status --porcelain=v1 --untracked-files=all)" || {
    echo "cannot inspect source state for the GPU crossover gate" >&2
    return 1
  }
  if [ -n "$source_status" ]; then
    echo "GPU crossover release evidence requires a clean source tree:" >&2
    printf '%s\n' "$source_status" >&2
    return 1
  fi
  artifact="$(mktemp "${TMPDIR:-/tmp}/keyhog-gpu-crossover.XXXXXX.toml")" || return 1
  KH_BENCH_ARTIFACT="$artifact" cargo bench \
    -p keyhog-scanner \
    --bench gpu_vs_hs_8mib \
    --features gpu \
    --profile "$PROFILE" -- || {
      rc=$?
      rm -f "$artifact"
      return "$rc"
    }
  head="$(git rev-parse --verify HEAD)" || {
    rm -f "$artifact"
    return 1
  }
  python3 -B scripts/gpu_crossover_artifact.py \
    "$artifact" --git-hash "$head"
  rc=$?
  rm -f "$artifact"
  return "$rc"
}

apply_version_bump() {
  local current="$1" next="$2" today current_re
  local -a versioned_files=(
    README.md
    .github/actions/keyhog/README.md
    docs/src/install.md
    docs/src/introduction.md
    docs/src/workflows/integrations.md
    docs/src/workflows/ci.md
    docs/src/first-scan.md
    docs/src/workflows/precommit.md
  )

  if ! [[ "$next" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    echo "invalid --bump version '$next'; expected X.Y.Z" >&2
    return 2
  fi
  if [ "$next" = "$current" ]; then
    echo "--bump version already equals workspace version $current" >&2
    return 2
  fi
  if [ "$(grep -c '^## \[Unreleased\]$' CHANGELOG.md)" -ne 1 ]; then
    echo "CHANGELOG.md must contain exactly one '## [Unreleased]' heading" >&2
    return 1
  fi
  if [ "$(grep -c "^version = \"$current\"$" Cargo.toml)" -ne 1 ] \
     || [ "$(grep -c "=$current\"" Cargo.toml)" -ne 4 ]; then
    echo "Cargo.toml does not contain the expected workspace version and four exact internal pins" >&2
    return 1
  fi
  for file in "${versioned_files[@]}"; do
    if ! grep -q "v$current" "$file"; then
      echo "$file does not contain the current canonical version v$current" >&2
      return 1
    fi
  done

  current_re="${current//./\\.}"
  sed_inplace "s/^version = \"$current_re\"/version = \"$next\"/" Cargo.toml || return 1
  sed_inplace "s/=$current_re\"/=$next\"/g" Cargo.toml || return 1

  python3 - "$current" "$next" Cargo.lock <<'PY' || return 1
import os
import pathlib
import sys

current, next_version, raw_path = sys.argv[1:]
path = pathlib.Path(raw_path)
lines = path.read_text().splitlines(keepends=True)
workspace = {"keyhog", "keyhog-core", "keyhog-scanner", "keyhog-sources", "keyhog-verifier"}
updated = set()
package = None
for index, line in enumerate(lines):
    if line == "[[package]]\n":
        package = None
    elif line.startswith('name = "') and line.rstrip().endswith('"'):
        package = line[len('name = "'):-2]
    elif package in workspace and line == f'version = "{current}"\n':
        lines[index] = f'version = "{next_version}"\n'
        updated.add(package)

missing = sorted(workspace - updated)
if missing:
    raise SystemExit(f"Cargo.lock did not contain expected {current} workspace packages: {missing}")
tmp = path.with_name(path.name + ".prerelease-tmp")
tmp.write_text("".join(lines))
os.chmod(tmp, path.stat().st_mode)
os.replace(tmp, path)
PY

  for file in "${versioned_files[@]}"; do
    sed_inplace "s/v$current_re/v$next/g" "$file" || return 1
  done

  today="$(date -u +%Y-%m-%d)"
  sed_inplace "0,/^## \[Unreleased\]$/s//## [$next] - $today/" CHANGELOG.md || return 1
  for file in \
    crates/cli/CHANGELOG.md \
    crates/core/CHANGELOG.md \
    crates/scanner/CHANGELOG.md \
    crates/sources/CHANGELOG.md \
    crates/verifier/CHANGELOG.md; do
    sed_inplace "0,/^## Unreleased$/s//## $next - $today/" "$file" || return 1
  done

  if rg -n "v$current" "${versioned_files[@]}"; then
    echo "canonical release docs still contain v$current" >&2
    return 1
  fi
  if [ "$(grep -c '^## \[Unreleased\]$' CHANGELOG.md)" -ne 0 ]; then
    echo "CHANGELOG.md still contains an Unreleased heading after bump" >&2
    return 1
  fi
  echo "  bumped workspace, lockfile, crate changelogs, and canonical docs to $next"
}

CUR="$(grep -m1 '^version = ' Cargo.toml | sed 's/.*"\(.*\)".*/\1/')"
validate_crate_changelogs || exit 1
step "keyhog prerelease, current ${CUR}${BUMP:+ → ${BUMP}} (profile=$PROFILE, skip_rust=$SKIP_RUST)"

if [ -n "$BUMP" ]; then
  step "candidate: bump $CUR → $BUMP"
  apply_version_bump "$CUR" "$BUMP" || exit $?
fi

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
  check "bench pytest" bash -c "cd benchmarks && PYTHONDONTWRITEBYTECODE=1 python3 -B -m pytest -p no:cacheprovider -q -m 'not target_spec' bench/tests"
else
  echo "  FAIL bench pytest, candidate binary is unavailable"
  fail=1
  FAILED+=("bench pytest prerequisite")
fi

step "bench: mirror corpus"
check "mirror corpus available" make -C benchmarks mirror

step "bench: regression + differential gate (vs committed baseline)"
check "bench gate" bash -c "cd benchmarks && python3 -m bench gate \
  --corpus mirror --scanners keyhog --no-beat-competitors \
  --baseline baselines/mirror-keyhog-baseline.json --epsilon 0.005"

step "bench: 8 MiB GPU versus fastest exact Hyperscan route"
check "GPU crossover evidence" run_gpu_crossover_gate

# ── 2. coherence gates ───────────────────────────────────────────────────────
# README bench tables must be regenerable-identical. A prerelease gate with
# stale generated claims is not release evidence.
step "coherence: README bench tables fresh"
check "README bench tables up to date" make -C benchmarks report-check
check "locked metadata matches manifests" bash -c "cargo metadata --locked --no-deps --format-version 1 >/dev/null"
check "publishable crate licenses match canonical payloads" python3 -B scripts/gates/package_licenses.py
check "documentation truth" python3 -B scripts/gates/docs_truth.py

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

# ── 4. shipped install-flow gate ─────────────────────────────────────────────
# The release bundle must already contain the signed binary and GPU literal
# sidecar that operators receive. Source builds cannot satisfy this gate.
step "install smoke: signed release bundle + installer + product workflow"
SMOKE="$(mktemp -d)"
if release_candidate_bundle_present "$RELEASE_CANDIDATE"; then
  mkdir -p "$SMOKE/home" "$SMOKE/kh/bin"
  if HOME="$SMOKE/home" XDG_CACHE_HOME="$SMOKE/cache" sh install.sh \
    --from-file="$RELEASE_CANDIDATE" \
    --install-dir="$SMOKE/kh/bin" \
    --yes --no-prompt --no-color >"$SMOKE/install.log" 2>&1; then
    KHS="$SMOKE/kh/bin/keyhog"
    check "installed --version" installed_version_smoke "$KHS"
    check "installed doctor" "$KHS" doctor
    # A live-shape AWS access-key pair (no checksum class, fires on shape).
    printf 'AWS_ACCESS_KEY_ID=AKIA2E0A8F3B244C9986\nAWS_SECRET_ACCESS_KEY=wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY01\n' > "$SMOKE/leak.env"
    check "installed binary detects a planted secret" installed_detection_smoke \
      "$KHS" "$SMOKE/leak.env" "$SMOKE/report.json" "$SMOKE/scan.stdout" "$SMOKE/scan.stderr"
    if HOME="$SMOKE/home" XDG_CACHE_HOME="$SMOKE/cache" sh install.sh \
      --uninstall --install-dir="$SMOKE/kh/bin" \
      --yes --no-prompt --no-color >"$SMOKE/uninstall.log" 2>&1 \
      && [ ! -e "$KHS" ]; then
      printf '  \033[32mPASS\033[0m shipped uninstall\n'
    else
      printf '  \033[31mFAIL\033[0m shipped uninstall\n'
      fail=1
      FAILED+=("shipped uninstall")
    fi
  else
    printf '  \033[31mFAIL\033[0m signed bundle install, tail:\n'
    tail -10 "$SMOKE/install.log"
    fail=1
    FAILED+=("signed bundle install")
  fi
else
  fail=1
  FAILED+=("signed release bundle")
fi
rm -rf "$SMOKE"

# ── 5. verdict ───────────────────────────────────────────────────────────────
step "verdict"
if [ "$fail" = "0" ]; then
  echo "  PRERELEASE OK${BUMP:+, bumped to $BUMP}"
  echo "  Next (human): review git diff, commit, tag v${BUMP:-$CUR}, push;"
  echo "  watch lanes: ci · bench-nightly · differential-bench · runners-nightly"
else
  echo "  PRERELEASE BLOCKED: ${#FAILED[@]} gate(s) failed: ${FAILED[*]}"
fi
exit "$fail"

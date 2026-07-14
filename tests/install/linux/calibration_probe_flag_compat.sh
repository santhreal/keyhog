#!/usr/bin/env bash
#
# Regression: install.sh autoroute-calibration probe must (1) work against a
# released binary that predates `--no-config` (it only has `--config <PATH>`),
# and (2) surface the real reason when a probe fails instead of a blind failure label.
#
# Dogfood origin: a clean `sh install.sh` of the published v0.5.40 CUDA build
# ran the calibration with `keyhog scan <probe> --no-config ...`; that binary
# rejects `--no-config` (clap: "unexpected argument '--no-config'"), so all
# three probes failed and the installer swallowed the cause with
# `>/dev/null 2>&1` (Law 10) - the install read as a broken product. The fix
# detects the binary's actual config flag via `--help` and prints the real
# stderr line on failure.
#
# This test mocks the published binary (rejects --no-config, accepts --config)
# and a hard-failing binary, drives `install.sh --calibrate` against each, and
# asserts the PASS / surfaced-reason behavior. Offline, deterministic, no network.

set -u
ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
INSTALL_SH="$ROOT/install.sh"
pass=0; fail=0; failed=""
_pass() { printf '  [PASS] %s\n' "$1"; pass=$((pass + 1)); }
_fail() { printf '  [FAIL] %s\n     %s\n' "$1" "$2"; fail=$((fail + 1)); failed="$failed\n  - $1"; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# --- mock A: a "published" binary that has --config but NOT --no-config -------
mkdir -p "$work/binA"
cat > "$work/binA/keyhog" <<'EOF'
#!/usr/bin/env sh
# Mimic a released Linux/CUDA keyhog: it ships autoroute calibration
# (`--autoroute-calibrate`, as the real Linux build does) and `scan --config
# <PATH>`, but predates `--no-config`. `scan --help` advertises
# --autoroute-calibrate and --config but NOT --no-config, so the installer runs
# calibration and picks the --config isolation flag.
if [ "$1 $2" = "scan --help" ] || [ "$1" = "--help" ]; then
    printf '%s\n' "Usage: keyhog scan --autoroute-calibrate --config <PATH> <PATH>"
    exit 0
fi
if [ "$1" = "scan" ]; then
    shift
    for a in "$@"; do
        case "$a" in
            --no-config) echo "error: unexpected argument '--no-config' found" >&2; exit 2 ;;
        esac
    done
    exit 0
fi
case "$1" in
    --version) echo "keyhog 0.5.40" ;;
    scan) : ;;
esac
exit 0
EOF
chmod +x "$work/binA/keyhog"

# --- mock B: a binary that ALWAYS fails the scan with a distinct reason -------
mkdir -p "$work/binB"
cat > "$work/binB/keyhog" <<'EOF'
#!/usr/bin/env sh
if [ "$1" = "scan" ]; then
    case " $* " in *" --help "*) echo "Usage: keyhog scan --autoroute-calibrate --no-config <PATH>"; exit 0;; esac
    echo "error: GPU adapter request failed (mock driver fault)" >&2
    exit 1
fi
[ "$1" = "--help" ] && echo "Usage: keyhog scan"
[ "$1" = "--version" ] && echo "keyhog 0.5.40"
exit 0
EOF
chmod +x "$work/binB/keyhog"

# --- mock C: a current binary that owns the canonical core sweep ------------
mkdir -p "$work/binC"
cat > "$work/binC/keyhog" <<'EOF'
#!/usr/bin/env sh
if [ "$1 $2" = "scan --help" ]; then
    printf '%s\n' "Usage: keyhog scan --autoroute-calibrate --no-config <PATH>"
    exit 0
fi
if [ "$1" = "--help" ]; then
    printf '%s\n' "Commands: scan calibrate-autoroute backend"
    exit 0
fi
if [ "$1" = "calibrate-autoroute" ]; then
    mkdir -p "$HOME/.cache/keyhog"
    printf '%s\n' cache > "$HOME/.cache/keyhog/autoroute.json"
    printf '%s\n' "calibrated 368 workload buckets across 4 scan policies"
    exit 0
fi
if [ "$1" = "backend" ]; then
    cat <<'JSON'
{
  "configs": [{
    "decisions": [{
      "backend": "simd-cpu",
      "sample_bytes": 65536,
      "sample_chunks": 1,
      "simd_ms": 1,
      "cpu_ms": 2,
      "gpu_cuda_ms": null,
      "gpu_wgpu_ms": null,
      "selected_margin_ns": 1000,
      "daemon_backend": null
    }]
  }]
}
JSON
    exit 0
fi
[ "$1" = "--version" ] && echo "keyhog 0.5.41"
exit 0
EOF
chmod +x "$work/binC/keyhog"

# --- mock D: scan help works but top-level capability inspection fails ------
mkdir -p "$work/binD"
cat > "$work/binD/keyhog" <<'EOF'
#!/usr/bin/env sh
if [ "$1 $2" = "scan --help" ]; then
    printf '%s\n' "Usage: keyhog scan --autoroute-calibrate --no-config <PATH>"
    exit 0
fi
if [ "$1" = "--help" ]; then
    echo "error: top-level help failed (mock corruption)" >&2
    exit 7
fi
[ "$1" = "--version" ] && echo "keyhog 0.5.41"
exit 0
EOF
chmod +x "$work/binD/keyhog"

run_calibrate() { # $1=install-dir-with-keyhog
    env -i PATH="/usr/bin:/bin" HOME="$work/home" TMPDIR="$work/tmp" \
        NO_COLOR=1 \
        sh "$INSTALL_SH" --install-dir="$1" --calibrate 2>&1
}
mkdir -p "$work/home" "$work/tmp"

# 1. Released-style binary (no --no-config): calibration must succeed, not fail.
outA="$(run_calibrate "$work/binA")"
if printf '%s' "$outA" | grep -q 'PASS .*MiB workload' && ! printf '%s' "$outA" | grep -q 'FAIL .*MiB workload'; then
    _pass "released binary without --no-config calibrates PASS (flag auto-detected)"
else
    _fail "released binary without --no-config calibrates PASS" "got: $(printf '%s' "$outA" | grep -i 'MiB workload' | tr '\n' '|')"
fi

# 2. The installer must NOT pass --no-config blindly: no probe may print the
#    'unexpected argument --no-config' clap error.
if printf '%s' "$outA" | grep -q "unexpected argument '--no-config'"; then
    _fail "installer never passes --no-config to a binary lacking it" "clap rejection leaked into calibration"
else
    _pass "installer never passes --no-config to a binary lacking it"
fi

# 3. A genuinely failing probe must SURFACE the real reason (Law 10), not swallow it.
outB="$(run_calibrate "$work/binB")"
if printf '%s' "$outB" | grep -q 'mock driver fault'; then
    _pass "failing probe surfaces the real reason (no silent swallow)"
else
    _fail "failing probe surfaces the real reason" "expected 'mock driver fault' in output; got: $(printf '%s' "$outB" | tr '\n' '|' | tail -c 300)"
fi

# 4. Structural guard: the probe redirect must capture stderr to a file, never
#    discard it with `2>&1`-to-null on the scan invocation.
if grep -q '2>"\$err"' "$INSTALL_SH"; then
    _pass "calibration probe captures stderr to a file (not /dev/null)"
else
    _fail "calibration probe captures stderr to a file" "expected 2>\"\$err\" in install.sh prime_autoroute_cache"
fi

# 5. Structural guard: help inspection must not discard failure and guess.
if grep -q 'scan --help 2>/dev/null || true' "$INSTALL_SH"; then
    _fail "calibration help inspection fails loud" "found retired scan --help suppression"
elif grep -q 'scan --help 2>"\$scan_help_err"' "$INSTALL_SH" \
     && grep -q 'refusing to guess calibration flags' "$INSTALL_SH"; then
    _pass "calibration help inspection fails loud"
else
    _fail "calibration help inspection fails loud" "expected captured scan_help_err and no-output refusal"
fi

# 6. Current binaries own the core matrix. The installer must invoke that one
#    command and must not replay its compatibility workload loop.
outC="$(run_calibrate "$work/binC")"
if printf '%s' "$outC" | grep -q 'calibrated 368 workload buckets' \
   && printf '%s' "$outC" | grep -q 'probes: 368' \
   && ! printf '%s' "$outC" | grep -q 'PASS .* workload'; then
    _pass "current binary canonical sweep replaces installer core replay"
else
    _fail "current binary canonical sweep replaces installer core replay" "got: $(printf '%s' "$outC" | tr '\n' '|' | tail -c 500)"
fi

# 7. A broken capability probe must not silently select the compatibility
#    matrix, because that matrix cannot calibrate current archive classes.
outD="$(run_calibrate "$work/binD")"
if printf '%s' "$outD" | grep -q 'top-level help failed (mock corruption)' \
   && printf '%s' "$outD" | grep -q 'Could not inspect installed keyhog --help' \
   && ! printf '%s' "$outD" | grep -q 'PASS .* workload'; then
    _pass "failed top-level capability inspection never falls back silently"
else
    _fail "failed top-level capability inspection never falls back silently" "got: $(printf '%s' "$outD" | tr '\n' '|' | tail -c 500)"
fi

total=$((pass + fail))
printf '\n--------------------------------------------------------------\n'
if [ "$fail" -eq 0 ]; then
    printf '\033[32m%d / %d passed.\033[0m\n' "$pass" "$total"; exit 0
else
    printf '\033[31m%d failed, %d passed (of %d).\033[0m%b\n' "$fail" "$pass" "$total" "$failed"; exit 1
fi

#!/usr/bin/env bash
#
# Hand-written edge-case battery for install.sh.
#
# Unlike scenarios.sh (which only drives --diagnose with KEYHOG_VERSION
# pinned so the network is never touched), this harness mocks the ENTIRE
# surface install.sh depends on - curl (releases API, asset download,
# .sha256), uname, nvidia-smi, ldconfig, ldd, and the downloaded binary
# itself - so the full install -> verify_checksum -> stage -> verify_install
# path runs offline and deterministically. Every documented mode, flag,
# detection branch, and failure path gets a real assertion against the
# real script. These are the tests that would have caught the resolve_tag
# JSON-indentation bug (the default `curl | sh` install failing outright).
#
# Each test runs install.sh in a per-test sandbox: env -i with PATH pointed
# at a mock bin/ dir, a throwaway HOME, and a throwaway KEYHOG_INSTALL. No
# network, no host mutation.

set -u

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
INSTALL_SH="$ROOT/install.sh"
if [ ! -f "$INSTALL_SH" ]; then
    echo "install.sh not found at $INSTALL_SH" >&2
    exit 1
fi

pass=0
fail=0
skipped=0
failed_names=""

# detect_linux_cuda probes real host paths (/proc/driver/nvidia,
# /usr/lib*/libcuda.so, /usr/local/cuda) that a PATH-only sandbox can't
# intercept. On a host with a real CUDA stack those probes win regardless
# of the mocked nvidia-smi/ldconfig, so CUDA-absence assertions can't be
# validated here. They ARE validated in the Docker matrix (clean,
# CUDA-free containers). Skip them locally when the host has CUDA.
HOST_HAS_CUDA=no
if [ -e /proc/driver/nvidia ] || [ -d /usr/local/cuda ] || [ -d /opt/cuda ] \
   || ls /usr/lib*/libcuda.so* >/dev/null 2>&1 \
   || ldconfig -p 2>/dev/null | grep -q 'libcuda\.so'; then
    HOST_HAS_CUDA=yes
fi
skip() { printf '  \033[33m-\033[0m %s (skipped: %s)\n' "$1" "$2"; skipped=$((skipped + 1)); }

# ── assertion helpers ─────────────────────────────────────────────────
# expect_match NAME PATTERN OUTPUT   - output matches extended regex
# expect_nomatch NAME PATTERN OUTPUT - output does NOT match
# expect_status NAME WANT GOT        - exit status equality
# expect_file NAME PATH              - file exists
# expect_nofile NAME PATH            - file does not exist

_record_pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; pass=$((pass + 1)); }
_record_fail() {
    printf '  \033[31m✗\033[0m %s\n' "$1"
    shift
    [ $# -gt 0 ] && printf '%s\n' "$*" | sed 's/^/      /'
    fail=$((fail + 1))
    failed_names="$failed_names\n  - $1"
}

expect_match() {
    if printf '%s' "$3" | grep -qE -- "$2"; then _record_pass "$1"
    else _record_fail "$1" "expected /$2/, got (head):" "$(printf '%s' "$3" | head -8)"; fi
}
expect_nomatch() {
    if printf '%s' "$3" | grep -qE -- "$2"; then
        _record_fail "$1" "did NOT expect /$2/, but it appeared:" "$(printf '%s' "$3" | grep -E -- "$2" | head -3)"
    else _record_pass "$1"; fi
}
expect_status() {
    if [ "$2" = "$3" ]; then _record_pass "$1"
    else _record_fail "$1" "expected exit $2, got $3"; fi
}
expect_file()   { if [ -e "$2" ]; then _record_pass "$1"; else _record_fail "$1" "missing file: $2"; fi; }
expect_nofile() { if [ ! -e "$2" ]; then _record_pass "$1"; else _record_fail "$1" "unexpected file: $2"; fi; }
expect_exec()   { if [ -x "$2" ]; then _record_pass "$1"; else _record_fail "$1" "not executable: $2"; fi; }

# ── fixtures ──────────────────────────────────────────────────────────
# Releases JSON shaped exactly like the GitHub REST API: the assets array's
# closing bracket is indented FOUR spaces, the trap the old awk fell into.
FIX_DIR=$(mktemp -d -t kh-fix-XXXXXX)
trap 'rm -rf "$FIX_DIR"' EXIT INT TERM

# Normal: newest release (v9.9.9) has assets.
cat > "$FIX_DIR/releases_normal.json" <<'JSON'
[
  {
    "tag_name": "v9.9.9",
    "assets": [
      {
        "name": "keyhog-linux-x86_64",
        "browser_download_url": "https://github.com/santhsecurity/keyhog/releases/download/v9.9.9/keyhog-linux-x86_64"
      }
    ]
  },
  {
    "tag_name": "v9.9.8",
    "assets": [
      {
        "name": "keyhog-linux-x86_64",
        "browser_download_url": "https://github.com/santhsecurity/keyhog/releases/download/v9.9.8/keyhog-linux-x86_64"
      }
    ]
  }
]
JSON

# Newest release has ZERO assets; installer must skip to v9.9.8.
cat > "$FIX_DIR/releases_latest_empty.json" <<'JSON'
[
  {
    "tag_name": "v9.9.9",
    "assets": [
    ]
  },
  {
    "tag_name": "v9.9.8",
    "assets": [
      {
        "name": "keyhog-linux-x86_64",
        "browser_download_url": "https://github.com/santhsecurity/keyhog/releases/download/v9.9.8/keyhog-linux-x86_64"
      }
    ]
  }
]
JSON

# Every release has zero assets -> hard error.
cat > "$FIX_DIR/releases_all_empty.json" <<'JSON'
[
  { "tag_name": "v9.9.9", "assets": [
    ] },
  { "tag_name": "v9.9.8", "assets": [
    ] }
]
JSON

# The fake "keyhog" binary the download step serves. A POSIX shell script
# so verify_install can actually execute it for --version + doctor.
cat > "$FIX_DIR/fake_keyhog_healthy" <<'SH'
#!/bin/sh
write_mock_autoroute_cache() {
  case "${KEYHOG_AUTOROUTE_CACHE:-}" in
    0|off|OFF|Off) return 0 ;;
    /*) cache="${KEYHOG_AUTOROUTE_CACHE}" ;;
    *)
      if [ "$(uname -s 2>/dev/null)" = "Darwin" ]; then
        cache="$HOME/Library/Caches/keyhog/autoroute.json"
      elif [ -n "${XDG_CACHE_HOME:-}" ]; then
        cache="$XDG_CACHE_HOME/keyhog/autoroute.json"
      else
        cache="$HOME/.cache/keyhog/autoroute.json"
      fi
      ;;
  esac
  mkdir -p "$(dirname "$cache")" || exit 1
  cat > "$cache" <<'JSON'
{
  "decisions": [
    [
      { "bytes_bucket": 0, "chunks_bucket": 0, "max_file_bucket": 0, "pattern_bucket": 0, "decode_density_bucket": 0, "source_class_hash": 1 },
      {
        "backend": "simd-regex",
        "sample_bytes": 0,
        "sample_chunks": 0,
        "correctness_digest": 1,
        "calibrated_at_unix_ms": 1,
        "simd_ms": 1,
        "cpu_ms": 3,
        "gpu_ms": null,
        "selected_margin_ns": 2000000,
        "trials": 3
      }
    ],
    [
      { "bytes_bucket": 12, "chunks_bucket": 1, "max_file_bucket": 12, "pattern_bucket": 9, "decode_density_bucket": 1, "source_class_hash": 2 },
      {
        "backend": "gpu-zero-copy",
        "sample_bytes": 8388608,
        "sample_chunks": 1,
        "correctness_digest": 2,
        "calibrated_at_unix_ms": 1,
        "simd_ms": 9,
        "cpu_ms": 12,
        "gpu_ms": 2,
        "selected_margin_ns": 7000000,
        "trials": 3
      }
    ]
  ]
}
JSON
}
case "$1" in
  --version) echo "KeyHog v9.9.9 (mock)" ;;
  doctor)    echo "mock doctor: healthy"; exit 0 ;;
  scan)
    case "${2:-}" in
      --help) echo "Usage: keyhog scan [--no-config]" ;;
      *) [ -n "${KEYHOG_AUTOROUTE_CALIBRATE:-}" ] && write_mock_autoroute_cache ;;
    esac
    exit 0
    ;;
  hook)      exit 0 ;;
  completion) echo "# mock completion for ${2:-sh}" ;;
  uninstall) printf '%s\n' "$*" > "$HOME/keyhog-uninstall-called"; exit 0 ;;
  *) ;;
esac
SH

# Binary that installs successfully, then fails the optional wizard's completion
# and hook commands with concrete stderr. The PTY test must surface those exact
# reasons instead of blaming an old/missing subcommand.
cat > "$FIX_DIR/fake_keyhog_wizard_fail" <<'SH'
#!/bin/sh
write_mock_autoroute_cache() {
  if [ "$(uname -s 2>/dev/null)" = "Darwin" ]; then
    cache="$HOME/Library/Caches/keyhog/autoroute.json"
  else
    cache="${XDG_CACHE_HOME:-$HOME/.cache}/keyhog/autoroute.json"
  fi
  mkdir -p "$(dirname "$cache")" || exit 1
  cat > "$cache" <<'JSON'
{
  "decisions": [
    [
      {},
      {
        "backend": "simd-regex",
        "sample_bytes": 4096,
        "sample_chunks": 1,
        "simd_ms": 1,
        "cpu_ms": 2,
        "gpu_ms": null,
        "selected_margin_ns": 1000000,
        "trials": 3
      }
    ]
  ]
}
JSON
}
case "$1" in
  --version) echo "KeyHog v9.9.9 (mock)" ;;
  doctor)    echo "mock doctor: healthy"; exit 0 ;;
  scan)
    case "${2:-}" in
      --help) echo "Usage: keyhog scan [--no-config]" ;;
      *) [ -n "${KEYHOG_AUTOROUTE_CALIBRATE:-}" ] && write_mock_autoroute_cache ;;
    esac
    exit 0
    ;;
  completion) echo "completion disk denied" >&2; exit 13 ;;
  hook)       echo "hook denied by policy" >&2; exit 12 ;;
  *) ;;
esac
SH

# Binary that advertises Docker source support while the sandbox intentionally
# lacks docker. Install must still calibrate filesystem/stdin and tell the
# operator Docker source autorouting is not calibrated on this host.
cat > "$FIX_DIR/fake_keyhog_docker_help" <<'SH'
#!/bin/sh
write_mock_autoroute_cache() {
  if [ "$(uname -s 2>/dev/null)" = "Darwin" ]; then
    cache="$HOME/Library/Caches/keyhog/autoroute.json"
  else
    cache="${XDG_CACHE_HOME:-$HOME/.cache}/keyhog/autoroute.json"
  fi
  mkdir -p "$(dirname "$cache")" || exit 1
  cat > "$cache" <<'JSON'
{
  "decisions": [
    [
      {},
      {
        "backend": "simd-regex",
        "sample_bytes": 4096,
        "sample_chunks": 1,
        "simd_ms": 1,
        "cpu_ms": 2,
        "gpu_ms": null,
        "selected_margin_ns": 1000000,
        "trials": 3
      }
    ]
  ]
}
JSON
}
case "$1" in
  --version) echo "KeyHog v9.9.9 (mock)" ;;
  doctor)    echo "mock doctor: healthy"; exit 0 ;;
  scan)
    case "$2" in
      --help) echo "Usage: keyhog scan [--docker-image IMAGE]" ;;
      *) [ -n "${KEYHOG_AUTOROUTE_CALIBRATE:-}" ] && write_mock_autoroute_cache ;;
    esac
    exit 0
    ;;
  hook)      exit 0 ;;
  completion) echo "# mock completion for ${2:-sh}" ;;
  *) ;;
esac
SH

# Binary that reaches calibration, starts a scan, and then stays alive until the
# installer signal trap terminates it. Used to prove calibration cleanup behavior
# through the real install path instead of only grepping source shape.
cat > "$FIX_DIR/fake_keyhog_slow_scan" <<'SH'
#!/bin/sh
case "$1" in
  --version) echo "KeyHog v9.9.9 (mock)" ;;
  doctor)    echo "mock doctor: healthy"; exit 0 ;;
  scan)
    case "${2:-}" in
      --help) echo "Usage: keyhog scan [--no-config]"; exit 0 ;;
      *) ;;
    esac
    mkdir -p "${MOCK_STATE_DIR:-/tmp}"
    : > "${MOCK_STATE_DIR:-/tmp}/scan-started"
    printf '%s\n' "$$" > "${MOCK_STATE_DIR:-/tmp}/scan-pid"
    i=0
    while :; do
      i=$((i + 1))
      [ "$i" -gt 1000000 ] && i=0
    done
    ;;
  hook)      exit 0 ;;
  completion) echo "# mock completion for ${2:-sh}" ;;
  *) ;;
esac
SH

# Binary whose --version fails (simulates a corrupt/wrong-arch download).
cat > "$FIX_DIR/fake_keyhog_broken" <<'SH'
#!/bin/sh
echo "illegal instruction" >&2
exit 132
SH

# Binary that runs but whose doctor fails (self-test unhealthy).
cat > "$FIX_DIR/fake_keyhog_doctor_fail" <<'SH'
#!/bin/sh
write_mock_autoroute_cache() {
  if [ "$(uname -s 2>/dev/null)" = "Darwin" ]; then
    cache="$HOME/Library/Caches/keyhog/autoroute.json"
  else
    cache="${XDG_CACHE_HOME:-$HOME/.cache}/keyhog/autoroute.json"
  fi
  mkdir -p "$(dirname "$cache")" || exit 1
  cat > "$cache" <<'JSON'
{
  "decisions": [
    [
      {},
      {
        "backend": "simd-regex",
        "sample_bytes": 4096,
        "sample_chunks": 1,
        "simd_ms": 1,
        "cpu_ms": 2,
        "gpu_ms": null,
        "selected_margin_ns": 1000000,
        "trials": 3
      }
    ]
  ]
}
JSON
}
case "$1" in
  --version) echo "KeyHog v9.9.9 (mock)" ;;
  doctor)    echo "mock doctor: UNHEALTHY" >&2; exit 4 ;;
  scan)
    case "${2:-}" in
      --help) echo "Usage: keyhog scan [--no-config]" ;;
      *) [ -n "${KEYHOG_AUTOROUTE_CALIBRATE:-}" ] && write_mock_autoroute_cache ;;
    esac
    exit 0
    ;;
  *) ;;
esac
SH

sha_of() {
    if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
    else shasum -a 256 "$1" | awk '{print $1}'; fi
}

# ── sandbox builder ───────────────────────────────────────────────────
# build_sandbox writes a bin/ of mocks. Behaviour is steered by env vars
# the mock curl reads at runtime (exported into the run via run_install):
#   MOCK_RELEASES   - path to releases JSON, or "DOWN" to simulate API down
#   MOCK_ASSET      - path to the binary to serve, or "404"
#   MOCK_LATEST_ASSET - path served by /releases/latest/download, or "404"
#   MOCK_FALLBACK   - path to serve for the *fallback* asset, or "404"
#   MOCK_SHA        - "match" | "mismatch" | "absent"
#   MOCK_LDD        - "ok" | path-to-missing-lib-name (e.g. "libhyperscan.so.5")
build_sandbox() {
    os=$1 arch=$2 nv=$3 lib=$4 toolkit=$5
    sb=$(mktemp -d -t kh-sb-XXXXXX)
    mkdir -p "$sb/bin"
    for tool in sh dash bash grep sed head tail awk cut tr cat mv cp rm mkdir rmdir \
                chmod chown ls find dirname basename printf date sleep test true false \
                command type stat readlink realpath sort uniq wc env tee xargs mktemp \
                sha256sum shasum touch; do
        real=$(command -v "$tool" 2>/dev/null) || continue
        ln -sf "$real" "$sb/bin/$tool" 2>/dev/null || true
    done

    cat > "$sb/bin/uname" <<EOF
#!/bin/sh
case "\$1" in -s) echo "$os" ;; -m) echo "$arch" ;; *) echo "$os" ;; esac
EOF
    chmod +x "$sb/bin/uname"

    if [ "$nv" = "yes" ]; then
        cat > "$sb/bin/nvidia-smi" <<'EOF'
#!/bin/sh
case "$1" in
  -L) echo "GPU 0: NVIDIA Mock (UUID: 0000)" ;;
  --query-gpu=name) echo "NVIDIA Mock" ;;
  *) ;;
esac
EOF
        chmod +x "$sb/bin/nvidia-smi"
    elif [ "$nv" = "empty" ]; then
        # nvidia-smi present but lists no GPUs.
        cat > "$sb/bin/nvidia-smi" <<'EOF'
#!/bin/sh
case "$1" in -L) echo "No devices were found" ;; *) ;; esac
EOF
        chmod +x "$sb/bin/nvidia-smi"
    fi

    if [ "$lib" = "yes" ]; then
        cat > "$sb/bin/ldconfig" <<'EOF'
#!/bin/sh
echo "        libcuda.so.1 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libcuda.so.1"
EOF
    else
        cat > "$sb/bin/ldconfig" <<'EOF'
#!/bin/sh
exit 0
EOF
    fi
    chmod +x "$sb/bin/ldconfig"

    if [ "$toolkit" = "yes" ]; then
        cat > "$sb/bin/nvcc" <<'EOF'
#!/bin/sh
echo "Cuda compilation tools, release 12.0"
EOF
        chmod +x "$sb/bin/nvcc"
    fi

    # ldd mock: reports missing libs per MOCK_LDD, else clean.
    cat > "$sb/bin/ldd" <<'EOF'
#!/bin/sh
case "${MOCK_LDD:-ok}" in
  ok) echo "    linux-vdso.so.1 (0x0000)"; exit 0 ;;
  *)  echo "    ${MOCK_LDD} => not found"; exit 0 ;;
esac
EOF
    chmod +x "$sb/bin/ldd"

    # The mock curl: URL-dispatched, scenario-driven.
    cat > "$sb/bin/curl" <<EOF
#!/bin/sh
FIX_DIR="$FIX_DIR"
EOF
    cat >> "$sb/bin/curl" <<'EOF'
url="" ; out="" ; prev=""
for a in "$@"; do
  case "$prev" in -o) out="$a" ;; esac
  case "$a" in http://*|https://*) url="$a" ;; esac
  prev="$a"
done
emit() { if [ -n "$out" ]; then cat > "$out"; else cat; fi; }

# Cross-invocation state (each curl call is a fresh process, so attempt
# ordering and the "what did we serve" record live in files, not env).
sd="${MOCK_STATE_DIR:-/tmp/kh-mock-state}"
mkdir -p "$sd" 2>/dev/null || true

case "$url" in
  *api.github.com*releases*)
    : > "$HOME/github-api-called"
    case " $* " in *"Authorization: Bearer "*) : > "$HOME/github-api-auth" ;; esac
    if [ "${MOCK_RELEASES:-DOWN}" = "DOWN" ]; then exit 22; fi
    emit < "$MOCK_RELEASES"; exit 0 ;;
  *.sha256)
    case "${MOCK_SHA:-absent}" in
      absent)   exit 22 ;;
      mismatch) printf '%s  asset\n' "0000000000000000000000000000000000000000000000000000000000000000" | emit; exit 0 ;;
      match)
        sf=$(cat "$sd/served" 2>/dev/null)
        h=$(sha256sum "$sf" 2>/dev/null | awk '{print $1}')
        [ -z "$h" ] && h=$(shasum -a 256 "$sf" 2>/dev/null | awk '{print $1}')
        printf '%s  asset\n' "$h" | emit; exit 0 ;;
    esac ;;
  *releases/latest/download/*)
    if [ "${MOCK_LATEST_ASSET:-${MOCK_ASSET:-404}}" = "404" ]; then exit 22; fi
    served="${MOCK_LATEST_ASSET:-$MOCK_ASSET}"
    printf '%s' "$served" > "$sd/served"
    cat "$served" > "$out"
    exit 0 ;;
  *releases/download/*)
    # First download attempt = primary asset, second = fallback. Tracked
    # via a marker file so the ordering survives across curl processes.
    if [ ! -e "$sd/primary_attempted" ]; then
      : > "$sd/primary_attempted"
      if [ "${MOCK_ASSET:-404}" = "404" ]; then exit 22; fi
      served="$MOCK_ASSET"
    else
      if [ "${MOCK_FALLBACK:-404}" = "404" ]; then exit 22; fi
      served="$MOCK_FALLBACK"
    fi
    printf '%s' "$served" > "$sd/served"
    cat "$served" > "$out"
    exit 0 ;;
  *) exit 22 ;;
esac
EOF
    chmod +x "$sb/bin/curl"
    echo "$sb"
}

# run_install SANDBOX HOME_DIR -- <install.sh args...>
# extra env passed via the caller's exported MOCK_* vars.
run_install() {
    sb=$1; home=$2; shift 2
    [ "$1" = "--" ] && shift
    state=$(mktemp -d -t kh-state-XXXXXX)
    env -i PATH="$sb/bin" HOME="$home" \
        KEYHOG_INSTALL="${KEYHOG_INSTALL_OVERRIDE:-$home/.local/bin}" \
        MOCK_STATE_DIR="$state" \
        MOCK_RELEASES="${MOCK_RELEASES:-DOWN}" \
        MOCK_ASSET="${MOCK_ASSET:-404}" \
        MOCK_LATEST_ASSET="${MOCK_LATEST_ASSET:-${MOCK_ASSET:-404}}" \
        MOCK_FALLBACK="${MOCK_FALLBACK:-404}" \
        MOCK_SHA="${MOCK_SHA:-absent}" \
        MOCK_LDD="${MOCK_LDD:-ok}" \
        KEYHOG_VARIANT="${KEYHOG_VARIANT:-auto}" \
        ${KEYHOG_VERSION:+KEYHOG_VERSION="$KEYHOG_VERSION"} \
        ${GITHUB_TOKEN:+GITHUB_TOKEN="$GITHUB_TOKEN"} \
        sh "$INSTALL_SH" "$@" 2>&1
    rc=$?
    rm -rf "$state"
    return $rc
}

newhome() { mktemp -d -t kh-home-XXXXXX; }

echo "=============================================================="
echo " install.sh edge-case battery"
echo "=============================================================="

reset_mocks() {
    unset MOCK_RELEASES MOCK_ASSET MOCK_LATEST_ASSET MOCK_FALLBACK MOCK_SHA MOCK_LDD \
          KEYHOG_VARIANT KEYHOG_VERSION KEYHOG_INSTALL_OVERRIDE GITHUB_TOKEN
}

# ======================================================================
# 1. Argument & help parsing
# ======================================================================
printf '\n[1] argument & help parsing\n'
out=$(sh "$INSTALL_SH" --help 2>&1); st=$?
expect_status "1.1 --help exits 0" 0 "$st"
expect_match  "1.2 --help shows curl-pipe"   "curl -fsSL"  "$out"
expect_match  "1.3 --help shows --repair"    "\-\-repair"  "$out"
expect_match  "1.4 --help shows --diagnose"  "\-\-diagnose" "$out"
expect_match  "1.5 --help shows --uninstall" "\-\-uninstall" "$out"
out=$(sh "$INSTALL_SH" -h 2>&1); expect_status "1.6 -h exits 0" 0 $?
out=$(sh "$INSTALL_SH" --bogus-flag 2>&1); st=$?
expect_status "1.7 unknown flag exits 1" 1 "$st"
expect_match  "1.8 unknown flag names it" "Unknown argument: --bogus-flag" "$out"
out=$(sh "$INSTALL_SH" --another 2>&1); expect_match "1.9 unknown flag suggests --help" "\-\-help" "$out"
# --help under the documented curl-pipe transport: $0 is "sh", not a readable
# file. The old `sed "$0"` printed "sed: can't read sh" and NO help. Assert the
# built-in fallback renders and no sed error leaks.
out=$(cat "$INSTALL_SH" | sh -s -- --help 2>&1)
expect_match   "1.10 piped --help shows synopsis"   "KeyHog installer" "$out"
expect_match   "1.11 piped --help shows quick install" "curl -fsSL" "$out"
expect_nomatch "1.12 piped --help has no sed error" "can't read|No such file" "$out"

# ======================================================================
# 2. resolve_tag (the JSON-indentation regression + siblings)
# ======================================================================
printf '\n[2] resolve_tag against GitHub-shaped JSON\n'
reset_mocks
sb=$(build_sandbox Linux x86_64 no no no); h=$(newhome)
out=$(MOCK_RELEASES="$FIX_DIR/releases_normal.json" MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "2.1 default install uses latest asset redirect" "Release tag:   latest" "$out"
expect_status "2.2 normal install exits 0" 0 "$st"
expect_nofile "2.3 default latest success skips GitHub API" "$h/github-api-called"
rm -rf "$h"; h=$(newhome)
out=$(MOCK_LATEST_ASSET=404 MOCK_RELEASES="$FIX_DIR/releases_latest_empty.json" MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt)
expect_match  "2.4 latest miss falls back to API release walk" "checking recent releases" "$out"
expect_match  "2.5 skips asset-less newest, picks v9.9.8" "Release tag: v9.9.8" "$out"
expect_file   "2.6 latest miss calls GitHub API" "$h/github-api-called"
rm -rf "$h"; h=$(newhome)
out=$(GITHUB_TOKEN=ghp_mock_token MOCK_LATEST_ASSET=404 MOCK_RELEASES="$FIX_DIR/releases_latest_empty.json" MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_status "2.7 authenticated API fallback install exits 0" 0 "$st"
expect_file   "2.8 API fallback sends Authorization when GITHUB_TOKEN is set" "$h/github-api-auth"
rm -rf "$h"; h=$(newhome)
out=$(MOCK_LATEST_ASSET=404 MOCK_RELEASES="$FIX_DIR/releases_all_empty.json" run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "2.9 all-empty releases errors" "No GitHub release" "$out"
expect_status "2.10 all-empty exits 1" 1 "$st"
rm -rf "$h"; h=$(newhome)
out=$(MOCK_LATEST_ASSET=404 run_install "$sb" "$h" -- --no-prompt); st=$?    # MOCK_RELEASES unset => DOWN
expect_match  "2.11 API down errors clearly after latest miss" "Could not query GitHub releases API" "$out"
expect_status "2.12 API down exits 1" 1 "$st"
rm -rf "$h"; h=$(newhome)
out=$(KEYHOG_VERSION=v1.2.3 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt)
expect_match  "2.13 --version pin skips API" "Release tag:   v1.2.3" "$out"
rm -rf "$h"; h=$(newhome)
# A bare semver (no leading v) must normalise to the v-prefixed tag. keyhog
# tags are all vX.Y.Z, so `--version=9.9.9` building a download URL from the
# un-prefixed tag 404s — exactly the bug that failed the Windows install smoke
# (the smoke passed "0.5.37", not "v0.5.37"). Assert the resolved tag is v-fixed
# AND the install completes, so the 404 can never come back silently.
out=$(KEYHOG_VERSION=9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "2.14 bare semver normalises to v-prefixed tag" "Release tag:   v9.9.9" "$out"
expect_status "2.15 bare-semver install exits 0" 0 "$st"
rm -rf "$sb" "$h"

# ======================================================================
# 3. Platform / asset resolution
# ======================================================================
printf '\n[3] platform & asset resolution (via --diagnose)\n'
reset_mocks
diag() { sb=$1; h=$2; KEYHOG_VERSION=v9.9.9 run_install "$sb" "$h" -- --diagnose --no-color; }
for spec in "Linux:x86_64:no:no:no:keyhog-linux-x86_64" \
            "Linux:amd64:no:no:no:keyhog-linux-x86_64" \
            "Darwin:arm64:no:no:no:keyhog-macos-aarch64" \
            "Darwin:aarch64:no:no:no:keyhog-macos-aarch64" \
            "Darwin:x86_64:no:no:no:keyhog-macos-x86_64" \
            "Darwin:amd64:no:no:no:keyhog-macos-x86_64"; do
    os=${spec%%:*}; rest=${spec#*:}; arch=${rest%%:*}; rest=${rest#*:}
    nv=${rest%%:*}; rest=${rest#*:}; lib=${rest%%:*}; rest=${rest#*:}
    tk=${rest%%:*}; want=${rest##*:}
    sb=$(build_sandbox "$os" "$arch" "$nv" "$lib" "$tk"); h=$(newhome)
    out=$(diag "$sb" "$h")
    expect_match "3.$os-$arch -> $want" "Would install: $want" "$out"
    rm -rf "$sb" "$h"
done
sb=$(build_sandbox FreeBSD x86_64 no no no); h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 run_install "$sb" "$h" -- --diagnose --no-color); st=$?
expect_match  "3.unsupported-os reports it" "Unsupported platform" "$out"
expect_status "3.unsupported-os exits 1" 1 "$st"
rm -rf "$sb" "$h"
sb=$(build_sandbox Linux armv7l no no no); h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 run_install "$sb" "$h" -- --diagnose --no-color); st=$?
expect_match  "3.unsupported-arch reports it" "Unsupported platform" "$out"
rm -rf "$sb" "$h"

# ======================================================================
# 4. CUDA detection gates (detect_linux_cuda via --diagnose)
# ======================================================================
printf '\n[4] CUDA detection gates\n'
reset_mocks
if [ "$HOST_HAS_CUDA" = "yes" ]; then
    for t in "4.1 no nvidia -> no-gpu" "4.2 no-gpu -> default asset" \
             "4.3 nvidia-smi empty -> no-gpu" "4.4 nvidia+libcuda+nvcc -> yes" \
             "4.5 cuda yes -> cuda asset" "4.6 nvidia+libcuda, no toolkit -> driver-only" \
             "4.7 driver-only -> default asset" "4.8 nvidia, no libcuda -> driver-only"; do
        skip "$t" "host has a real CUDA stack; validated in the Docker matrix"
    done
else
    # no nvidia-smi, no driver dir -> no-gpu
    sb=$(build_sandbox Linux x86_64 no no no); h=$(newhome)
    out=$(KEYHOG_VERSION=v9.9.9 run_install "$sb" "$h" -- --diagnose --no-color)
    expect_match "4.1 no nvidia -> no-gpu" "CUDA detection: no-gpu" "$out"
    expect_match "4.2 no-gpu -> default asset" "Would install: keyhog-linux-x86_64$" "$out"
    rm -rf "$sb" "$h"
    # nvidia-smi present but lists no GPU -> no-gpu
    sb=$(build_sandbox Linux x86_64 empty no no); h=$(newhome)
    out=$(KEYHOG_VERSION=v9.9.9 run_install "$sb" "$h" -- --diagnose --no-color)
    expect_match "4.3 nvidia-smi empty -> no-gpu" "CUDA detection: no-gpu" "$out"
    rm -rf "$sb" "$h"
    # nvidia + libcuda + toolkit -> yes
    sb=$(build_sandbox Linux x86_64 yes yes yes); h=$(newhome)
    out=$(KEYHOG_VERSION=v9.9.9 run_install "$sb" "$h" -- --diagnose --no-color)
    expect_match "4.4 nvidia+libcuda+nvcc -> yes" "CUDA detection: yes" "$out"
    expect_match "4.5 cuda yes -> cuda asset" "Would install: keyhog-linux-x86_64-cuda" "$out"
    rm -rf "$sb" "$h"
    # nvidia + libcuda + NO toolkit -> driver-only
    sb=$(build_sandbox Linux x86_64 yes yes no); h=$(newhome)
    out=$(KEYHOG_VERSION=v9.9.9 run_install "$sb" "$h" -- --diagnose --no-color)
    expect_match "4.6 nvidia+libcuda, no toolkit -> driver-only" "CUDA detection: driver-only" "$out"
    expect_match "4.7 driver-only -> default asset" "Would install: keyhog-linux-x86_64$" "$out"
    rm -rf "$sb" "$h"
    # nvidia + NO libcuda -> driver-only
    sb=$(build_sandbox Linux x86_64 yes no no); h=$(newhome)
    out=$(KEYHOG_VERSION=v9.9.9 run_install "$sb" "$h" -- --diagnose --no-color)
    expect_match "4.8 nvidia, no libcuda -> driver-only" "CUDA detection: driver-only" "$out"
    rm -rf "$sb" "$h"
fi

# ======================================================================
# 5. Variant overrides
# ======================================================================
printf '\n[5] variant overrides\n'
reset_mocks
sb=$(build_sandbox Linux x86_64 yes yes yes); h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 KEYHOG_VARIANT=cpu run_install "$sb" "$h" -- --diagnose --no-color)
expect_match "5.1 variant=cpu beats cuda host" "Would install: keyhog-linux-x86_64$" "$out"
rm -rf "$h"; h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 KEYHOG_VARIANT=cuda run_install "$sb" "$h" -- --diagnose --no-color)
expect_match "5.2 variant=cuda forces cuda asset" "Would install: keyhog-linux-x86_64-cuda" "$out"
rm -rf "$sb" "$h"
sb=$(build_sandbox Linux x86_64 no no no); h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 KEYHOG_VARIANT=cuda run_install "$sb" "$h" -- --diagnose --no-color)
expect_match "5.3 variant=cuda on no-gpu still cuda asset" "Would install: keyhog-linux-x86_64-cuda" "$out"
rm -rf "$sb" "$h"

# ======================================================================
# 6. Download + checksum + staging (full offline install)
# ======================================================================
printf '\n[6] download, checksum, staging\n'
reset_mocks
sb=$(build_sandbox Linux x86_64 no no no)
# 6.1 happy path: install + verify + binary on disk + executable
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_status "6.1 healthy install exits 0" 0 "$st"
expect_match  "6.2 reports installed version" "KeyHog v9.9.9" "$out"
expect_match  "6.3 SHA256 verified line"      "SHA256 verified" "$out"
expect_exec   "6.4 binary is executable"      "$h/.local/bin/keyhog"
expect_match  "6.4a calibration summary table printed" "Autoroute calibration decisions" "$out"
expect_match  "6.4b calibration summary reports persisted decision count" "decisions persisted: 2" "$out"
expect_match  "6.4c calibration summary shows backend margin" "gpu-zero-copy.*7\\.0ms" "$out"
rm -rf "$h"
# 6.5 checksum mismatch refuses + no install
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=mismatch run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "6.5 mismatch refuses"   "SHA256 mismatch" "$out"
expect_status "6.6 mismatch exits 1"   1 "$st"
expect_nofile "6.7 no binary written on mismatch" "$h/.local/bin/keyhog"
rm -rf "$h"
# 6.8 no .sha256 published: fail closed unless explicit insecure override.
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=absent run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "6.8 absent .sha256 refuses unverified install" "No \\.sha256 checksum|Refusing to install an unverified" "$out"
expect_status "6.9 absent .sha256 exits 1" 1 "$st"
expect_nofile "6.10 no binary written without checksum" "$h/.local/bin/keyhog"
rm -rf "$h"
# 6.11 absent .sha256 with --insecure is loud and installs.
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=absent run_install "$sb" "$h" -- --no-prompt --insecure); st=$?
expect_match  "6.11 absent .sha256 insecure override is loud" "INSECURE" "$out"
expect_status "6.12 absent .sha256 insecure override installs" 0 "$st"
expect_exec   "6.13 binary present after insecure override" "$h/.local/bin/keyhog"
rm -rf "$h"
# 6.14 install dir created when missing
h=$(newhome); rm -rf "$h/.local"
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt)
expect_file "6.14 mkdir -p created install dir" "$h/.local/bin/keyhog"
rm -rf "$h"
# 6.15 optional source-class calibration tool missing: warn, do not brick install.
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_docker_help" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "6.15 missing docker source tool warns" "Docker image calibration unavailable" "$out"
expect_status "6.16 missing docker source tool does not fail filesystem install" 0 "$st"
expect_exec   "6.17 binary present when optional source tool missing" "$h/.local/bin/keyhog"
rm -rf "$h"
rm -rf "$sb"

# ======================================================================
# 7. Explicit CUDA fails closed; auto CUDA may use portable asset
# ======================================================================
printf '\n[7] cuda asset fallback policy\n'
reset_mocks
sb=$(build_sandbox Linux x86_64 yes yes yes); h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 KEYHOG_VARIANT=cuda MOCK_ASSET=404 MOCK_FALLBACK="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "7.1 explicit cuda missing asset refuses" "Download failed|release published" "$out"
expect_status "7.2 explicit cuda missing asset exits 1" 1 "$st"
expect_nofile "7.3 explicit cuda missing asset writes no binary" "$h/.local/bin/keyhog"
rm -rf "$h"; h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET=404 MOCK_FALLBACK="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "7.4 auto cuda falls back to portable asset" "Falling back to keyhog-linux-x86_64" "$out"
expect_status "7.5 auto cuda fallback install exits 0" 0 "$st"
expect_exec   "7.6 binary installed via auto fallback" "$h/.local/bin/keyhog"
rm -rf "$h"; h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET=404 MOCK_FALLBACK=404 run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "7.7 auto cuda both assets missing errors" "Neither .* could be downloaded|could not be downloaded" "$out"
expect_status "7.8 auto cuda both assets missing exits 1" 1 "$st"
rm -rf "$sb" "$h"

# ======================================================================
# 8. verify_install failure modes
# ======================================================================
printf '\n[8] verify_install failure modes\n'
reset_mocks
sb=$(build_sandbox Linux x86_64 no no no)
# 8.1 broken binary (nonzero --version) -> error, exit 1
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_broken" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "8.1 broken binary reported" "could not run|could not run\." "$out"
expect_status "8.2 broken binary exits 1" 1 "$st"
rm -rf "$h"
# 8.3 missing libhyperscan -> hint
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_broken" MOCK_SHA=match MOCK_LDD=libhyperscan.so.5 run_install "$sb" "$h" -- --no-prompt)
expect_match  "8.3 hyperscan hint shown" "libhyperscan5|Hyperscan runtime" "$out"
rm -rf "$h"
# 8.4 missing libssl -> hint
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_broken" MOCK_SHA=match MOCK_LDD=libssl.so.3 run_install "$sb" "$h" -- --no-prompt)
expect_match  "8.4 openssl hint shown" "libssl3|OpenSSL runtime" "$out"
rm -rf "$h"
# 8.5 doctor fails -> install still succeeds but warns
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_doctor_fail" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "8.5 doctor-fail warns" "may not be fully healthy" "$out"
expect_status "8.6 doctor-fail install exit 0" 0 "$st"
rm -rf "$sb" "$h"

# ======================================================================
# 9. repair / diagnose / uninstall modes
# ======================================================================
printf '\n[9] repair / diagnose / uninstall\n'
reset_mocks
sb=$(build_sandbox Linux x86_64 no no no)
# 9.1 repair with no existing binary -> fresh install
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --repair --no-prompt); st=$?
expect_match  "9.1 repair w/o binary installs fresh" "No existing keyhog|Installing fresh" "$out"
expect_exec   "9.2 repair produced a binary" "$h/.local/bin/keyhog"
# 9.3 repair with healthy existing binary -> re-downloads
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --repair --no-prompt)
expect_match  "9.3 repair re-downloads over healthy" "Re-downloading|Repair complete" "$out"
rm -rf "$h"
# 9.4 diagnose with no binary -> shell diagnostic, no writes
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 run_install "$sb" "$h" -- --diagnose --no-color); st=$?
expect_match  "9.4 diagnose shows host" "OS:" "$out"
expect_match  "9.5 diagnose reports no install" "no keyhog found|does not run|no keyhog" "$out"
expect_nofile "9.6 diagnose writes nothing" "$h/.local/bin/keyhog"
expect_status "9.7 diagnose exits 0" 0 "$st"
# 9.8 diagnose PATH-not-on warning
expect_match  "9.8 diagnose flags PATH" "NOT on PATH|is on PATH" "$out"
rm -rf "$h"
# 9.9 uninstall with nothing installed -> safe no-op
h=$(newhome)
out=$(run_install "$sb" "$h" -- --uninstall --no-color); st=$?
expect_match  "9.9 uninstall no-op message" "Nothing to remove" "$out"
expect_status "9.10 uninstall no-op exits 0" 0 "$st"
# 9.11 uninstall removes an installed binary (--yes to auto-confirm)
KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt >/dev/null 2>&1
expect_file   "9.11 pre-uninstall binary exists" "$h/.local/bin/keyhog"
mkdir -p "$h/.local/share/bash-completion/completions" "$h/.zfunc" \
    "$h/.config/fish/completions" "$h/.config/fish"
printf 'keep-bash-before\n# keyhog\nexport PATH="%s:$PATH"\nkeep-bash-after\n' "$h/.local/bin" > "$h/.bashrc"
{
    printf '%s\n' 'keep-zsh-before'
    printf '%s\n' '# keyhog'
    printf 'export PATH="%s:$PATH"\n' "$h/.local/bin"
    printf '%s\n' '# keyhog completions'
    printf '%s\n' 'if [ -d "$HOME/.zfunc" ]; then'
    printf '%s\n' '  fpath=("$HOME/.zfunc" $fpath)'
    printf '%s\n' '  autoload -Uz compinit'
    printf '%s\n' '  compinit'
    printf '%s\n' 'fi'
    printf '%s\n' 'keep-zsh-after'
} > "$h/.zshrc"
printf '# keyhog\nset -gx PATH %s $PATH\n' "$h/.local/bin" > "$h/.config/fish/config.fish"
touch "$h/.local/share/bash-completion/completions/keyhog" \
    "$h/.zfunc/_keyhog" \
    "$h/.config/fish/completions/keyhog.fish"
out=$(run_install "$sb" "$h" -- --uninstall --yes --no-color); st=$?
expect_match  "9.12 uninstall removes binary" "Removed" "$out"
expect_nofile "9.13 binary gone after uninstall" "$h/.local/bin/keyhog"
expect_file   "9.14 shell uninstall delegates to binary uninstall first" "$h/keyhog-uninstall-called"
expect_nofile "9.15 shell uninstall removes bash completion" "$h/.local/share/bash-completion/completions/keyhog"
expect_nofile "9.16 shell uninstall removes zsh completion" "$h/.zfunc/_keyhog"
expect_nofile "9.17 shell uninstall removes fish completion" "$h/.config/fish/completions/keyhog.fish"
if grep -F "$h/.local/bin" "$h/.bashrc" "$h/.zshrc" "$h/.config/fish/config.fish" >/dev/null 2>&1 \
   || grep -F '# keyhog completions' "$h/.zshrc" >/dev/null 2>&1; then
    _record_fail "9.18 shell uninstall removes installer-owned rc blocks" \
        "$(printf '%s\n---\n%s\n---\n%s\n' "$(cat "$h/.bashrc")" "$(cat "$h/.zshrc")" "$(cat "$h/.config/fish/config.fish")")"
else
    _record_pass "9.18 shell uninstall removes installer-owned rc blocks"
fi
rm -rf "$sb" "$h"

# ======================================================================
# 10. color / interactivity / install-dir override
# ======================================================================
printf '\n[10] color, non-interactive, install-dir\n'
reset_mocks
sb=$(build_sandbox Linux x86_64 no no no)
# 10.1 --no-color: no ANSI escapes in output
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt --no-color)
if printf '%s' "$out" | grep -q "$(printf '\033')"; then _record_fail "10.1 --no-color strips ANSI" "found escape sequences"; else _record_pass "10.1 --no-color strips ANSI"; fi
# 10.2 non-interactive (piped, no tty) defaults through without prompting
expect_match "10.2 non-interactive completes" "Next steps:" "$out"
rm -rf "$h"
# 10.3 custom install dir honored
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt --install-dir="$h/custom/dir")
expect_file "10.3 binary at custom --install-dir" "$h/custom/dir/keyhog"
rm -rf "$h"
# 10.4 KEYHOG_INSTALL env honored
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 KEYHOG_INSTALL_OVERRIDE="$h/envdir" MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt)
expect_file "10.4 binary at KEYHOG_INSTALL dir" "$h/envdir/keyhog"
rm -rf "$h"
# 10.5 spaces in install dir
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt --install-dir="$h/dir with spaces")
expect_file "10.5 binary installs to path with spaces" "$h/dir with spaces/keyhog"
rm -rf "$sb" "$h"

# ======================================================================
# 11. idempotency / re-install
# ======================================================================
printf '\n[11] idempotent re-install\n'
reset_mocks
sb=$(build_sandbox Linux x86_64 no no no); h=$(newhome)
KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt >/dev/null 2>&1
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_status "11.1 second install exits 0" 0 "$st"
expect_match  "11.2 second install shows existing" "Existing:" "$out"
expect_exec   "11.3 binary still good" "$h/.local/bin/keyhog"
rm -rf "$sb" "$h"

# ======================================================================
# 12. checksum tooling fallbacks
# ======================================================================
printf '\n[12] checksum tooling fallbacks\n'
reset_mocks
# 12.1 sha256sum absent, shasum present -> still verifies (macOS shape).
# Needs a real `shasum` on the host to symlink into the sandbox; skip where
# absent (e.g. debian-slim has no perl). The mock curl computes the expected
# digest the same way install.sh does, so the fallback path is genuinely
# exercised when shasum exists.
if command -v shasum >/dev/null 2>&1; then
    sb=$(build_sandbox Linux x86_64 no no no); rm -f "$sb/bin/sha256sum"; h=$(newhome)
    out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
    expect_match  "12.1 shasum fallback verifies" "SHA256 verified" "$out"
    expect_status "12.2 shasum fallback installs" 0 "$st"
    rm -rf "$sb" "$h"
else
    skip "12.1 shasum fallback verifies" "no shasum on host to mock"
    skip "12.2 shasum fallback installs" "no shasum on host to mock"
fi
# 12.3 no sha tool at all -> fail closed unless explicit insecure override.
sb=$(build_sandbox Linux x86_64 no no no); rm -f "$sb/bin/sha256sum" "$sb/bin/shasum"; h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "12.3 no sha tool refuses" "No sha256sum or shasum|Refusing to install an unverified" "$out"
expect_status "12.4 no sha tool exits 1" 1 "$st"
expect_nofile "12.5 no binary written without checksum tool" "$h/.local/bin/keyhog"
rm -rf "$sb" "$h"
sb=$(build_sandbox Linux x86_64 no no no); rm -f "$sb/bin/sha256sum" "$sb/bin/shasum"; h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt --insecure); st=$?
expect_match  "12.6 no sha tool insecure override is loud" "INSECURE" "$out"
expect_status "12.7 no sha tool insecure override installs" 0 "$st"
expect_exec   "12.8 binary present after insecure override" "$h/.local/bin/keyhog"
rm -rf "$sb" "$h"

# ======================================================================
# 13. empty / truncated download guard
# ======================================================================
printf '\n[13] empty download guard\n'
reset_mocks
sb=$(build_sandbox Linux x86_64 no no no); h=$(newhome)
: > "$FIX_DIR/empty_asset"
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/empty_asset" MOCK_SHA=absent run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "13.1 empty download refused" "is empty \(0 bytes\)" "$out"
expect_status "13.2 empty download exits 1" 1 "$st"
expect_nofile "13.3 no binary written for empty download" "$h/.local/bin/keyhog"
rm -rf "$sb" "$h"

# ======================================================================
# 14. version pin formats
# ======================================================================
printf '\n[14] version pin formats\n'
reset_mocks
sb=$(build_sandbox Linux x86_64 no no no); h=$(newhome)
out=$(KEYHOG_VERSION=v1.2.3 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt)
expect_match "14.1 v-prefixed tag used verbatim" "Release tag:   v1.2.3" "$out"
rm -rf "$h"; h=$(newhome)
# A bare numeric --version normalises to the v-prefixed release tag. keyhog
# tags are all vX.Y.Z, so honoring "2.0.0" verbatim built a 404 download URL —
# the regression that failed the Windows install smoke. The resolved tag must
# carry the v.
out=$(MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --version=2.0.0 --no-prompt)
expect_match "14.2 bare numeric tag normalises to v-prefixed" "Release tag:   v2.0.0" "$out"
rm -rf "$h"; h=$(newhome)
out=$(MOCK_RELEASES="$FIX_DIR/releases_normal.json" MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --version= --no-prompt)
expect_match "14.3 empty --version uses default latest redirect" "Release tag:   latest" "$out"
expect_nofile "14.4 empty --version does not call GitHub API when latest succeeds" "$h/github-api-called"
rm -rf "$sb" "$h"

# ======================================================================
# 15. unsupported arch on supported OS
# ======================================================================
printf '\n[15] unsupported arch\n'
reset_mocks
for arch in aarch64 arm64 armv7l i686 ppc64le; do
    sb=$(build_sandbox Linux "$arch" no no no); h=$(newhome)
    out=$(KEYHOG_VERSION=v9.9.9 run_install "$sb" "$h" -- --diagnose --no-color); st=$?
    expect_match  "15.$arch reports unsupported" "Unsupported platform" "$out"
    expect_status "15.$arch exits 1" 1 "$st"
    rm -rf "$sb" "$h"
done

# ======================================================================
# 16. arg vs env precedence + short flags
# ======================================================================
printf '\n[16] arg/env precedence + short flags\n'
reset_mocks
sb=$(build_sandbox Linux x86_64 no no no); h=$(newhome)
# --install-dir flag beats KEYHOG_INSTALL env
out=$(KEYHOG_VERSION=v9.9.9 KEYHOG_INSTALL_OVERRIDE="$h/envdir" MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt --install-dir="$h/flagdir")
expect_file   "16.1 --install-dir beats env" "$h/flagdir/keyhog"
expect_nofile "16.2 env dir unused when flag set" "$h/envdir/keyhog"
rm -rf "$h"; h=$(newhome)
# -y short flag accepted (no unknown-arg error)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- -y); st=$?
expect_status "16.3 -y short flag accepted" 0 "$st"
expect_nomatch "16.4 -y not treated as unknown" "Unknown argument" "$out"
rm -rf "$sb" "$h"

# ======================================================================
# 17. repair replaces a broken existing binary
# ======================================================================
printf '\n[17] repair replaces broken binary\n'
reset_mocks
sb=$(build_sandbox Linux x86_64 no no no); h=$(newhome)
mkdir -p "$h/.local/bin"; printf '#!/bin/sh\nexit 1\n' > "$h/.local/bin/keyhog"; chmod +x "$h/.local/bin/keyhog"
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --repair --no-prompt); st=$?
expect_match  "17.1 repair detects broken binary" "does not run|Replacing" "$out"
expect_match  "17.2 repair completes" "Repair complete" "$out"
expect_status "17.3 repair exits 0" 0 "$st"
rm -rf "$sb" "$h"

# ======================================================================
# 18. diagnose with a runnable installed binary uses keyhog doctor
# ======================================================================
printf '\n[18] diagnose defers to keyhog doctor when a binary runs\n'
reset_mocks
sb=$(build_sandbox Linux x86_64 no no no); h=$(newhome)
mkdir -p "$h/.local/bin"; cp "$FIX_DIR/fake_keyhog_healthy" "$h/.local/bin/keyhog"; chmod +x "$h/.local/bin/keyhog"
out=$(KEYHOG_VERSION=v9.9.9 run_install "$sb" "$h" -- --diagnose --no-color); st=$?
expect_match  "18.1 diagnose runs keyhog doctor" "mock doctor: healthy" "$out"
expect_match  "18.2 diagnose appends latest release" "Would install:" "$out"
expect_status "18.3 diagnose exits 0" 0 "$st"
rm -rf "$sb" "$h"

# ======================================================================
# 19. script hygiene: installers invoke REAL subcommand names
# ======================================================================
printf '\n[19] script hygiene (subcommand names match the binary)\n'
# The binary subcommand is `completion` (singular). The wizard historically
# called `keyhog completions <shell>` (plural) -> unknown subcommand -> the
# install always fell into the bogus "completions subcommand not in this
# build" warning and the completion file was deleted. Guard the regression in
# both installers: assert the real `completion` invocation is present and the
# plural subcommand invocation is gone.
if grep -q 'keyhog" completion "' install.sh; then
    _record_pass "19.1 install.sh invokes 'keyhog completion' (singular)"
else
    _record_fail "19.1 install.sh invokes 'keyhog completion' (singular)" "not found"
fi
if grep -q 'keyhog" completions ' install.sh; then
    _record_fail "19.2 install.sh has no 'keyhog completions' (plural)" "$(grep -n 'keyhog\" completions ' install.sh)"
else
    _record_pass "19.2 install.sh has no 'keyhog completions' (plural) subcommand call"
fi
if [ -f install.ps1 ]; then
    if grep -q "keyhog.exe') completion " install.ps1; then
        _record_pass "19.3 install.ps1 invokes 'keyhog.exe completion' (singular)"
    else
        _record_fail "19.3 install.ps1 invokes 'keyhog.exe completion' (singular)" "not found"
    fi
    if grep -q "keyhog.exe') completions " install.ps1; then
        _record_fail "19.4 install.ps1 has no 'completions' plural call" "found plural call"
    else
        _record_pass "19.4 install.ps1 has no 'keyhog.exe completions' (plural) call"
    fi
fi

# 19.5+ recoverability primitives must stay present in BOTH installers. The
# Windows installer can't be executed on this Linux host, so these structural
# guards are the regression net for its rollback path (the full behavioural
# matrix for the shell installer lives in section 20). Each greps for a
# load-bearing line of the fix; removing the rollback would flip the test red.
if grep -q 'finalize_install' install.sh && grep -q 'INSTALL_BACKUP' install.sh; then
    _record_pass "19.5 install.sh has backup+rollback (finalize_install/INSTALL_BACKUP)"
else
    _record_fail "19.5 install.sh has backup+rollback" "finalize_install/INSTALL_BACKUP missing"
fi
if grep -q 'Rolled back to your previous working keyhog' install.sh; then
    _record_pass "19.6 install.sh announces rollback to the user"
else
    _record_fail "19.6 install.sh announces rollback" "rollback message missing"
fi
if [ -f install.ps1 ]; then
    if grep -q 'InstallBackup' install.ps1 && grep -q 'Finalize-Install' install.ps1; then
        _record_pass "19.7 install.ps1 has backup+rollback (Finalize-Install/InstallBackup)"
    else
        _record_fail "19.7 install.ps1 has backup+rollback" "Finalize-Install/InstallBackup missing"
    fi
    # The old Verify-Install ignored $LASTEXITCODE, so a binary that launched
    # but exited nonzero was reported as installed. The fix must check it.
    if grep -q 'LASTEXITCODE -ne 0' install.ps1; then
        _record_pass "19.8 install.ps1 checks \$LASTEXITCODE when verifying the binary"
    else
        _record_fail "19.8 install.ps1 checks \$LASTEXITCODE" "missing exit-code verification"
    fi
    if grep -q 'Rolled back to your previous working keyhog' install.ps1; then
        _record_pass "19.9 install.ps1 announces rollback to the user"
    else
        _record_fail "19.9 install.ps1 announces rollback" "rollback message missing"
    fi
fi
if grep -q 'mktemp -d -t keyhog-autoroute-prime-XXXXXX' install.sh \
   && ! grep -q 'keyhog-autoroute-prime\.\$\$' install.sh \
   && ! grep -q 'keyhog-autoroute-calibration:\$\$' install.sh; then
    _record_pass "19.10 install.sh calibration uses unpredictable workspace and docker tag"
else
    _record_fail "19.10 install.sh calibration uses unpredictable workspace and docker tag" \
        'expected mktemp -d workspace and no $$-derived calibration names'
fi
if grep -q 'cleanup_autoroute_calibration()' install.sh \
   && grep -q "trap 'cleanup_autoroute_calibration" install.sh \
   && grep -q 'INT TERM' install.sh \
   && grep -q 'exit 130' install.sh; then
    _record_pass "19.11 install.sh calibration has cleanup traps for exit and signal"
else
    _record_fail "19.11 install.sh calibration has cleanup traps for exit and signal" \
        "cleanup_autoroute_calibration EXIT/INT/TERM trap missing"
fi
if grep -q 'stop_calibration_web_server "$cleanup_web_pid_file"' install.sh; then
    _record_pass "19.12 install.sh calibration cleanup stops the loopback web server"
else
    _record_fail "19.12 install.sh calibration cleanup stops web server" \
        "stop_calibration_web_server not owned by cleanup helper"
fi
if grep -q 'image rm -f "$cleanup_docker_image"' install.sh; then
    _record_pass "19.13 install.sh calibration cleanup removes the docker probe image"
else
    _record_fail "19.13 install.sh calibration cleanup removes docker image" \
        "docker image cleanup not owned by cleanup helper"
fi
if ! grep -q 'total=9' install.sh \
   && grep -q 'for _kib in $kib_sizes' install.sh \
   && grep -q 'for _mib in $mib_sizes' install.sh; then
    _record_pass "19.14 install.sh calibration derives progress totals from workloads"
else
    _record_fail "19.14 install.sh calibration derives progress totals" \
        "hardcoded total=9 or missing workload-derived total loop"
fi
if grep -q 'show_autoroute_calibration_summary "$total"' install.sh \
   && grep -q 'selected backend margin' install.sh \
   && grep -q 'selected_margin_ns' install.sh; then
    _record_pass "19.14a install.sh renders persisted autoroute decisions after calibration"
else
    _record_fail "19.14a install.sh renders persisted autoroute decisions" \
        "summary table must read selected backend and selected_margin_ns from the cache"
fi
if grep -q 'while kill -0 "$pid"' install.sh \
   && grep -q 'calibration_probe_pid="$pid"' install.sh \
   && grep -q 'sleep 0.15' install.sh; then
    _record_pass "19.14b install.sh calibration probes have live spinner progress"
else
    _record_fail "19.14b install.sh calibration probes have live spinner progress" \
        "probe loop must keep an active pid and update progress while it runs"
fi
reset_mocks
sb=$(build_sandbox Linux x86_64 no no no); h=$(newhome)
signal_state=$(mktemp -d -t kh-signal-state-XXXXXX)
signal_tmp=$(mktemp -d -t kh-signal-tmp-XXXXXX)
signal_out="$h/signal.out"
env -i PATH="$sb/bin" HOME="$h" \
    KEYHOG_INSTALL="$h/.local/bin" \
    TMPDIR="$signal_tmp" \
    MOCK_STATE_DIR="$signal_state" \
    MOCK_RELEASES="$FIX_DIR/releases_normal.json" \
    MOCK_ASSET="$FIX_DIR/fake_keyhog_slow_scan" \
    MOCK_FALLBACK=404 \
    MOCK_SHA=match \
    MOCK_LDD=ok \
    KEYHOG_VARIANT=auto \
    KEYHOG_VERSION=v9.9.9 \
    sh "$INSTALL_SH" --no-prompt --no-color >"$signal_out" 2>&1 &
signal_pid=$!
i=0
while [ "$i" -lt 200 ]; do
    [ -e "$signal_state/scan-started" ] && break
    if ! kill -0 "$signal_pid" 2>/dev/null; then
        break
    fi
    sleep 0.05
    i=$((i + 1))
done
if [ -e "$signal_state/scan-started" ]; then
    _record_pass "19.15 install.sh calibration signal test reaches a real scan"
    kill -TERM "$signal_pid" >/dev/null 2>&1 || true
    wait "$signal_pid"
    signal_status=$?
    expect_status "19.16 install.sh calibration TERM exits 130" 130 "$signal_status"
    if find "$signal_tmp" -maxdepth 1 -name 'keyhog-autoroute-prime-*' -print | grep -q .; then
        _record_fail "19.17 install.sh calibration TERM removes workspace" \
            "$(find "$signal_tmp" -maxdepth 1 -name 'keyhog-autoroute-prime-*' -print)"
    else
        _record_pass "19.17 install.sh calibration TERM removes workspace"
    fi
    scan_pid="$(cat "$signal_state/scan-pid" 2>/dev/null || true)"
    if [ -n "$scan_pid" ] && kill -0 "$scan_pid" 2>/dev/null; then
        _record_fail "19.18 install.sh calibration TERM terminates active probe" \
            "probe pid still alive: $scan_pid"
        kill "$scan_pid" >/dev/null 2>&1 || true
    else
        _record_pass "19.18 install.sh calibration TERM terminates active probe"
    fi
else
    kill -TERM "$signal_pid" >/dev/null 2>&1 || true
    wait "$signal_pid" 2>/dev/null || true
    _record_fail "19.15 install.sh calibration signal test reaches a real scan" \
        "$(head -20 "$signal_out" 2>/dev/null)"
    _record_fail "19.16 install.sh calibration TERM exits 130" "signal path was not reached"
    _record_fail "19.17 install.sh calibration TERM removes workspace" "signal path was not reached"
    _record_fail "19.18 install.sh calibration TERM terminates active probe" "signal path was not reached"
fi
rm -rf "$signal_state" "$signal_tmp" "$sb" "$h"
if command -v script >/dev/null 2>&1 && script -qefc true /dev/null >/dev/null 2>&1; then
    reset_mocks
    sb=$(build_sandbox Linux x86_64 no no no); h=$(newhome)
    repo="$h/repo"
    mkdir -p "$repo/.git"
    wizard_cmd="cd $repo && env -i PATH=$h/.local/bin:$sb/bin HOME=$h SHELL=/bin/bash KEYHOG_INSTALL=$h/.local/bin MOCK_STATE_DIR=$h/state MOCK_RELEASES=$FIX_DIR/releases_normal.json MOCK_ASSET=$FIX_DIR/fake_keyhog_wizard_fail MOCK_FALLBACK=404 MOCK_SHA=match MOCK_LDD=ok KEYHOG_VARIANT=auto KEYHOG_VERSION=v9.9.9 sh $INSTALL_SH --no-color"
    out=$(printf 'y\ny\ny\n' | script -qefc "$wizard_cmd" /dev/null 2>&1); st=$?
    expect_status "19.19 interactive wizard failure test exits 0" 0 "$st"
    expect_match  "19.20 completion wizard surfaces real stderr" "completion generation failed: completion disk denied" "$out"
    expect_match  "19.21 hook wizard surfaces real stderr" "pre-commit hook install failed: hook denied by policy" "$out"
    expect_nomatch "19.22 wizard failures are not mis-attributed to upgrade" "upgrade keyhog|v0\\.5\\.30" "$out"
    rm -rf "$sb" "$h"
else
    skip "19.19 interactive wizard failure test exits 0" "script(1) PTY helper unavailable"
    skip "19.20 completion wizard surfaces real stderr" "script(1) PTY helper unavailable"
    skip "19.21 hook wizard surfaces real stderr" "script(1) PTY helper unavailable"
    skip "19.22 wizard failures are not mis-attributed to upgrade" "script(1) PTY helper unavailable"
fi
if [ -f install.ps1 ]; then
    if grep -q 'completion powershell > $file 2> $errFile' install.ps1 \
       && grep -q 'hook install 2> $errFile' install.ps1; then
        _record_pass "19.23 install.ps1 captures wizard stderr for completion and hook"
    else
        _record_fail "19.23 install.ps1 captures wizard stderr" \
            "completion/hook wizard calls must redirect native stderr to errFile"
    fi
    if grep -q 'Warn-WizardCommandFailure' install.ps1 \
       && grep -q '$LASTEXITCODE' install.ps1 \
       && grep -q 'upgrade keyhog and rerun install' install.ps1; then
        _record_pass "19.24 install.ps1 classifies wizard failures before showing upgrade hint"
    else
        _record_fail "19.24 install.ps1 classifies wizard failures" \
            "missing Warn-WizardCommandFailure/LASTEXITCODE/unknown-subcommand-only hint"
    fi
fi

# ======================================================================
# 20. recoverability: a failed upgrade/repair must never leave the host
#     without a working binary (the recoverability invariant)
# ======================================================================
printf '\n[20] recoverability (rollback on failed upgrade/repair)\n'
reset_mocks
sb=$(build_sandbox Linux x86_64 no no no)

# Pre-place a KNOWN-GOOD binary, marked so we can prove it survived a botched
# upgrade rather than being silently re-downloaded.
preinstall_good() {
    mkdir -p "$1/.local/bin"
    cat > "$1/.local/bin/keyhog" <<'SH'
#!/bin/sh
case "$1" in
  --version) echo "KeyHog v1.0.0 (preexisting-good)" ;;
  doctor)    echo "ok"; exit 0 ;;
  *) ;;
esac
SH
    chmod +x "$1/.local/bin/keyhog"
}
installed_version() { "$1/.local/bin/keyhog" --version 2>/dev/null; }

# 20.1-20.4 UPGRADE over a working binary, new download is BROKEN (wrong CPU):
# the working binary must be restored, the install must report failure, and no
# staging/backup turds may be left behind.
h=$(newhome); preinstall_good "$h"
out=$(KEYHOG_VERSION=v2.0.0 MOCK_ASSET="$FIX_DIR/fake_keyhog_broken" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt --no-color); st=$?
expect_status "20.1 botched upgrade exits nonzero" 1 "$st"
expect_exec   "20.2 binary still present after botched upgrade" "$h/.local/bin/keyhog"
if printf '%s' "$(installed_version "$h")" | grep -q "preexisting-good"; then
    _record_pass "20.3 ROLLBACK: previous working binary preserved"
else
    _record_fail "20.3 ROLLBACK: previous working binary preserved" "version now: $(installed_version "$h")"
fi
expect_match  "20.4 rollback announced to user" "Rolled back|previous working" "$out"
expect_nofile "20.4b no .bak turd left behind" "$h/.local/bin/.keyhog.bak.$$"
if ls "$h/.local/bin/".keyhog.bak.* "$h/.local/bin/".keyhog.new.* >/dev/null 2>&1; then
    _record_fail "20.4c no staging/backup files leak" "$(ls -a "$h/.local/bin/")"
else
    _record_pass "20.4c no staging/backup files leak"
fi
rm -rf "$h"

# 20.5-20.6 UPGRADE over a working binary, new download needs a MISSING LIB:
# on an upgrade the OLD binary ran, so even a "correct but unlinkable" new one
# must roll back (the user keeps a keyhog that works on this host).
h=$(newhome); preinstall_good "$h"
out=$(KEYHOG_VERSION=v2.0.0 MOCK_ASSET="$FIX_DIR/fake_keyhog_broken" MOCK_SHA=match MOCK_LDD=libhyperscan.so.5 run_install "$sb" "$h" -- --no-prompt --no-color); st=$?
expect_status "20.5 missing-lib upgrade exits nonzero" 1 "$st"
if printf '%s' "$(installed_version "$h")" | grep -q "preexisting-good"; then
    _record_pass "20.6 missing-lib upgrade rolls back to working binary"
else
    _record_fail "20.6 missing-lib upgrade rolls back to working binary" "version now: $(installed_version "$h")"
fi
rm -rf "$h"

# 20.7-20.8 UPGRADE over a working binary, new download is HEALTHY: it upgrades
# cleanly and the backup is dropped (no turds).
h=$(newhome); preinstall_good "$h"
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt --no-color); st=$?
expect_status "20.7 healthy upgrade exits 0" 0 "$st"
if printf '%s' "$(installed_version "$h")" | grep -q "v9.9.9"; then
    _record_pass "20.8 healthy upgrade actually replaced the binary"
else
    _record_fail "20.8 healthy upgrade actually replaced the binary" "version now: $(installed_version "$h")"
fi
if ls "$h/.local/bin/".keyhog.bak.* "$h/.local/bin/".keyhog.new.* >/dev/null 2>&1; then
    _record_fail "20.9 successful upgrade leaves no backup turd" "$(ls -a "$h/.local/bin/")"
else
    _record_pass "20.9 successful upgrade leaves no backup turd"
fi
rm -rf "$h"

# 20.10-20.11 FRESH install, broken (wrong-CPU) binary, no prior install:
# nothing was overwritten, so the non-runnable download is removed - leaving a
# binary that errors on every call would be worse than leaving none.
h=$(newhome)
out=$(KEYHOG_VERSION=v2.0.0 MOCK_ASSET="$FIX_DIR/fake_keyhog_broken" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt --no-color); st=$?
expect_status "20.10 fresh broken install exits nonzero" 1 "$st"
expect_nofile "20.11 non-runnable fresh download is removed" "$h/.local/bin/keyhog"
rm -rf "$h"

# 20.12-20.13 FRESH install, correct binary missing only a SYSTEM LIBRARY:
# keep it on disk (it is the right binary) and print the actionable hint, so
# the user installs the lib instead of being told to re-download.
h=$(newhome)
out=$(KEYHOG_VERSION=v2.0.0 MOCK_ASSET="$FIX_DIR/fake_keyhog_broken" MOCK_SHA=match MOCK_LDD=libhyperscan.so.5 run_install "$sb" "$h" -- --no-prompt --no-color); st=$?
expect_status  "20.12 fresh missing-lib install exits nonzero" 1 "$st"
expect_exec    "20.13 correct-but-unlinkable binary is kept for the user to fix" "$h/.local/bin/keyhog"
expect_match   "20.13b missing-lib hint shown" "libhyperscan5|Hyperscan runtime" "$out"
rm -rf "$h"

# 20.14-20.15 UPGRADE where the new download CHECKSUM MISMATCHES: the overwrite
# must never even begin, so the working binary is untouched (not merely
# restored - never replaced).
h=$(newhome); preinstall_good "$h"
out=$(KEYHOG_VERSION=v2.0.0 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=mismatch run_install "$sb" "$h" -- --no-prompt --no-color); st=$?
expect_status "20.14 checksum-mismatch upgrade exits 1" 1 "$st"
if printf '%s' "$(installed_version "$h")" | grep -q "preexisting-good"; then
    _record_pass "20.15 checksum mismatch leaves working binary untouched"
else
    _record_fail "20.15 checksum mismatch leaves working binary untouched" "version now: $(installed_version "$h")"
fi
rm -rf "$h"

# 20.16-20.17 UPGRADE where the new download is EMPTY (0 bytes): same guarantee
# - the empty-guard fires before any overwrite.
h=$(newhome); preinstall_good "$h"
: > "$FIX_DIR/empty_asset"
out=$(KEYHOG_VERSION=v2.0.0 MOCK_ASSET="$FIX_DIR/empty_asset" MOCK_SHA=absent run_install "$sb" "$h" -- --no-prompt --no-color); st=$?
expect_status "20.16 empty-download upgrade exits 1" 1 "$st"
if printf '%s' "$(installed_version "$h")" | grep -q "preexisting-good"; then
    _record_pass "20.17 empty download leaves working binary untouched"
else
    _record_fail "20.17 empty download leaves working binary untouched" "version now: $(installed_version "$h")"
fi
rm -rf "$h"

# 20.18-20.20 REPAIR over a working binary with a BROKEN new download: repair
# must also roll back (this is the "botched repair, unrecoverable" class).
h=$(newhome); preinstall_good "$h"
out=$(KEYHOG_VERSION=v2.0.0 MOCK_ASSET="$FIX_DIR/fake_keyhog_broken" MOCK_SHA=match run_install "$sb" "$h" -- --repair --no-prompt --no-color); st=$?
expect_status "20.18 botched repair exits nonzero" 1 "$st"
expect_exec   "20.19 binary present after botched repair" "$h/.local/bin/keyhog"
if printf '%s' "$(installed_version "$h")" | grep -q "preexisting-good"; then
    _record_pass "20.20 botched repair rolls back to working binary"
else
    _record_fail "20.20 botched repair rolls back to working binary" "version now: $(installed_version "$h")"
fi
rm -rf "$h"
rm -rf "$sb"

# ======================================================================
# 21. PATH setup: idempotent rc block and macOS bash profile target
# ======================================================================
printf '\n[21] PATH setup idempotency and macOS bash rc target\n'
if command -v script >/dev/null 2>&1 && script -qefc true /dev/null >/dev/null 2>&1; then
    reset_mocks
    sb=$(build_sandbox Linux x86_64 no no no); h=$(newhome)
    path_env="PATH=$sb/bin HOME=$h SHELL=/bin/bash KEYHOG_INSTALL=$h/.local/bin MOCK_RELEASES=$FIX_DIR/releases_normal.json MOCK_ASSET=$FIX_DIR/fake_keyhog_healthy MOCK_FALLBACK=404 MOCK_SHA=match MOCK_LDD=ok KEYHOG_VARIANT=auto KEYHOG_VERSION=v9.9.9"
    path_cmd1="env -i $path_env MOCK_STATE_DIR=$h/state-1 sh $INSTALL_SH --no-color"
    path_cmd2="env -i $path_env MOCK_STATE_DIR=$h/state-2 sh $INSTALL_SH --no-color"
    out=$(printf 'y\ny\ny\nn\nn\n' | script -qefc "$path_cmd1" /dev/null 2>&1); st=$?
    expect_status "21.1 first bash PATH setup install exits 0" 0 "$st"
    out=$(printf 'y\ny\nn\nn\n' | script -qefc "$path_cmd2" /dev/null 2>&1); st=$?
    expect_status "21.2 second bash PATH setup install exits 0" 0 "$st"
    expect_match  "21.3 second bash PATH setup reports already configured" "PATH already configured" "$out"
    markers=$(grep -c '^# keyhog$' "$h/.bashrc" 2>/dev/null || true)
    exports=$(grep -c "export PATH=\"$h/.local/bin:" "$h/.bashrc" 2>/dev/null || true)
    if [ "$markers" = "1" ] && [ "$exports" = "1" ]; then
        _record_pass "21.4 bash PATH setup writes exactly one rc block across reruns"
    else
        _record_fail "21.4 bash PATH setup writes exactly one rc block" \
            "markers=$markers exports=$exports rc=$(cat "$h/.bashrc" 2>/dev/null)"
    fi
    rm -rf "$sb" "$h"

    reset_mocks
    sb=$(build_sandbox Darwin x86_64 no no no); h=$(newhome)
    mac_cmd="env -i PATH=$sb/bin HOME=$h SHELL=/bin/bash KEYHOG_INSTALL=$h/.local/bin MOCK_STATE_DIR=$h/state MOCK_RELEASES=$FIX_DIR/releases_normal.json MOCK_ASSET=$FIX_DIR/fake_keyhog_healthy MOCK_FALLBACK=404 MOCK_SHA=match MOCK_LDD=ok KEYHOG_VARIANT=auto KEYHOG_VERSION=v9.9.9 sh $INSTALL_SH --no-color"
    out=$(printf 'y\ny\ny\nn\nn\n' | script -qefc "$mac_cmd" /dev/null 2>&1); st=$?
    expect_status "21.5 macOS bash PATH setup install exits 0" 0 "$st"
    expect_file   "21.6 macOS bash PATH setup writes login profile" "$h/.bash_profile"
    expect_nofile "21.7 macOS bash PATH setup does not write .bashrc" "$h/.bashrc"
    rm -rf "$sb" "$h"

    reset_mocks
    sb=$(build_sandbox Linux x86_64 no no no); h=$(newhome)
    zsh_env="PATH=$sb/bin HOME=$h SHELL=/bin/zsh KEYHOG_INSTALL=$h/.local/bin MOCK_RELEASES=$FIX_DIR/releases_normal.json MOCK_ASSET=$FIX_DIR/fake_keyhog_healthy MOCK_FALLBACK=404 MOCK_SHA=match MOCK_LDD=ok KEYHOG_VARIANT=auto KEYHOG_VERSION=v9.9.9"
    zsh_cmd1="env -i $zsh_env MOCK_STATE_DIR=$h/zsh-state-1 sh $INSTALL_SH --no-color"
    zsh_cmd2="env -i $zsh_env MOCK_STATE_DIR=$h/zsh-state-2 sh $INSTALL_SH --no-color"
    out=$(printf 'y\ny\ny\ny\nn\n' | script -qefc "$zsh_cmd1" /dev/null 2>&1); st=$?
    expect_status "21.8 zsh completion setup install exits 0" 0 "$st"
    expect_file   "21.9 zsh completion file is written" "$h/.zfunc/_keyhog"
    expect_match  "21.10 zsh completion setup reports rc wiring" "zsh completion path configured" "$out"
    out=$(printf 'y\ny\ny\nn\n' | script -qefc "$zsh_cmd2" /dev/null 2>&1); st=$?
    expect_status "21.11 zsh completion setup rerun exits 0" 0 "$st"
    expect_match  "21.12 zsh completion setup rerun reports existing wiring" "zsh completion path already configured" "$out"
    zsh_markers=$(grep -c '^# keyhog completions$' "$h/.zshrc" 2>/dev/null || true)
    zsh_fpath=$(grep -c 'fpath=("$HOME/.zfunc" $fpath)' "$h/.zshrc" 2>/dev/null || true)
    if [ "$zsh_markers" = "1" ] && [ "$zsh_fpath" = "1" ]; then
        _record_pass "21.13 zsh completion wiring writes exactly one fpath block"
    else
        _record_fail "21.13 zsh completion wiring writes exactly one fpath block" \
            "markers=$zsh_markers fpath=$zsh_fpath rc=$(cat "$h/.zshrc" 2>/dev/null)"
    fi
    rm -rf "$sb" "$h"
else
    skip "21.1 first bash PATH setup install exits 0" "script(1) PTY helper unavailable"
    skip "21.2 second bash PATH setup install exits 0" "script(1) PTY helper unavailable"
    skip "21.3 second bash PATH setup reports already configured" "script(1) PTY helper unavailable"
    skip "21.4 bash PATH setup writes exactly one rc block across reruns" "script(1) PTY helper unavailable"
    skip "21.5 macOS bash PATH setup install exits 0" "script(1) PTY helper unavailable"
    skip "21.6 macOS bash PATH setup writes login profile" "script(1) PTY helper unavailable"
    skip "21.7 macOS bash PATH setup does not write .bashrc" "script(1) PTY helper unavailable"
    skip "21.8 zsh completion setup install exits 0" "script(1) PTY helper unavailable"
    skip "21.9 zsh completion file is written" "script(1) PTY helper unavailable"
    skip "21.10 zsh completion setup reports rc wiring" "script(1) PTY helper unavailable"
    skip "21.11 zsh completion setup rerun exits 0" "script(1) PTY helper unavailable"
    skip "21.12 zsh completion setup rerun reports existing wiring" "script(1) PTY helper unavailable"
    skip "21.13 zsh completion wiring writes exactly one fpath block" "script(1) PTY helper unavailable"
fi

# ======================================================================
# Summary
# ======================================================================
total=$((pass + fail))
printf '\n%s\n' "--------------------------------------------------------------"
if [ "$fail" -eq 0 ]; then
    printf '\033[32m%d / %d passed' "$pass" "$total"
    [ "$skipped" -gt 0 ] && printf ', %d skipped (run in the Docker matrix for full coverage)' "$skipped"
    printf '.\033[0m\n'
    exit 0
else
    printf '\033[31m%d failed, %d passed (of %d), %d skipped.\033[0m\n' "$fail" "$pass" "$total" "$skipped"
    printf '%b\n' "$failed_names"
    exit 1
fi

#!/usr/bin/env bash
#
# Hand-written edge-case battery for install.sh.
#
# Unlike scenarios.sh (which only drives --diagnose with KEYHOG_VERSION
# pinned so the network is never touched), this harness mocks the ENTIRE
# surface install.sh depends on - curl (releases API, asset download,
# .minisig, .sha256), minisign, uname, nvidia-smi, ldconfig, ldd, and the
# downloaded binary itself - so the full install -> verify_release_signature
# -> verify_checksum -> stage -> verify_install
# path runs offline and deterministically. Every documented mode, flag,
# detection branch, and failure path gets a real assertion against the
# real script. These are the tests that would have caught the resolve_tag
# JSON-indentation bug (the default `curl | sh` install failing outright).
#
# Each test runs install.sh in a per-test sandbox: env -i with PATH pointed
# at a mock bin/ dir and a throwaway HOME. No
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
    else _record_fail "$1" "expected /$2/, got (tail):" "$(printf '%s' "$3" | tail -20)"; fi
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

# Normal: newest release (v9.9.9) has a complete signed host bundle.
cat > "$FIX_DIR/releases_normal.json" <<'JSON'
[
  {
    "tag_name": "v9.9.9",
    "draft": false,
    "prerelease": false,
    "assets": [
      { "name": "keyhog-linux-x86_64" },
      { "name": "keyhog-linux-x86_64.sha256" },
      { "name": "keyhog-linux-x86_64.minisig" },
      { "name": "keyhog-linux-x86_64.gpu-literals.tar.gz" },
      { "name": "keyhog-linux-x86_64.gpu-literals.tar.gz.sha256" },
      { "name": "keyhog-linux-x86_64.gpu-literals.tar.gz.minisig" }
    ]
  },
  {
    "tag_name": "v9.9.8",
    "draft": false,
    "prerelease": false,
    "assets": [
      { "name": "keyhog-linux-x86_64" },
      { "name": "keyhog-linux-x86_64.sha256" },
      { "name": "keyhog-linux-x86_64.minisig" },
      { "name": "keyhog-linux-x86_64.gpu-literals.tar.gz" },
      { "name": "keyhog-linux-x86_64.gpu-literals.tar.gz.sha256" },
      { "name": "keyhog-linux-x86_64.gpu-literals.tar.gz.minisig" }
    ]
  }
]
JSON

# Newest release has only a binary; installer must skip the partial manifest
# and select the complete stable v9.9.8 bundle.
cat > "$FIX_DIR/releases_latest_empty.json" <<'JSON'
[
  {
    "tag_name": "v9.9.9",
    "draft": false,
    "prerelease": false,
    "assets": [
      { "name": "keyhog-linux-x86_64" }
    ]
  },
  {
    "tag_name": "v9.9.8",
    "draft": false,
    "prerelease": false,
    "assets": [
      { "name": "keyhog-linux-x86_64" },
      { "name": "keyhog-linux-x86_64.sha256" },
      { "name": "keyhog-linux-x86_64.minisig" },
      { "name": "keyhog-linux-x86_64.gpu-literals.tar.gz" },
      { "name": "keyhog-linux-x86_64.gpu-literals.tar.gz.sha256" },
      { "name": "keyhog-linux-x86_64.gpu-literals.tar.gz.minisig" }
    ]
  }
]
JSON

# Every release has zero assets -> hard error.
cat > "$FIX_DIR/releases_all_empty.json" <<'JSON'
[
  { "tag_name": "v9.9.9", "draft": false, "prerelease": false, "assets": [
    ] },
  { "tag_name": "v9.9.8", "draft": false, "prerelease": false, "assets": [
    ] }
]
JSON

# The fake "keyhog" binary the download step serves. A POSIX shell script
# so verify_install can actually execute it for --version + doctor.
cat > "$FIX_DIR/fake_keyhog_healthy" <<'SH'
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
        "backend": "gpu-region-presence",
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
      --help) echo "Usage: keyhog scan [--no-config] [--autoroute-calibrate]" ;;
      *) case " $* " in *" --autoroute-calibrate "*) write_mock_autoroute_cache ;; esac ;;
    esac
    exit 0
    ;;
  hook)      exit 0 ;;
  completion) echo "# mock completion for ${2:-sh}" ;;
  uninstall) printf '%s\n' "$*" > "$HOME/keyhog-uninstall-called"; exit 0 ;;
  *) ;;
esac
SH
sed 's/v9\.9\.9/v9.9.8/g' "$FIX_DIR/fake_keyhog_healthy" > "$FIX_DIR/fake_keyhog_healthy_v998"

# Signed/checksummed older release substitute. The installer must reject it when
# the resolved release tag is v9.9.9, even though authenticity and integrity
# sidecars are valid for the served bytes.
cat > "$FIX_DIR/fake_keyhog_old_signed" <<'SH'
#!/bin/sh
case "$1" in
  --version) echo "KeyHog v9.9.8 (mock older signed release)" ;;
  *) exit 0 ;;
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
      --help) echo "Usage: keyhog scan [--no-config] [--autoroute-calibrate]" ;;
      *) case " $* " in *" --autoroute-calibrate "*) write_mock_autoroute_cache ;; esac ;;
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
      --help) echo "Usage: keyhog scan [--docker-image IMAGE] [--autoroute-calibrate]" ;;
      *) case " $* " in *" --autoroute-calibrate "*) write_mock_autoroute_cache ;; esac ;;
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
      --help) echo "Usage: keyhog scan [--no-config] [--autoroute-calibrate]"; exit 0 ;;
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
      --help) echo "Usage: keyhog scan [--no-config] [--autoroute-calibrate]" ;;
      *) case " $* " in *" --autoroute-calibrate "*) write_mock_autoroute_cache ;; esac ;;
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

mkdir -p "$FIX_DIR/gpu-sidecar/keyhog-linux-x86_64.gpu-literals"
printf 'mock gpu literal artifact\n' > "$FIX_DIR/gpu-sidecar/keyhog-linux-x86_64.gpu-literals/lit-mock.bin"
tar -czf "$FIX_DIR/gpu-literals.tar.gz" -C "$FIX_DIR/gpu-sidecar" keyhog-linux-x86_64.gpu-literals
mkdir -p "$FIX_DIR/gpu-sidecar-link/keyhog-linux-x86_64.gpu-literals"
ln -s /tmp/keyhog-gpu-literal-link-target "$FIX_DIR/gpu-sidecar-link/keyhog-linux-x86_64.gpu-literals/lit-link.bin"
tar -czf "$FIX_DIR/gpu-literals-link.tar.gz" -C "$FIX_DIR/gpu-sidecar-link" keyhog-linux-x86_64.gpu-literals
printf 'mock absolute gpu literal artifact\n' > "$FIX_DIR/abs-lit.bin"
tar -czPf "$FIX_DIR/gpu-literals-absolute.tar.gz" "$FIX_DIR/abs-lit.bin"
printf '%s  fake_keyhog_healthy\n' "$(sha_of "$FIX_DIR/fake_keyhog_healthy")" > "$FIX_DIR/fake_keyhog_healthy.sha256"
cp "$FIX_DIR/gpu-literals.tar.gz" "$FIX_DIR/fake_keyhog_healthy.gpu-literals.tar.gz"
printf '%s  fake_keyhog_healthy.gpu-literals.tar.gz\n' "$(sha_of "$FIX_DIR/fake_keyhog_healthy.gpu-literals.tar.gz")" > "$FIX_DIR/fake_keyhog_healthy.gpu-literals.tar.gz.sha256"
cp "$FIX_DIR/fake_keyhog_healthy" "$FIX_DIR/local_keyhog_no_sidecar"
printf '%s  local_keyhog_no_sidecar\n' "$(sha_of "$FIX_DIR/local_keyhog_no_sidecar")" > "$FIX_DIR/local_keyhog_no_sidecar.sha256"

# ── sandbox builder ───────────────────────────────────────────────────
# build_sandbox writes a bin/ of mocks. Behaviour is steered by env vars
# the mock curl reads at runtime (exported into the run via run_install):
#   MOCK_RELEASES   - path to releases JSON, or "DOWN" to simulate API down
#   MOCK_ASSET      - path to the binary to serve, or "404"
#   MOCK_LATEST_ASSET - legacy latest-redirect fixture hook, or "404"
#   MOCK_GPU_LITERAL_SIDECAR - path to serve for <asset>.gpu-literals.tar.gz, or
#                     "404" (curl exit 22 = HTTP 404 = not published) or
#                     "neterror" (curl exit 6 = a network/transport failure)
#   MOCK_SIG        - "match" | "invalid" | "absent" | "neterror"
#   MOCK_SHA        - "match" | "mismatch" | "absent" | "neterror"
#     ("absent" = curl exit 22 / HTTP 404 = asset genuinely not published;
#      "neterror" = curl exit 6 = a network/transport failure, which must NOT
#      be silently downgraded to "not published", see tests 6.4ac-6.4ai.)
#   MOCK_LDD        - "ok" | path-to-missing-lib-name (e.g. "libhyperscan.so.5")
build_sandbox() {
    os=$1 arch=$2 nv=$3 lib=$4 toolkit=$5
    sb=$(mktemp -d -t kh-sb-XXXXXX)
    mkdir -p "$sb/bin"
    for tool in sh dash bash grep sed head tail awk cut tr cat mv cp rm mkdir rmdir \
                chmod chown ls find dirname basename printf date sleep test true false \
                command type stat readlink realpath sort uniq wc env tee xargs mktemp \
                sha256sum shasum touch tar gzip git; do
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

    # Mock minisign: validates that the installer downloaded a non-empty
    # signature file and honors MOCK_SIG for success/failure cases.
    cat > "$sb/bin/minisign" <<'EOF'
#!/bin/sh
sigfile=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    -x) shift; sigfile="${1:-}" ;;
  esac
  shift || break
done
case "${MOCK_SIG:-match}" in
  match)
    [ -s "$sigfile" ] || { echo "missing signature file" >&2; exit 1; }
    echo "Signature and comment signature verified"
    exit 0
    ;;
  invalid)
    echo "Signature verification failed" >&2
    exit 1
    ;;
  *)
    echo "unexpected mock signature mode: ${MOCK_SIG:-}" >&2
    exit 1
    ;;
esac
EOF
    chmod +x "$sb/bin/minisign"

    # The mock curl: URL-dispatched, scenario-driven.
    cat > "$sb/bin/curl" <<EOF
#!/bin/sh
FIX_DIR="$FIX_DIR"
EOF
    cat >> "$sb/bin/curl" <<'EOF'
url="" ; out="" ; write_out="" ; prev=""
for a in "$@"; do
  case "$prev" in -o) out="$a" ;; esac
  case "$prev" in -w) write_out="$a" ;; esac
  case "$a" in http://*|https://*) url="$a" ;; esac
  prev="$a"
done
emit() { if [ -n "$out" ]; then cat > "$out"; else cat; fi; }
emit_redirect_url() {
  case "$write_out" in
    *'%{redirect_url}'*) printf '%s' "$1" ;;
  esac
}

# Cross-invocation state (each curl call is a fresh process, so attempt
# ordering and the "what did we serve" record live in files, not env).
sd="${MOCK_STATE_DIR:-/tmp/kh-mock-state}"
mkdir -p "$sd" 2>/dev/null || true

case "$url" in
  *api.github.com*releases*)
    : > "$HOME/github-api-called"
    case " $* " in *"Authorization: Bearer "*) : > "$HOME/github-api-auth" ;; esac
    if [ "${MOCK_RELEASES:-DOWN}" = "DOWN" ]; then
      echo "mock GitHub API down" >&2
      exit 22
    fi
    emit < "$MOCK_RELEASES"; exit 0 ;;
  *.minisig)
    case "${MOCK_SIG:-match}" in
      absent)  exit 22 ;;
      neterror) echo "mock curl: could not resolve host" >&2; exit 6 ;;
      invalid) printf 'invalid mock minisig\n' | emit; exit 0 ;;
      match)   printf 'trusted mock minisig\n' | emit; exit 0 ;;
    esac ;;
  *.sha256)
    case "${MOCK_SHA:-absent}" in
      absent)   exit 22 ;;
      neterror) echo "mock curl: could not resolve host" >&2; exit 6 ;;
      mismatch) printf '%s  asset\n' "0000000000000000000000000000000000000000000000000000000000000000" | emit; exit 0 ;;
      match)
        sf=$(cat "$sd/served" 2>/dev/null)
        h=$(sha256sum "$sf" 2>/dev/null | awk '{print $1}')
        [ -z "$h" ] && h=$(shasum -a 256 "$sf" 2>/dev/null | awk '{print $1}')
        printf '%s  asset\n' "$h" | emit; exit 0 ;;
    esac ;;
  *releases/latest/download/*)
    asset_name="${url##*/}"
    case "$asset_name" in
      *.gpu-literals.tar.gz)
        served="${MOCK_GPU_LITERAL_SIDECAR:-$FIX_DIR/gpu-literals.tar.gz}"
        if [ "$served" = "neterror" ]; then echo "mock curl: could not resolve host" >&2; exit 6; fi ;;
      *)
        served="${MOCK_LATEST_ASSET:-${MOCK_ASSET:-404}}" ;;
    esac
    if [ "$served" = "404" ]; then exit 22; fi
    printf '%s' "$served" > "$sd/served"
    if [ -n "$out" ]; then cat "$served" > "$out"; fi
    emit_redirect_url "https://github.com/santhsecurity/keyhog/releases/download/${MOCK_LATEST_TAG:-v9.9.9}/$asset_name"
    exit 0 ;;
  *releases/download/*)
    asset_name="${url##*/}"
    case "$asset_name" in
      *.gpu-literals.tar.gz)
        served="${MOCK_GPU_LITERAL_SIDECAR:-$FIX_DIR/gpu-literals.tar.gz}"
        if [ "$served" = "neterror" ]; then echo "mock curl: could not resolve host" >&2; exit 6; fi
        if [ "$served" = "404" ]; then exit 22; fi
        printf '%s' "$served" > "$sd/served"
        if [ -n "$out" ]; then cat "$served" > "$out"; fi
        emit_redirect_url "$url"
        exit 0 ;;
    esac
    if [ "${MOCK_ASSET:-404}" = "404" ]; then exit 22; fi
    served="$MOCK_ASSET"
    printf '%s' "$served" > "$sd/served"
    if [ -n "$out" ]; then cat "$served" > "$out"; fi
    emit_redirect_url "$url"
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
    if [ "${INSTALL_DIR_OVERRIDE:-}" != "" ]; then
        set -- "--install-dir=$INSTALL_DIR_OVERRIDE" "$@"
    fi
    state=$(mktemp -d -t kh-state-XXXXXX)
    env -i PATH="$sb/bin" HOME="$home" \
        MOCK_STATE_DIR="$state" \
        MOCK_RELEASES="${MOCK_RELEASES:-DOWN}" \
        MOCK_ASSET="${MOCK_ASSET:-404}" \
        MOCK_LATEST_ASSET="${MOCK_LATEST_ASSET:-${MOCK_ASSET:-404}}" \
        MOCK_GPU_LITERAL_SIDECAR="${MOCK_GPU_LITERAL_SIDECAR:-$FIX_DIR/gpu-literals.tar.gz}" \
        MOCK_SIG="${MOCK_SIG:-match}" \
        MOCK_SHA="${MOCK_SHA:-absent}" \
        MOCK_LDD="${MOCK_LDD:-ok}" \
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
    unset MOCK_RELEASES MOCK_ASSET MOCK_LATEST_ASSET MOCK_GPU_LITERAL_SIDECAR MOCK_SIG MOCK_SHA MOCK_LDD \
          KEYHOG_VERSION INSTALL_DIR_OVERRIDE GITHUB_TOKEN
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
# 2. resolve_tag (concrete latest resolution + JSON-indentation regression)
# ======================================================================
printf '\n[2] resolve_tag against GitHub-shaped JSON\n'
reset_mocks
sb=$(build_sandbox Linux x86_64 no no no); h=$(newhome)
out=$(MOCK_RELEASES="$FIX_DIR/releases_normal.json" MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "2.1 default install resolves latest to a concrete tag" "Release tag:   v9.9.9" "$out"
expect_status "2.2 normal install exits 0" 0 "$st"
expect_nofile "2.3 default latest resolution skips GitHub API when redirect proves tag" "$h/github-api-called"
rm -rf "$h"; h=$(newhome)
out=$(MOCK_LATEST_ASSET=404 MOCK_RELEASES="$FIX_DIR/releases_latest_empty.json" MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy_v998" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt)
expect_match  "2.4 unproven latest bundle falls back to API release walk" "checking recent stable releases" "$out"
expect_match  "2.5 skips partial newest bundle, picks v9.9.8" "Release tag:   v9.9.8" "$out"
expect_file   "2.6 asset walk calls GitHub API" "$h/github-api-called"
rm -rf "$h"; h=$(newhome)
out=$(GITHUB_TOKEN=ghp_mock_token MOCK_LATEST_ASSET=404 MOCK_RELEASES="$FIX_DIR/releases_latest_empty.json" MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy_v998" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_status "2.7 authenticated latest-resolution install exits 0" 0 "$st"
expect_file   "2.8 latest-resolution API sends Authorization when GITHUB_TOKEN is set" "$h/github-api-auth"
rm -rf "$h"; h=$(newhome)
out=$(MOCK_LATEST_ASSET=404 MOCK_RELEASES="$FIX_DIR/releases_all_empty.json" run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "2.9 no complete release errors" "No stable GitHub release" "$out"
expect_status "2.10 all-empty exits 1" 1 "$st"
rm -rf "$h"; h=$(newhome)
out=$(MOCK_LATEST_ASSET=404 run_install "$sb" "$h" -- --no-prompt); st=$?    # MOCK_RELEASES unset => DOWN
expect_match  "2.11 API down errors clearly during latest resolution" "Could not query GitHub releases API" "$out"
expect_match  "2.12 API down surfaces curl detail" "GitHub API error: mock GitHub API down" "$out"
expect_status "2.13 API down exits 1" 1 "$st"
rm -rf "$h"; h=$(newhome)
out=$(KEYHOG_VERSION=v1.2.3 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt)
expect_match  "2.14 --version pin skips API" "Release tag:   v1.2.3" "$out"
rm -rf "$h"; h=$(newhome)
# A bare semver (no leading v) must normalise to the v-prefixed tag. keyhog
# tags are all vX.Y.Z, so `--version=9.9.9` building a download URL from the
# un-prefixed tag 404s, exactly the bug that failed the Windows install smoke
# (the smoke passed "0.5.37", not "v0.5.37"). Assert the resolved tag is v-fixed
# AND the install completes, so the 404 can never come back silently.
out=$(KEYHOG_VERSION=9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "2.15 bare semver normalises to v-prefixed tag" "Release tag:   v9.9.9" "$out"
expect_status "2.16 bare-semver install exits 0" 0 "$st"
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
expect_match  "6.3a minisign verified line"   "Minisign signature verified" "$out"
expect_exec   "6.4 binary is executable"      "$h/.local/bin/keyhog"
expect_match  "6.4a calibration summary table printed" "Autoroute calibration decisions" "$out"
expect_match  "6.4b calibration summary reports persisted decision count" "decisions persisted: 2" "$out"
expect_match  "6.4c calibration summary shows backend margin" "gpu-region-presence.*7\\.0ms" "$out"
expect_match  "6.4d GPU literal sidecar is installed" "Installed 1 GPU literal matcher artifact" "$out"
expect_file   "6.4e GPU literal artifact seeds runtime cache" "$h/.cache/keyhog/programs/lit-mock.bin"
rm -rf "$h"
# 6.4f missing GPU literal sidecar refuses before binary overwrite.
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match MOCK_GPU_LITERAL_SIDECAR=404 run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "6.4f missing GPU literal sidecar refuses" "No GPU literal artifact sidecar" "$out"
expect_status "6.4g missing GPU literal sidecar exits 1" 1 "$st"
expect_nofile "6.4h no binary written without GPU literal sidecar" "$h/.local/bin/keyhog"
rm -rf "$h"
# 6.4f-net a network/transport failure fetching the sidecar must NOT be reported
# as "not published" (Law 10: never conflate a transport failure with a missing
# asset). curl exit 6 (DNS) != exit 22 (HTTP 404), so the operator is told the
# sidecar may well exist and a retry may succeed (never to rebuild the workflow).
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match MOCK_GPU_LITERAL_SIDECAR=neterror run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match   "6.4f-net sidecar transport failure names the transport error" "network/transport failure, not a missing asset" "$out"
expect_match   "6.4f-net2 sidecar transport failure invites a retry" "A retry may succeed" "$out"
expect_nomatch "6.4f-net3 sidecar transport failure does NOT claim 'not published'" "was published" "$out"
expect_nomatch "6.4f-net4 sidecar transport failure does NOT tell operator to rebuild the workflow" "rebuild the release workflow" "$out"
expect_status "6.4f-net5 sidecar transport failure still fails closed (exit 1)" 1 "$st"
expect_nofile "6.4f-net6 no binary written after sidecar transport failure" "$h/.local/bin/keyhog"
rm -rf "$h"
# 6.4i link entries in the GPU literal sidecar refuse before binary overwrite.
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match MOCK_GPU_LITERAL_SIDECAR="$FIX_DIR/gpu-literals-link.tar.gz" run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "6.4i GPU literal sidecar link entry refuses" "GPU literal artifact sidecar contains link entries" "$out"
expect_status "6.4j GPU literal sidecar link entry exits 1" 1 "$st"
expect_nofile "6.4k no binary written after GPU literal sidecar link entry" "$h/.local/bin/keyhog"
rm -rf "$h"
# 6.4l absolute paths in the GPU literal sidecar refuse before binary overwrite.
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match MOCK_GPU_LITERAL_SIDECAR="$FIX_DIR/gpu-literals-absolute.tar.gz" run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "6.4l GPU literal sidecar absolute path refuses" "GPU literal artifact sidecar contains unsafe archive paths" "$out"
expect_status "6.4m GPU literal sidecar absolute path exits 1" 1 "$st"
expect_nofile "6.4n no binary written after GPU literal sidecar absolute path" "$h/.local/bin/keyhog"
rm -rf "$h"
# 6.4o missing .minisig refuses by default.
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SIG=absent MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "6.4o absent .minisig refuses unverified install" "No \\.minisig signature|Refusing to install an unverified" "$out"
expect_status "6.4p absent .minisig exits 1" 1 "$st"
expect_nofile "6.4q no binary written without signature" "$h/.local/bin/keyhog"
rm -rf "$h"
# 6.4r missing .minisig with --insecure is loud and still requires checksum.
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SIG=absent MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt --insecure); st=$?
expect_match  "6.4r absent .minisig insecure override is loud" "INSECURE" "$out"
expect_match  "6.4s absent .minisig insecure override still checks checksum" "SHA256 verified" "$out"
expect_status "6.4t absent .minisig insecure override installs" 0 "$st"
expect_exec   "6.4u binary present after signature bypass" "$h/.local/bin/keyhog"
rm -rf "$h"
# 6.4v invalid signatures are known-bad proof and cannot be bypassed.
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SIG=invalid MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "6.4v invalid .minisig refuses" "Minisign signature verification failed" "$out"
expect_status "6.4w invalid .minisig exits 1" 1 "$st"
expect_nofile "6.4x no binary written after invalid signature" "$h/.local/bin/keyhog"
rm -rf "$h"
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SIG=invalid MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt --insecure); st=$?
expect_match  "6.4y invalid .minisig still refuses with insecure" "Minisign signature verification failed" "$out"
expect_status "6.4z invalid .minisig insecure exits 1" 1 "$st"
expect_nofile "6.4aa no binary written after invalid signature with insecure" "$h/.local/bin/keyhog"
rm -rf "$h"
# 6.4na a transient network/transport failure fetching the .sha256 must NOT be
# silently downgraded to "no checksum published" and skipped (a CDN blip would
# otherwise waive integrity verification). Under strict mode it fails closed with
# an HONEST message that names it a network failure, not a missing checksum.
# (The GPU literal sidecar is left present/default since it is mandatory; its own
# .sha256 fetch also hits neterror, so whichever checksum runs first fails.)
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SIG=match MOCK_SHA=neterror run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match   "6.4na checksum network error is named honestly" "network/transport failure, not a missing checksum" "$out"
expect_nomatch "6.4nb checksum network error is NOT mislabeled 'not published'" "No \\.sha256 checksum was published" "$out"
expect_status  "6.4nc checksum network error fails closed" 1 "$st"
expect_nofile  "6.4nd no binary written when the checksum fetch fails on the network" "$h/.local/bin/keyhog"
rm -rf "$h"
# 6.4ne with --insecure the operator may waive verification, but the skip is loud
# and still honestly names the network failure (never a false "not published").
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SIG=match MOCK_SHA=neterror run_install "$sb" "$h" -- --no-prompt --insecure); st=$?
expect_match   "6.4ne checksum network error insecure override is loud + honest" "INSECURE.*network/transport failure" "$out"
expect_status  "6.4nf checksum network error insecure override installs" 0 "$st"
expect_exec    "6.4ng binary present after explicit insecure checksum waiver" "$h/.local/bin/keyhog"
rm -rf "$h"
# 6.4nh a transient network/transport failure fetching the .minisig is likewise
# fail-closed with an honest message (not a false "no signature published").
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SIG=neterror MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match   "6.4nh signature network error is named honestly" "network/transport failure, not a missing signature" "$out"
expect_nomatch "6.4ni signature network error is NOT mislabeled 'not published'" "No \\.minisig signature was published" "$out"
expect_status  "6.4nj signature network error fails closed" 1 "$st"
expect_nofile  "6.4nk no binary written when the signature fetch fails on the network" "$h/.local/bin/keyhog"
rm -rf "$h"
# 6.4ab missing minisign verifier fails closed unless explicitly insecure.
sb_no_minisign=$(build_sandbox Linux x86_64 no no no); rm -f "$sb_no_minisign/bin/minisign"
cat > "$sb_no_minisign/bin/apt-get" <<'EOF'
#!/bin/sh
exit 0
EOF
chmod +x "$sb_no_minisign/bin/apt-get"
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb_no_minisign" "$h" -- --no-prompt); st=$?
expect_match  "6.4ab no minisign tool refuses" "minisign is not installed|Refusing to install an unverified" "$out"
expect_match  "6.4ac no minisign tool gives Debian install command" "sudo apt-get update && sudo apt-get install -y minisign" "$out"
expect_status "6.4ad no minisign tool exits 1" 1 "$st"
expect_nofile "6.4ae no binary written without minisign" "$h/.local/bin/keyhog"
rm -rf "$h"
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb_no_minisign" "$h" -- --no-prompt --insecure); st=$?
expect_match  "6.4af no minisign tool insecure override is loud" "INSECURE" "$out"
expect_status "6.4ag no minisign tool insecure override installs" 0 "$st"
expect_exec   "6.4ah binary present after verifier-tool bypass" "$h/.local/bin/keyhog"
rm -rf "$sb_no_minisign" "$h"
# 6.4ai --from-file still requires a local GPU literal sidecar and seeds it before calibration.
h=$(newhome)
out=$(run_install "$sb" "$h" -- --from-file="$FIX_DIR/fake_keyhog_healthy" --no-prompt); st=$?
expect_status "6.4ai from-file with local GPU sidecar installs" 0 "$st"
expect_match  "6.4aj from-file local GPU sidecar installs cache artifact" "Installed 1 GPU literal matcher artifact" "$out"
expect_file   "6.4ak from-file local GPU sidecar seeds runtime cache" "$h/.cache/keyhog/programs/lit-mock.bin"
rm -rf "$h"
h=$(newhome)
out=$(run_install "$sb" "$h" -- --from-file="$FIX_DIR/local_keyhog_no_sidecar" --no-prompt); st=$?
expect_match  "6.4al from-file missing local GPU sidecar refuses" "--from-file requires a sibling GPU literal sidecar" "$out"
expect_status "6.4am from-file missing local GPU sidecar exits 1" 1 "$st"
expect_nofile "6.4an no binary written without from-file GPU sidecar" "$h/.local/bin/keyhog"
rm -rf "$h"
# 6.4ao valid older signed release cannot substitute for the resolved tag.
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_old_signed" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "6.4ao signed older release substitution refuses" "Candidate binary version does not match release tag" "$out"
expect_match  "6.4ap signed older release names mismatch" "v9\\.9\\.8.*v9\\.9\\.9" "$out"
expect_status "6.4aq signed older release substitution exits 1" 1 "$st"
expect_nofile "6.4ar no binary written after signed older release substitution" "$h/.local/bin/keyhog"
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
sb_dead_docker=$(build_sandbox Linux x86_64 no no no)
cat > "$sb_dead_docker/bin/docker" <<'SH'
#!/bin/sh
case "$1" in
  info)  echo "mock docker daemon unavailable" >&2; exit 1 ;;
  build) : > "$HOME/docker-build-called"; exit 1 ;;
  *)     exit 1 ;;
esac
SH
chmod +x "$sb_dead_docker/bin/docker"
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_docker_help" MOCK_SHA=match run_install "$sb_dead_docker" "$h" -- --no-prompt); st=$?
expect_match  "6.18 dead docker daemon warns" "Docker daemon is not responding" "$out"
expect_status "6.19 dead docker daemon does not fail filesystem install" 0 "$st"
expect_exec   "6.20 binary present when docker daemon is dead" "$h/.local/bin/keyhog"
expect_nofile "6.21 dead docker daemon is not used for calibration build" "$h/docker-build-called"
rm -rf "$h" "$sb_dead_docker"
rm -rf "$sb"

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
# 8.5 doctor UNHEALTHY (exit 4) -> install FAILS CLOSED + rolls back.
#     Law 10: a freshly-installed scanner that fails its own end-to-end scan
#     self-test must NOT report "installed". The installer honors doctor's
#     exit-4 unhealthy verdict, removes the staged binary, and exits non-zero
#     rather than silently leaving a scanner that cannot detect secrets.
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 MOCK_ASSET="$FIX_DIR/fake_keyhog_doctor_fail" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt); st=$?
expect_match  "8.5 doctor-unhealthy reported" "UNHEALTHY \(exit 4\)|failed its own end-to-end scan self-test" "$out"
expect_match  "8.5b doctor-unhealthy rolls back" "rolling back this install" "$out"
expect_nomatch "8.5c doctor-unhealthy does not falsely claim installed" "may not be fully healthy" "$out"
expect_status "8.6 doctor-unhealthy install fails closed" 1 "$st"
expect_nofile "8.6b doctor-unhealthy leaves no binary on PATH" "$h/.local/bin/keyhog"
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
expect_match  "9.3 repair verifies before replacing healthy binary" "download and verify|Repair complete" "$out"
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
# 10.4 install-dir helper uses the explicit flag path
h=$(newhome)
out=$(KEYHOG_VERSION=v9.9.9 INSTALL_DIR_OVERRIDE="$h/flagdir" MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt)
expect_file "10.4 binary at explicit install dir" "$h/flagdir/keyhog"
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
# tags are all vX.Y.Z, so honoring "2.0.0" verbatim built a 404 download URL 
# the regression that failed the Windows install smoke. The resolved tag must
# carry the v.
out=$(MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --version=2.0.0 --no-prompt)
expect_match "14.2 bare numeric tag normalises to v-prefixed" "Release tag:   v2.0.0" "$out"
rm -rf "$h"; h=$(newhome)
out=$(MOCK_RELEASES="$FIX_DIR/releases_normal.json" MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --version= --no-prompt)
expect_match "14.3 empty --version resolves latest to concrete tag" "Release tag:   v9.9.9" "$out"
expect_nofile "14.4 empty --version skips GitHub API when latest redirect proves tag" "$h/github-api-called"
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
printf '\n[16] arg precedence + short flags\n'
reset_mocks
sb=$(build_sandbox Linux x86_64 no no no); h=$(newhome)
# later --install-dir beats an earlier install-dir helper flag
out=$(KEYHOG_VERSION=v9.9.9 INSTALL_DIR_OVERRIDE="$h/firstdir" MOCK_ASSET="$FIX_DIR/fake_keyhog_healthy" MOCK_SHA=match run_install "$sb" "$h" -- --no-prompt --install-dir="$h/flagdir")
expect_file   "16.1 later --install-dir wins" "$h/flagdir/keyhog"
expect_nofile "16.2 earlier install-dir unused when later flag set" "$h/firstdir/keyhog"
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
   && grep -q 'sleep 0.15' install.sh \
   && grep -q 'elapsed_ms_since "$probe_started_ms"' install.sh \
   && grep -q 'PASS %s (%sms)' install.sh; then
    _record_pass "19.14b install.sh calibration probes have live spinner progress"
else
    _record_fail "19.14b install.sh calibration probes have live spinner progress" \
        "probe loop must keep an active pid, update progress while it runs, and print per-probe elapsed ms"
fi
reset_mocks
sb=$(build_sandbox Linux x86_64 no no no); h=$(newhome)
signal_state=$(mktemp -d -t kh-signal-state-XXXXXX)
signal_tmp=$(mktemp -d -t kh-signal-tmp-XXXXXX)
signal_out="$h/signal.out"
env -i PATH="$sb/bin" HOME="$h" \
    TMPDIR="$signal_tmp" \
    MOCK_STATE_DIR="$signal_state" \
    MOCK_RELEASES="$FIX_DIR/releases_normal.json" \
    MOCK_ASSET="$FIX_DIR/fake_keyhog_slow_scan" \
    MOCK_SHA=match \
    MOCK_LDD=ok \
    KEYHOG_VERSION=v9.9.9 \
    sh "$INSTALL_SH" --install-dir="$h/.local/bin" --no-prompt --no-color >"$signal_out" 2>&1 &
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
    mkdir -p "$repo"
    "$sb/bin/git" -C "$repo" init -q
    wizard_cmd="cd $repo && env -i PATH=$h/.local/bin:$sb/bin HOME=$h SHELL=/bin/bash MOCK_STATE_DIR=$h/state MOCK_RELEASES=$FIX_DIR/releases_normal.json MOCK_ASSET=$FIX_DIR/fake_keyhog_wizard_fail MOCK_SHA=match MOCK_LDD=ok KEYHOG_VERSION=v9.9.9 sh $INSTALL_SH --install-dir=$h/.local/bin --no-color"
    out=$(printf 'y\ny\ny\ny\n' | script -qefc "$wizard_cmd" /dev/null 2>&1); st=$?
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
    if grep -q 'Show-AutorouteCalibrationSummary -ProbeCount' install.ps1 \
       && grep -q 'ConvertFrom-Json -ErrorAction Stop' install.ps1 \
       && grep -q 'selected backend margin' install.ps1 \
       && grep -q 'TotalMilliseconds' install.ps1 \
       && grep -q 'PASS {0} ({1}ms)' install.ps1; then
        _record_pass "19.25 install.ps1 renders persisted autoroute calibration decisions"
    else
        _record_fail "19.25 install.ps1 renders persisted autoroute calibration decisions" \
            "PowerShell calibration must read the cache JSON, print selected backend margins, and show per-probe elapsed ms"
    fi
    if grep -q 'Get-AutorouteCachePathForInstall' install.ps1 \
       && grep -q 'LocalApplicationData' install.ps1 \
       && ! grep -q 'KEYHOG_.*AUTOROUTE_CACHE' install.ps1; then
        _record_pass "19.26 install.ps1 resolves the same persistent autoroute cache path"
    else
        _record_fail "19.26 install.ps1 resolves the same persistent autoroute cache path" \
            "missing LocalApplicationData default or stale autoroute cache env override remains"
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
    path_env="PATH=$sb/bin HOME=$h SHELL=/bin/bash MOCK_RELEASES=$FIX_DIR/releases_normal.json MOCK_ASSET=$FIX_DIR/fake_keyhog_healthy MOCK_SHA=match MOCK_LDD=ok KEYHOG_VERSION=v9.9.9"
    path_cmd1="env -i $path_env MOCK_STATE_DIR=$h/state-1 sh $INSTALL_SH --install-dir=$h/.local/bin --no-color"
    path_cmd2="env -i $path_env MOCK_STATE_DIR=$h/state-2 sh $INSTALL_SH --install-dir=$h/.local/bin --no-color"
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
    mac_cmd="env -i PATH=$sb/bin HOME=$h SHELL=/bin/bash MOCK_STATE_DIR=$h/state MOCK_RELEASES=$FIX_DIR/releases_normal.json MOCK_ASSET=$FIX_DIR/fake_keyhog_healthy MOCK_SHA=match MOCK_LDD=ok KEYHOG_VERSION=v9.9.9 sh $INSTALL_SH --install-dir=$h/.local/bin --no-color"
    out=$(printf 'y\ny\ny\nn\nn\n' | script -qefc "$mac_cmd" /dev/null 2>&1); st=$?
    expect_status "21.5 macOS bash PATH setup install exits 0" 0 "$st"
    expect_file   "21.6 macOS bash PATH setup writes login profile" "$h/.bash_profile"
    expect_nofile "21.7 macOS bash PATH setup does not write .bashrc" "$h/.bashrc"
    rm -rf "$sb" "$h"

    reset_mocks
    sb=$(build_sandbox Linux x86_64 no no no); h=$(newhome)
    zsh_env="PATH=$sb/bin HOME=$h SHELL=/bin/zsh MOCK_RELEASES=$FIX_DIR/releases_normal.json MOCK_ASSET=$FIX_DIR/fake_keyhog_healthy MOCK_SHA=match MOCK_LDD=ok KEYHOG_VERSION=v9.9.9"
    zsh_cmd1="env -i $zsh_env MOCK_STATE_DIR=$h/zsh-state-1 sh $INSTALL_SH --install-dir=$h/.local/bin --no-color"
    zsh_cmd2="env -i $zsh_env MOCK_STATE_DIR=$h/zsh-state-2 sh $INSTALL_SH --install-dir=$h/.local/bin --no-color"
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

    # 21.14 A hand-edited rc that spells INSTALL_DIR with $HOME (not the absolute
    #       path install.sh itself writes) must still be RECOGNIZED, so a
    #       re-install reports "already configured" and appends NO duplicate
    #       keyhog PATH block. Before the fix, path_setup_entry_present grepped
    #       only the absolute path and missed the $HOME form.
    reset_mocks
    sb=$(build_sandbox Linux x86_64 no no no); h=$(newhome)
    # Pre-seed .bashrc with a $HOME-form keyhog block, literal '$HOME' preserved
    # by the single-quoted printf format string.
    printf '\n# keyhog\nexport PATH="$HOME/.local/bin:$PATH"\n' > "$h/.bashrc"
    home_env="PATH=$sb/bin HOME=$h SHELL=/bin/bash MOCK_RELEASES=$FIX_DIR/releases_normal.json MOCK_ASSET=$FIX_DIR/fake_keyhog_healthy MOCK_SHA=match MOCK_LDD=ok KEYHOG_VERSION=v9.9.9"
    home_cmd="env -i $home_env MOCK_STATE_DIR=$h/home-state sh $INSTALL_SH --install-dir=$h/.local/bin --no-color"
    out=$(printf 'y\ny\ny\nn\nn\n' | script -qefc "$home_cmd" /dev/null 2>&1); st=$?
    expect_status "21.14 install over a \$HOME-form rc exits 0" 0 "$st"
    expect_match  "21.15 \$HOME-form PATH entry recognized as already configured" "PATH already configured" "$out"
    home_markers=$(grep -c '^# keyhog$' "$h/.bashrc" 2>/dev/null || true)
    if [ "$home_markers" = "1" ]; then
        _record_pass "21.16 \$HOME-form rc gets no duplicate keyhog PATH block"
    else
        _record_fail "21.16 \$HOME-form rc gets no duplicate keyhog PATH block" \
            "markers=$home_markers rc=$(cat "$h/.bashrc" 2>/dev/null)"
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
    skip "21.14 install over a \$HOME-form rc exits 0" "script(1) PTY helper unavailable"
    skip "21.15 \$HOME-form PATH entry recognized as already configured" "script(1) PTY helper unavailable"
    skip "21.16 \$HOME-form rc gets no duplicate keyhog PATH block" "script(1) PTY helper unavailable"
fi

# ======================================================================
# 22. cross-installer coherence (install.sh vs install.ps1)
# ======================================================================
# The minisign release public key is the installer's trust root: it verifies
# every downloaded release signature, so it MUST be baked into each bootstrap
# installer (fetching it would defeat the verification it enables). That makes
# the value unavoidably duplicated across the sh and ps1 installers, and the one
# real hazard is DRIFT - a key rotation that updates only one platform. Lock the
# two together so a divergence fails CI instead of shipping a broken installer.
printf '\n[22] cross-installer coherence\n'
INSTALL_PS1="$ROOT/install.ps1"
if [ -f "$INSTALL_PS1" ]; then
    sh_key=$(sed -n 's/^RELEASE_PUBLIC_KEY="\([^"]*\)".*/\1/p' "$INSTALL_SH" | head -n1)
    ps_key=$(sed -n "s/.*ReleasePublicKey *= *'\([^']*\)'.*/\1/p" "$INSTALL_PS1" | head -n1)
    if [ -n "$sh_key" ]; then _record_pass "22.1 install.sh pins a minisign public key"
    else _record_fail "22.1 install.sh pins a minisign public key" "no RELEASE_PUBLIC_KEY found"; fi
    if [ -n "$ps_key" ]; then _record_pass "22.2 install.ps1 pins a minisign public key"
    else _record_fail "22.2 install.ps1 pins a minisign public key" "no ReleasePublicKey found"; fi
    if [ -n "$sh_key" ] && [ "$sh_key" = "$ps_key" ]; then
        _record_pass "22.3 both installers pin the SAME minisign key (no drift)"
    else
        _record_fail "22.3 both installers pin the SAME minisign key (no drift)" "sh=[$sh_key] ps=[$ps_key]"
    fi
else
    skip "22.1 install.sh pins a minisign public key" "install.ps1 not found"
    skip "22.2 install.ps1 pins a minisign public key" "install.ps1 not found"
    skip "22.3 both installers pin the SAME minisign key (no drift)" "install.ps1 not found"
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

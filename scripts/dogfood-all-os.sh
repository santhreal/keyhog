#!/usr/bin/env bash
# Deep cross-OS dogfooding for keyhog.
#
# Builds the real binary and exercises two real surfaces on every machine in
# the fleet, then prints a per-OS PASS / FAIL / SKIP matrix:
#   [cli]     the headless CLI on real inputs (planted secrets, clean trees,
#             source-failure exit codes, lossy binary stdin)
#   [install] the real installer (install.sh --from-file -> doctor self-test ->
#             seeded scan -> SARIF -> rollback), via the shared install proof
# The point is to catch OS-specific breakage (path/encoding handling,
# #[cfg(unix)] routes, mmap windowing, native-dep builds, the install + doctor
# path) that a single-Linux unit gate never sees.
#
# Unreachable machines fail the required matrix by default. Set ALLOW_OS_SKIP=1
# only for an explicit diagnostic run where missing machines are not release
# evidence.
#
#   scripts/dogfood-all-os.sh                  # every machine
#   scripts/dogfood-all-os.sh work-linux win   # a subset (names below)
#   PROFILE=dev scripts/dogfood-all-os.sh      # faster debug build for a smoke run
#
# Run from the work-linux hub: it holds the source tree and has ssh entries for
# every box (santhserver, tt-macbook, windows-thinkpad). Knobs: PROFILE
# (release-fast), CONNECT_TIMEOUT (8s).
#
# Machine registry  (name | transport | os | tree | cargo-target | features)
#   work-linux    local ssh work-linux   linux   NFS tree              GPU host, default features
#   santhserver   ssh santhserver        linux   /mnt/santh-desktop    portable (no system libs assumed)
#   macbook       ssh tt-macbook         macos   discovered            portable
#   win           ssh windows-thinkpad   windows shipped to C:         portable (Windows-shippable)
set -uo pipefail

PROFILE="${PROFILE:-release-fast}"
CONNECT_TIMEOUT="${CONNECT_TIMEOUT:-8}"
ALLOW_OS_SKIP="${ALLOW_OS_SKIP:-0}"
SSH=(ssh -o BatchMode=yes -o "ConnectTimeout=${CONNECT_TIMEOUT}")
NFS_TREE="/media/mukund-thiru/SanthData/Santh/software/keyhog"
ALL=(work-linux santhserver macbook win)

# --- per-machine config -----------------------------------------------------
# Echoes: transport_host|os|tree|cargo_target|cargo_features
config_for() {
  case "$1" in
    work-linux)  echo "local|linux|${NFS_TREE}|/mnt/FlareTraining/santh-archive/cargo-target|" ;;
    # user@tailscale-ip (the fleet is reached over Tailscale, not the LAN; the
    # ~/.ssh/config aliases still carry stale on-site LAN IPs). Absolute remote
    # paths -- `cd '$tree'` is single-quoted, so a ~ would not expand.
    santhserver) echo "santh@100.110.246.73|linux|/mnt/santh-desktop/software/keyhog|/var/santh-cargo-target|--no-default-features --features portable" ;;
    macbook)     echo "thiruthangarathinam@100.103.221.82|macos|/Users/thiruthangarathinam/Santh/software/keyhog|/Users/thiruthangarathinam/.cache/keyhog-cargo-target|--no-default-features --features portable" ;;
    win)         echo "windows-thinkpad|windows|-|C:/cargo-target|" ;;
    *)           echo "" ;;
  esac
}

# --- the dogfood payload run on a unix target (arg1 = built binary) ---------
# Single-quoted heredoc: nothing here is expanded locally; it runs on the box.
unix_payload() {
  cat <<'PAYLOAD'
set -uo pipefail
KH="$1"; fail=0
pass() { echo "  PASS $1"; }
fail_check() {
  echo "  FAIL $1"
  [ $# -gt 1 ] && printf '    %s\n' "$2"
  fail=1
}
expect_rc() {
  label="$1"; actual="$2"; expected="$3"; log="${4:-}"
  if [ "$actual" -eq "$expected" ]; then
    pass "$label"
  else
    fail_check "$label" "exit $actual, expected $expected"
    [ -n "$log" ] && sed -n '1,30p' "$log" | sed 's/^/    stderr: /'
  fi
}
expect_version() {
  out="$1"; rc="$2"; log="$3"
  if [ "$rc" -eq 0 ] && printf '%s' "$out" | grep -q KeyHog; then
    pass "version"
  else
    fail_check "version" "version command exit $rc or unexpected output"
    sed -n '1,20p' "$log" | sed 's/^/    stderr: /'
  fi
}
expect_aws_json() {
  report="$1"
  python3 - "$report" <<'PY'
import json
import pathlib
import sys

report = pathlib.Path(sys.argv[1])
try:
    data = json.loads(report.read_text())
except Exception as exc:
    print(f"parse failed for {report}: {exc}", file=sys.stderr)
    raise SystemExit(1)

if isinstance(data, list):
    findings = data
elif isinstance(data, dict):
    findings = data.get("findings", [])
else:
    print(f"unexpected JSON root {type(data).__name__}", file=sys.stderr)
    raise SystemExit(1)

for finding in findings:
    if not isinstance(finding, dict):
        continue
    detector = str(finding.get("detector_id", "")).lower()
    credential = str(finding.get("credential_redacted", "")).lower()
    if detector == "aws-access-key" or "akiaz4rnvt5qw3mxk7pd" in credential:
        raise SystemExit(0)

print(f"no planted AWS finding in {report}", file=sys.stderr)
raise SystemExit(1)
PY
}
t="$(mktemp -d)"; trap 'rm -rf "$t"' EXIT
printf 'aws_access_key_id = AKIAZ4RNVT5QW3MXK7PD\ngithub_token = ghp_0123456789abcdefghijklmnopqrstuvwxyz\n' > "$t/leak.env"
printf 'nothing secret here, just prose\n' > "$t/clean.txt"

version_out="$("$KH" --version 2>"$t/version.err")"; version_rc=$?
expect_version "$version_out" "$version_rc" "$t/version.err"

"$KH" scan "$t/leak.env" --backend simd --format json --output "$t/leak.json" >"$t/leak.out" 2>"$t/leak.err"
rc=$?
expect_rc "planted secret -> exit 1" "$rc" 1 "$t/leak.err"
if expect_aws_json "$t/leak.json" 2>"$t/leak.parse.err"; then
  pass "planted secret -> aws-access-key detector"
else
  fail_check "planted secret -> aws-access-key detector" "$(cat "$t/leak.parse.err")"
fi

"$KH" scan "$t/clean.txt" --backend simd >"$t/clean.out" 2>"$t/clean.err"
expect_rc "clean tree -> exit 0" "$?" 0 "$t/clean.err"

"$KH" scan --git-history "$t" --backend simd >"$t/history.out" 2>"$t/history.err"
expect_rc "git-history non-repo -> exit 2 (fail-closed)" "$?" 2 "$t/history.err"

printf '\x00\x01aws_access_key_id = AKIAZ4RNVT5QW3MXK7PD\n' | "$KH" scan --stdin --backend simd >"$t/stdin.out" 2>"$t/stdin.err"
expect_rc "binary stdin (lossy) -> exit 1" "$?" 1 "$t/stdin.err"
exit $fail
PAYLOAD
}

# --- runners ----------------------------------------------------------------
# Run a command on a unix machine, locally or over ssh depending on transport.
on_unix() { local host="$1"; shift; if [ "$host" = local ]; then bash -c "$*"; else "${SSH[@]}" "$host" "$*"; fi; }

run_unix() {  # $1 name  $2 host(or 'local')  $3 os  $4 tree  $5 target  $6 features
  local name="$1" host="$2" os="$3" tree="$4" tgt="$5" feats="$6"
  echo "----- $name ($host, unix) -----"
  if [ "$host" = local ]; then
    [ -d "$tree" ] || { echo "  local tree missing ($tree) -- run this on the work-linux hub"; return 64; }
  elif ! timeout 25 "${SSH[@]}" "$host" true 2>/dev/null; then
    # `timeout` bounds the probe: TCP connect succeeds but auth can hang
    # indefinitely on a box whose Tailscale-SSH ACL requires an interactive
    # `check` (e.g. santhserver). Without it one stuck box hangs the whole
    # matrix; with it that box SKIPs loudly like any other unreachable host.
    echo "  unreachable (or auth timed out)"; return 64
  fi
  echo "  building (profile=$PROFILE ${feats:-default})..."
  local build_log
  build_log="$(mktemp)"
  if ! on_unix "$host" "cd '$tree' && CARGO_TARGET_DIR='$tgt' cargo build --profile '$PROFILE' -p keyhog $feats" >"$build_log" 2>&1; then
    echo "  FAIL build"
    sed -n '1,80p' "$build_log" | sed 's/^/    /'
    rm -f "$build_log"
    return 1
  fi
  rm -f "$build_log"
  # cargo's `dev` profile emits to target/debug; custom profiles use their own name.
  local pdir="$PROFILE"; [ "$PROFILE" = dev ] && pdir=debug
  local bin="$tgt/$pdir/keyhog"
  local rc=0

  # Phase 1 -- headless CLI: real exit codes, detector hits, clean tree,
  # fail-closed git-history, lossy binary stdin.
  echo "  [cli]"
  if [ "$host" = local ]; then unix_payload | bash -s "$bin"
  else unix_payload | "${SSH[@]}" "$host" "bash -s '$bin'"; fi
  [ $? -ne 0 ] && rc=1

  # Phase 2 -- installer. Reuses the canonical local-build install proof
  # (install.sh --from-file -> backup/atomic-swap -> `keyhog doctor` self-test
  # -> seeded scan -> SARIF -> rollback). Same script every OS runs in CI, so
  # the dogfood exercises the exact installer users get, not a parallel copy.
  echo "  [install]"
  local install_script="tests/install/linux/install_from_local_build.sh"
  [ "$os" = macos ] && install_script="tests/install/macos/install_from_local_build.sh"
  on_unix "$host" "bash '$tree/$install_script' '$bin'" || rc=1

  return $rc
}

run_win() {  # ships source from the NFS tree, builds + dogfoods locally on Windows
  local host="windows-thinkpad"
  echo "----- win ($host, windows) -----"
  if ! "${SSH[@]}" "$host" "powershell -NoProfile -Command exit 0" 2>/dev/null; then
    echo "  unreachable"; return 64
  fi
  echo "  shipping source + ps1 to C:\\keyhog-dogfood ..."
  "${SSH[@]}" "$host" 'powershell -NoProfile -Command "New-Item -ItemType Directory -Force C:\keyhog-dogfood\src | Out-Null"' >/dev/null 2>&1
  tar -C "$NFS_TREE" --exclude=target --exclude=.git -cf - crates detectors Cargo.toml Cargo.lock install.ps1 \
    | "${SSH[@]}" "$host" 'tar.exe -x -f - -C C:\keyhog-dogfood\src' 2>/dev/null
  scp -q -o BatchMode=yes "$NFS_TREE/scripts/dogfood-windows.ps1" "$host:C:/keyhog-dogfood/dogfood-windows.ps1" 2>/dev/null
  "${SSH[@]}" "$host" "powershell -NoProfile -ExecutionPolicy Bypass -File C:\\keyhog-dogfood\\dogfood-windows.ps1 -Source C:\\keyhog-dogfood\\src -Profile $PROFILE"
}

# --- driver -----------------------------------------------------------------
TARGETS=("$@"); [ ${#TARGETS[@]} -eq 0 ] && TARGETS=("${ALL[@]}")
declare -A RESULT
for name in "${TARGETS[@]}"; do
  cfg="$(config_for "$name")"
  if [ -z "$cfg" ]; then echo "unknown machine: $name (known: ${ALL[*]})"; continue; fi
  IFS='|' read -r host os tree tgt feats <<<"$cfg"
  if [ "$os" = "windows" ]; then run_win; rc=$?; else run_unix "$name" "$host" "$os" "$tree" "$tgt" "$feats"; rc=$?; fi
  case $rc in
    0)  RESULT[$name]="PASS" ;;
    64) RESULT[$name]="SKIP (unreachable)" ;;
    *)  RESULT[$name]="FAIL" ;;
  esac
done

echo
echo "================ keyhog cross-OS dogfood ================"
worst=0
for name in "${TARGETS[@]}"; do
  printf "  %-12s %s\n" "$name" "${RESULT[$name]:-?}"
  case "${RESULT[$name]:-}" in FAIL*) worst=1 ;; esac
  case "${RESULT[$name]:-}" in SKIP*) [ "$ALLOW_OS_SKIP" = "1" ] || worst=1 ;; esac
done
echo "========================================================="
if [ $worst -eq 0 ]; then
  if [ "$ALLOW_OS_SKIP" = "1" ]; then
    echo "RESULT: OK (diagnostic mode allowed skipped machines)"
  else
    echo "RESULT: OK (every required machine passed)"
  fi
else
  echo "RESULT: FAIL (required machine failed or was skipped)"
fi
exit $worst

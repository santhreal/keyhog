#!/usr/bin/env bash
#
# Proof that install.sh translates a freshly-BUILT binary into a working
# install on this OS — the gap the mocked detection-path scenarios
# (scenarios.sh / edge_cases.sh) and the published-release smoke
# (integration-smoke.yml) leave open: neither proves that the CURRENT
# source, once built, installs and actually runs end-to-end.
#
# Uses install.sh's `--from-file` path (offline/air-gapped install of a
# pre-built artifact) to install the binary under test into a throwaway
# prefix, then drives the real post-install surface: --version, the native
# `keyhog doctor` self-test (must exit 0), a seeded scan (must exit 1 with a
# finding), and SARIF emission. Also proves the local checksum gate and the
# premium interactive wizard (best-effort, needs a PTY via `expect`).
#
# Usage:  install_from_local_build.sh [path-to-keyhog-binary]
#   binary resolves from: $1  ->  $KEYHOG_TEST_BINARY  ->  common target dirs.
# CI builds keyhog for the host OS/variant, then runs this with that binary.

set -u

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
INSTALL_SH="$ROOT/install.sh"
[ -f "$INSTALL_SH" ] || { echo "install.sh not found at $INSTALL_SH" >&2; exit 1; }

# ------------------------------------------------------------------
# Resolve the binary under test.
# ------------------------------------------------------------------
BIN="${1:-${KEYHOG_TEST_BINARY:-}}"
if [ -z "$BIN" ]; then
    for cand in \
        "${CARGO_TARGET_DIR:-$ROOT/target}/release-fast/keyhog" \
        "${CARGO_TARGET_DIR:-$ROOT/target}/release/keyhog" \
        "$ROOT/target/release-fast/keyhog" \
        "$ROOT/target/release/keyhog"; do
        [ -x "$cand" ] && { BIN="$cand"; break; }
    done
fi
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
    echo "no keyhog binary found; pass one as \$1 or build with" >&2
    echo "  cargo build -p keyhog --no-default-features --features portable --profile release-fast" >&2
    exit 1
fi
echo "binary under test: $BIN"

pass=0
fail=0
failed_names=""
ok_()   { printf '  \033[32m✓\033[0m %s\n' "$1"; pass=$((pass + 1)); }
bad_()  { printf '  \033[31m✗\033[0m %s\n' "$1"; [ -n "${2:-}" ] && printf '    %s\n' "$2"; fail=$((fail + 1)); failed_names="$failed_names\n  - $1"; }
skip_() { printf '  \033[33m-\033[0m %s (skipped: %s)\n' "$1" "$2"; }

# Throwaway HOME + prefix so the test never touches the real environment.
WORK="$(mktemp -d -t kh-fromfile-XXXXXX)"
trap 'rm -rf "$WORK"' EXIT INT TERM
export HOME="$WORK/home"
mkdir -p "$HOME"
PREFIX="$WORK/bin"
KEYHOG="$PREFIX/keyhog"

# Seeded credentials as a single base64 blob (same approach as
# integration-smoke.yml): the test file then contains no recognisable secret
# pattern for push-protection, while the scanner sees fully-formed strings.
SEED='T1BFTkFJX0FQSV9LRVk9c2stcHJvai1BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFfQkJCQkJCQkJCQkJCQkJCQkJCQkJCQkJCX0NDQ0NDQ0NDQ0NDQ0NDCkFXU19BQ0NFU1NfS0VZX0lEPUFLSUFRVlpTTDFBWVA5UEVYQU1QCkFXU19TRUNSRVRfQUNDRVNTX0tFWT13SmFsclhVdG5GRU1JL0s3TURFTkcvYlB4UmZpQ1lESUZGRVhBTVBLClNMQUNLX1RPS0VOPXhveGItMTIzNDU2Nzg5MC0xMjM0NTY3ODkwMTIzNC1BYkNkRWZHaElqS2xNbk9wUXJTdFV2V3gKR0hfUEFUPWdocF9BQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUFBQUEK'
mkdir -p "$WORK/scanme"
if command -v base64 >/dev/null 2>&1; then
    printf '%s' "$SEED" | base64 -d > "$WORK/scanme/seeded.env" 2>/dev/null || \
    printf '%s' "$SEED" | base64 --decode > "$WORK/scanme/seeded.env"
else
    python3 -c "import base64,sys;sys.stdout.buffer.write(base64.b64decode(sys.stdin.read()))" <<<"$SEED" > "$WORK/scanme/seeded.env"
fi

run_install() {  # args... -> install.sh; output captured to $OUT, status to $RC
    OUT=$(sh "$INSTALL_SH" --from-file="$BIN" --install-dir="$PREFIX" --no-color "$@" 2>&1)
    RC=$?
}

# ==================================================================
# A. Non-interactive --from-file install of the freshly-built binary.
# ==================================================================
printf '\nA. install --from-file (non-interactive)\n'
rm -f "$KEYHOG"
run_install --yes --no-prompt
[ "$RC" = "0" ] && ok_ "A.1 installer exits 0" || bad_ "A.1 installer exits 0" "rc=$RC; $(printf '%s' "$OUT" | tail -3)"
[ -x "$KEYHOG" ] && ok_ "A.2 binary placed at install-dir" || bad_ "A.2 binary placed at install-dir"

if [ -x "$KEYHOG" ]; then
    "$KEYHOG" --version >/dev/null 2>&1 && ok_ "A.3 installed --version runs" || bad_ "A.3 installed --version runs"

    # The native doctor self-test is the real "does this build work on this
    # host" gate: it plants a synthetic secret and confirms detection.
    if "$KEYHOG" doctor >/dev/null 2>&1; then
        ok_ "A.4 keyhog doctor exits 0 (healthy)"
    else
        bad_ "A.4 keyhog doctor exits 0 (healthy)" "doctor: $("$KEYHOG" doctor 2>&1 | tail -3)"
    fi

    # Seeded scan: must find the planted secrets and exit 1.
    "$KEYHOG" scan "$WORK/scanme" >/dev/null 2>&1; sc=$?
    [ "$sc" = "1" ] && ok_ "A.5 seeded scan exits 1 (findings)" || bad_ "A.5 seeded scan exits 1 (findings)" "exit=$sc"

    # Clean dir: exit 0.
    mkdir -p "$WORK/empty"
    "$KEYHOG" scan "$WORK/empty" >/dev/null 2>&1; ec=$?
    [ "$ec" = "0" ] && ok_ "A.6 empty scan exits 0" || bad_ "A.6 empty scan exits 0" "exit=$ec"

    # SARIF emission is well-formed and carries results.
    "$KEYHOG" scan "$WORK/scanme" --format sarif --output "$WORK/out.sarif" >/dev/null 2>&1 || true
    if [ -s "$WORK/out.sarif" ] && grep -q '2.1.0' "$WORK/out.sarif" && grep -q '"results"' "$WORK/out.sarif"; then
        ok_ "A.7 SARIF output well-formed with results"
    else
        bad_ "A.7 SARIF output well-formed with results"
    fi
fi

# ==================================================================
# B. Local checksum gate (--from-file PATH.sha256 sibling).
# ==================================================================
printf '\nB. --from-file checksum gate\n'
sha_tool=""
command -v sha256sum >/dev/null 2>&1 && sha_tool="sha256sum"
command -v shasum    >/dev/null 2>&1 && [ -z "$sha_tool" ] && sha_tool="shasum -a 256"
if [ -z "$sha_tool" ]; then
    skip_ "B.* checksum gate" "no sha256sum/shasum on host"
else
    STAGE="$WORK/stage"; mkdir -p "$STAGE"
    cp "$BIN" "$STAGE/keyhog"
    $sha_tool "$STAGE/keyhog" | awk -v f="$STAGE/keyhog" '{print $1"  "f}' > "$STAGE/keyhog.sha256"
    OUT=$(sh "$INSTALL_SH" --from-file="$STAGE/keyhog" --install-dir="$PREFIX" --no-color --yes --no-prompt 2>&1); RC=$?
    { [ "$RC" = "0" ] && printf '%s' "$OUT" | grep -q "SHA256 verified"; } \
        && ok_ "B.1 correct sibling .sha256 verifies + installs" \
        || bad_ "B.1 correct sibling .sha256 verifies + installs" "rc=$RC"

    printf '%s\n' "0000000000000000000000000000000000000000000000000000000000000000  $STAGE/keyhog" > "$STAGE/keyhog.sha256"
    OUT=$(sh "$INSTALL_SH" --from-file="$STAGE/keyhog" --install-dir="$PREFIX" --no-color --yes --no-prompt 2>&1); RC=$?
    { [ "$RC" != "0" ] && printf '%s' "$OUT" | grep -q "SHA256 mismatch"; } \
        && ok_ "B.2 tampered .sha256 is refused (no install)" \
        || bad_ "B.2 tampered .sha256 is refused (no install)" "rc=$RC"
fi

# ==================================================================
# C. Missing-file error path.
# ==================================================================
printf '\nC. --from-file error handling\n'
OUT=$(sh "$INSTALL_SH" --from-file="$WORK/does-not-exist" --install-dir="$PREFIX" --no-color --yes --no-prompt 2>&1); RC=$?
{ [ "$RC" != "0" ] && printf '%s' "$OUT" | grep -q "no such file"; } \
    && ok_ "C.1 missing --from-file path fails cleanly" \
    || bad_ "C.1 missing --from-file path fails cleanly" "rc=$RC"

# ==================================================================
# D. Premium interactive path (best-effort; needs a PTY via expect).
# ==================================================================
printf '\nD. premium interactive install (best-effort)\n'
if command -v expect >/dev/null 2>&1; then
    rm -f "$KEYHOG"
    # Write the driver to a file so the shell interpolates the (space-free)
    # paths as BARE spawn args; escaping them inside `expect -c "..."` made the
    # quotes part of the filename. `\r` and the {..} regexes stay literal for Tcl.
    EXP="$WORK/drive.exp"
    cat > "$EXP" <<EXPECT
set timeout 120
spawn sh $INSTALL_SH --from-file=$BIN --install-dir=$PREFIX --no-color
expect {
    -re {[Pp]roceed}     { send "y\r"; exp_continue }
    -re {PATH}           { send "n\r"; exp_continue }
    -re {[Cc]ompletions} { send "n\r"; exp_continue }
    -re {pre-commit}     { send "n\r"; exp_continue }
    eof
}
EXPECT
    exp_log=$(expect "$EXP" 2>&1) || true
    if [ -x "$KEYHOG" ] && "$KEYHOG" --version >/dev/null 2>&1; then
        ok_ "D.1 interactive wizard installs a working binary"
    else
        bad_ "D.1 interactive wizard installs a working binary" "$(printf '%s' "$exp_log" | tail -4)"
    fi
else
    skip_ "D.1 interactive wizard" "expect not installed (non-interactive path proven in A)"
fi

# ==================================================================
printf '\n------------------------------------------------------------\n'
total=$((pass + fail))
if [ "$fail" -eq 0 ]; then
    printf '\033[32m%d / %d passed.\033[0m\n' "$pass" "$total"
    exit 0
else
    printf '\033[31m%d / %d failed.\033[0m\n' "$fail" "$total"
    printf '%b\n' "$failed_names"
    exit 1
fi

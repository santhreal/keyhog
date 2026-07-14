#!/usr/bin/env bash
#
# Exercise install.sh across detection paths + modes.
#
# Strategy: mock uname / nvidia-smi / ldconfig via a per-scenario
# sandbox dir prepended to PATH so we can simulate macOS, no-GPU
# Linux, NVIDIA-but-no-libcuda, etc., from any host without hitting
# the network or rewriting the script.
#
# Network: --diagnose does call the GitHub releases API to resolve
# the latest tag. We use KEYHOG_VERSION=v0.5.29 throughout so that
# call is skipped. The download step is never exercised by these
# tests (they only run --diagnose); a separate live-install test
# covers the download path against a real release.

set -u

INSTALL_SH="$(cd "$(dirname "$0")/../../.." && pwd)/install.sh"
if [ ! -f "$INSTALL_SH" ]; then
    echo "install.sh not found at $INSTALL_SH" >&2
    exit 1
fi

pass=0
fail=0
failed_names=""

expect() {
    name=$1
    pattern=$2
    output=$3
    if printf '%s' "$output" | grep -qE -- "$pattern"; then
        printf '  \033[32m✓\033[0m %s\n' "$name"
        pass=$((pass + 1))
    else
        printf '  \033[31m✗\033[0m %s\n' "$name"
        printf '    expected pattern: %s\n' "$pattern"
        printf '    got (first 15 lines):\n'
        printf '%s\n' "$output" | head -15 | sed 's/^/      /'
        fail=$((fail + 1))
        failed_names="$failed_names\n  - $name"
    fi
}

# build_sandbox <name> <os> <arch> <has_nvidia_smi> <has_libcuda> [has_toolkit]
# Constructs a sandbox bin/ dir of mocks + symlinks to real coreutils. GPU mocks
# remain available to prove platform selection is independent of device state.
build_sandbox() {
    name=$1
    os=$2
    arch=$3
    nv=$4
    lib=$5
    toolkit=${6:-no}
    sb=$(mktemp -d -t "kh-test-${name}-XXXXXX")
    mkdir -p "$sb/bin"

    # Symlink real tools we need. Skip uname/nvidia-smi/ldconfig/curl
    # because we're about to write mocks for those, and `cat > FILE`
    # on a pre-existing symlink dereferences and fails on the (root-
    # owned) symlink target.
    for tool in sh dash bash grep sed head tail awk cut tr cat mv cp rm mkdir rmdir \
                chmod chown ls find dirname basename printf date sleep test true false \
                command type stat readlink realpath sort uniq wc env tee xargs; do
        real=$(command -v "$tool" 2>/dev/null) || continue
        ln -sf "$real" "$sb/bin/$tool" 2>/dev/null || true
    done

    # Mock uname.
    cat > "$sb/bin/uname" <<EOF
#!/bin/sh
case "\$1" in
  -s) echo "$os" ;;
  -m) echo "$arch" ;;
  *)  echo "$os" ;;
esac
EOF
    chmod +x "$sb/bin/uname"

    # Mock nvidia-smi (or absent).
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
    fi

    # Mock ldconfig.
    if [ "$lib" = "yes" ]; then
        cat > "$sb/bin/ldconfig" <<'EOF'
#!/bin/sh
echo "        libcuda.so.1 (libc6,x86-64) => /usr/lib/x86_64-linux-gnu/libcuda.so.1"
EOF
    else
        cat > "$sb/bin/ldconfig" <<'EOF'
#!/bin/sh
# no libcuda
exit 0
EOF
    fi
    chmod +x "$sb/bin/ldconfig"

    # Mock nvcc when requested; unified asset selection ignores its presence.
    if [ "$toolkit" = "yes" ]; then
        cat > "$sb/bin/nvcc" <<'EOF'
#!/bin/sh
echo "Cuda compilation tools, release 12.0"
EOF
        chmod +x "$sb/bin/nvcc"
    fi

    # curl: stub so resolve_tag short-circuits via KEYHOG_VERSION.
    # If the script does hit network we want to know.
    cat > "$sb/bin/curl" <<'EOF'
#!/bin/sh
echo "TEST_FAIL: install.sh hit network in a unit test" >&2
exit 1
EOF
    chmod +x "$sb/bin/curl"

    echo "$sb"
}

# A throwaway HOME (with no keyhog installed) per call. Without this, a
# real keyhog in the developer's $HOME/.local/bin makes --diagnose defer
# to `keyhog doctor`, which never prints the "CUDA detection:" line these
# scenarios assert - so the suite passed on clean CI but failed on any dev
# box with keyhog installed.
clean_home() { mktemp -d -t kh-diag-home-XXXXXX; }

run_diagnose() {
    sb=$1
    ch=$(clean_home)
    env -i PATH="$sb/bin" HOME="$ch" \
            KEYHOG_VERSION=v0.5.29 \
            sh "$INSTALL_SH" --diagnose --no-color 2>&1
    rm -rf "$ch"
}

# ============================================================
# Scenario A: Linux x86_64, NVIDIA + libcuda
# ============================================================
printf '\n[A] Linux x86_64, NVIDIA + libcuda + toolkit (the desktop case)\n'
sb=$(build_sandbox "A" "Linux" "x86_64" "yes" "yes" "yes")
out=$(run_diagnose "$sb")
expect "A.1 unified Linux asset picked" "Would install: keyhog-linux-x86_64$" "$out"
expect "A.2 runtime backend selection"  "runtime CUDA/WGPU probe"             "$out"
rm -rf "$sb"

# ============================================================
# Scenario B: Linux x86_64, NVIDIA but NO libcuda
# ============================================================
printf '\n[B] Linux x86_64, NVIDIA GPU but libcuda.so missing\n'
sb=$(build_sandbox "B" "Linux" "x86_64" "yes" "no")
out=$(run_diagnose "$sb")
expect "B.1 unified Linux asset picked" "Would install: keyhog-linux-x86_64$" "$out"
rm -rf "$sb"

# ============================================================
# Scenario C: Linux x86_64, no GPU at all
# ============================================================
printf '\n[C] Linux x86_64, no GPU\n'
sb=$(build_sandbox "C" "Linux" "x86_64" "no" "no")
out=$(run_diagnose "$sb")
expect "C.1 unified Linux asset picked" "Would install: keyhog-linux-x86_64$" "$out"
rm -rf "$sb"

# ============================================================
# Scenario D: macOS arm64
# ============================================================
printf '\n[D] macOS arm64 (Apple Silicon)\n'
sb=$(build_sandbox "D" "Darwin" "arm64" "no" "no")
out=$(run_diagnose "$sb")
expect "D.1 mac-aarch64 picked"         "Would install: keyhog-macos-aarch64"     "$out"
rm -rf "$sb"

# ============================================================
# Scenario E: macOS x86_64 (Intel Mac)
# ============================================================
printf '\n[E] macOS x86_64 (Intel Mac)\n'
sb=$(build_sandbox "E" "Darwin" "x86_64" "no" "no")
out=$(run_diagnose "$sb")
expect "E.1 mac-x86_64 picked"          "Would install: keyhog-macos-x86_64"      "$out"
rm -rf "$sb"

# ============================================================
# Scenario H: Unsupported platform
# ============================================================
printf '\n[H] Unsupported platform exits cleanly\n'
sb=$(build_sandbox "H" "FreeBSD" "x86_64" "no" "no")
hh=$(clean_home)
out=$(env -i PATH="$sb/bin" HOME="$hh" KEYHOG_VERSION=v0.5.29 \
      sh "$INSTALL_SH" --diagnose --no-color 2>&1) || true
rm -rf "$hh"
expect "H.1 reports unsupported"        "Unsupported platform"                    "$out"
rm -rf "$sb"

# ============================================================
# Scenario I: --help renders the authenticated install path
# ============================================================
printf '\n[I] --help mode\n'
out=$(sh "$INSTALL_SH" --help 2>&1)
expect "I.1 help downloads tagged files" "curl -fSLO.*install.sh.*install.sh.minisig" "$out"
expect "I.2 help verifies the signature" "minisign -Vm install.sh -P"                "$out"
expect "I.3 help shows --repair"         "--repair"                                  "$out"
expect "I.4 help shows --diagnose"       "--diagnose"                                "$out"

# ============================================================
# Scenario J: --uninstall on a no-binary host is a safe no-op
# ============================================================
printf '\n[J] --uninstall is a safe no-op when nothing is installed\n'
sb=$(build_sandbox "J" "Linux" "x86_64" "no" "no")
nodir=$(mktemp -d -t kh-noinstall-XXXXXX)
out=$(env -i PATH="$sb/bin" HOME="$nodir" KEYHOG_VERSION=v0.5.29 \
      sh "$INSTALL_SH" --install-dir="$nodir/bin" --uninstall --no-color 2>&1) || true
expect "J.1 says nothing to remove"     "Nothing to remove"                       "$out"
rm -rf "$sb" "$nodir"

# ============================================================
# Summary
# ============================================================
total=$((pass + fail))
printf '\n%s\n' "------------------------------------------------------------"
if [ "$fail" -eq 0 ]; then
    printf '\033[32m%d / %d passed.\033[0m\n' "$pass" "$total"
    exit 0
else
    printf '\033[31m%d / %d failed.\033[0m\n' "$fail" "$total"
    printf '%b\n' "$failed_names"
    exit 1
fi

#!/usr/bin/env sh
#
# KeyHog installer (Linux + macOS).
#
# Curl-pipe-sh quick install:
#   curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh | sh
#
# Interactive install (recommended when you want to pick a variant
# or wire keyhog into your shell + Claude Code + pre-commit):
#   curl -fsSL https://raw.githubusercontent.com/santhsecurity/keyhog/main/install.sh -o keyhog-install.sh
#   sh keyhog-install.sh
#
# Modes:
#   (default)         install or upgrade keyhog
#   --repair          detect a broken install and re-download
#   --diagnose        print full host + binary status, make no changes
#   --calibrate       rerun visible autoroute calibration for the installed binary
#   --uninstall       remove the binary + optionally clean up hooks
#
# Common flags:
#   --version=v0.5.37   pin a release tag (default: latest release with assets)
#   --variant=cuda      force CUDA variant (Linux only)
#   --variant=cpu       force the default WGPU + SIMD variant
#   --install-dir=PATH  override $KEYHOG_INSTALL
#   --from-file=PATH    install a pre-built/pre-downloaded keyhog binary instead
#                       of downloading a release (offline / air-gapped installs,
#                       and CI proving a freshly-built binary). Skips the GitHub
#                       release lookup; still runs the full backup + atomic swap
#                       + verify (`keyhog doctor`) + rollback path. Requires a
#                       sibling PATH.sha256 unless --insecure is explicit.
#   --yes / -y          non-interactive: accept defaults, no prompts
#   --insecure          allow an install only when checksum proof is unavailable;
#                       checksum mismatches still fail
#   --no-color          disable ANSI colors
#   --help / -h         show this help and exit
#
# Env overrides (same effect as the flags):
#   KEYHOG_VERSION, KEYHOG_VARIANT, KEYHOG_INSTALL, KEYHOG_FROM_FILE,
#   KEYHOG_INSECURE_INSTALL, NO_COLOR

set -eu

REPO="santhsecurity/keyhog"
INSTALL_DIR="${KEYHOG_INSTALL:-$HOME/.local/bin}"
VERSION="${KEYHOG_VERSION:-}"
VARIANT="${KEYHOG_VARIANT:-auto}"
FROM_FILE="${KEYHOG_FROM_FILE:-}"
INSECURE_INSTALL="${KEYHOG_INSECURE_INSTALL:-0}"
MODE="install"
INTERACTIVE=1
ASSUME_YES=0
USE_COLOR=1

# ============================================================
# colors / style
# ============================================================

if [ "${NO_COLOR:-}" != "" ] || [ ! -t 1 ]; then
    USE_COLOR=0
fi

setup_colors() {
    if [ "$USE_COLOR" = "1" ]; then
        C_RESET=$(printf '\033[0m')
        C_BOLD=$(printf '\033[1m')
        C_DIM=$(printf '\033[2m')
        C_RED=$(printf '\033[31m')
        C_GREEN=$(printf '\033[32m')
        C_YELLOW=$(printf '\033[33m')
        C_BLUE=$(printf '\033[34m')
        C_CYAN=$(printf '\033[36m')
    else
        C_RESET='' C_BOLD='' C_DIM='' C_RED='' C_GREEN='' C_YELLOW='' C_BLUE='' C_CYAN=''
    fi
}

say()  { printf '%s\n' "$*"; }
info() { printf '%s%s%s\n' "$C_CYAN" "$*" "$C_RESET"; }
ok()   { printf '%s%s%s\n' "$C_GREEN" "$*" "$C_RESET"; }
warn() { printf '%s%s%s\n' "$C_YELLOW" "$*" "$C_RESET"; }
err()  { printf '%s%s%s\n' "$C_RED" "$*" "$C_RESET" >&2; }
dim()  { printf '%s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }

banner() {
    if [ "$INTERACTIVE" = "1" ]; then
        printf '\n%s   KeyHog installer%s   %s(secret scanner, %s)%s\n\n' \
            "$C_BOLD" "$C_RESET" "$C_DIM" "$REPO" "$C_RESET"
    else
        say "keyhog installer (non-interactive)"
    fi
}

# Prompt the user with a default. Usage: prompt "Question?" "default" -> sets $REPLY
prompt() {
    question="$1"
    default="${2:-}"
    if [ "$INTERACTIVE" != "1" ] || [ "$ASSUME_YES" = "1" ]; then
        REPLY="$default"
        return
    fi
    if [ -n "$default" ]; then
        printf '%s %s[%s]%s: ' "$question" "$C_DIM" "$default" "$C_RESET"
    else
        printf '%s: ' "$question"
    fi
    if ! IFS= read -r REPLY < /dev/tty 2>/dev/null; then
        REPLY="$default"
        printf '\n'
        return
    fi
    [ -z "$REPLY" ] && REPLY="$default"
}

# yes/no prompt. Usage: confirm "Question?" "Y" -> returns 0 if yes, 1 if no
confirm() {
    question="$1"
    default="${2:-Y}"
    if [ "$ASSUME_YES" = "1" ]; then
        return 0
    fi
    if [ "$INTERACTIVE" != "1" ]; then
        case "$default" in Y|y) return 0 ;; *) return 1 ;; esac
    fi
    hint="[Y/n]"
    if [ "$default" = "N" ] || [ "$default" = "n" ]; then
        hint="[y/N]"
    fi
    while :; do
        printf '%s %s%s%s ' "$question" "$C_DIM" "$hint" "$C_RESET"
        if ! IFS= read -r ans < /dev/tty 2>/dev/null; then
            ans="$default"
            printf '\n'
        fi
        [ -z "$ans" ] && ans="$default"
        case "$ans" in
            y|Y|yes|YES) return 0 ;;
            n|N|no|NO)   return 1 ;;
            *) warn "Please answer y or n." ;;
        esac
    done
}

# ============================================================
# argument parsing
# ============================================================

usage() {
    # When invoked from a file (`sh install.sh --help`) the header comment IS
    # the help, so reproduce it from $0. Under `curl ... | sh -s -- --help`
    # there is no readable $0 - the old `sed "$0"` printed "sed: can't read sh"
    # and NO help at all. Fall back to a built-in synopsis so --help works on
    # every transport.
    help_text=""
    if [ -r "$0" ]; then
        help_text=$(sed -n '2,35p' "$0" 2>/dev/null | sed 's/^# \{0,1\}//')
    fi
    if [ -n "$help_text" ]; then
        printf '%s\n' "$help_text"
    else
        printf '%s\n' \
"KeyHog installer (Linux + macOS)." \
"" \
"Quick install:" \
"  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh | sh" \
"" \
"Modes:  (default) install/upgrade   --repair   --diagnose   --uninstall" \
"Flags:  --version=vX.Y.Z  --variant=cpu|cuda  --install-dir=PATH" \
"        --from-file=PATH  --yes/-y  --no-prompt  --insecure  --no-color  --help/-h" \
"Env:    KEYHOG_VERSION  KEYHOG_VARIANT  KEYHOG_INSTALL  KEYHOG_FROM_FILE  KEYHOG_INSECURE_INSTALL  NO_COLOR"
    fi
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --repair)          MODE="repair" ;;
        --diagnose)        MODE="diagnose" ;;
        --calibrate)       MODE="calibrate" ;;
        --uninstall)       MODE="uninstall" ;;
        --version=*)       VERSION="${1#--version=}" ;;
        --variant=*)       VARIANT="${1#--variant=}" ;;
        --install-dir=*)   INSTALL_DIR="${1#--install-dir=}" ;;
        --from-file=*)     FROM_FILE="${1#--from-file=}" ;;
        --yes|-y)          ASSUME_YES=1 ;;
        --no-prompt)       INTERACTIVE=0 ;;
        --insecure)        INSECURE_INSTALL=1 ;;
        --no-color)        USE_COLOR=0 ;;
        --help|-h)         usage ;;
        *)
            printf 'Unknown argument: %s\n' "$1" >&2
            printf "Try: %s --help\n" "$0" >&2
            exit 1
            ;;
    esac
    shift
done

# stdin not a TTY (curl | sh) means we can't prompt at all.
[ -t 0 ] || INTERACTIVE=0

setup_colors

# ============================================================
# detection
# ============================================================

OS=$(uname -s | tr '[:upper:]' '[:lower:]')
ARCH=$(uname -m)

# detect_linux_cuda: yes / driver-only / no-gpu
#
# "yes" requires THREE signals, in order of strictness:
#   1. nvidia-smi reports at least one GPU,
#   2. libcuda.so is loadable (in ldconfig or a well-known path),
#   3. the host has a CUDA TOOLKIT installed (nvcc OR /usr/local/cuda
#      OR $CUDA_HOME) - this is the new gate.
#
# Why the third gate: the WGPU build already runs the same vyre AC /
# RulePipeline dispatch on the same NVIDIA card via the wgpu vulkan
# backend. The CUDA variant only wins on truly large scans (>1 GiB)
# and ONLY when the user actively maintains a CUDA install. A driver-
# only host (libcuda.so present but no toolkit) is signalling "I run
# CUDA apps as a consumer, not a developer with the toolkit on PATH" -
# WGPU is the better default there because the binary is smaller, has
# no runtime libcuda lookup, and the dispatch latency penalty against
# native CUDA is in the single-digit-percent range for typical repo
# scans. See task #57.
#
# Earlier versions of this script auto-picked CUDA whenever libcuda
# was loadable, which gave a strictly heavier install for the median
# user with no offsetting throughput win on typical workloads.
detect_linux_cuda() {
    if ! command -v nvidia-smi >/dev/null 2>&1; then
        if [ -d /proc/driver/nvidia ]; then
            printf 'driver-only\n'
            return
        fi
        printf 'no-gpu\n'
        return
    fi
    if ! nvidia-smi -L 2>/dev/null | grep -q "GPU "; then
        printf 'no-gpu\n'
        return
    fi

    # Gate 2: libcuda.so loadable?
    libcuda_present=0
    if ldconfig -p 2>/dev/null | grep -q "libcuda\.so"; then
        libcuda_present=1
    else
        for p in /usr/lib/x86_64-linux-gnu/libcuda.so /usr/lib64/libcuda.so \
                 /usr/local/cuda/lib64/libcuda.so /opt/cuda/lib64/libcuda.so; do
            if [ -e "$p" ]; then
                libcuda_present=1
                break
            fi
        done
    fi
    if [ "$libcuda_present" -eq 0 ]; then
        printf 'driver-only\n'
        return
    fi

    # Gate 3: CUDA toolkit installed? nvcc on PATH OR CUDA_HOME set
    # OR /usr/local/cuda exists OR /opt/cuda exists. Any one suffices.
    if command -v nvcc >/dev/null 2>&1; then
        printf 'yes\n'
        return
    fi
    if [ -n "${CUDA_HOME:-}" ] && [ -d "$CUDA_HOME" ]; then
        printf 'yes\n'
        return
    fi
    if [ -d /usr/local/cuda ] || [ -d /opt/cuda ]; then
        printf 'yes\n'
        return
    fi

    # Driver + libcuda but no toolkit: signal driver-only so the auto
    # path stays on WGPU. User can still --variant=cuda if they want.
    printf 'driver-only\n'
}

gpu_name() {
    nvidia-smi --query-gpu=name --format=csv,noheader 2>/dev/null | head -n 1
}

# resolve_asset: sets ASSET, ASSET_FALLBACK, GPU_NOTE
resolve_asset() {
    ASSET=""
    ASSET_FALLBACK=""
    GPU_NOTE=""

    case "$OS-$ARCH" in
      linux-x86_64|linux-amd64)
        case "$VARIANT" in
          cpu)
            ASSET="keyhog-linux-x86_64"
            GPU_NOTE="Variant=cpu, installing default build (WGPU + SIMD)."
            ;;
          cuda)
            ASSET="keyhog-linux-x86_64-cuda"
            ASSET_FALLBACK=""
            GPU_NOTE="Variant=cuda, installing CUDA-accelerated build."
            ;;
          auto|*)
            case "$(detect_linux_cuda)" in
              yes)
                ASSET="keyhog-linux-x86_64-cuda"
                ASSET_FALLBACK="keyhog-linux-x86_64"
                gpu=$(gpu_name)
                # nvidia-smi --query-gpu=name already prefixes "NVIDIA"
                # ("NVIDIA GeForce RTX 5090"). Skip our own prefix when
                # the reported name already starts with NVIDIA so we
                # don't print "NVIDIA NVIDIA GeForce RTX 5090".
                label="${gpu:-NVIDIA GPU}"
                case "$label" in
                    NVIDIA*) ;;
                    *) label="NVIDIA $label" ;;
                esac
                GPU_NOTE="${label} with CUDA toolkit detected (nvcc / CUDA_HOME / /usr/local/cuda). Picking the CUDA build for the small native-dispatch perf win on large scans. Pass --variant=cpu to keep the default WGPU build instead."
                ;;
              driver-only)
                ASSET="keyhog-linux-x86_64"
                gpu=$(gpu_name)
                label="${gpu:-NVIDIA GPU}"
                case "$label" in
                    NVIDIA*) ;;
                    *) label="NVIDIA $label" ;;
                esac
                GPU_NOTE="${label} detected. Picking the default WGPU build - it already runs the same vyre AC/RulePipeline on your GPU via vulkan, with a smaller binary and no libcuda dependency. If you have the full CUDA toolkit installed and want the native-dispatch variant, rerun with --variant=cuda."
                ;;
              *)
                ASSET="keyhog-linux-x86_64"
                GPU_NOTE="No NVIDIA GPU detected. Picking default build: WGPU GPU dispatch on any compatible adapter + SIMD on the CPU path."
                ;;
            esac
            ;;
        esac
        ;;
      darwin-arm64|darwin-aarch64)
        ASSET="keyhog-macos-aarch64"
        GPU_NOTE="Apple Silicon. Native Metal GPU acceleration is on the roadmap; the current build runs SIMD on CPU + the WGPU GPU path (slower than a CUDA build on equivalent NVIDIA hardware, fine for typical use)."
        ;;
      darwin-x86_64|darwin-amd64)
        ASSET="keyhog-macos-x86_64"
        GPU_NOTE="Intel Mac. Current build runs SIMD on CPU + WGPU on a compatible discrete adapter. Metal GPU acceleration is on the roadmap."
        ;;
      *)
        err "Unsupported platform: $OS-$ARCH"
        err "Supported: linux-x86_64, darwin-x86_64, darwin-arm64."
        err "On Windows use install.ps1."
        exit 1
        ;;
    esac
}

resolve_tag() {
    if [ -n "$VERSION" ]; then
        # keyhog release tags are all v-prefixed (v0.5.37). Accept a bare
        # semver too (`--version=0.5.37`): a download URL built from the
        # un-prefixed tag 404s, which is exactly what broke the Windows
        # install smoke (it passed "0.5.37"). Normalise a digit-leading
        # version to the v-prefixed tag; leave an explicit v… or any other
        # ref (branch, sha, custom tag) untouched.
        case "$VERSION" in
            [0-9]*) TAG="v$VERSION" ;;
            *)      TAG="$VERSION" ;;
        esac
        return
    fi

    # /releases/latest reports the most recently-published release. But
    # a release can exist with zero assets (e.g. the release-workflow
    # built the workspace but failed to upload), in which case every
    # subsequent download from that tag will 404. Walk back through
    # /releases (most-recent first) and pick the newest tag that has
    # ANY asset attached. This survives a one-off release-workflow
    # failure without forcing the operator to pass --version manually.
    releases_json=$(curl -fsSL "https://api.github.com/repos/$REPO/releases?per_page=10" 2>/dev/null || true)
    if [ -z "$releases_json" ]; then
        err "Could not query GitHub releases API."
        err "Try --version=v0.5.37 (or another known tag) explicitly."
        exit 1
    fi

    # Parse the first 10 releases (most-recent first) and pick the newest
    # tag whose release has at least one downloadable asset. POSIX awk-only,
    # no jq dep.
    #
    # This is deliberately indentation-INDEPENDENT. The previous version
    # keyed on `/^  \]/` to find the close of the assets array, assuming a
    # two-space indent - but the GitHub REST API indents the assets array's
    # closing bracket FOUR spaces (`    ],`), so that pattern never matched
    # and the default `curl | sh` install always failed with "no release has
    # assets" unless the user passed --version. Within each release object
    # the API emits "tag_name" BEFORE its "assets" array, and
    # "browser_download_url" appears ONLY inside an asset entry. So the first
    # browser_download_url we encounter belongs to the first (newest) release
    # that actually has an asset, and `tag` still holds that release's tag.
    TAG=$(printf '%s' "$releases_json" | awk '
        /"tag_name": / {
            sub(/.*"tag_name": *"/, "")
            sub(/".*/, "")
            tag = $0
        }
        /"browser_download_url": / {
            if (tag != "") { print tag; exit }
        }
    ')

    if [ -z "$TAG" ]; then
        err "No GitHub release in the last 10 has any assets uploaded."
        err "Try --version=v0.5.37 (or another known tag) explicitly."
        exit 1
    fi
}

current_binary() {
    if [ -x "$INSTALL_DIR/keyhog" ]; then
        printf '%s\n' "$INSTALL_DIR/keyhog"
    elif command -v keyhog >/dev/null 2>&1; then
        command -v keyhog
    fi
}

current_version() {
    bin=$(current_binary)
    [ -z "$bin" ] && return
    "$bin" --version 2>/dev/null | head -n 1
}

# ============================================================
# install flow
# ============================================================

download_asset() {
    name="$1"
    out="$2"
    url="https://github.com/$REPO/releases/download/$TAG/$name"
    # --retry rides out transient transfer failures (timeouts, connection
    # resets, a CDN dropping a multi-MB body mid-stream). Without it a single
    # flaky connection turns into a failed install - the failure mode that broke
    # the Windows install smoke. --retry-connrefused also retries the initial
    # connect; both are POSIX-curl flags available since 7.52.
    retry="--retry 5 --retry-delay 2 --retry-connrefused"
    if [ "$INTERACTIVE" = "1" ]; then
        info "Downloading $name from $TAG..."
        # shellcheck disable=SC2086
        curl -fL $retry --progress-bar "$url" -o "$out"
    else
        printf 'keyhog: downloading %s\n' "$url"
        # shellcheck disable=SC2086
        curl -fsSL $retry "$url" -o "$out"
    fi
}

allow_unverified_install() {
    reason="$1"
    if [ "$INSECURE_INSTALL" = "1" ]; then
        warn "  INSECURE: $reason"
        warn "  Proceeding without checksum verification because --insecure or KEYHOG_INSECURE_INSTALL=1 is set."
        return 0
    fi
    err "$reason"
    err "Refusing to install an unverified keyhog binary."
    err "Fix: provide the .sha256 file and ensure sha256sum or shasum is installed."
    err "Only for emergency/local diagnostics, rerun with --insecure to accept an unverified binary."
    return 1
}

# Verify the SHA256 of $1 against the per-asset .sha256 file on the
# release. Returns 0 on match. Missing proof fails closed unless the
# operator explicitly chooses --insecure / KEYHOG_INSECURE_INSTALL=1.
verify_checksum() {
    binary="$1"
    asset_name="$2"
    checksum_url="https://github.com/$REPO/releases/download/$TAG/$asset_name.sha256"
    expected=$(curl -fsSL "$checksum_url" 2>/dev/null | awk '{print $1}' | head -n1)
    if [ -z "$expected" ]; then
        allow_unverified_install "No .sha256 checksum was published for $asset_name at $TAG."
        return $?
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$binary" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$binary" | awk '{print $1}')
    else
        allow_unverified_install "No sha256sum or shasum tool is installed, so $asset_name cannot be verified."
        return $?
    fi
    if [ "$expected" = "$actual" ]; then
        ok "SHA256 verified ($expected)."
        return 0
    fi
    err "SHA256 mismatch on $asset_name!"
    err "  Expected: $expected"
    err "  Got:      $actual"
    err "Refusing to install. The download may have been corrupted or tampered with."
    return 1
}

# Verify $1 against a LOCAL checksum file $2 (a `<sha256>  <name>` line, as
# written by `sha256sum binary > binary.sha256` or shipped beside a release
# asset). Used by --from-file installs so an offline/CI install can still
# integrity-check the artifact. Returns 0 on match. Missing proof fails closed
# unless the operator explicitly chooses --insecure / KEYHOG_INSECURE_INSTALL=1.
verify_local_checksum() {
    binary="$1"
    sumfile="$2"
    expected=$(awk '{print $1}' "$sumfile" 2>/dev/null | head -n1)
    if [ -z "$expected" ]; then
        allow_unverified_install "Local checksum file $sumfile is empty or unreadable."
        return $?
    fi
    if command -v sha256sum >/dev/null 2>&1; then
        actual=$(sha256sum "$binary" | awk '{print $1}')
    elif command -v shasum >/dev/null 2>&1; then
        actual=$(shasum -a 256 "$binary" | awk '{print $1}')
    else
        allow_unverified_install "No sha256sum or shasum tool is installed, so $binary cannot be verified against $sumfile."
        return $?
    fi
    if [ "$expected" = "$actual" ]; then
        ok "SHA256 verified ($expected)."
        return 0
    fi
    err "SHA256 mismatch against $sumfile!"
    err "  Expected: $expected"
    err "  Got:      $actual"
    err "Refusing to install the local binary."
    return 1
}

# Holds the path to the pre-upgrade binary backup so a failed verification can
# roll back to the previously-working binary instead of leaving the user with a
# broken one. Empty when there was nothing to back up (fresh install).
INSTALL_BACKUP=""

stage_and_install() {
    tmp=$(mktemp)
    staged=""
    INSTALL_BACKUP=""
    # shellcheck disable=SC2064
    trap 'rm -f "$tmp" "$staged" 2>/dev/null' EXIT INT TERM

    if [ -n "$FROM_FILE" ]; then
        # Local-binary source: install a pre-built/pre-downloaded artifact
        # instead of a GitHub release. Everything below (empty-file guard,
        # backup, atomic swap, verify_install/doctor, rollback) is identical to
        # the download path - only the origin of $tmp differs.
        if [ ! -f "$FROM_FILE" ]; then
            err "--from-file: no such file: $FROM_FILE"
            rm -f "$tmp"
            trap - EXIT INT TERM
            exit 1
        fi
        if ! cp "$FROM_FILE" "$tmp" 2>/dev/null; then
            err "--from-file: could not read $FROM_FILE"
            rm -f "$tmp"
            trap - EXIT INT TERM
            exit 1
        fi
    elif ! download_asset "$ASSET" "$tmp" 2>/dev/null; then
        if [ -n "$ASSET_FALLBACK" ] && [ "$ASSET_FALLBACK" != "$ASSET" ]; then
            warn "$ASSET is not published for $TAG yet. Falling back to $ASSET_FALLBACK."
            if ! download_asset "$ASSET_FALLBACK" "$tmp"; then
                err "Neither $ASSET nor $ASSET_FALLBACK could be downloaded for $TAG."
                err "Browse https://github.com/$REPO/releases to confirm."
                exit 1
            fi
            ASSET="$ASSET_FALLBACK"
        else
            err "Download failed. Is the release published yet?"
            err "Browse https://github.com/$REPO/releases to confirm."
            exit 1
        fi
    fi

    # A zero-byte download means the asset 404'd into an empty file, the
    # connection dropped before the first byte, or a proxy served an empty
    # body. An empty file is still chmod-able and, with no shebang, executes
    # as a no-op shell script that exits 0 - so verify_install would wave it
    # through and "install" a binary that does nothing. Refuse up front.
    # This happens BEFORE any backup/overwrite, so a pre-existing working
    # binary is never touched.
    if [ ! -s "$tmp" ]; then
        err "Downloaded asset $ASSET is empty (0 bytes)."
        err "The release asset may be missing or the download was interrupted."
        err "Browse https://github.com/$REPO/releases to confirm asset availability."
        rm -f "$tmp"
        trap - EXIT INT TERM
        exit 1
    fi

    # Checksum is verified BEFORE we overwrite, so a corrupt artifact can never
    # replace a working binary. Downloads check against the release's per-asset
    # .sha256; a --from-file install requires a sibling PATH.sha256 unless the
    # operator explicitly accepts an unverified local artifact.
    if [ -n "$FROM_FILE" ]; then
        if [ -f "$FROM_FILE.sha256" ]; then
            if ! verify_local_checksum "$tmp" "$FROM_FILE.sha256"; then
                rm -f "$tmp"
                trap - EXIT INT TERM
                exit 1
            fi
        else
            if ! allow_unverified_install "No local checksum file found beside --from-file binary: $FROM_FILE.sha256"; then
                rm -f "$tmp"
                trap - EXIT INT TERM
                exit 1
            fi
        fi
    elif ! verify_checksum "$tmp" "$ASSET"; then
        rm -f "$tmp"
        trap - EXIT INT TERM
        exit 1
    fi

    mkdir -p "$INSTALL_DIR"
    target="$INSTALL_DIR/keyhog"

    # Recoverability invariant: never destroy a working binary before the
    # replacement has proven itself on THIS host. Back the current one up, stage
    # the new one beside it (same filesystem, so the final swap is an atomic
    # rename), then let finalize_install verify and roll back on failure.
    if [ -e "$target" ]; then
        INSTALL_BACKUP="$INSTALL_DIR/.keyhog.bak.$$"
        if ! cp -p "$target" "$INSTALL_BACKUP" 2>/dev/null; then
            err "Could not back up the existing binary at $target."
            err "Refusing to overwrite it - your current install is left untouched."
            rm -f "$tmp"
            INSTALL_BACKUP=""
            trap - EXIT INT TERM
            exit 1
        fi
    fi

    staged="$INSTALL_DIR/.keyhog.new.$$"
    # $tmp may live on a different filesystem (TMPDIR), so copy (not rename)
    # into the install dir; the atomic rename is the same-dir mv below.
    if ! cp "$tmp" "$staged" 2>/dev/null; then
        err "Could not stage the download into $INSTALL_DIR (directory not writable?)."
        rm -f "$tmp" "$INSTALL_BACKUP"
        INSTALL_BACKUP=""
        trap - EXIT INT TERM
        exit 1
    fi
    rm -f "$tmp"
    chmod +x "$staged"
    # Atomic same-directory replace: a concurrent `keyhog` exec sees either the
    # old inode or the fully-written new one, never a half-copied file.
    mv -f "$staged" "$target"
    staged=""
    trap - EXIT INT TERM
}

# Restore the pre-upgrade binary after a failed verification. On a fresh
# install (no backup) the broken download is removed unless it is merely
# missing a system library (then it is kept, because it is the correct binary
# and the user can fix the lib without re-downloading). Either way the host is
# never left strictly worse off than before the install ran.
finalize_install() {
    vrc=0
    verify_install || vrc=$?
    if [ "$vrc" = "0" ]; then
        # New binary works: drop the backup.
        [ -n "$INSTALL_BACKUP" ] && rm -f "$INSTALL_BACKUP"
        INSTALL_BACKUP=""
        return 0
    fi

    if [ -n "$INSTALL_BACKUP" ] && [ -e "$INSTALL_BACKUP" ]; then
        # Upgrade/repair over a binary that worked: the old one ran, the new
        # one does not on this host - restore the one that worked.
        mv -f "$INSTALL_BACKUP" "$INSTALL_DIR/keyhog"
        INSTALL_BACKUP=""
        warn "Rolled back to your previous working keyhog at $INSTALL_DIR/keyhog."
    elif [ "$vrc" = "2" ]; then
        # Fresh install, correct binary, missing system library: keep it so the
        # user can install the lib (hint already printed) without re-downloading.
        warn "Left the binary in place; install the library listed above, then run 'keyhog doctor' to confirm."
    else
        # Fresh install, non-runnable binary (wrong CPU / corrupt): leaving it
        # on PATH would fail confusingly on every call - remove it.
        rm -f "$INSTALL_DIR/keyhog"
        warn "Removed the non-runnable download; no working keyhog was overwritten."
    fi
    return 1
}

# Verify the freshly-staged binary. Returns:
#   0 - healthy (ran --version cleanly)
#   2 - runs but a required system library is missing (binary is correct)
#   1 - non-runnable for any other reason (wrong CPU, corrupt, ...)
# Never exits the script: finalize_install owns rollback/cleanup decisions.
verify_install() {
    # Capture stderr so we can decode the real reason --version refused to run.
    # The previous "may be corrupt" message hid the most common failure mode:
    # a missing shared library on Linux (Hyperscan, libssl, etc.).
    verify_status=0
    verify_err=$("$INSTALL_DIR/keyhog" --version 2>&1 >/dev/null) || verify_status=$?

    # Success is exit 0 from --version. A warning on stderr (deprecation note,
    # config-load warning, locale grumble) is NOT a broken binary - the old
    # `-z "$verify_err"` gate treated any such noise as a failure and would,
    # post-rollback-fix, needlessly roll back a perfectly good upgrade.
    if [ "$verify_status" = "0" ]; then
        ok "Installed $("$INSTALL_DIR/keyhog" --version)"
        [ -n "$verify_err" ] && dim "  (binary emitted a startup notice: $verify_err)"
        # Native post-install health check. `keyhog doctor` reuses the same
        # hw_probe the scanner uses (so there's no shell-side GPU detection to
        # drift from runtime) and runs an end-to-end scan self-test: it plants
        # a synthetic secret and confirms the freshly-installed binary actually
        # detects it on THIS host. Exit 4 means the self-test failed (broken
        # binary) - surface it, but don't fail the install over a PATH warning.
        say ""
        if ! "$INSTALL_DIR/keyhog" doctor; then
            warn "keyhog doctor reported issues above; the binary is installed but may not be fully healthy."
        fi
        if ! prime_autoroute_cache "$INSTALL_DIR/keyhog"; then
            err "Autoroute calibration failed; refusing to leave an install whose default auto route is not usable."
            return 1
        fi
        return 0
    fi

    err "Installed binary at $INSTALL_DIR/keyhog could not run."
    err "  exit=$verify_status"
    [ -n "$verify_err" ] && err "  stderr: $verify_err"

    # Surface dynamic-link failures on Linux. The Linux Hyperscan build
    # depends on libhyperscan.so.5 at runtime; Ubuntu hosted runners
    # ship libhyperscan-dev only when explicitly installed.
    if [ "$OS" = "linux" ] && command -v ldd >/dev/null 2>&1; then
        missing=$(ldd "$INSTALL_DIR/keyhog" 2>/dev/null | awk '/not found/ {print $1}' | sort -u | tr '\n' ' ')
        if [ -n "$missing" ]; then
            err "  Missing shared libraries: $missing"
            case "$missing" in
                *libhyperscan*)
                    err "  Install Hyperscan runtime:"
                    err "    Ubuntu/Debian: sudo apt-get install -y libhyperscan5"
                    err "    Fedora/RHEL:   sudo dnf install -y hyperscan"
                    err "    Arch:          sudo pacman -S vectorscan"
                    err "  Or rebuild from source with no Hyperscan dep:"
                    err "    cargo install --git https://github.com/santhsecurity/keyhog --no-default-features --features portable"
                    ;;
                *libssl*|*libcrypto*)
                    err "  Install OpenSSL runtime:"
                    err "    Ubuntu/Debian: sudo apt-get install -y libssl3 ca-certificates"
                    err "    Fedora/RHEL:   sudo dnf install -y openssl ca-certificates"
                    ;;
            esac
            # The binary itself is correct; it just needs a runtime library.
            return 2
        fi
    fi

    err "The download may be corrupt or wrong for this CPU."
    err "  Picked asset: $ASSET"
    err "  Browse https://github.com/$REPO/releases to confirm asset availability."
    return 1
}

cleanup_autoroute_calibration() {
    cleanup_tmpdir="$1"
    cleanup_web_pid_file="$2"
    cleanup_docker_bin="$3"
    cleanup_docker_image="$4"
    cleanup_docker_ready="$5"
    cleanup_probe_pid="$6"

    if [ -n "$cleanup_probe_pid" ]; then
        kill "$cleanup_probe_pid" >/dev/null 2>&1 || true
        wait "$cleanup_probe_pid" 2>/dev/null || true
    fi
    if [ -n "$cleanup_web_pid_file" ]; then
        stop_calibration_web_server "$cleanup_web_pid_file"
    fi
    if [ "$cleanup_docker_ready" = "1" ] && [ -n "$cleanup_docker_bin" ] && [ -n "$cleanup_docker_image" ]; then
        if ! "$cleanup_docker_bin" image rm -f "$cleanup_docker_image" >/dev/null 2>&1; then
            dim "  Docker calibration image cleanup failed for $cleanup_docker_image"
        fi
    fi
    if [ -n "$cleanup_tmpdir" ]; then
        if ! rm -rf "$cleanup_tmpdir" 2>/dev/null; then
            dim "  Autoroute calibration workspace cleanup failed for $cleanup_tmpdir"
        fi
    fi
}

prime_autoroute_cache() {
    bin="$1"
    if ! tmpdir="$(mktemp -d -t keyhog-autoroute-prime-XXXXXX)"; then
        err "Could not create autoroute calibration workspace with mktemp."
        return 1
    fi
    web_pid_file=""
    docker_bin=""
    docker_image=""
    docker_image_ready=0
    calibration_probe_pid=""
    trap 'cleanup_autoroute_calibration "$tmpdir" "$web_pid_file" "$docker_bin" "$docker_image" "$docker_image_ready" "$calibration_probe_pid"' EXIT
    trap 'cleanup_autoroute_calibration "$tmpdir" "$web_pid_file" "$docker_bin" "$docker_image" "$docker_image_ready" "$calibration_probe_pid"; trap - EXIT INT TERM; exit 130' INT TERM

    say ""
    info "Autoroute calibration"
    dim "  visible install phase; persistent until you run install.sh --calibrate again"

    # Pick the config-isolation flag the INSTALLED binary actually accepts. A
    # released binary that predates `--no-config` only has `--config <PATH>`;
    # passing `--no-config` to it makes clap exit 2 and every probe "FAILED"
    # for a reason the old `>/dev/null 2>&1` hid (Law 10: a swallowed installer
    # error reads as a broken product). Detect once, never guess.
    scan_help="$("$bin" scan --help 2>/dev/null || true)"
    if printf '%s' "$scan_help" | grep -q -- '--no-config'; then
        cfg_flag="--no-config"
    else
        : > "$tmpdir/empty-config.toml"
        cfg_flag="--config $tmpdir/empty-config.toml"
    fi
    unavailable_calibrations=""
    git_calibration=0
    git_bin=""
    if printf '%s' "$scan_help" | grep -q -- '--git-history' && \
       printf '%s' "$scan_help" | grep -q -- '--git-diff'; then
        git_bin="$(command -v git 2>/dev/null || true)"
        if [ -z "$git_bin" ]; then
            warn "  Git source calibration unavailable: git was not found on PATH."
            warn "  Filesystem/stdin calibration will continue; install git and rerun install.sh --calibrate before relying on git-source autorouting."
            unavailable_calibrations="${unavailable_calibrations} git"
        else
            git_calibration=1
        fi
    fi
    docker_calibration=0
    if printf '%s' "$scan_help" | grep -q -- '--docker-image'; then
        docker_bin="$(command -v docker 2>/dev/null || true)"
        if [ -z "$docker_bin" ]; then
            warn "  Docker image calibration unavailable: docker was not found on PATH."
            warn "  Filesystem/stdin calibration will continue; install Docker and rerun install.sh --calibrate before relying on Docker image autorouting."
            unavailable_calibrations="${unavailable_calibrations} docker"
        else
            docker_calibration=1
        fi
    fi
    web_calibration=0
    python_bin=""
    if printf '%s' "$scan_help" | grep -q -- '--url'; then
        python_bin="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || true)"
        if [ -z "$python_bin" ]; then
            warn "  Web URL calibration unavailable: python3/python was not found on PATH."
            warn "  Filesystem/stdin calibration will continue; install Python and rerun install.sh --calibrate before relying on Web URL autorouting."
            unavailable_calibrations="${unavailable_calibrations} web"
        else
            web_calibration=1
        fi
    fi

    kib_sizes="4 64"
    mib_sizes="1 8 32"
    total=0
    total=$((total + 1)) # empty stdin
    total=$((total + 1)) # stdin 64 KiB
    for _kib in $kib_sizes; do
        total=$((total + 1))
    done
    for _mib in $mib_sizes; do
        total=$((total + 1))
    done
    total=$((total + 1)) # decode-heavy 256 KiB
    total=$((total + 1)) # 32 x 4 KiB files
    if [ "$git_calibration" = "1" ]; then
        total=$((total + 3))
    fi
    if [ "$docker_calibration" = "1" ]; then
        total=$((total + 1))
    fi
    if [ "$web_calibration" = "1" ]; then
        total=$((total + 1))
    fi
    idx=0
    failed=0

    idx=$((idx + 1))
    probe="$tmpdir/probe-stdin-empty.txt"
    out="$tmpdir/out-stdin-empty.json"
    err="$tmpdir/err-stdin-empty.txt"
    label="empty stdin workload"
    : > "$probe"
    if ! run_autoroute_stdin_probe "$idx" "$total" "$label" "$probe" "$out" "$err"; then
        failed=1
    fi

    idx=$((idx + 1))
    probe="$tmpdir/probe-stdin-64kib.txt"
    out="$tmpdir/out-stdin-64kib.json"
    err="$tmpdir/err-stdin-64kib.txt"
    label="stdin 64 KiB workload"
    if ! make_calibration_probe_kib "$probe" 64; then
        printf '  [%s/%s] %s FAILED\n' "$idx" "$total" "$label"
        err "Could not create 64 KiB stdin autoroute calibration probe at $probe."
        failed=1
    elif ! run_autoroute_stdin_probe "$idx" "$total" "$label" "$probe" "$out" "$err"; then
        failed=1
    fi

    for kib in $kib_sizes; do
        idx=$((idx + 1))
        probe="$tmpdir/probe-${kib}kib.txt"
        out="$tmpdir/out-${kib}kib.json"
        err="$tmpdir/err-${kib}kib.txt"
        label="${kib} KiB workload"
        if ! make_calibration_probe_kib "$probe" "$kib"; then
            printf '  [%s/%s] %s FAILED\n' "$idx" "$total" "$label"
            err "Could not create ${kib} KiB autoroute calibration probe at $probe."
            failed=1
            continue
        fi
        if ! run_autoroute_probe "$idx" "$total" "$label" "$probe" "$out" "$err"; then
            failed=1
        fi
    done

    for mib in $mib_sizes; do
        idx=$((idx + 1))
        probe="$tmpdir/probe-${mib}mib.txt"
        out="$tmpdir/out-${mib}mib.json"
        err="$tmpdir/err-${mib}mib.txt"
        label="${mib} MiB workload"
        if ! make_calibration_probe "$probe" "$mib"; then
            printf '  [%s/%s] %s FAILED\n' "$idx" "$total" "$label"
            err "Could not create ${mib} MiB autoroute calibration probe at $probe."
            failed=1
            continue
        fi
        if ! run_autoroute_probe "$idx" "$total" "$label" "$probe" "$out" "$err"; then
            failed=1
        fi
    done

    idx=$((idx + 1))
    probe="$tmpdir/probe-decode-heavy-256kib.txt"
    out="$tmpdir/out-decode-heavy-256kib.json"
    err="$tmpdir/err-decode-heavy-256kib.txt"
    label="decode-heavy 256 KiB workload"
    if ! make_decode_heavy_calibration_probe_kib "$probe" 256; then
        printf '  [%s/%s] %s FAILED\n' "$idx" "$total" "$label"
        err "Could not create decode-heavy autoroute calibration probe at $probe."
        failed=1
    elif ! run_autoroute_probe "$idx" "$total" "$label" "$probe" "$out" "$err"; then
        failed=1
    fi

    idx=$((idx + 1))
    probe_dir="$tmpdir/many-4k"
    out="$tmpdir/out-many-4k.json"
    err="$tmpdir/err-many-4k.txt"
    label="32 x 4 KiB files workload"
    if ! make_calibration_tree_kib "$probe_dir" 32 4; then
        printf '  [%s/%s] %s FAILED\n' "$idx" "$total" "$label"
        err "Could not create many-file autoroute calibration probe at $probe_dir."
        failed=1
    elif ! run_autoroute_probe "$idx" "$total" "$label" "$probe_dir" "$out" "$err"; then
        failed=1
    fi

    if [ "$git_calibration" = "1" ]; then
        git_repo="$tmpdir/git-source"
        if ! make_calibration_git_repo "$git_repo" "$git_bin"; then
            err "Could not create git source autoroute calibration repository at $git_repo."
            failed=1
        else
            idx=$((idx + 1))
            out="$tmpdir/out-git-history.json"
            err="$tmpdir/err-git-history.txt"
            label="git history 4 KiB source workload"
            if ! run_autoroute_git_history_probe "$idx" "$total" "$label" "$git_repo" "$out" "$err"; then
                failed=1
            fi

            idx=$((idx + 1))
            out="$tmpdir/out-git-blobs.json"
            err="$tmpdir/err-git-blobs.txt"
            label="git blobs head/history source workload"
            if ! run_autoroute_git_blobs_probe "$idx" "$total" "$label" "$git_repo" "$out" "$err"; then
                failed=1
            fi

            idx=$((idx + 1))
            out="$tmpdir/out-git-diff.json"
            err="$tmpdir/err-git-diff.txt"
            label="git diff 12 KiB source workload"
            if ! run_autoroute_git_diff_probe "$idx" "$total" "$label" "$git_repo" "$out" "$err"; then
                failed=1
            fi
        fi
    fi

    if [ "$web_calibration" = "1" ]; then
        idx=$((idx + 1))
        web_dir="$tmpdir/web-source"
        web_port_file="$tmpdir/web-source.port"
        web_pid_file="$tmpdir/web-source.pid"
        web_log="$tmpdir/web-source.log"
        out="$tmpdir/out-web-url.json"
        err="$tmpdir/err-web-url.txt"
        label="web URL 4 KiB source workload"
        if ! make_calibration_web_fixture "$web_dir"; then
            printf '  [%s/%s] %s FAILED\n' "$idx" "$total" "$label"
            err "Could not create Web URL autoroute calibration fixture at $web_dir."
            failed=1
        elif ! start_calibration_web_server "$web_dir" "$web_port_file" "$web_pid_file" "$web_log" "$python_bin"; then
            printf '  [%s/%s] %s FAILED\n' "$idx" "$total" "$label"
            stop_calibration_web_server "$web_pid_file"
            web_pid_file=""
            real_err="$(head -n 1 "$web_log" 2>/dev/null)"
            [ -n "$real_err" ] && dim "    reason: $real_err"
            err "Could not start loopback Web URL autoroute calibration server."
            failed=1
        else
            web_url="http://127.0.0.1:$(cat "$web_port_file")/probe.js"
            if ! run_autoroute_url_probe "$idx" "$total" "$label" "$web_url" "$out" "$err"; then
                failed=1
            fi
            stop_calibration_web_server "$web_pid_file"
            web_pid_file=""
        fi
    fi

    if [ "$docker_calibration" = "1" ]; then
        idx=$((idx + 1))
        docker_dir="$tmpdir/docker-source"
        calibration_id="$(basename "$tmpdir")"
        docker_image="keyhog-autoroute-calibration:$calibration_id"
        out="$tmpdir/out-docker-image.json"
        err="$tmpdir/err-docker-image.txt"
        label="docker image 4 KiB source workload"
        if ! make_calibration_docker_image "$docker_dir" "$docker_image" "$docker_bin" 2>"$err"; then
            printf '  [%s/%s] %s FAILED\n' "$idx" "$total" "$label"
            real_err="$(head -n 1 "$err" 2>/dev/null)"
            [ -n "$real_err" ] && dim "    reason: $real_err"
            err "Could not create Docker image autoroute calibration probe at $docker_image."
            failed=1
        else
            docker_image_ready=1
            if ! run_autoroute_docker_image_probe "$idx" "$total" "$label" "$docker_image" "$out" "$err"; then
                failed=1
            fi
        fi
    fi

    cleanup_autoroute_calibration "$tmpdir" "$web_pid_file" "$docker_bin" "$docker_image" "$docker_image_ready" "$calibration_probe_pid"
    trap - EXIT INT TERM
    tmpdir=""
    web_pid_file=""
    docker_image=""
    docker_image_ready=0
    calibration_probe_pid=""
    if [ "$failed" != "0" ]; then
        err "Autoroute calibration phase failed; persisted auto routing was not updated for every required workload."
        return 1
    fi
    if [ -n "$unavailable_calibrations" ]; then
        warn "Autoroute calibration incomplete for unavailable source classes:$unavailable_calibrations."
        warn "Install the required source tools and rerun install.sh --calibrate before using those source routes."
    fi
    ok "Autoroute calibration phase complete."
    return 0
}

run_autoroute_probe() {
    run_autoroute_scan_probe "$1" "$2" "$3" path "$4" "$5" "$6"
}

run_autoroute_stdin_probe() {
    run_autoroute_scan_probe "$1" "$2" "$3" stdin "$4" "$5" "$6"
}

run_autoroute_git_history_probe() {
    run_autoroute_scan_probe "$1" "$2" "$3" git-history "$4" "$5" "$6"
}

run_autoroute_git_blobs_probe() {
    run_autoroute_scan_probe "$1" "$2" "$3" git-blobs "$4" "$5" "$6"
}

run_autoroute_git_diff_probe() {
    run_autoroute_scan_probe "$1" "$2" "$3" git-diff "$4" "$5" "$6"
}

run_autoroute_url_probe() {
    run_autoroute_scan_probe "$1" "$2" "$3" url "$4" "$5" "$6"
}

run_autoroute_docker_image_probe() {
    run_autoroute_scan_probe "$1" "$2" "$3" docker-image "$4" "$5" "$6"
}

run_autoroute_scan_probe() {
    idx="$1"
    total="$2"
    label="$3"
    mode="$4"
    probe="$5"
    out="$6"
    errfile="$7"
    printf '  [%s/%s] %s ' "$idx" "$total" "$label"
    case "$mode" in
        path)
            KEYHOG_AUTOROUTE_CALIBRATE=1 KEYHOG_BATCH_PIPELINE=1 KEYHOG_GPU_AUTOROUTE=1 \
                "$bin" scan "$probe" $cfg_flag --format json -o "$out" >/dev/null 2>"$errfile" &
            ;;
        stdin)
            KEYHOG_AUTOROUTE_CALIBRATE=1 KEYHOG_BATCH_PIPELINE=1 KEYHOG_GPU_AUTOROUTE=1 \
                "$bin" scan --stdin $cfg_flag --format json -o "$out" < "$probe" >/dev/null 2>"$errfile" &
            ;;
        git-history)
            KEYHOG_AUTOROUTE_CALIBRATE=1 KEYHOG_BATCH_PIPELINE=1 KEYHOG_GPU_AUTOROUTE=1 \
                "$bin" scan --git-history "$probe" --max-commits 1 $cfg_flag --format json -o "$out" >/dev/null 2>"$errfile" &
            ;;
        git-blobs)
            KEYHOG_AUTOROUTE_CALIBRATE=1 KEYHOG_BATCH_PIPELINE=1 KEYHOG_GPU_AUTOROUTE=1 \
                "$bin" scan --git-blobs "$probe" --max-commits 2 $cfg_flag --format json -o "$out" >/dev/null 2>"$errfile" &
            ;;
        git-diff)
            KEYHOG_AUTOROUTE_CALIBRATE=1 KEYHOG_BATCH_PIPELINE=1 KEYHOG_GPU_AUTOROUTE=1 \
                "$bin" scan --git-diff HEAD --git-diff-path "$probe" $cfg_flag --format json -o "$out" >/dev/null 2>"$errfile" &
            ;;
        url)
            KEYHOG_AUTOROUTE_CALIBRATE=1 KEYHOG_BATCH_PIPELINE=1 KEYHOG_GPU_AUTOROUTE=1 \
                "$bin" scan --url "$probe" $cfg_flag --format json -o "$out" >/dev/null 2>"$errfile" &
            ;;
        docker-image)
            KEYHOG_AUTOROUTE_CALIBRATE=1 KEYHOG_BATCH_PIPELINE=1 KEYHOG_GPU_AUTOROUTE=1 \
                "$bin" scan --docker-image "$probe" $cfg_flag --format json -o "$out" >/dev/null 2>"$errfile" &
            ;;
        *)
            (
                printf 'unsupported autoroute calibration mode: %s\n' "$mode" > "$errfile"
                exit 2
            ) &
            ;;
    esac
    pid=$!
    calibration_probe_pid="$pid"
    spin='-\|/'
    n=0
    while kill -0 "$pid" 2>/dev/null; do
        n=$(( (n + 1) % 4 ))
        c=$(printf '%s' "$spin" | cut -c $((n + 1)))
        printf '\r  [%s/%s] %s %s' "$idx" "$total" "$label" "$c"
        sleep 0.15
    done
    if wait "$pid"; then
        calibration_probe_pid=""
        printf '\r  [%s/%s] %s OK\n' "$idx" "$total" "$label"
        return 0
    fi
    calibration_probe_pid=""
    printf '\r  [%s/%s] %s FAILED\n' "$idx" "$total" "$label"
    # Surface the REAL reason, not a blind "FAILED" (Law 10). One line is
    # enough to tell a flag mismatch from a GPU/driver fault.
    real_err="$(head -n 1 "$errfile" 2>/dev/null)"
    [ -n "$real_err" ] && dim "    reason: $real_err"
    err "Autoroute calibration probe failed for $label."
    return 1
}

make_calibration_probe() {
    path="$1"
    mib="$2"
    make_calibration_probe_kib "$path" $((mib * 1024))
}

make_calibration_probe_kib() {
    path="$1"
    kib="$2"
    block="$(plain_calibration_block)" || return 1
    awk -v block="$block" -v kib="$kib" 'BEGIN { for (i = 0; i < kib; i++) printf "%s", block }' > "$path"
}

plain_calibration_block() {
    seed='src path one. scan text two. keyhog route plain. config value sample. '
    block="$seed"
    while [ "${#block}" -lt 1024 ]; do
        block="${block}${seed}"
    done
    printf '%.1024s' "$block"
}

make_decode_heavy_calibration_probe_kib() {
    path="$1"
    kib="$2"
    block="$(decode_heavy_calibration_block)" || return 1
    awk -v block="$block" -v kib="$kib" 'BEGIN { for (i = 0; i < kib; i++) printf "%s", block }' > "$path"
}

decode_heavy_calibration_block() {
    seed='apiVersion:v1 kind:Secret data token:QUtJQUlPU0ZPRE5ON0VYQU1QTEVBS0lBSU9TRk9ETk43RVhBTVBMRT0= payload:c2stcHJvai1BQkNkZWZHSElKS0xtbm9QUVJTVFVWV1hZWjAxMjM0NTY3ODkwPQ== '
    block="$seed"
    while [ "${#block}" -lt 1024 ]; do
        block="${block}${seed}"
    done
    printf '%.1024s' "$block"
}

make_calibration_git_repo() {
    dir="$1"
    git_cmd="$2"
    mkdir -p "$dir" || return 1
    "$git_cmd" init -q "$dir" || return 1
    "$git_cmd" -C "$dir" config user.email keyhog-calibration@example.invalid || return 1
    "$git_cmd" -C "$dir" config user.name "Keyhog Autoroute Calibration" || return 1
    "$git_cmd" -C "$dir" config commit.gpgsign false || return 1
    make_calibration_probe_kib "$dir/probe.txt" 4 || return 1
    "$git_cmd" -C "$dir" add probe.txt || return 1
    "$git_cmd" -C "$dir" commit -q -m "keyhog autoroute calibration baseline" || return 1
    make_calibration_probe_kib "$dir/probe.txt" 8 || return 1
    "$git_cmd" -C "$dir" add probe.txt || return 1
    "$git_cmd" -C "$dir" commit -q -m "keyhog autoroute calibration head" || return 1
    make_calibration_probe_kib "$dir/probe.txt" 12 || return 1
}

make_calibration_docker_image() {
    dir="$1"
    image="$2"
    docker_cmd="$3"
    context="$dir/context"
    mkdir -p "$context" || return 1
    make_calibration_probe_kib "$context/probe.txt" 4 || return 1
    {
        printf '%s\n' 'FROM scratch'
        printf '%s\n' 'COPY probe.txt /keyhog-autoroute-probe.txt'
    } > "$context/Dockerfile" || return 1
    "$docker_cmd" build -q -t "$image" "$context" >/dev/null || return 1
}

make_calibration_web_fixture() {
    dir="$1"
    mkdir -p "$dir" || return 1
    make_calibration_probe_kib "$dir/probe.js" 4 || return 1
}

start_calibration_web_server() {
    dir="$1"
    port_file="$2"
    pid_file="$3"
    log_file="$4"
    python_cmd="$5"
    (
        cd "$dir" || exit 1
        "$python_cmd" - "$port_file" <<'PY'
import http.server
import socketserver
import sys

port_file = sys.argv[1]

class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

class Server(socketserver.TCPServer):
    allow_reuse_address = True

with Server(("127.0.0.1", 0), Handler) as httpd:
    with open(port_file, "w", encoding="ascii") as f:
        f.write(str(httpd.server_address[1]))
    httpd.serve_forever()
PY
    ) >"$log_file" 2>&1 &
    server_pid=$!
    printf '%s\n' "$server_pid" > "$pid_file" || return 1
    i=0
    while [ "$i" -lt 100 ]; do
        if [ -s "$port_file" ]; then
            return 0
        fi
        if ! kill -0 "$server_pid" 2>/dev/null; then
            return 1
        fi
        sleep 0.05
        i=$((i + 1))
    done
    return 1
}

stop_calibration_web_server() {
    pid_file="$1"
    [ -s "$pid_file" ] || return 0
    server_pid="$(cat "$pid_file" 2>/dev/null || true)"
    [ -n "$server_pid" ] || return 0
    kill "$server_pid" >/dev/null 2>&1 || true
    wait "$server_pid" 2>/dev/null || true
}

make_calibration_tree_kib() {
    dir="$1"
    files="$2"
    kib="$3"
    mkdir -p "$dir" || return 1
    i=0
    while [ "$i" -lt "$files" ]; do
        if ! make_calibration_probe_kib "$dir/file-$i.txt" "$kib"; then
            return 1
        fi
        i=$((i + 1))
    done
}

show_summary() {
    info "Host: $OS-$ARCH"
    say  "  GPU note: $GPU_NOTE"
    say  "  Picked asset:  $ASSET"
    say  "  Install dir:   $INSTALL_DIR"
    say  "  Release tag:   $TAG"
    existing=$(current_version)
    if [ -n "$existing" ]; then
        say  "  Existing:      $existing"
    fi
}

# Offer to wire keyhog into common entry points. Each is opt-in so we
# never silently mutate config files the user didn't ask us to touch.
post_install_wizard() {
    [ "$INTERACTIVE" != "1" ] && return
    [ "$ASSUME_YES" = "1" ] && return

    printf '\n%sOptional post-install steps%s\n' "$C_BOLD" "$C_RESET"

    case ":$PATH:" in
      *":$INSTALL_DIR:"*)
        : ;;
      *)
        if confirm "Add $INSTALL_DIR to your shell PATH?" Y; then
            offer_path_setup
        else
            dim "  Skipped. To add later: export PATH=\"$INSTALL_DIR:\$PATH\""
        fi
        ;;
    esac

    if confirm "Install shell completions for your current shell?" N; then
        install_completions
    fi

    # Claude Code / Cursor agent-hook wiring is roadmap, not shipped.
    # The previous prompt called `keyhog hook install --agent claude-code`
    # which never existed as a flag, so the wizard always graceful-
    # failed with a misleading "upgrade" message. Drop the prompt until
    # the feature lands.

    if confirm "Wire keyhog as a git pre-commit hook in the CURRENT directory?" N; then
        if [ -d .git ]; then
            "$INSTALL_DIR/keyhog" hook install 2>/dev/null && \
                ok "  Pre-commit hook installed in $(pwd)/.git/hooks/pre-commit" || \
                warn "  keyhog hook install failed in this directory."
        else
            warn "  No .git directory here, skipping."
        fi
    fi
}

offer_path_setup() {
    shell_name=$(basename "${SHELL:-/bin/sh}")
    case "$shell_name" in
      bash) rc="$HOME/.bashrc" ;;
      zsh)  rc="$HOME/.zshrc"  ;;
      fish) rc="$HOME/.config/fish/config.fish" ;;
      *)    rc="" ;;
    esac
    if [ -n "$rc" ]; then
        if confirm "  Append to $rc?" Y; then
            mkdir -p "$(dirname "$rc")"
            if [ "$shell_name" = "fish" ]; then
                printf '\n# keyhog\nset -gx PATH %s $PATH\n' "$INSTALL_DIR" >> "$rc"
            else
                printf '\n# keyhog\nexport PATH="%s:$PATH"\n' "$INSTALL_DIR" >> "$rc"
            fi
            ok "  Added. Restart your shell or 'source $rc' to pick it up."
            return
        fi
    fi
    dim "  Add manually: export PATH=\"$INSTALL_DIR:\$PATH\""
}

install_completions() {
    shell_name=$(basename "${SHELL:-/bin/sh}")
    case "$shell_name" in
      bash) dir="$HOME/.local/share/bash-completion/completions"; file="$dir/keyhog" ;;
      zsh)  dir="$HOME/.zfunc"; file="$dir/_keyhog" ;;
      fish) dir="$HOME/.config/fish/completions"; file="$dir/keyhog.fish" ;;
      *) warn "  Unknown shell ($shell_name), skipping completions."; return ;;
    esac
    mkdir -p "$dir"
    if "$INSTALL_DIR/keyhog" completion "$shell_name" > "$file" 2>/dev/null; then
        ok "  Completions written to $file"
    else
        warn "  completions subcommand not in this build, skipping (upgrade to v0.5.30+)."
        rm -f "$file"
    fi
}

# ============================================================
# install / repair / diagnose / uninstall
# ============================================================

do_install() {
    if [ -n "$FROM_FILE" ]; then
        # Local-binary install: no GitHub release lookup, no network. ASSET/TAG
        # are populated for show_summary and the verify messages only.
        ASSET=$(basename "$FROM_FILE")
        ASSET_FALLBACK=""
        TAG="(local file)"
        GPU_NOTE="installing local binary: $FROM_FILE"
    else
        resolve_asset
        resolve_tag
    fi

    show_summary

    if [ "$INTERACTIVE" = "1" ] && [ "$ASSUME_YES" != "1" ]; then
        if ! confirm "Proceed with this install?" Y; then
            warn "Aborted."
            exit 0
        fi
    fi

    stage_and_install
    if ! finalize_install; then
        err "Install failed verification; see above."
        exit 1
    fi
    post_install_wizard

    printf '\n%sNext steps:%s\n' "$C_BOLD" "$C_RESET"
    say "  keyhog scan .            # scan the current directory"
    say "  keyhog scan --help       # full options"
    say "  keyhog --version         # verify"
}

do_repair() {
    info "Repair mode."
    resolve_asset
    resolve_tag
    bin=$(current_binary)
    if [ -z "$bin" ]; then
        warn "No existing keyhog binary found. Installing fresh."
        stage_and_install
        if ! finalize_install; then
            err "Repair failed; see above."
            exit 1
        fi
        ok "Repair complete."
        return
    fi
    say "Found existing binary: $bin"
    if "$bin" --version >/dev/null 2>&1; then
        ok "Binary runs cleanly. Re-downloading $ASSET to overwrite anyway (--repair)."
    else
        warn "Existing binary does not run. Replacing with $ASSET."
    fi
    stage_and_install
    if ! finalize_install; then
        err "Repair failed; your previous binary state was preserved where possible (see above)."
        exit 1
    fi
    ok "Repair complete."
}

do_diagnose() {
    # Prefer the binary's own `keyhog doctor` when it runs: it reuses the same
    # hw_probe the scanner uses and runs an end-to-end scan self-test, so it is
    # authoritative in a way this shell (which only guesses from the outside)
    # can't be. We still append the install-side "latest release / would
    # install" lines, which doctor doesn't know about. Falls back to the full
    # shell diagnostic below when there's no runnable binary to ask.
    bin=$(current_binary)
    if [ -n "$bin" ] && "$bin" --version >/dev/null 2>&1; then
        "$bin" doctor
        printf '\n%sLatest release%s\n' "$C_BOLD" "$C_RESET"
        resolve_tag
        say "  Tag: $TAG"
        resolve_asset
        say "  Would install: $ASSET"
        return
    fi

    info "Diagnostic report ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    printf '\n%sHost%s\n' "$C_BOLD" "$C_RESET"
    say "  OS:    $OS"
    say "  Arch:  $ARCH"
    if [ "$OS" = "linux" ]; then
        cuda_state=$(detect_linux_cuda)
        say "  CUDA detection: $cuda_state"
        gn=$(gpu_name)
        [ -n "$gn" ] && say "  GPU name:       $gn"
    fi
    printf '\n%sExisting install%s\n' "$C_BOLD" "$C_RESET"
    bin=$(current_binary)
    if [ -n "$bin" ]; then
        say  "  Path:    $bin"
        ver=$(current_version)
        say  "  Version: ${ver:-(does not run)}"
    else
        say "  (no keyhog found in PATH or $INSTALL_DIR)"
    fi
    printf '\n%sPATH%s\n' "$C_BOLD" "$C_RESET"
    case ":$PATH:" in
      *":$INSTALL_DIR:"*) ok "  $INSTALL_DIR is on PATH." ;;
      *) warn "  $INSTALL_DIR is NOT on PATH. Add: export PATH=\"$INSTALL_DIR:\$PATH\"" ;;
    esac
    printf '\n%sLatest release%s\n' "$C_BOLD" "$C_RESET"
    resolve_tag
    say "  Tag: $TAG"
    resolve_asset
    say "  Would install: $ASSET"
}

do_calibrate() {
    bin=$(current_binary || true)
    if [ -z "$bin" ] || [ ! -x "$bin" ]; then
        err "No installed keyhog binary found to calibrate. Run install first."
        exit 1
    fi
    if ! prime_autoroute_cache "$bin"; then
        exit 1
    fi
}

do_uninstall() {
    bin=$(current_binary)
    if [ -z "$bin" ]; then
        warn "No keyhog binary found in $INSTALL_DIR or PATH. Nothing to remove."
        return
    fi
    if ! confirm "Remove $bin?" Y; then
        warn "Aborted."
        return
    fi
    rm -f "$bin"
    ok "Removed $bin"
    # Completions + shell rc entries are left alone on purpose. We don't
    # know which lines in your .bashrc / .zshrc are ours vs yours, and
    # silently editing those files is exactly the kind of installer
    # behavior we don't want. Remove manually if needed.
    dim "  (Shell rc entries and completions, if any, are left in place.)"
}

# ============================================================
# main
# ============================================================

banner

if [ "$INTERACTIVE" = "0" ] && [ "$MODE" = "install" ] && [ ! -t 0 ]; then
    dim "Tip: re-run interactively for variant + post-install wizard:"
    dim "  curl -fsSL https://raw.githubusercontent.com/$REPO/main/install.sh -o keyhog-install.sh && sh keyhog-install.sh"
fi

case "$MODE" in
    install)   do_install ;;
    repair)    do_repair ;;
    diagnose)  do_diagnose ;;
    calibrate) do_calibrate ;;
    uninstall) do_uninstall ;;
esac

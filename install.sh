#!/usr/bin/env sh
#
# KeyHog installer (Linux + macOS).
#
# Authenticated install from one tagged release:
#   TAG=v0.5.41
#   BASE="https://github.com/santhreal/keyhog/releases/download/$TAG"
#   PUB='RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go'
#   curl -fSLO "$BASE/install.sh" -fSLO "$BASE/install.sh.minisig"
#   minisign -Vm install.sh -P "$PUB"
#   KEYHOG_VERSION="$TAG" sh install.sh
#
# Modes:
#   (default)         install or upgrade keyhog
#   --repair          detect a broken install and re-download
#   --diagnose        print full host + binary status, make no changes
#   --calibrate       rerun visible autoroute calibration for the installed binary
#   --uninstall       remove the binary plus installer-owned PATH and completions
#
# Common flags:
#   --version=vX.Y.Z    pin a release tag (default: latest stable complete bundle)
#   --install-dir=PATH  override the default install directory
#   --from-file=PATH    install a pre-built/pre-downloaded keyhog binary instead
#                       of downloading a release (offline / air-gapped installs,
#                       and CI proving a freshly-built binary). Skips the GitHub
#                       release lookup; still runs the full backup + atomic swap
#                       + verify (`keyhog doctor`) + rollback path. Requires a
#                       sibling PATH.sha256, PATH.gpu-literals.tar.gz, and
#                       PATH.gpu-literals.tar.gz.sha256 unless --insecure is
#                       explicit.
#   --yes / -y          non-interactive: accept defaults, no prompts
#   --insecure          allow an install only when release signature/checksum
#                       proof is unavailable; fetched mismatches still fail
#   --no-color          disable ANSI colors
#   --help / -h         show this help and exit
#
# Env overrides:
#   KEYHOG_VERSION, GITHUB_TOKEN, NO_COLOR

set -eu

# Refuse to run when SOURCED. This installer calls `exit` on many paths, and
# `exit` inside a sourced script terminates the caller's interactive shell, a
# nasty surprise for anyone who runs `. install.sh` / `source install.sh`. The
# guard is scoped to bash/zsh (the shells that expose a sourcing signal); under a
# plain POSIX `sh` the documented `curl | sh` RUN path hits neither branch and is
# left completely unchanged. `if`/`then` (not `[ ] && …`) keeps it safe under the
# `set -e` above when the condition is false on the normal run path.
if [ -n "${BASH_SOURCE:-}" ]; then
    if [ "${BASH_SOURCE}" != "$0" ]; then
        printf '%s\n' "keyhog installer: run this script (sh install.sh), do not source it." >&2
        return 1
    fi
elif [ -n "${ZSH_EVAL_CONTEXT:-}" ]; then
    case "$ZSH_EVAL_CONTEXT" in
        *:file)
            printf '%s\n' "keyhog installer: run this script (sh install.sh), do not source it." >&2
            return 1
            ;;
    esac
fi

REPO="santhreal/keyhog"
RELEASE_PUBLIC_KEY="RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go"
INSTALL_DIR="$HOME/.local/bin"
VERSION="${KEYHOG_VERSION:-}"
FROM_FILE=""
INSECURE_INSTALL=0
MODE="install"
INTERACTIVE=1
ASSUME_YES=0
USE_COLOR=1
LATEST_RELEASE_ALIAS=0

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
        C_CYAN=$(printf '\033[36m')
    else
        C_RESET='' C_BOLD='' C_DIM='' C_RED='' C_GREEN='' C_YELLOW='' C_CYAN=''
    fi
}

say() { printf '%s\n' "$*"; }
status() {
    kh_status_label="$1"
    kh_status_color="$2"
    shift 2
    printf '%s%s%s %s\n' "$kh_status_color" "$kh_status_label" "$C_RESET" "$*"
}
status_err() {
    kh_status_label="$1"
    kh_status_color="$2"
    shift 2
    printf '%s%s%s %s\n' "$kh_status_color" "$kh_status_label" "$C_RESET" "$*" >&2
}
info() { status INFO "$C_CYAN" "$*"; }
ok()   { status PASS "$C_GREEN" "$*"; }
warn() { status WARN "$C_YELLOW" "$*"; }
err()  { status_err FAIL "$C_RED" "$*"; }
dim()  { printf '%s%s%s\n' "$C_DIM" "$*" "$C_RESET"; }

now_ms() {
    kh_now_ms="$(date +%s%3N 2>/dev/null || true)"
    case "$kh_now_ms" in
        ''|*[!0123456789]*)
            kh_now_s="$(date +%s 2>/dev/null || printf '0')"
            printf '%s000\n' "$kh_now_s"
            ;;
        *)
            printf '%s\n' "$kh_now_ms"
            ;;
    esac
}

elapsed_ms_since() {
    kh_elapsed_start_ms="$1"
    kh_elapsed_end_ms="$(now_ms)"
    case "$kh_elapsed_start_ms:$kh_elapsed_end_ms" in
        *[!0123456789:]*|:*|*:)
            printf '0\n'
            ;;
        *)
            if [ "$kh_elapsed_end_ms" -ge "$kh_elapsed_start_ms" ]; then
                printf '%s\n' "$((kh_elapsed_end_ms - kh_elapsed_start_ms))"
            else
                printf '0\n'
            fi
            ;;
    esac
}

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
        case "$default" in Y|y) return 0 ;; *) return 1 ;; esac
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
"Authenticated install:" \
"  Download install.sh and install.sh.minisig from one tagged release," \
"  verify with Minisign key RWTPnJ/p6xVJ3TJIxr+ZVHMD/MTHWZhsdE38Go/oD3DYBoi4bePR55go," \
"  then run KEYHOG_VERSION=<tag> sh install.sh." \
"" \
"Modes:  (default) install/upgrade   --repair   --diagnose   --calibrate   --uninstall" \
"Flags:  --version=vX.Y.Z  --install-dir=PATH" \
"        --from-file=PATH  --yes/-y  --no-prompt  --insecure  --no-color  --help/-h" \
"Env:    KEYHOG_VERSION  GITHUB_TOKEN  NO_COLOR"
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

# resolve_asset: sets ASSET and GPU_NOTE. The Linux binary probes CUDA and WGPU
# dynamically, so host accelerator state does not change the release artifact.
resolve_asset() {
    ASSET=""
    GPU_NOTE=""

    case "$OS-$ARCH" in
      linux-x86_64|linux-amd64)
        ASSET="keyhog-linux-x86_64"
        GPU_NOTE="One Linux build probes CUDA and WGPU at runtime, then autoroute selects only from persisted fastest-correct evidence."
        ;;
      darwin-arm64|darwin-aarch64)
        ASSET="keyhog-macos-aarch64"
        GPU_NOTE="Apple Silicon. Installing the portable no-system-library macOS build (no Hyperscan, WGPU, CUDA, or native Metal asset in the current release)."
        ;;
      darwin-x86_64|darwin-amd64)
        ASSET="keyhog-macos-x86_64"
        GPU_NOTE="Intel Mac. Installing the portable no-system-library macOS build (no Hyperscan, WGPU, CUDA, or native Metal asset in the current release)."
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
        # keyhog release tags are all v-prefixed (vX.Y.Z). Accept a bare
        # semver too (`--version=X.Y.Z`): a download URL built from the
        # un-prefixed tag 404s. Normalise a digit-leading
        # version to the v-prefixed tag; leave an explicit v… or any other
        # ref (branch, sha, custom tag) untouched.
        case "$VERSION" in
            [0-9]*) TAG="v$VERSION" ;;
            *)      TAG="$VERSION" ;;
        esac
        return
    fi

    TAG="latest"
}

github_api_get() {
    url="$1"
    if [ -n "${GITHUB_TOKEN:-}" ]; then
        curl -fsSL \
            -H "Authorization: Bearer $GITHUB_TOKEN" \
            -H "X-GitHub-Api-Version: 2022-11-28" \
            "$url"
    else
        curl -fsSL "$url"
    fi
}

resolve_tag_from_api() {
    # Walk recent releases in publication order and admit only a stable,
    # non-draft release with this host's complete signed bundle. Selecting a
    # release merely because it has one asset can choose a partial publication
    # or an asset for another platform.
    releases_api_err=$(mktemp "${TMPDIR:-/tmp}/keyhog-releases-api.XXXXXX")
    if ! releases_json=$(github_api_get "https://api.github.com/repos/$REPO/releases?per_page=10" 2>"$releases_api_err"); then
        releases_api_msg=$(sed -n '1p' "$releases_api_err")
        rm -f "$releases_api_err"
        err "Could not query GitHub releases API."
        if [ -n "$releases_api_msg" ]; then
            err "GitHub API error: $releases_api_msg"
        fi
        err "Try --version=vX.Y.Z with a known published release tag explicitly."
        exit 1
    fi
    rm -f "$releases_api_err"
    if [ -z "$releases_json" ]; then
        err "Could not query GitHub releases API."
        err "GitHub releases API returned an empty response."
        err "Try --version=vX.Y.Z with a known published release tag explicitly."
        exit 1
    fi

    # GitHub emits tag/draft/prerelease before the assets array. Match exact
    # asset names, independent of JSON indentation, without requiring jq.
    # curl returns compact JSON in production while tests and proxies may
    # pretty-print it. Split only the release fields we consume into records so
    # the state machine is independent of whitespace and line layout.
    normalized_releases=$(printf '%s' "$releases_json" | awk '
        {
            gsub(/"(tag_name|draft|prerelease|name)"[[:space:]]*:/, "\n&")
            print
        }
    ')
    TAG=$(printf '%s' "$normalized_releases" | awk -v base="$ASSET" '
        /"tag_name"[[:space:]]*:/ {
            line = $0
            sub(/.*"tag_name"[[:space:]]*:[[:space:]]*"/, "", line)
            sub(/".*/, "", line)
            tag = line
            stable = published = 0
            binary = checksum = signature = sidecar = sidecar_checksum = sidecar_signature = 0
        }
        /"draft"[[:space:]]*:[[:space:]]*false/ { published = 1 }
        /"prerelease"[[:space:]]*:[[:space:]]*false/ { stable = 1 }
        /"name"[[:space:]]*:/ {
            name = $0
            sub(/.*"name"[[:space:]]*:[[:space:]]*"/, "", name)
            sub(/".*/, "", name)
            if (name == base) binary = 1
            if (name == base ".sha256") checksum = 1
            if (name == base ".minisig") signature = 1
            if (name == base ".gpu-literals.tar.gz") sidecar = 1
            if (name == base ".gpu-literals.tar.gz.sha256") sidecar_checksum = 1
            if (name == base ".gpu-literals.tar.gz.minisig") sidecar_signature = 1
        }
        {
            if (tag != "" && published && stable && binary && checksum && signature && sidecar && sidecar_checksum && sidecar_signature) {
                print tag
                exit
            }
        }
    ')

    if [ -z "$TAG" ]; then
        err "No stable GitHub release in the last 10 has the complete signed bundle for $ASSET."
        err "Required: binary, SHA-256, minisign, GPU literal sidecar, sidecar SHA-256, and sidecar minisign."
        err "Try --version=vX.Y.Z with a known published release tag explicitly."
        exit 1
    fi
}

release_bundle_is_complete() {
    bundle_tag=$1
    for bundle_asset in \
        "$ASSET" \
        "$ASSET.sha256" \
        "$ASSET.minisig" \
        "$ASSET.gpu-literals.tar.gz" \
        "$ASSET.gpu-literals.tar.gz.sha256" \
        "$ASSET.gpu-literals.tar.gz.minisig"; do
        if ! curl -fsSI "https://github.com/$REPO/releases/download/$bundle_tag/$bundle_asset" >/dev/null 2>&1; then
            return 1
        fi
    done
    return 0
}

resolve_tag_from_latest_redirect() {
    name="$1"
    [ -n "$name" ] || return 1
    latest_url=$(printf 'https://github.com/%s/releases/latest/download/%s\n' "$REPO" "$name")
    if ! redirect_url=$(curl -fsSI -o /dev/null -w '%{redirect_url}' "$latest_url" 2>/dev/null); then
        return 1
    fi
    redirect_tag=$(printf '%s\n' "$redirect_url" | sed -n 's#.*/releases/download/\([^/][^/]*\)/.*#\1#p' | head -n 1)
    [ -n "$redirect_tag" ] || return 1
    release_bundle_is_complete "$redirect_tag" || return 1
    TAG="$redirect_tag"
    return 0
}

resolve_operator_release_tag() {
    resolve_tag
    LATEST_RELEASE_ALIAS=0
    if [ -z "$VERSION" ] && [ "$TAG" = "latest" ]; then
        if resolve_tag_from_latest_redirect "$ASSET"; then
            LATEST_RELEASE_ALIAS=1
            return
        fi
        warn "Latest release redirect did not prove a complete signed host bundle; checking recent stable releases."
        resolve_tag_from_api
        LATEST_RELEASE_ALIAS=1
    fi
}

release_tag_label() {
    if [ "$LATEST_RELEASE_ALIAS" = "1" ]; then
        printf '%s (latest)\n' "$TAG"
    else
        printf '%s\n' "$TAG"
    fi
}

version_tag_from_text() {
    printf '%s\n' "$1" | sed -n 's/.*\(v[0-9][0-9A-Za-z._-]*\).*/\1/p' | head -n 1
}

show_installed_release_relation() {
    existing="$1"
    [ "$LATEST_RELEASE_ALIAS" = "1" ] || return 0
    [ -n "$existing" ] || return 0
    existing_tag=$(version_tag_from_text "$existing")
    [ -n "$existing_tag" ] || return 0
    if [ "$existing_tag" = "$TAG" ]; then
        say "  Update:        up to date"
    else
        say "  Update:        update available ($existing_tag -> $TAG)"
    fi
}

release_asset_url() {
    name="$1"
    if [ "$TAG" = "latest" ]; then
        printf 'https://github.com/%s/releases/latest/download/%s\n' "$REPO" "$name"
    else
        printf 'https://github.com/%s/releases/download/%s/%s\n' "$REPO" "$TAG" "$name"
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
    url=$(release_asset_url "$name")
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
        warn "  Proceeding without full release verification because --insecure is set."
        return 0
    fi
    err "$reason"
    err "Refusing to install an unverified keyhog binary."
    case "$reason" in
      *"minisign is not installed"*)
        print_minisign_install_hint
        ;;
      *)
        err "Fix: ensure the .minisig and .sha256 files are published, minisign is installed, and sha256sum or shasum is available."
        ;;
    esac
    err "Only for emergency/local diagnostics, rerun with --insecure to accept an unverified binary."
    return 1
}

print_minisign_install_hint() {
    case "$OS" in
      darwin)
        if command -v brew >/dev/null 2>&1; then
            err "Fix: install minisign with: brew install minisign"
        else
            err "Fix: install Homebrew, then run: brew install minisign"
            err "Portable fallback: cargo install minisign"
        fi
        ;;
      linux)
        if command -v apt-get >/dev/null 2>&1; then
            err "Fix: install minisign with: sudo apt-get update && sudo apt-get install -y minisign"
        elif command -v dnf >/dev/null 2>&1; then
            err "Fix: install minisign with: sudo dnf install -y minisign"
        elif command -v yum >/dev/null 2>&1; then
            err "Fix: install minisign with: sudo yum install -y minisign"
        elif command -v apk >/dev/null 2>&1; then
            err "Fix: install minisign with: sudo apk add minisign"
        elif command -v pacman >/dev/null 2>&1; then
            err "Fix: install minisign with: sudo pacman -S --needed minisign"
        else
            err "Fix: install minisign with your distro package manager, or run: cargo install minisign"
        fi
        ;;
      *)
        err "Fix: install minisign, then rerun this command."
        ;;
    esac
}

# Verify the release minisign signature of $1 against the pinned keyhog release
# public key. Missing proof/tooling fails closed unless the operator explicitly
# chooses --insecure. A fetched signature that does not verify is always fatal.
verify_release_signature() {
    binary="$1"
    asset_name="$2"
    sigfile=$(mktemp)

    # Classify the signature fetch: a transient transport failure (DNS/timeout/
    # reset) must NOT be silently downgraded to "no signature published" and
    # skipped (fail closed for security controls). download_asset already
    # --retries transient blips; its curl exit code then distinguishes a genuine
    # HTTP 404 (curl -f exit 22, asset absent) from a network/transport error
    # (any other non-zero). Only the former legitimately means "not published".
    if download_asset "$asset_name.minisig" "$sigfile" 2>/dev/null; then
        sig_dl_rc=0
    else
        sig_dl_rc=$?
    fi
    if [ "$sig_dl_rc" -ne 0 ] && [ "$sig_dl_rc" -ne 22 ]; then
        rm -f "$sigfile"
        allow_unverified_install "Could not fetch the .minisig signature for $asset_name (curl error $sig_dl_rc): a network/transport failure, not a missing signature. A retry may succeed."
        return $?
    fi
    if [ ! -s "$sigfile" ]; then
        rm -f "$sigfile"
        allow_unverified_install "No .minisig signature was published for $asset_name at $TAG."
        return $?
    fi
    if ! command -v minisign >/dev/null 2>&1; then
        rm -f "$sigfile"
        allow_unverified_install "minisign is not installed, so the $asset_name release signature cannot be verified."
        return $?
    fi
    if minisign -Vm "$binary" -P "$RELEASE_PUBLIC_KEY" -x "$sigfile" >/dev/null 2>&1; then
        rm -f "$sigfile"
        ok "Minisign signature verified."
        return 0
    fi
    rm -f "$sigfile"
    err "Minisign signature verification failed for $asset_name."
    err "Refusing to install. The release asset may have been tampered with or signed by the wrong key."
    return 1
}

# Verify the SHA256 of $1 against the per-asset .sha256 file on the
# release. Returns 0 on match. Missing proof fails closed unless the
# operator explicitly chooses --insecure.
verify_checksum() {
    binary="$1"
    asset_name="$2"
    checksum_url=$(release_asset_url "$asset_name.sha256")
    # Fetch the checksum in its own step (not inside a pipe) so curl's exit
    # status can be classified: a transient transport failure (DNS/timeout/reset)
    # must NOT be silently downgraded to "no checksum published" and skipped
    # (fail closed for security controls). --retry rides out transient blips
    # first, matching download_asset's policy; a genuine HTTP 404 (curl -f exit
    # 22) then legitimately means the checksum asset is absent.
    if checksum_body=$(curl -fsSL --retry 5 --retry-delay 2 --retry-connrefused "$checksum_url" 2>/dev/null); then
        checksum_rc=0
    else
        checksum_rc=$?
    fi
    if [ "$checksum_rc" -ne 0 ] && [ "$checksum_rc" -ne 22 ]; then
        allow_unverified_install "Could not fetch the .sha256 checksum for $asset_name (curl error $checksum_rc): a network/transport failure, not a missing checksum. A retry may succeed."
        return $?
    fi
    expected=$(printf '%s\n' "$checksum_body" | awk '{print $1}' | head -n1)
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
# unless the operator explicitly chooses --insecure.
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
GPU_LITERAL_SIDECAR_TMP=""
GPU_PROGRAMS_CACHE_BACKUP=""
GPU_PROGRAMS_CACHE_WAS_MISSING=0

gpu_programs_cache_dir_for_install() {
    if [ "$OS" = "darwin" ]; then
        printf '%s/Library/Caches/keyhog/programs\n' "$HOME"
    elif [ -n "${XDG_CACHE_HOME:-}" ]; then
        printf '%s/keyhog/programs\n' "$XDG_CACHE_HOME"
    else
        printf '%s/.cache/keyhog/programs\n' "$HOME"
    fi
}

cleanup_gpu_literal_sidecar_tmp() {
    if [ -n "$GPU_LITERAL_SIDECAR_TMP" ]; then
        rm -f "$GPU_LITERAL_SIDECAR_TMP" 2>/dev/null || true
        GPU_LITERAL_SIDECAR_TMP=""
    fi
}

clear_gpu_programs_cache_backup() {
    if [ -n "$GPU_PROGRAMS_CACHE_BACKUP" ]; then
        rm -rf "$GPU_PROGRAMS_CACHE_BACKUP" 2>/dev/null || true
        GPU_PROGRAMS_CACHE_BACKUP=""
    fi
    GPU_PROGRAMS_CACHE_WAS_MISSING=0
}

backup_gpu_programs_cache_for_install() {
    clear_gpu_programs_cache_backup
    programs_dir="$(gpu_programs_cache_dir_for_install)"
    backup_root=$(mktemp -d -t keyhog-gpu-programs-backup-XXXXXX)
    if [ -z "$backup_root" ] || [ ! -d "$backup_root" ]; then
        err "Could not create a temporary GPU literal cache backup directory."
        return 1
    fi
    if [ -d "$programs_dir" ]; then
        if ! cp -Rp "$programs_dir" "$backup_root/programs" 2>/dev/null; then
            rm -rf "$backup_root"
            err "Could not back up GPU literal cache directory at $programs_dir."
            return 1
        fi
        GPU_PROGRAMS_CACHE_WAS_MISSING=0
    else
        GPU_PROGRAMS_CACHE_WAS_MISSING=1
    fi
    GPU_PROGRAMS_CACHE_BACKUP="$backup_root"
}

restore_gpu_programs_cache_backup() {
    [ -n "$GPU_PROGRAMS_CACHE_BACKUP" ] || return 0
    programs_dir="$(gpu_programs_cache_dir_for_install)"
    if ! rm -rf "$programs_dir" 2>/dev/null; then
        err "Could not remove GPU literal cache directory at $programs_dir during rollback."
        return 1
    fi
    if [ "$GPU_PROGRAMS_CACHE_WAS_MISSING" != "1" ] && [ -d "$GPU_PROGRAMS_CACHE_BACKUP/programs" ]; then
        if ! mkdir -p "$(dirname "$programs_dir")" || ! mv "$GPU_PROGRAMS_CACHE_BACKUP/programs" "$programs_dir"; then
            err "Could not restore GPU literal cache directory at $programs_dir."
            return 1
        fi
    fi
    clear_gpu_programs_cache_backup
}

stage_local_gpu_literal_sidecar() {
    local_sidecar="$FROM_FILE.gpu-literals.tar.gz"
    local_sum="$local_sidecar.sha256"
    sidecar_tmp=$(mktemp)
    if [ ! -f "$local_sidecar" ] || [ ! -s "$local_sidecar" ]; then
        rm -f "$sidecar_tmp"
        err "--from-file requires a sibling GPU literal sidecar: $local_sidecar"
        err "Refusing to install a local binary that would recompile shipped detector matchers at runtime."
        return 1
    fi
    if [ -f "$local_sum" ]; then
        if ! verify_local_checksum "$local_sidecar" "$local_sum"; then
            rm -f "$sidecar_tmp"
            return 1
        fi
    else
        if ! allow_unverified_install "No local checksum file found beside --from-file GPU literal sidecar: $local_sum"; then
            rm -f "$sidecar_tmp"
            return 1
        fi
    fi
    if ! cp "$local_sidecar" "$sidecar_tmp" 2>/dev/null; then
        rm -f "$sidecar_tmp"
        err "--from-file: could not read GPU literal sidecar $local_sidecar"
        return 1
    fi
    if ! validate_gpu_literal_sidecar_archive "$sidecar_tmp"; then
        rm -f "$sidecar_tmp"
        err "Refusing GPU literal sidecar with unsafe archive contents."
        return 1
    fi
    cleanup_gpu_literal_sidecar_tmp
    GPU_LITERAL_SIDECAR_TMP="$sidecar_tmp"
}

download_verified_gpu_literal_sidecar() {
    if [ -n "$FROM_FILE" ]; then
        stage_local_gpu_literal_sidecar
        return $?
    fi
    sidecar_name="$ASSET.gpu-literals.tar.gz"
    sidecar_tmp=$(mktemp)
    # Classify the fetch (Law 10: never conflate a transport failure with a
    # missing asset). curl's exit 22 (via download_asset) means the server
    # returned an HTTP error >=400 (a real 404 => not published); any other
    # non-zero exit is a network/DNS/transport failure and must NOT tell the
    # operator to rebuild the release workflow for a sidecar that may be present.
    if download_asset "$sidecar_name" "$sidecar_tmp" 2>/dev/null; then
        sidecar_dl_rc=0
    else
        sidecar_dl_rc=$?
    fi
    if [ "$sidecar_dl_rc" -ne 0 ] && [ "$sidecar_dl_rc" -ne 22 ]; then
        rm -f "$sidecar_tmp"
        err "Could not download the GPU literal artifact sidecar $sidecar_name (curl error $sidecar_dl_rc): a network/transport failure, not a missing asset. A retry may succeed."
        err "Refusing to install a release whose shipped detector matchers could not be fetched (they must not be recompiled at runtime)."
        return 1
    fi
    if [ ! -s "$sidecar_tmp" ]; then
        rm -f "$sidecar_tmp"
        err "No GPU literal artifact sidecar was published for $ASSET at $TAG."
        err "Refusing to install a release that would recompile shipped detector matchers at runtime."
        err "Fix: rebuild the release workflow so $sidecar_name, $sidecar_name.sha256, and $sidecar_name.minisig are uploaded."
        return 1
    fi
    if ! verify_release_signature "$sidecar_tmp" "$sidecar_name"; then
        rm -f "$sidecar_tmp"
        return 1
    fi
    if ! verify_checksum "$sidecar_tmp" "$sidecar_name"; then
        rm -f "$sidecar_tmp"
        return 1
    fi
    if ! validate_gpu_literal_sidecar_archive "$sidecar_tmp"; then
        rm -f "$sidecar_tmp"
        err "Refusing GPU literal sidecar with unsafe archive contents."
        return 1
    fi
    cleanup_gpu_literal_sidecar_tmp
    GPU_LITERAL_SIDECAR_TMP="$sidecar_tmp"
}

rollback_staged_install_after_sidecar_failure() {
    target="$1"
    cleanup_gpu_literal_sidecar_tmp
    if [ -n "$INSTALL_BACKUP" ] && [ -e "$INSTALL_BACKUP" ]; then
        mv -f "$INSTALL_BACKUP" "$target"
        INSTALL_BACKUP=""
        warn "Rolled back to your previous working keyhog at $target."
    else
        rm -f "$target" 2>/dev/null || true
        warn "Removed the binary because shipped GPU literal artifacts could not be seeded."
    fi
}

validate_gpu_literal_sidecar_archive() {
    archive="$1"
    if ! tar -tzf "$archive" >/dev/null 2>&1; then
        err "GPU literal artifact sidecar is not a readable tar.gz archive."
        return 1
    fi
    if ! tar -tzf "$archive" | while IFS= read -r entry; do
        case "$entry" in
          ""|/*)
            printf '%s\n' "$entry"
            exit 1
            ;;
        esac
        if printf '%s\n' "$entry" | grep -Eq '(^|[\\/])\.\.[[:space:].]*([\\/]|$)'; then
            printf '%s\n' "$entry"
            exit 1
        fi
    done >/dev/null; then
        err "GPU literal artifact sidecar contains unsafe archive paths."
        return 1
    fi
    if ! tar -tvzf "$archive" | while IFS= read -r listing; do
        entry_kind=$(printf '%s' "$listing" | cut -c 1)
        case "$entry_kind" in
          l|h)
            printf '%s\n' "$listing"
            exit 1
            ;;
        esac
    done >/dev/null; then
        err "GPU literal artifact sidecar contains link entries."
        return 1
    fi
}

install_verified_gpu_literal_sidecar() {
    [ -n "$GPU_LITERAL_SIDECAR_TMP" ] || return 0
    if ! validate_gpu_literal_sidecar_archive "$GPU_LITERAL_SIDECAR_TMP"; then
        cleanup_gpu_literal_sidecar_tmp
        err "Refusing GPU literal sidecar with unsafe archive paths."
        return 1
    fi
    programs_dir="$(gpu_programs_cache_dir_for_install)"
    extract_dir=$(mktemp -d -t keyhog-gpu-literals-XXXXXX)
    if ! mkdir -p "$programs_dir"; then
        rm -rf "$extract_dir"
        cleanup_gpu_literal_sidecar_tmp
        err "Could not create GPU literal cache directory at $programs_dir."
        return 1
    fi
    if ! tar -xzf "$GPU_LITERAL_SIDECAR_TMP" -C "$extract_dir"; then
        rm -rf "$extract_dir"
        cleanup_gpu_literal_sidecar_tmp
        err "Could not extract GPU literal artifact sidecar."
        return 1
    fi
    find "$extract_dir" -type f -name '*.bin' | while IFS= read -r artifact; do
        base=$(basename "$artifact")
        tmp_target="$programs_dir/.$base.$$"
        if ! cp "$artifact" "$tmp_target"; then
            rm -f "$tmp_target"
            exit 2
        fi
        if ! mv -f "$tmp_target" "$programs_dir/$base"; then
            rm -f "$tmp_target"
            exit 3
        fi
        installed=$(cat "$extract_dir/.installed-count" 2>/dev/null || printf '0')
        printf '%s\n' "$((installed + 1))" > "$extract_dir/.installed-count"
    done
    install_status=$?
    installed=$(cat "$extract_dir/.installed-count" 2>/dev/null || printf '0')
    rm -rf "$extract_dir"
    cleanup_gpu_literal_sidecar_tmp
    if [ "$install_status" != "0" ]; then
        err "Could not install GPU literal artifacts into $programs_dir."
        return 1
    fi
    if [ "$installed" = "0" ]; then
        err "GPU literal artifact sidecar contained no matcher .bin files."
        return 1
    fi
    ok "Installed $installed GPU literal matcher artifact(s) into $programs_dir."
}

download_selected_release_asset() {
    out="$1"
    quiet="${2:-0}"
    if download_asset "$ASSET" "$out" 2>/dev/null; then
        return 0
    fi
    if [ "$quiet" != "1" ]; then
        err "Download failed. Is the release published yet?"
        err "Browse https://github.com/$REPO/releases to confirm."
    fi
    return 1
}

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
    elif ! download_selected_release_asset "$tmp"; then
        rm -f "$tmp"
        trap - EXIT INT TERM
        exit 1
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

    # Release verification happens BEFORE we overwrite, so a corrupt or unsigned
    # artifact can never replace a working binary. Downloads check the release's
    # per-asset .minisig and .sha256; a --from-file install requires a sibling
    # PATH.sha256 unless the operator explicitly accepts an unverified local
    # artifact.
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
        if ! download_verified_gpu_literal_sidecar; then
            rm -f "$tmp"
            cleanup_gpu_literal_sidecar_tmp
            trap - EXIT INT TERM
            exit 1
        fi
    else
        if ! verify_release_signature "$tmp" "$ASSET"; then
            rm -f "$tmp"
            trap - EXIT INT TERM
            exit 1
        fi
        if ! verify_checksum "$tmp" "$ASSET"; then
            rm -f "$tmp"
            trap - EXIT INT TERM
            exit 1
        fi
        if ! download_verified_gpu_literal_sidecar; then
            rm -f "$tmp"
            cleanup_gpu_literal_sidecar_tmp
            trap - EXIT INT TERM
            exit 1
        fi
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
    verify_err_file=$(mktemp -t keyhog-version-stderr.XXXXXX)
    verify_out=$("$INSTALL_DIR/keyhog" --version 2>"$verify_err_file") || verify_status=$?
    verify_err=$(cat "$verify_err_file" 2>/dev/null || true)
    rm -f "$verify_err_file"

    # Success is exit 0 from --version. A warning on stderr (deprecation note,
    # config-load warning, locale grumble) is NOT a broken binary - the old
    # `-z "$verify_err"` gate treated any such noise as a failure and would,
    # post-rollback-fix, needlessly roll back a perfectly good upgrade.
    if [ "$verify_status" = "0" ]; then
        if [ -n "$TAG" ] && [ "$TAG" != "latest" ] && [ "$TAG" != "(local file)" ]; then
            observed_tag=$(version_tag_from_text "$verify_out")
            if [ -z "$observed_tag" ]; then
                err "Installed binary did not report a version tag; refusing to trust release $TAG."
                return 1
            fi
            if [ "$observed_tag" != "$TAG" ]; then
                err "Candidate binary version does not match release tag: binary reports $observed_tag but release resolved $TAG."
                err "Refusing to install a mismatched binary (possible substitution or downgrade attack)."
                return 1
            fi
        fi
        ok "Installed $(printf '%s\n' "$verify_out" | head -n 1)"
        [ -n "$verify_err" ] && dim "  (binary emitted a startup notice: $verify_err)"
        # Native post-install health check. `keyhog doctor` reuses the same
        # hw_probe the scanner uses (so there's no shell-side GPU detection to
        # drift from runtime) and runs an end-to-end scan self-test: it plants
        # a synthetic secret and confirms the freshly-installed binary actually
        # detects it on THIS host. Per doctor's contract it exits 4
        # (EXIT_HEALTH_FAILURE) iff it deems the binary UNHEALTHY - the planted
        # secret was NOT detected, the detector corpus is missing, or (on a
        # GPU-capable host) the fail-closed DEFAULT GPU scan route is dead - and
        # exits 0 otherwise (PATH-only notices are exit-0 warnings, never a
        # failure; GPU self-tests are skipped on no-GPU/headless hosts so CI
        # stays green). A non-zero exit therefore means the binary we just
        # installed cannot do its primary job on the route it will actually
        # use. That is a disqualifying install condition, not a cosmetic
        # warning: fail closed and let finalize_install roll back rather than
        # leave a broken scanner reporting "installed" (Law 10 - no silent
        # fallback past a failed self-test; and consistent with the autoroute
        # gate immediately below, which already refuses a broken default route).
        say ""
        "$INSTALL_DIR/keyhog" doctor
        doctor_status=$?
        if [ "$doctor_status" -eq 4 ]; then
            err "keyhog doctor reports the freshly-installed binary is UNHEALTHY (exit 4): it failed its own end-to-end scan self-test above."
            err "Refusing to leave a scanner that cannot detect secrets on its default route; rolling back this install."
            err "  If only the GPU route is broken, the CPU/SIMD paths still work - reinstall, then scan with an explicit '--backend cpu' or '--backend simd' override."
            return 1
        elif [ "$doctor_status" -ne 0 ]; then
            err "keyhog doctor did not complete (exit $doctor_status): the installed binary could not even run its own health self-test."
            err "Rolling back rather than leaving an install whose health is unknown."
            return 1
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
                    err "    cargo install --git https://github.com/santhreal/keyhog --no-default-features --features portable"
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

docker_daemon_ready() {
    docker_cmd="$1"
    "$docker_cmd" info >/dev/null 2>&1
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
    calibration_started_s="$(date +%s 2>/dev/null || printf '0')"

    # Pick the config-isolation flag the INSTALLED binary actually accepts. A
    # released binary that predates `--no-config` only has `--config <PATH>`;
    # passing `--no-config` to it makes clap exit 2 and every probe fail
    # for a reason the old `>/dev/null 2>&1` hid (Law 10: a swallowed installer
    # error reads as a broken product). Detect once, never guess.
    scan_help_err="$tmpdir/scan-help.err"
    if ! scan_help="$("$bin" scan --help 2>"$scan_help_err")"; then
        real_err="$(head -n 1 "$scan_help_err" 2>/dev/null)"
        err "Could not inspect installed keyhog scan --help before autoroute calibration."
        if [ -n "$real_err" ]; then
            err "scan --help error: $real_err"
        fi
        return 1
    fi
    if [ -z "$scan_help" ]; then
        err "Installed keyhog scan --help returned no output; refusing to guess calibration flags."
        return 1
    fi
    if ! printf '%s' "$scan_help" | grep -q -- '--autoroute-calibrate'; then
        # This build does not expose autoroute calibration. The portable
        # macOS/Windows builds gate it out (only the Linux build ships it), so
        # the binary routes with its compiled-in defaults and has no cache to
        # prime -- calibration is a no-op here. Passing --autoroute-calibrate to
        # a binary that lacks it makes every probe fail with "unexpected
        # argument" and (before this guard) rolled back the whole install on
        # those platforms; skip calibration and report success instead.
        warn "  Autoroute calibration not supported by this build (no --autoroute-calibrate flag); using the binary's compiled-in routing."
        return 0
    fi
    if printf '%s' "$scan_help" | grep -q -- '--no-config'; then
        cfg_flag="--no-config"
        cfg_file=""
    else
        : > "$tmpdir/empty-config.toml"
        cfg_flag="--config"
        cfg_file="$tmpdir/empty-config.toml"
    fi
    core_via_subcommand=0
    top_help_err="$tmpdir/top-help.err"
    if ! top_help="$("$bin" --help 2>"$top_help_err")"; then
        real_err="$(head -n 1 "$top_help_err" 2>/dev/null)"
        err "Could not inspect installed keyhog --help before core autoroute calibration."
        if [ -n "$real_err" ]; then
            err "keyhog --help error: $real_err"
        fi
        return 1
    fi
    if [ -z "$top_help" ]; then
        err "Installed keyhog --help returned no output; refusing to guess the core calibration path."
        return 1
    fi
    if printf '%s\n' "$top_help" | grep -q -- 'calibrate-autoroute'; then
        if ! core_output="$("$bin" calibrate-autoroute --quiet)"; then
            err "The installed binary's canonical core autoroute calibration failed."
            return 1
        fi
        core_total="$(printf '%s\n' "$core_output" | sed -n 's/.*ran \([0-9][0-9]*\) workload probe[s]*.*/\1/p' | tail -n 1)"
        if [ -z "$core_total" ]; then
            # Compatibility for binaries that shipped the unified command
            # before its summary distinguished probes from unique route keys.
            core_total="$(printf '%s\n' "$core_output" | sed -n 's/.*calibrated \([0-9][0-9]*\) workload bucket[s]*.*/\1/p' | tail -n 1)"
        fi
        case "$core_total" in
            ''|*[!0-9]*)
                err "Canonical core calibration completed without a readable probe count."
                return 1
                ;;
        esac
        printf '%s\n' "$core_output"
        core_via_subcommand=1
    fi
    # Calibrate the SAME resolved-config digest a real scan requests.
    # `--autoroute-gpu` controls candidate admission during calibration and is
    # intentionally excluded from that digest, so the persisted winner is valid
    # for a later normal auto scan that does not repeat the calibration flag.
    # `--batch-pipeline` does change execution identity and remains absent.
    autoroute_scan_flags=""
    # Calibrate the documented scan-policy presets too. Each preset changes
    # scanner fields hashed into the autoroute config digest, so `keyhog scan .
    # --fast` resolves a DIFFERENT digest than the default and needs its own
    # calibrated decisions or it fails closed (exit 2). The current multi-config
    # cache lets the default policy and every preset coexist in one file. The
    # empty first entry is the default policy; only presets the installed binary
    # actually exposes are calibrated (a released build may predate one).
    autoroute_presets=""
    for preset_flag in --fast --deep --precision; do
        if printf '%s' "$scan_help" | grep -q -- "$preset_flag"; then
            autoroute_presets="$autoroute_presets $preset_flag"
        fi
    done
    # Count: default policy + each supported preset.
    preset_count=1
    for _preset_flag in $autoroute_presets; do
        preset_count=$((preset_count + 1))
    done
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
        elif ! docker_daemon_ready "$docker_bin"; then
            warn "  Docker image calibration unavailable: the Docker daemon is not responding (is Docker Desktop or dockerd running?)."
            warn "  Filesystem/stdin calibration will continue; start Docker and rerun install.sh --calibrate before relying on Docker image autorouting."
            unavailable_calibrations="${unavailable_calibrations} docker"
        else
            docker_calibration=1
        fi
    fi
    web_calibration=0
    python_bin=""
    if printf '%s' "$scan_help" | grep -q -- '--url'; then
        python_bin="$(command -v python3 2>/dev/null || true)"
        if [ -z "$python_bin" ]; then
            candidate_python="$(command -v python 2>/dev/null || true)"
            if [ -n "$candidate_python" ] && "$candidate_python" -c 'import http.server' >/dev/null 2>&1; then
                python_bin="$candidate_python"
            fi
        fi
        if [ -z "$python_bin" ]; then
            warn "  Web URL calibration unavailable: python3/python was not found on PATH."
            warn "  Filesystem/stdin calibration will continue; install Python and rerun install.sh --calibrate before relying on Web URL autorouting."
            unavailable_calibrations="${unavailable_calibrations} web"
        else
            web_calibration=1
        fi
    fi

    # One representative for every power-of-two file-size band from 1 B
    # through 32 MiB. Autoroute never interpolates an unmeasured band.
    byte_sizes="1 2 4 8 16 32 64 128 256 512"
    kib_sizes="1 2 4 8 16 32 64 128 256 512"
    mib_sizes="1 2 4 8 16 32"
    # Directory scans have a distinct source identity from a direct file scan.
    # Include the one-file bucket used by small repositories and install smoke
    # tests; calibrating a same-sized file path cannot stand in for it.
    many_file_counts="1 2 4 8 16 32"
    # The stdin + filesystem "core" probes run once per scan-policy preset
    # (default + each supported preset); the external-source probes
    # (git/docker/web) calibrate the default policy only.
    if [ "$core_via_subcommand" = "1" ]; then
        total=$core_total
    else
        core_total=0
        core_total=$((core_total + 1)) # empty stdin compatibility probe
        core_total=$((core_total + 1)) # stdin 64 KiB
        for _bytes in $byte_sizes; do
            core_total=$((core_total + 1))
        done
        for _kib in $kib_sizes; do
            core_total=$((core_total + 1))
        done
        for _mib in $mib_sizes; do
            core_total=$((core_total + 1))
        done
        core_total=$((core_total + 1)) # decode-heavy 256 KiB
        for _count in $many_file_counts; do
            core_total=$((core_total + 1))
        done
        total=$((core_total * preset_count))
    fi
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
    if [ "$core_via_subcommand" = "1" ]; then
        idx=$core_total
    fi
    failed=0

    # Calibrate the core stdin + filesystem workloads once per scan-policy preset.
    # The default policy (empty flags) runs first; `autoroute_scan_flags` carries
    # the preset into run_keyhog_calibration_scan, so each pass resolves and
    # persists the exact digest a real `keyhog scan <path> [preset]` requests.
    if [ "$core_via_subcommand" = "0" ]; then
    for autoroute_scan_flags in "" $autoroute_presets; do

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
        printf '  [%s/%s] FAIL %s\n' "$idx" "$total" "$label"
        err "Could not create 64 KiB stdin autoroute calibration probe at $probe."
        failed=1
    elif ! run_autoroute_stdin_probe "$idx" "$total" "$label" "$probe" "$out" "$err"; then
        failed=1
    fi

    for bytes in $byte_sizes; do
        idx=$((idx + 1))
        probe="$tmpdir/probe-${bytes}b.txt"
        out="$tmpdir/out-${bytes}b.json"
        err="$tmpdir/err-${bytes}b.txt"
        label="${bytes} B workload"
        if ! make_calibration_probe_bytes "$probe" "$bytes"; then
            printf '  [%s/%s] FAIL %s\n' "$idx" "$total" "$label"
            err "Could not create ${bytes} B autoroute calibration probe at $probe."
            failed=1
            continue
        fi
        if ! run_autoroute_probe "$idx" "$total" "$label" "$probe" "$out" "$err"; then
            failed=1
        fi
    done

    for kib in $kib_sizes; do
        idx=$((idx + 1))
        probe="$tmpdir/probe-${kib}kib.txt"
        out="$tmpdir/out-${kib}kib.json"
        err="$tmpdir/err-${kib}kib.txt"
        label="${kib} KiB workload"
        if ! make_calibration_probe_kib "$probe" "$kib"; then
            printf '  [%s/%s] FAIL %s\n' "$idx" "$total" "$label"
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
            printf '  [%s/%s] FAIL %s\n' "$idx" "$total" "$label"
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
        printf '  [%s/%s] FAIL %s\n' "$idx" "$total" "$label"
        err "Could not create decode-heavy autoroute calibration probe at $probe."
        failed=1
    elif ! run_autoroute_probe "$idx" "$total" "$label" "$probe" "$out" "$err"; then
        failed=1
    fi

    for file_count in $many_file_counts; do
        idx=$((idx + 1))
        probe_dir="$tmpdir/many-${file_count}x4k"
        out="$tmpdir/out-many-${file_count}x4k.json"
        err="$tmpdir/err-many-${file_count}x4k.txt"
        label="${file_count} x 4 KiB files workload"
        if ! make_calibration_tree_kib "$probe_dir" "$file_count" 4; then
            printf '  [%s/%s] FAIL %s\n' "$idx" "$total" "$label"
            err "Could not create ${file_count}-file autoroute calibration probe at $probe_dir."
            failed=1
        elif ! run_autoroute_probe "$idx" "$total" "$label" "$probe_dir" "$out" "$err"; then
            failed=1
        fi
    done

    done # end per-preset core workload sweep
    fi

    # External-source probes (git/docker/web) calibrate the default policy only.
    autoroute_scan_flags=""

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
            printf '  [%s/%s] FAIL %s\n' "$idx" "$total" "$label"
            err "Could not create Web URL autoroute calibration fixture at $web_dir."
            failed=1
        elif ! start_calibration_web_server "$web_dir" "$web_port_file" "$web_pid_file" "$web_log" "$python_bin"; then
            printf '  [%s/%s] FAIL %s\n' "$idx" "$total" "$label"
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
            printf '  [%s/%s] FAIL %s\n' "$idx" "$total" "$label"
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
    if ! show_autoroute_calibration_summary "$total" "$calibration_started_s"; then
        err "Autoroute calibration completed but persisted decisions could not be read back."
        return 1
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

run_keyhog_calibration_scan() {
    if [ "$cfg_flag" = "--no-config" ]; then
        exec "$bin" "$@" --no-config
    else
        exec "$bin" "$@" --config "$cfg_file"
    fi
}

run_autoroute_scan_probe() {
    idx="$1"
    total="$2"
    label="$3"
    mode="$4"
    probe="$5"
    out="$6"
    errfile="$7"
    probe_started_ms="$(now_ms)"
    printf '  [%s/%s] %s ' "$idx" "$total" "$label"
    # $autoroute_scan_flags carries one preset's flag string (e.g. "--fast", or
    # empty for the default policy) and MUST word-split into separate argv entries
    # below. It is an internal, controlled value (preset list, never user input),
    # so the split is intentional and safe; POSIX sh has no arrays to express it.
    # shellcheck disable=SC2086
    case "$mode" in
        path)
            run_keyhog_calibration_scan scan --autoroute-calibrate --autoroute-gpu "$probe" $autoroute_scan_flags --format json -o "$out" >/dev/null 2>"$errfile" &
            ;;
        stdin)
            run_keyhog_calibration_scan scan --autoroute-calibrate --autoroute-gpu --stdin $autoroute_scan_flags --format json -o "$out" < "$probe" >/dev/null 2>"$errfile" &
            ;;
        git-history)
            run_keyhog_calibration_scan scan --autoroute-calibrate --autoroute-gpu --git-history "$probe" --max-commits 1 $autoroute_scan_flags --format json -o "$out" >/dev/null 2>"$errfile" &
            ;;
        git-blobs)
            run_keyhog_calibration_scan scan --autoroute-calibrate --autoroute-gpu --git-blobs "$probe" --max-commits 2 $autoroute_scan_flags --format json -o "$out" >/dev/null 2>"$errfile" &
            ;;
        git-diff)
            run_keyhog_calibration_scan scan --autoroute-calibrate --autoroute-gpu --git-diff HEAD --git-diff-path "$probe" $autoroute_scan_flags --format json -o "$out" >/dev/null 2>"$errfile" &
            ;;
        url)
            run_keyhog_calibration_scan scan --autoroute-calibrate --autoroute-gpu --url "$probe" $autoroute_scan_flags --format json -o "$out" >/dev/null 2>"$errfile" &
            ;;
        docker-image)
            run_keyhog_calibration_scan scan --autoroute-calibrate --autoroute-gpu --docker-image "$probe" $autoroute_scan_flags --format json -o "$out" >/dev/null 2>"$errfile" &
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
        printf '\r  [%s/%s] INFO %s %s' "$idx" "$total" "$label" "$c"
        sleep 0.15
    done
    if wait "$pid"; then
        calibration_probe_pid=""
        probe_elapsed_ms="$(elapsed_ms_since "$probe_started_ms")"
        printf '\r  [%s/%s] PASS %s (%sms)\n' "$idx" "$total" "$label" "$probe_elapsed_ms"
        return 0
    fi
    calibration_probe_pid=""
    probe_elapsed_ms="$(elapsed_ms_since "$probe_started_ms")"
    printf '\r  [%s/%s] FAIL %s (%sms)\n' "$idx" "$total" "$label" "$probe_elapsed_ms"
    # Surface the real reason, not a blind failure label (Law 10). One line is
    # enough to tell a flag mismatch from a GPU/driver fault.
    real_err="$(head -n 1 "$errfile" 2>/dev/null)"
    [ -n "$real_err" ] && dim "    reason: $real_err"
    err "Autoroute calibration probe failed for $label."
    return 1
}

autoroute_cache_path_for_install() {
    if [ "$OS" = "darwin" ]; then
        printf '%s/Library/Caches/keyhog/autoroute.json\n' "$HOME"
    elif [ -n "${XDG_CACHE_HOME:-}" ]; then
        printf '%s/keyhog/autoroute.json\n' "$XDG_CACHE_HOME"
    else
        printf '%s/.cache/keyhog/autoroute.json\n' "$HOME"
    fi
}

show_autoroute_calibration_summary() {
    calibration_probe_total="$1"
    calibration_started_s="$2"
    cache_path="$(autoroute_cache_path_for_install || true)"
    if [ -z "$cache_path" ]; then
        warn "Autoroute calibration summary unavailable: platform cache directory is unavailable."
        return 1
    fi
    if [ ! -s "$cache_path" ] || [ ! -r "$cache_path" ]; then
        warn "Autoroute calibration summary unavailable: no readable cache at $cache_path."
        return 1
    fi
    if ! inspection_json="$("$bin" backend --autoroute --autoroute-cache "$cache_path" --json 2>/dev/null)"; then
        warn "Autoroute calibration summary unavailable: typed cache inspection failed for $cache_path."
        return 1
    fi

    calibration_now_s="$(date +%s 2>/dev/null || printf '0')"
    case "$calibration_started_s:$calibration_now_s" in
        *[!0123456789:]*|0:*|*:0) calibration_elapsed_s="-1" ;;
        *) calibration_elapsed_s=$((calibration_now_s - calibration_started_s)) ;;
    esac

    if ! calibration_summary="$(printf '%s\n' "$inspection_json" | awk -v probes="$calibration_probe_total" -v elapsed="$calibration_elapsed_s" '
        function json_string(line, v) {
            v = line
            sub(/^[^:]*:[[:space:]]*"/, "", v)
            sub(/".*$/, "", v)
            return v
        }
        function json_number(line, v) {
            v = line
            sub(/^[^:]*:[[:space:]]*/, "", v)
            sub(/[[:space:],]*$/, "", v)
            gsub(/"/, "", v)
            if (v == "" || v == "null") {
                return "-"
            }
            return v
        }
        function bytes_label(value) {
            value += 0
            if (value >= 1073741824) {
                return sprintf("%.1fGiB", value / 1073741824)
            }
            if (value >= 1048576) {
                return sprintf("%.1fMiB", value / 1048576)
            }
            if (value >= 1024) {
                return sprintf("%.1fKiB", value / 1024)
            }
            return sprintf("%dB", value)
        }
        function ms_label(value) {
            if (value == "" || value == "-") {
                return "-"
            }
            return sprintf("%sms", value)
        }
        function margin_label(value, ns) {
            if (value == "" || value == "-") {
                return "tie"
            }
            ns = value + 0
            if (ns <= 0) {
                return "tie"
            }
            if (ns < 1000) {
                return sprintf("%dns", ns)
            }
            if (ns < 1000000) {
                return sprintf("%.1fus", ns / 1000)
            }
            if (ns < 1000000000) {
                return sprintf("%.1fms", ns / 1000000)
            }
            return sprintf("%.2fs", ns / 1000000000)
        }
        function emit_row(sample, chunk_label, row) {
            if (backend == "") {
                return
            }
            if (sample_bytes == "") {
                sample_bytes = 0
            }
            if (sample_chunks == "") {
                sample_chunks = 0
            }
            sample = bytes_label(sample_bytes)
            chunk_label = sample_chunks "ch"
            row = sprintf("  %-18s %-27s %-9s %-7s %-7s %-7s %-7s",
                sample " / " chunk_label,
                backend,
                margin_label(selected_margin_ns),
                ms_label(simd_ms),
                ms_label(cpu_ms),
                ms_label(gpu_cuda_ms),
                ms_label(gpu_wgpu_ms))
            rows[++count] = row
            backend = ""
            sample_bytes = ""
            sample_chunks = ""
            simd_ms = ""
            cpu_ms = ""
            gpu_cuda_ms = ""
            gpu_wgpu_ms = ""
            selected_margin_ns = ""
        }
        /"backend"[[:space:]]*:/ {
            backend = json_string($0)
            next
        }
        backend != "" && /"sample_bytes"[[:space:]]*:/ {
            sample_bytes = json_number($0)
            next
        }
        backend != "" && /"sample_chunks"[[:space:]]*:/ {
            sample_chunks = json_number($0)
            next
        }
        backend != "" && /"simd_ms"[[:space:]]*:/ {
            simd_ms = json_number($0)
            next
        }
        backend != "" && /"cpu_ms"[[:space:]]*:/ {
            cpu_ms = json_number($0)
            next
        }
        backend != "" && /"gpu_cuda_ms"[[:space:]]*:/ {
            gpu_cuda_ms = json_number($0)
            next
        }
        backend != "" && /"gpu_wgpu_ms"[[:space:]]*:/ {
            gpu_wgpu_ms = json_number($0)
            next
        }
        backend != "" && /"selected_margin_ns"[[:space:]]*:/ {
            selected_margin_ns = json_number($0)
            next
        }
        backend != "" && /"daemon_backend"[[:space:]]*:/ {
            emit_row()
            next
        }
        END {
            emit_row()
            if (count == 0) {
                exit 1
            }
            if (elapsed >= 0) {
                printf "  probes: %s in %ss; decisions persisted: %d\n", probes, elapsed, count
            } else {
                printf "  probes: %s; decisions persisted: %d\n", probes, count
            }
            print "  sample/chunks       selected backend            margin    simd    cpu     cuda    wgpu"
            for (i = 1; i <= count; i++) {
                print rows[i]
            }
        }
    ' 2>/dev/null)"; then
        warn "Autoroute calibration summary unavailable: could not parse typed cache inspection for $cache_path."
        return 1
    fi

    say ""
    info "Autoroute calibration decisions"
    dim "  cache: $cache_path"
    printf '%s\n' "$calibration_summary"
    return 0
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
    trigger='GITHUB_TOKEN=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
'
    awk -v block="$block" -v trigger="$trigger" -v kib="$kib" 'BEGIN {
        for (i = 1; i <= kib; i++) {
            if (i % 64 == 0) {
                printf "%s%s", substr(block, 1, length(block) - length(trigger)), trigger
            } else {
                printf "%s", block
            }
        }
    }' > "$path"
}

make_calibration_probe_bytes() {
    path="$1"
    bytes="$2"
    block="$(plain_calibration_block)" || return 1
    printf '%.*s' "$bytes" "$block" > "$path"
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
    "$git_cmd" -C "$dir" config user.name "KeyHog Autoroute Calibration" || return 1
    "$git_cmd" -C "$dir" config commit.gpgsign false || return 1
    make_calibration_probe_kib "$dir/probe.txt" 4 || return 1
    "$git_cmd" -C "$dir" add probe.txt || return 1
    "$git_cmd" -C "$dir" commit -q -m "keyhog autoroute calibration baseline" || return 1
    make_calibration_probe_kib "$dir/probe.txt" 8 || return 1
    "$git_cmd" -C "$dir" add probe.txt || return 1
    "$git_cmd" -C "$dir" commit -q -m "keyhog autoroute calibration head" || return 1
    make_calibration_probe_kib "$dir/probe.txt" 12 || return 1
    make_calibration_probe_kib "$dir/untracked-probe.txt" 4 || return 1
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
        # exec so this subshell process BECOMES the Python server: $! below then
        # captures the server's real PID, so stop_calibration_web_server's kill
        # reaps the actual HTTP server. Without exec, POSIX sh forks Python as a
        # child of the subshell and $! is the subshell's PID, killing it orphans
        # the Python process, leaking a server that still holds the loopback port.
        exec "$python_cmd" - "$port_file" <<'PY'
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
    say  "  Release tag:   $(release_tag_label)"
    existing=$(current_version)
    if [ -n "$existing" ]; then
        say  "  Existing:      $existing"
        show_installed_release_relation "$existing"
    fi
}

wizard_command_unavailable() {
    case "$1" in
      *"unknown subcommand"*|*"unrecognized subcommand"*|*"invalid subcommand"*|*"No such subcommand"*)
        return 0 ;;
      *) return 1 ;;
    esac
}

warn_wizard_command_failure() {
    label="$1"
    errfile="$2"
    unavailable_msg="$3"
    direct_hint="$4"
    reason="$(head -n 1 "$errfile" 2>/dev/null || true)"
    if [ -n "$unavailable_msg" ] && wizard_command_unavailable "$reason"; then
        warn "$unavailable_msg"
    elif [ -n "$reason" ]; then
        warn "  $label failed: $reason"
    else
        warn "  $label failed without stderr. Run '$direct_hint' directly for details."
    fi
}

# Offer to wire keyhog into common entry points. The displayed default is the
# contract in both interactive and --yes modes: PATH defaults on, while shell
# completion and the repository hook default off.
post_install_wizard() {
    [ "$INTERACTIVE" != "1" ] && [ "$ASSUME_YES" != "1" ] && return

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

    # Claude Code / Cursor agent-hook wiring has no shipped CLI flag. The
    # previous prompt called `keyhog hook install --agent claude-code`, which
    # never existed, and then reported a misleading upgrade message. The
    # unsupported prompt is intentionally absent.

    if confirm "Wire keyhog as a git pre-commit hook in the CURRENT directory?" N; then
        # `[ -d .git ]` is wrong inside a git WORKTREE, where `.git` is a FILE
        # (a `gitdir:` pointer), not a directory, the hook install was silently
        # skipped there. `git rev-parse --is-inside-work-tree` is true for a
        # regular repo, a worktree, and a subdirectory alike.
        if git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
            hook_path="$(git rev-parse --git-path hooks/pre-commit 2>/dev/null || echo .git/hooks/pre-commit)"
            if ! hook_err="$(mktemp -t keyhog-hook-err-XXXXXX)"; then
                warn "  pre-commit hook install failed: could not create a temporary stderr file."
            elif "$INSTALL_DIR/keyhog" hook install 2>"$hook_err"; then
                ok "  Pre-commit hook installed in $hook_path"
                rm -f "$hook_err"
            else
                warn_wizard_command_failure \
                    "pre-commit hook install" \
                    "$hook_err" \
                    "  hook subcommand not in this build, skipping (upgrade keyhog and rerun install)." \
                    "keyhog hook install"
                rm -f "$hook_err"
            fi
        else
            warn "  Not inside a git work tree here, skipping."
        fi
    fi
}

offer_path_setup() {
    shell_name=$(basename "${SHELL:-/bin/sh}")
    rc=$(path_setup_rc_file "$shell_name")
    if [ -n "$rc" ] && path_setup_entry_present "$rc" "$shell_name"; then
        ok "  PATH already configured in $rc"
        return
    fi
    if [ -n "$rc" ]; then
        if confirm "  Append to $rc?" Y; then
            mkdir -p "$(dirname "$rc")"
            if path_setup_entry_present "$rc" "$shell_name"; then
                ok "  PATH already configured in $rc"
                return
            fi
            if [ "$shell_name" = "fish" ]; then
                # shellcheck disable=SC2016 # write a literal $PATH into the user's rc file
                printf '\n# keyhog\nset -gx PATH %s $PATH\n' "$INSTALL_DIR" >> "$rc"
            else
                # shellcheck disable=SC2016 # write a literal $PATH into the user's rc file
                printf '\n# keyhog\nexport PATH="%s:$PATH"\n' "$INSTALL_DIR" >> "$rc"
            fi
            ok "  Added. Restart your shell or 'source $rc' to pick it up."
            return
        fi
    fi
    dim "  Add manually: export PATH=\"$INSTALL_DIR:\$PATH\""
}

path_setup_rc_file() {
    shell_name="$1"
    case "$shell_name" in
      bash)
        if [ "${OS:-}" = "darwin" ]; then
            if [ -f "$HOME/.bash_profile" ] || [ ! -f "$HOME/.profile" ]; then
                printf '%s\n' "$HOME/.bash_profile"
            else
                printf '%s\n' "$HOME/.profile"
            fi
        else
            printf '%s\n' "$HOME/.bashrc"
        fi
        ;;
      zsh)  printf '%s\n' "$HOME/.zshrc" ;;
      fish) printf '%s\n' "$HOME/.config/fish/config.fish" ;;
      *)    printf '%s\n' "" ;;
    esac
}

path_setup_entry_present() {
    rc="$1"
    shell_name="$2"
    [ -f "$rc" ] || return 1
    # The PATH-wiring line shape to require, per shell.
    if [ "$shell_name" = "fish" ]; then
        _wiring='set -gx PATH|fish_add_path'
    else
        _wiring='(^|[^A-Za-z0-9_])PATH='
    fi
    # Match ANY PATH wiring that mentions INSTALL_DIR -- quoted or unquoted,
    # prepended or appended, fish_add_path or set -gx, AND under any spelling of
    # the directory. `set --` builds the candidate spellings: the absolute path
    # always, plus the ~ / $HOME / ${HOME} relative forms when INSTALL_DIR lives
    # under $HOME (a hand-edited rc commonly writes `~/.local/bin` or
    # `$HOME/.local/bin`). Matching one exact spelling missed those variants and
    # appended a DUPLICATE block on every re-install.
    set -- "$INSTALL_DIR"
    case "$INSTALL_DIR" in
        "$HOME"/*)
            _rel="${INSTALL_DIR#"$HOME"}"
            set -- "$@" "~$_rel" "\$HOME$_rel" "\${HOME}$_rel"
            ;;
    esac
    for _spelling in "$@"; do
        grep -F "$_spelling" "$rc" 2>/dev/null | grep -E "$_wiring" >/dev/null 2>&1 && return 0
    done
    # Fallback: our own marker comment plus any spelling of the dir anywhere.
    grep -F '# keyhog' "$rc" >/dev/null 2>&1 || return 1
    for _spelling in "$@"; do
        grep -F "$_spelling" "$rc" >/dev/null 2>&1 && return 0
    done
    return 1
}

install_completions() {
    shell_name=$(basename "${SHELL:-/bin/sh}")
    case "$shell_name" in
      bash) dir="$HOME/.local/share/bash-completion/completions"; file="$dir/keyhog" ;;
      zsh)  dir="$HOME/.zfunc"; file="$dir/_keyhog" ;;
      fish) dir="$HOME/.config/fish/completions"; file="$dir/keyhog.fish" ;;
      *) warn "  Unknown shell ($shell_name), skipping completions."; return ;;
    esac
    if ! completion_err="$(mktemp -t keyhog-completion-err-XXXXXX)"; then
        warn "  completion generation failed: could not create a temporary stderr file."
        return
    fi
    if ! mkdir -p "$dir" 2>"$completion_err"; then
        warn_wizard_command_failure "completion directory setup" "$completion_err" "" "mkdir -p $dir"
        rm -f "$completion_err"
        return
    fi
    if "$INSTALL_DIR/keyhog" completion "$shell_name" > "$file" 2>"$completion_err"; then
        ok "  Completions written to $file"
        if [ "$shell_name" = "zsh" ]; then
            ensure_zsh_completion_wiring "$dir"
        fi
    else
        warn_wizard_command_failure \
            "completion generation" \
            "$completion_err" \
            "  completion subcommand not in this build, skipping (upgrade keyhog and rerun install)." \
            "keyhog completion $shell_name"
        rm -f "$file"
    fi
    rm -f "$completion_err"
}

ensure_zsh_completion_wiring() {
    completion_dir="$1"
    rc=$(path_setup_rc_file zsh)
    if [ -z "$rc" ]; then
        warn "  zsh completion path setup skipped: unknown zsh rc file."
        return
    fi
    if zsh_completion_wiring_present "$rc"; then
        ok "  zsh completion path already configured in $rc"
        return
    fi
    if ! mkdir -p "$(dirname "$rc")"; then
        warn "  zsh completion path setup failed: could not create $(dirname "$rc")."
        return
    fi
    if ! {
        printf '\n# keyhog completions\n'
        # shellcheck disable=SC2016 # write literal zsh startup code into the user's rc file
        printf 'if [ -d "$HOME/.zfunc" ]; then\n'
        # shellcheck disable=SC2016 # write literal zsh startup code into the user's rc file
        printf '  fpath=("$HOME/.zfunc" $fpath)\n'
        printf '  autoload -Uz compinit\n'
        printf '  compinit\n'
        printf 'fi\n'
    } >> "$rc"; then
        warn "  zsh completion path setup failed: could not append to $rc."
        return
    fi
    ok "  zsh completion path configured in $rc for $completion_dir"
}

zsh_completion_wiring_present() {
    rc="$1"
    [ -f "$rc" ] || return 1
    grep -F '# keyhog completions' "$rc" >/dev/null 2>&1 && return 0
    # A bare `.zfunc` mention (a comment, an alias, another tool's docs) does
    # NOT prove the completion dir is on fpath -- completions would silently
    # never load. Require an actual fpath entry naming .zfunc plus compinit.
    grep -E 'fpath=.*\.zfunc' "$rc" >/dev/null 2>&1 && grep -F 'compinit' "$rc" >/dev/null 2>&1
}

run_binary_uninstall() {
    bin="$1"
    if [ ! -x "$bin" ]; then
        return
    fi
    if ! uninstall_err="$(mktemp -t keyhog-uninstall-err-XXXXXX)"; then
        warn "  installed-binary uninstall skipped: could not create a temporary stderr file."
        return
    fi
    if "$bin" uninstall --yes 2>"$uninstall_err"; then
        rm -f "$uninstall_err"
        return
    fi
    reason="$(head -n 1 "$uninstall_err" 2>/dev/null || true)"
    if wizard_command_unavailable "$reason"; then
        warn "  installed keyhog has no uninstall subcommand; removing installer-owned files directly."
    elif [ -n "$reason" ]; then
        warn "  keyhog uninstall --yes failed: $reason"
    else
        warn "  keyhog uninstall --yes failed without stderr; removing installer-owned files directly."
    fi
    rm -f "$uninstall_err"
}

remove_completion_file() {
    file="$1"
    label="$2"
    if [ ! -e "$file" ]; then
        return
    fi
    if rm -f "$file"; then
        ok "  Removed $label: $file"
    else
        warn "  Could not remove $label: $file"
    fi
}

remove_path_setup_entry() {
    rc="$1"
    install_dir="$2"
    [ -f "$rc" ] || return 0
    grep -F '# keyhog' "$rc" >/dev/null 2>&1 || return 0
    grep -F "$install_dir" "$rc" >/dev/null 2>&1 || return 0
    if ! tmp="$(mktemp -t keyhog-rc-clean-XXXXXX)"; then
        warn "  Could not create a temporary file to clean $rc."
        return
    fi
    if awk -v install_dir="$install_dir" '
        $0 == "# keyhog" {
            status = getline nextline
            if (status > 0 && index(nextline, install_dir) > 0 &&
                (index(nextline, "export PATH=\"") == 1 || index(nextline, "set -gx PATH ") == 1)) {
                next
            }
            print $0
            if (status > 0) {
                print nextline
            }
            next
        }
        { print }
    ' "$rc" > "$tmp" && cat "$tmp" > "$rc"; then
        ok "  Removed PATH entry from $rc"
    else
        warn "  Could not remove PATH entry from $rc"
    fi
    rm -f "$tmp"
}

remove_zsh_completion_wiring() {
    rc="$1"
    [ -f "$rc" ] || return 0
    grep -Fx '# keyhog completions' "$rc" >/dev/null 2>&1 || return 0
    if ! tmp="$(mktemp -t keyhog-zsh-clean-XXXXXX)"; then
        warn "  Could not create a temporary file to clean $rc."
        return
    fi
    if awk '
        $0 == "# keyhog completions" {
            skip = 5
            next
        }
        skip > 0 {
            skip--
            next
        }
        { print }
    ' "$rc" > "$tmp" && cat "$tmp" > "$rc"; then
        ok "  Removed zsh completion wiring from $rc"
    else
        warn "  Could not remove zsh completion wiring from $rc"
    fi
    rm -f "$tmp"
}

remove_installer_owned_integrations() {
    install_dir="$1"
    remove_path_setup_entry "$HOME/.bashrc" "$install_dir"
    remove_path_setup_entry "$HOME/.bash_profile" "$install_dir"
    remove_path_setup_entry "$HOME/.profile" "$install_dir"
    remove_path_setup_entry "$HOME/.zshrc" "$install_dir"
    remove_path_setup_entry "$HOME/.config/fish/config.fish" "$install_dir"
    remove_zsh_completion_wiring "$HOME/.zshrc"
    remove_completion_file "$HOME/.local/share/bash-completion/completions/keyhog" "bash completion"
    remove_completion_file "$HOME/.zfunc/_keyhog" "zsh completion"
    remove_completion_file "$HOME/.config/fish/completions/keyhog.fish" "fish completion"
}

# ============================================================
# install / repair / diagnose / uninstall
# ============================================================

do_install() {
    if [ -n "$FROM_FILE" ]; then
        # Local-binary install: no GitHub release lookup, no network. ASSET/TAG
        # are populated for show_summary and the verify messages only.
        ASSET=$(basename "$FROM_FILE")
        TAG="(local file)"
        GPU_NOTE="installing local binary: $FROM_FILE"
    else
        resolve_asset
        resolve_operator_release_tag
    fi

    show_summary

    if [ "$INTERACTIVE" = "1" ] && [ "$ASSUME_YES" != "1" ]; then
        if ! confirm "Proceed with this install?" Y; then
            warn "Aborted."
            exit 0
        fi
    fi

    stage_and_install
    if ! backup_gpu_programs_cache_for_install; then
        rollback_staged_install_after_sidecar_failure "$INSTALL_DIR/keyhog"
        err "Install failed while backing up GPU literal cache state."
        exit 1
    fi
    if ! install_verified_gpu_literal_sidecar; then
        restore_gpu_programs_cache_backup || true
        rollback_staged_install_after_sidecar_failure "$INSTALL_DIR/keyhog"
        err "Install failed while seeding shipped GPU literal artifacts."
        exit 1
    fi
    if ! finalize_install; then
        restore_gpu_programs_cache_backup || true
        cleanup_gpu_literal_sidecar_tmp
        err "Install failed verification; see above."
        exit 1
    fi
    clear_gpu_programs_cache_backup
    post_install_wizard

    printf '\n%sNext steps:%s\n' "$C_BOLD" "$C_RESET"
    say "  keyhog scan .            # scan the current directory"
    say "  keyhog scan --help       # full options"
    say "  keyhog --version         # verify"
}

do_repair() {
    info "Repair mode."
    resolve_asset
    resolve_operator_release_tag
    bin=$(current_binary)
    if [ -z "$bin" ]; then
        warn "No existing keyhog binary found. Installing fresh."
        stage_and_install
        if ! backup_gpu_programs_cache_for_install; then
            rollback_staged_install_after_sidecar_failure "$INSTALL_DIR/keyhog"
            err "Repair failed while backing up GPU literal cache state."
            exit 1
        fi
        if ! install_verified_gpu_literal_sidecar; then
            restore_gpu_programs_cache_backup || true
            rollback_staged_install_after_sidecar_failure "$INSTALL_DIR/keyhog"
            err "Repair failed while seeding shipped GPU literal artifacts."
            exit 1
        fi
        if ! finalize_install; then
            restore_gpu_programs_cache_backup || true
            cleanup_gpu_literal_sidecar_tmp
            err "Repair failed; see above."
            exit 1
        fi
        clear_gpu_programs_cache_backup
        ok "Repair complete."
        return
    fi
    say "Found existing binary: $bin"
    if "$bin" --version >/dev/null 2>&1; then
        ok "Binary runs cleanly. Repair will download and verify $ASSET before replacing it (--repair)."
    else
        warn "Existing binary does not run. Replacing with $ASSET."
    fi
    stage_and_install
    if ! backup_gpu_programs_cache_for_install; then
        rollback_staged_install_after_sidecar_failure "$INSTALL_DIR/keyhog"
        err "Repair failed while backing up GPU literal cache state."
        exit 1
    fi
    if ! install_verified_gpu_literal_sidecar; then
        restore_gpu_programs_cache_backup || true
        rollback_staged_install_after_sidecar_failure "$INSTALL_DIR/keyhog"
        err "Repair failed while seeding shipped GPU literal artifacts."
        exit 1
    fi
    if ! finalize_install; then
        restore_gpu_programs_cache_backup || true
        cleanup_gpu_literal_sidecar_tmp
        err "Repair failed; your previous binary state was preserved where possible (see above)."
        exit 1
    fi
    clear_gpu_programs_cache_backup
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
        resolve_asset
        resolve_operator_release_tag
        say "  Tag: $(release_tag_label)"
        existing=$(current_version)
        show_installed_release_relation "$existing"
        say "  Would install: $ASSET"
        return
    fi

    info "Diagnostic report ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
    printf '\n%sHost%s\n' "$C_BOLD" "$C_RESET"
    say "  OS:    $OS"
    say "  Arch:  $ARCH"
    if [ "$OS" = "linux" ]; then
        say "  Accelerator selection: runtime CUDA/WGPU probe + persisted autoroute evidence"
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
    resolve_asset
    resolve_operator_release_tag
    say "  Tag: $(release_tag_label)"
    ver=$(current_version)
    show_installed_release_relation "$ver"
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
    install_dir=$(dirname "$bin")
    run_binary_uninstall "$bin"
    if [ -e "$bin" ]; then
        if rm -f "$bin"; then
            ok "Removed $bin"
        else
            err "Could not remove $bin. Fix: check permissions or rerun with sudo if it lives in a system path."
            exit 1
        fi
    else
        ok "Removed $bin"
    fi
    remove_installer_owned_integrations "$install_dir"
}

# ============================================================
# main
# ============================================================

banner

if [ "$INTERACTIVE" = "0" ] && [ "$MODE" = "install" ] && [ ! -t 0 ]; then
    dim "Tip: re-run interactively for the post-install wizard:"
    dim "  verify the tagged release's install.sh.minisig, then run KEYHOG_VERSION=<tag> sh install.sh"
fi

case "$MODE" in
    install)   do_install ;;
    repair)    do_repair ;;
    diagnose)  do_diagnose ;;
    calibrate) do_calibrate ;;
    uninstall) do_uninstall ;;
esac

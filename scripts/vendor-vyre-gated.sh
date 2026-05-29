#!/usr/bin/env bash
# Build-gated vyre refresh.
#
# vyre is under heavy churn, so keyhog tracks it by VENDORING rather than a
# crates.io version bump on every change. This script refreshes the vendored
# copy to a chosen upstream ref and KEEPS it only if keyhog still builds clean
# AND a smoke scan still finds a planted secret. If either gate fails it
# restores the last-known-good vendored tree (the committed state) and the
# matching keyhog dependency pins, so a broken upstream can never wedge a
# keyhog release.
#
# Usage:
#   scripts/vendor-vyre-gated.sh                 # refresh to upstream HEAD
#   scripts/vendor-vyre-gated.sh --ref v0.6.4    # pin to a ref
#   VYRE_REPO=/path/to/vyre scripts/vendor-vyre-gated.sh
#
# On success the vendored tree + Cargo.toml pins are left updated and staged
# for you to review and commit. On failure nothing is left changed.

set -euo pipefail

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
KEYHOG_ROOT="$( cd "${SCRIPT_DIR}/.." && pwd )"
VENDOR_DIR="${KEYHOG_ROOT}/vendor/vyre"
ROOT_MANIFEST="${KEYHOG_ROOT}/Cargo.toml"
VENDOR_MANIFEST="${VENDOR_DIR}/Cargo.toml"

REF_ARGS=()
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ref) REF_ARGS=(--ref "$2"); shift 2 ;;
        -h|--help) sed -n '2,20p' "$0"; exit 0 ;;
        *) echo "unknown arg: $1" >&2; exit 2 ;;
    esac
done

read_core_version() {
    grep -m1 '^version' "${VENDOR_DIR}/vyre-core/Cargo.toml" | sed 's/.*"\(.*\)".*/\1/'
}

# Only rewrite the version on the vyre dep lines (those carrying a
# vendor/vyre path), never unrelated deps that happen to match.
set_keyhog_pins() {
    local v="$1"
    sed -i -E "/path = \"vendor\/vyre\//{ s/version = \"=?[0-9]+\.[0-9]+\.[0-9]+\"/version = \"=${v}\"/ }" "${ROOT_MANIFEST}"
}
set_vendor_pins() {
    local from="$1" to="$2"
    sed -i "s/version = \"${from}\"/version = \"${to}\"/g" "${VENDOR_MANIFEST}"
}

restore_last_known_good() {
    echo "→ restoring last-known-good vendored tree + pins"
    git -C "${KEYHOG_ROOT}" checkout -- "vendor/vyre" "Cargo.toml" 2>/dev/null || true
}

OLD_VERSION="$(read_core_version)"
echo "→ current vendored vyre version: ${OLD_VERSION}"

# Refresh the vendored subdirs (atomic per-subdir; see vendor-vyre.sh).
"${SCRIPT_DIR}/vendor-vyre.sh" "${REF_ARGS[@]}"

NEW_VERSION="$(read_core_version)"
echo "→ refreshed vendored vyre version: ${NEW_VERSION}"

# The vendored workspace manifest is keyhog-local and survives the refresh,
# so its intra-vyre version pins still point at the old version. Realign
# them and keyhog's own dep pins to the freshly vendored crates.
if [[ "${OLD_VERSION}" != "${NEW_VERSION}" ]]; then
    set_vendor_pins "${OLD_VERSION}" "${NEW_VERSION}"
fi
set_keyhog_pins "${NEW_VERSION}"

echo "→ gate 1/2: cargo build -p keyhog"
if ! CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-}" cargo build --release -p keyhog; then
    echo "✗ build FAILED against vyre@${NEW_VERSION}"
    restore_last_known_good
    echo "✓ kept last-known-good vyre@${OLD_VERSION}"
    exit 1
fi

echo "→ gate 2/2: smoke scan (planted secret must be found)"
KEYHOG_BIN="$(find "${CARGO_TARGET_DIR:-${KEYHOG_ROOT}/target}" -name keyhog -type f -path '*release*' 2>/dev/null | head -1)"
SMOKE_DIR="$(mktemp -d)"
trap 'rm -rf "${SMOKE_DIR}"' EXIT
printf 'aws_key = "AKIAIOSFODNN7EXAMPLE"\nsecret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n' > "${SMOKE_DIR}/leak.txt"
if "${KEYHOG_BIN}" scan --path "${SMOKE_DIR}" >/dev/null 2>&1; then
    # exit 0 means NO findings - the scan path is broken with the new vyre
    echo "✗ smoke scan found NOTHING against vyre@${NEW_VERSION} (scan path regressed)"
    restore_last_known_good
    echo "✓ kept last-known-good vyre@${OLD_VERSION}"
    exit 1
fi

echo
echo "✓ vyre@${NEW_VERSION} passed both gates - vendored tree + pins updated and staged."
echo "  review:  git -C ${KEYHOG_ROOT} diff --stat HEAD -- vendor/vyre Cargo.toml"
echo "  commit:  git add vendor/vyre Cargo.toml && git commit"

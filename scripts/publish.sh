#!/usr/bin/env bash
# Publish the current workspace version of keyhog to crates.io.
#
# Reads `workspace.package.version` from the root Cargo.toml so this
# script doesn't need a version bump every release; the version is
# whatever the tree at HEAD says.
#
# Each `cargo publish` waits up to 45s between crates so the index has time
# to settle. The script changes to the workspace root before invoking Cargo.
#
# Re-runnable: cargo publish refuses to re-publish an already-published
# version, so a partial run is safe to resume.
#
# Pre-flight (mandatory before running):
#   1. Workspace test suite green at this version.
#   2. Git working tree clean on this version's commit.
#   3. `cargo login` configured for crates.io.
#
# Usage:
#     scripts/publish.sh                       # publish for real
#     WAIT_BETWEEN_PUBLISH=60 scripts/publish.sh   # slower

set -euo pipefail

WAIT_BETWEEN_PUBLISH="${WAIT_BETWEEN_PUBLISH:-45}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PUBLISH_TIER_1=(keyhog-core)
PUBLISH_TIER_2=(keyhog-verifier)
PUBLISH_TIER_3=(keyhog-sources keyhog-scanner)
PUBLISH_TIER_4=(keyhog)
PUBLISH_ORDER=(
    "${PUBLISH_TIER_1[@]}"
    "${PUBLISH_TIER_2[@]}"
    "${PUBLISH_TIER_3[@]}"
    "${PUBLISH_TIER_4[@]}"
)
PACKAGE_TARGET=""
declare -a PACKAGE_ARCHIVES=()

cleanup() {
    if [[ -n "$PACKAGE_TARGET" ]]; then
        rm -rf -- "$PACKAGE_TARGET"
    fi
}
trap cleanup EXIT

require_clean_tree() {
    local status
    status="$(git -C "$ROOT" status --porcelain --untracked-files=all)"
    if [[ -n "$status" ]]; then
        echo "error: refusing to package or publish from a dirty working tree" >&2
        echo "Fix: commit or intentionally remove every staged, modified, and untracked path, then rerun." >&2
        printf '%s\n' "$status" >&2
        return 1
    fi
}

require_complete_publish_order() {
    local -a discovered=()
    local -a declared=()
    mapfile -t discovered < <(python3 -B \
        "$ROOT/scripts/gates/package_licenses.py" --print-package-names)
    mapfile -t discovered < <(printf '%s\n' "${discovered[@]}" | LC_ALL=C sort)
    mapfile -t declared < <(printf '%s\n' "${PUBLISH_ORDER[@]}" | LC_ALL=C sort)
    if [[ "${discovered[*]}" != "${declared[*]}" ]]; then
        echo "error: publish order does not match the publishable workspace packages" >&2
        printf 'Discovered: %s\nDeclared: %s\n' \
            "${discovered[*]}" "${declared[*]}" >&2
        return 1
    fi
}

# Pull the version out of the workspace Cargo.toml so the echo lines
# stay accurate without a per-release edit. `awk` over the [workspace.package]
# table is enough - the version key is unique within Cargo.toml.
VERSION=$(awk -F'"' '
    /^\[workspace\.package\]/ { in_pkg = 1; next }
    in_pkg && /^version[[:space:]]*=/ { print $2; exit }
' "$ROOT/Cargo.toml")
if [[ -z "${VERSION}" ]]; then
    echo "error: missing workspace.package.version in $ROOT/Cargo.toml" >&2
    exit 2
fi

preflight() {
    require_clean_tree
    require_complete_publish_order
    echo "==> verifying canonical license files in publishable crate roots"
    python3 -B "$ROOT/scripts/gates/package_licenses.py"
    PACKAGE_TARGET="$(mktemp -d "${TMPDIR:-/tmp}/keyhog-publish-package.XXXXXX")"
}

package_and_verify() {
    local crate="$1"
    local archive="$PACKAGE_TARGET/package/${crate}-${VERSION}.crate"
    echo "==> packaging $crate in isolated target $PACKAGE_TARGET"
    CARGO_TARGET_DIR="$PACKAGE_TARGET" cargo package \
        --no-verify \
        --locked \
        --package "$crate"
    if [[ ! -f "$archive" ]]; then
        echo "error: cargo package did not create expected archive $archive" >&2
        return 1
    fi
    python3 -B "$ROOT/scripts/gates/package_licenses.py" "$archive"
    PACKAGE_ARCHIVES+=("$archive")
}

publish() {
    local crate="$1"
    # Unpredictable per-crate log path via mktemp: a fixed `/tmp/publish-<crate>.log`
    # is a symlink-TOCTOU target and collides between concurrent publish runs.
    local log
    log="$(mktemp "${TMPDIR:-/tmp}/publish-${crate}.XXXXXX")"
    require_clean_tree
    echo
    echo "==> cargo publish --locked --registry crates-io -p $crate"
    if cargo publish --locked --registry crates-io -p "$crate" 2>&1 | tee "$log"; then
        echo "==> $crate published."
        sleep "$WAIT_BETWEEN_PUBLISH"
    else
        if grep -qE "already uploaded|already exists on crates.io index|crate version .* is already uploaded" "$log"; then
            echo "==> $crate already at this version on crates.io; skipping."
        else
            echo "==> ERROR: $crate publish failed. See $log"
            exit 1
        fi
    fi
}

publish_tier() {
    local crate
    for crate in "$@"; do
        package_and_verify "$crate"
    done
    for crate in "$@"; do
        publish "$crate"
    done
}

# Cargo resolves exact registry dependencies while packaging, so each archive
# can be created only after its current-version dependencies are visible in the
# crates.io index. Source licenses and the complete publish inventory are still
# checked before the first upload. Every archive is then checked immediately
# before its tier is published.
preflight

# Tier 1 - foundation (no internal deps).
publish_tier "${PUBLISH_TIER_1[@]}"

# Tier 2 - depend on core.
publish_tier "${PUBLISH_TIER_2[@]}"

# Tier 3 - depend on core and verifier.
publish_tier "${PUBLISH_TIER_3[@]}"

# Tier 4 - the CLI binary, pulls in the whole stack. Before its upload, prove
# that the accumulated archives cover the exact discovered package inventory.
for crate in "${PUBLISH_TIER_4[@]}"; do
    package_and_verify "$crate"
done
python3 -B "$ROOT/scripts/gates/package_licenses.py" \
    --require-all-archives "${PACKAGE_ARCHIVES[@]}"
for crate in "${PUBLISH_TIER_4[@]}"; do
    publish "$crate"
done

echo
echo "==> All v${VERSION} crates published."
echo "==> Next: git tag v${VERSION} && git push origin v${VERSION}"

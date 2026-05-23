#!/usr/bin/env bash
# Publish the current workspace version of keyhog to crates.io.
#
# Reads `workspace.package.version` from the root Cargo.toml so this
# script doesn't need a version bump every release; the version is
# whatever the tree at HEAD says.
#
# Run from the workspace root. Each `cargo publish` waits up to 45s
# between crates so the index has time to settle.
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

# Pull the version out of the workspace Cargo.toml so the echo lines
# stay accurate without a per-release edit. `awk` over the [workspace.package]
# table is enough — the version key is unique within Cargo.toml.
VERSION=$(awk -F'"' '
    /^\[workspace\.package\]/ { in_pkg = 1; next }
    in_pkg && /^version[[:space:]]*=/ { print $2; exit }
' "$(dirname "$0")/../Cargo.toml" 2>/dev/null)
if [[ -z "${VERSION}" ]]; then
    VERSION="unknown"
fi

publish() {
    local crate="$1"
    echo
    echo "==> cargo publish -p $crate"
    if cargo publish -p "$crate" 2>&1 | tee "/tmp/publish-${crate}.log"; then
        echo "==> $crate published."
        sleep "$WAIT_BETWEEN_PUBLISH"
    else
        if grep -qE "already uploaded|already exists on crates.io index|crate version .* is already uploaded" "/tmp/publish-${crate}.log"; then
            echo "==> $crate already at this version on crates.io; skipping."
        else
            echo "==> ERROR: $crate publish failed. See /tmp/publish-${crate}.log"
            exit 1
        fi
    fi
}

# Tier 1 — foundation (no internal deps).
publish keyhog-core

# Tier 2 — depend on core.
publish keyhog-verifier
publish keyhog-sources
publish keyhog-scanner

# Tier 3 — the CLI binary, pulls in the whole stack.
publish keyhog

echo
echo "==> All v${VERSION} crates published."
echo "==> Next: git tag v${VERSION} && git push origin v${VERSION}"

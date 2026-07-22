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
#     PACKAGE_BUILD_JOBS=8 scripts/publish.sh       # wider verification builds

set -euo pipefail

WAIT_BETWEEN_PUBLISH="${WAIT_BETWEEN_PUBLISH:-45}"
PACKAGE_BUILD_JOBS="${PACKAGE_BUILD_JOBS:-4}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
PUBLISH_TIER_1=(keyhog-core)
PUBLISH_TIER_2=(keyhog-verifier)
PUBLISH_TIER_3=(keyhog-sources keyhog-scanner)
PUBLISH_TIER_4=(keyhog)
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
    python3 -B "$ROOT/scripts/gates/package_licenses.py" \
        --publish-tier "${PUBLISH_TIER_1[@]}" \
        --publish-tier "${PUBLISH_TIER_2[@]}" \
        --publish-tier "${PUBLISH_TIER_3[@]}" \
        --publish-tier "${PUBLISH_TIER_4[@]}"
}

archive_sha256() {
    python3 -B - "$1" <<'PY'
import hashlib
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
digest = hashlib.sha256()
with path.open("rb") as handle:
    for chunk in iter(lambda: handle.read(1024 * 1024), b""):
        digest.update(chunk)
print(digest.hexdigest())
PY
}

registry_sha256() {
    python3 -B - "$1" "$VERSION" <<'PY'
import json
import string
import sys
import urllib.parse
import urllib.request

crate, version = sys.argv[1:]
url = "https://crates.io/api/v1/crates/{}/{}".format(
    urllib.parse.quote(crate, safe=""), urllib.parse.quote(version, safe="")
)
request = urllib.request.Request(
    url,
    headers={"User-Agent": f"keyhog-release-gate/{version} (security@santh.dev)"},
)
try:
    with urllib.request.urlopen(request, timeout=30) as response:
        document = json.load(response)
except Exception as error:
    raise SystemExit(f"cannot read crates.io checksum for {crate} {version}: {error}")
checksum = document.get("version", {}).get("checksum")
if (
    not isinstance(checksum, str)
    or len(checksum) != 64
    or any(character not in string.hexdigits for character in checksum)
):
    raise SystemExit(f"crates.io returned no valid SHA-256 for {crate} {version}")
print(checksum.lower())
PY
}

download_registry_archive() {
    python3 -B - "$1" "$VERSION" "$2" <<'PY'
import hashlib
import json
import os
import pathlib
import sys
import urllib.error
import urllib.parse
import urllib.request

crate, version, destination = sys.argv[1:]
escaped_crate = urllib.parse.quote(crate, safe="")
escaped_version = urllib.parse.quote(version, safe="")
headers = {"User-Agent": f"keyhog-release-gate/{version} (security@santh.dev)"}
metadata_url = f"https://crates.io/api/v1/crates/{escaped_crate}/{escaped_version}"
try:
    with urllib.request.urlopen(
        urllib.request.Request(metadata_url, headers=headers), timeout=30
    ) as response:
        metadata = json.load(response)
except urllib.error.HTTPError as error:
    if error.code == 404:
        raise SystemExit(4)
    raise SystemExit(f"cannot query {crate} {version} on crates.io: HTTP {error.code}")
except Exception as error:
    raise SystemExit(f"cannot query {crate} {version} on crates.io: {error}")

expected_digest = metadata.get("version", {}).get("checksum")
if not isinstance(expected_digest, str) or len(expected_digest) != 64:
    raise SystemExit(f"crates.io returned no valid SHA-256 for {crate} {version}")

url = f"https://crates.io/api/v1/crates/{escaped_crate}/{escaped_version}/download"
request = urllib.request.Request(url, headers=headers)
destination = pathlib.Path(destination)
temporary = destination.with_suffix(destination.suffix + ".download")
digest = hashlib.sha256()
try:
    with urllib.request.urlopen(request, timeout=30) as response, temporary.open("wb") as output:
        for chunk in iter(lambda: response.read(1024 * 1024), b""):
            digest.update(chunk)
            output.write(chunk)
except Exception as error:
    temporary.unlink(missing_ok=True)
    raise SystemExit(f"cannot download {crate} {version} from crates.io: {error}")
downloaded_digest = digest.hexdigest()
if downloaded_digest != expected_digest.lower():
    temporary.unlink(missing_ok=True)
    raise SystemExit(
        f"downloaded {crate} {version} checksum {downloaded_digest} "
        f"does not match crates.io metadata {expected_digest.lower()}"
    )
os.replace(temporary, destination)
print(downloaded_digest)
PY
}

verify_registry_archive_build() {
    local crate="$1"
    local archive="$2"
    local unpack_root="$PACKAGE_TARGET/registry-source/$crate"
    local manifest="$unpack_root/${crate}-${VERSION}/Cargo.toml"
    rm -rf -- "$unpack_root"
    mkdir -p "$unpack_root"
    python3 -B - "$archive" "$unpack_root" <<'PY'
import pathlib
import sys
import tarfile

archive, destination = map(pathlib.Path, sys.argv[1:])
destination = destination.resolve()
with tarfile.open(archive, "r:gz") as package:
    for member in package.getmembers():
        target = (destination / member.name).resolve()
        if not target.is_relative_to(destination):
            raise SystemExit(f"unsafe archive path in {archive}: {member.name}")
    package.extractall(destination, filter="data")
PY
    if [[ ! -f "$manifest" ]]; then
        echo "error: $archive does not contain expected manifest $manifest" >&2
        return 1
    fi
    echo "==> building immutable crates.io archive for $crate with every feature"
    CARGO_TARGET_DIR="$PACKAGE_TARGET/registry-build" cargo build \
        --locked \
        --all-features \
        --jobs "$PACKAGE_BUILD_JOBS" \
        --manifest-path "$manifest"
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
    local downloaded_digest
    local remote_digest
    local download_status
    mkdir -p "$(dirname "$archive")"
    echo "==> checking crates.io for an existing $crate v$VERSION archive"
    if downloaded_digest="$(download_registry_archive "$crate" "$archive")"; then
        remote_digest="$(registry_sha256 "$crate")"
        if [[ "$downloaded_digest" != "$remote_digest" ]]; then
            echo "error: downloaded $crate archive checksum does not match crates.io metadata" >&2
            printf 'Downloaded SHA-256: %s\nRegistry SHA-256:   %s\n' \
                "$downloaded_digest" "$remote_digest" >&2
            return 1
        fi
        echo "==> using immutable crates.io archive for already-published $crate v$VERSION"
        verify_registry_archive_build "$crate" "$archive"
    else
        download_status=$?
        if [[ "$download_status" -ne 4 ]]; then
            return "$download_status"
        fi
        echo "==> packaging $crate in isolated target $PACKAGE_TARGET"
        CARGO_TARGET_DIR="$PACKAGE_TARGET" cargo package \
            --locked \
            --all-features \
            --jobs "$PACKAGE_BUILD_JOBS" \
            --package "$crate"
        if [[ ! -f "$archive" ]]; then
            echo "error: cargo package did not create expected archive $archive" >&2
            return 1
        fi
    fi
    python3 -B "$ROOT/scripts/gates/package_licenses.py" "$archive"
    archive_sha256 "$archive" > "$archive.verified.sha256"
    PACKAGE_ARCHIVES+=("$archive")
}

publish() {
    local crate="$1"
    local archive="$PACKAGE_TARGET/package/${crate}-${VERSION}.crate"
    local digest_file="$archive.verified.sha256"
    local verified_digest
    local packaged_digest
    local remote_digest
    # Unpredictable per-crate log path via mktemp: a fixed `/tmp/publish-<crate>.log`
    # is a symlink-TOCTOU target and collides between concurrent publish runs.
    local log
    log="$(mktemp "${TMPDIR:-/tmp}/publish-${crate}.XXXXXX")"
    require_clean_tree
    if [[ ! -s "$digest_file" ]]; then
        echo "error: missing verified package digest for $crate" >&2
        return 1
    fi
    verified_digest="$(<"$digest_file")"
    echo
    echo "==> cargo publish --locked --registry crates-io -p $crate"
    if CARGO_TARGET_DIR="$PACKAGE_TARGET" cargo publish \
        --locked --jobs "$PACKAGE_BUILD_JOBS" --registry crates-io -p "$crate" 2>&1 | tee "$log"; then
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
    # Cargo does not expose a supported "upload this prebuilt .crate" option.
    # It may rebuild the archive during `cargo publish`. Bind that rebuild to the
    # same isolated target, verify its license payload again, and require both
    # byte identity with the prechecked archive and the checksum crates.io
    # records for the uploaded object. A mismatch is reported after Cargo has
    # returned because there is no supported pre-upload archive hook.
    python3 -B "$ROOT/scripts/gates/package_licenses.py" "$archive"
    packaged_digest="$(archive_sha256 "$archive")"
    if [[ "$packaged_digest" != "$verified_digest" ]]; then
        echo "error: cargo publish produced different archive bytes for $crate" >&2
        printf 'Prechecked SHA-256: %s\nPublished SHA-256:  %s\n' \
            "$verified_digest" "$packaged_digest" >&2
        echo "The upload may already have completed. Stop the release and inspect crates.io." >&2
        return 1
    fi
    remote_digest="$(registry_sha256 "$crate")"
    if [[ "$remote_digest" != "$packaged_digest" ]]; then
        echo "error: crates.io checksum does not match the verified $crate archive" >&2
        printf 'Local SHA-256:  %s\nRemote SHA-256: %s\n' \
            "$packaged_digest" "$remote_digest" >&2
        return 1
    fi
    echo "==> $crate archive checksum verified on crates.io: $remote_digest"
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

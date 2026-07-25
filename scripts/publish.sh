#!/usr/bin/env bash
# Publish the exact source workspace version of KeyHog to crates.io.
#
# Reads `workspace.package.version` from the selected source checkout. With
# `--source-root`, hardened automation and gates stay anchored beside this
# script while every Git/Cargo/package input comes only from that exact source.
#
# Newly uploaded package versions are polled until the exact crates.io API
# record is visible. The script changes to the selected source root before Cargo runs.
#
# Re-runnable: an already-published archive is downloaded, checksum/build/license
# verified, and compared byte-for-byte with a fresh package of the selected source
# before Cargo publication is skipped.
#
# Pre-flight (mandatory before running):
#   1. Workspace test suite green at this version.
#   2. Git working tree clean on this version's commit.
#   3. `CARGO_REGISTRY_TOKEN` configured for crates.io.
#
# Usage:
#     scripts/publish.sh
#     scripts/publish.sh --source-root /exact/tag/checkout
#     CRATES_IO_POLL_TIMEOUT_SECONDS=300 scripts/publish.sh --source-root ./source

set -euo pipefail

CRATES_IO_POLL_INITIAL_SECONDS="${CRATES_IO_POLL_INITIAL_SECONDS:-1}"
CRATES_IO_POLL_MAX_SECONDS="${CRATES_IO_POLL_MAX_SECONDS:-15}"
CRATES_IO_POLL_TIMEOUT_SECONDS="${CRATES_IO_POLL_TIMEOUT_SECONDS:-300}"
PACKAGE_BUILD_JOBS="${PACKAGE_BUILD_JOBS:-1}"
AUTOMATION_ROOT="$(cd -P -- "$(dirname -- "$0")/.." && pwd -P)"
SOURCE_ROOT="$AUTOMATION_ROOT"
DUAL_CHECKOUT=0
if [[ "${1:-}" == "--source-root" ]]; then
    if [[ -z "${2:-}" || "$#" -ne 2 ]]; then
        echo "error: --source-root requires exactly one checkout path" >&2
        exit 2
    fi
    DUAL_CHECKOUT=1
    SOURCE_ROOT="$(cd -P -- "$2" && pwd -P)"
elif [[ "$#" -ne 0 ]]; then
    echo "error: usage: scripts/publish.sh [--source-root PATH]" >&2
    exit 2
fi
if [[ "$DUAL_CHECKOUT" == "1" ]] && {
    [[ "$SOURCE_ROOT" == "$AUTOMATION_ROOT" ]] ||
        [[ "$SOURCE_ROOT" == "$AUTOMATION_ROOT/"* ]] ||
        [[ "$AUTOMATION_ROOT" == "$SOURCE_ROOT/"* ]];
}; then
    echo "error: --source-root must be a separate, non-overlapping checkout" >&2
    exit 2
fi
if [[ -z "${CARGO_REGISTRY_TOKEN:-}" ]]; then
    echo "error: CARGO_REGISTRY_TOKEN is required for crates.io publication" >&2
    exit 2
fi
REGISTRY_TOKEN="$CARGO_REGISTRY_TOKEN"
unset CARGO_REGISTRY_TOKEN
readonly REGISTRY_TOKEN
cd "$SOURCE_ROOT"
PUBLISH_TIER_1=(keyhog-core)
PUBLISH_TIER_2=(keyhog-verifier)
PUBLISH_TIER_3=(keyhog-sources keyhog-scanner)
PUBLISH_TIER_4=(keyhog)
PACKAGE_TARGET=""
declare -a PACKAGE_ARCHIVES=()
declare -A ALREADY_PUBLISHED=()

cleanup() {
    if [[ -n "$PACKAGE_TARGET" ]]; then
        rm -rf -- "$PACKAGE_TARGET"
    fi
}
trap cleanup EXIT

require_clean_tree() {
    local status
    status="$(git -C "$SOURCE_ROOT" status --porcelain --untracked-files=all)"
    if [[ -n "$status" ]]; then
        echo "error: refusing to package or publish from a dirty working tree" >&2
        echo "Fix: commit or intentionally remove every staged, modified, and untracked path, then rerun." >&2
        printf '%s\n' "$status" >&2
        return 1
    fi
}
package_license_gate() {
    python3 -B - \
        "$AUTOMATION_ROOT/scripts/gates/package_licenses.py" \
        "$SOURCE_ROOT" \
        "$@" <<'PY'
import pathlib
import runpy
import sys

gate_path, source_root, *arguments = sys.argv[1:]
namespace = runpy.run_path(gate_path, run_name="keyhog_package_license_gate")
namespace["REPO"] = pathlib.Path(source_root).resolve()
raise SystemExit(namespace["main"](arguments))
PY
}


require_complete_publish_order() {
    package_license_gate \
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

validate_poll_configuration() {
    python3 -B - \
        "$CRATES_IO_POLL_INITIAL_SECONDS" \
        "$CRATES_IO_POLL_MAX_SECONDS" \
        "$CRATES_IO_POLL_TIMEOUT_SECONDS" <<'PY'
import decimal
import math
import sys

names = (
    "CRATES_IO_POLL_INITIAL_SECONDS",
    "CRATES_IO_POLL_MAX_SECONDS",
    "CRATES_IO_POLL_TIMEOUT_SECONDS",
)
values = []
for name, raw in zip(names, sys.argv[1:]):
    try:
        value = decimal.Decimal(raw)
    except decimal.InvalidOperation:
        raise SystemExit(f"error: {name} must be a positive finite decimal, got {raw!r}")
    seconds = float(value)
    if not value.is_finite() or seconds <= 0 or not math.isfinite(seconds):
        raise SystemExit(f"error: {name} must be a positive finite decimal, got {raw!r}")
    values.append(value)
if values[1] < values[0]:
    raise SystemExit(
        "error: CRATES_IO_POLL_MAX_SECONDS must be greater than or equal to "
        "CRATES_IO_POLL_INITIAL_SECONDS"
    )
PY
}

wait_for_registry_version() {
    local crate="$1"
    local expected_checksum="$2"
    python3 -B - \
        "$crate" \
        "$VERSION" \
        "$expected_checksum" \
        "$CRATES_IO_POLL_INITIAL_SECONDS" \
        "$CRATES_IO_POLL_MAX_SECONDS" \
        "$CRATES_IO_POLL_TIMEOUT_SECONDS" <<'PY'
import json
import os
import string
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

crate, version, expected_checksum, initial_raw, maximum_raw, timeout_raw = sys.argv[1:]
initial = float(initial_raw)
maximum = float(maximum_raw)
timeout = float(timeout_raw)
api_base = os.environ.get("CRATES_IO_API_BASE", "https://crates.io").rstrip("/")
endpoint = "{}/api/v1/crates/{}/{}".format(
    api_base, urllib.parse.quote(crate, safe=""), urllib.parse.quote(version, safe="")
)
request = urllib.request.Request(
    endpoint,
    headers={"User-Agent": f"keyhog-release-gate/{version} (security@santh.dev)"},
)
deadline = time.monotonic() + timeout
interval = initial
attempt = 0
while True:
    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SystemExit(
            f"error: timed out after {timeout_raw}s waiting for {crate} {version} at "
            f"{endpoint}. Remediation: confirm the exact version is visible on crates.io, "
            "then rerun this idempotent publisher."
        )
    attempt += 1
    try:
        with urllib.request.urlopen(request, timeout=max(0.001, min(30.0, remaining))) as response:
            document = json.load(response)
    except urllib.error.HTTPError as error:
        if error.code != 404:
            raise SystemExit(
                f"error: crates.io visibility check failed for {crate} {version} at "
                f"{endpoint}: HTTP {error.code}. Remediation: inspect crates.io status "
                "and the published version, then rerun this idempotent publisher."
            )
    except Exception as error:
        raise SystemExit(
            f"error: crates.io visibility check failed for {crate} {version} at "
            f"{endpoint}: {error}. Remediation: check registry connectivity and "
            "crates.io status, then rerun this idempotent publisher."
        )
    else:
        checksum = document.get("version", {}).get("checksum")
        if (
            not isinstance(checksum, str)
            or len(checksum) != 64
            or any(character not in string.hexdigits for character in checksum)
        ):
            raise SystemExit(
                f"error: crates.io returned no valid checksum for {crate} {version} at "
                f"{endpoint}. Remediation: inspect the registry record before continuing."
            )
        checksum = checksum.lower()
        if checksum != expected_checksum:
            raise SystemExit(
                f"error: crates.io checksum does not match the verified {crate} "
                f"{version} archive at {endpoint}: local {expected_checksum}, remote "
                f"{checksum}. Remediation: stop the release and inspect crates.io."
            )
        print(
            f"==> {crate} {version} visible on crates.io after {attempt} attempt(s).",
            file=sys.stderr,
        )
        print(checksum)
        break

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise SystemExit(
            f"error: timed out after {timeout_raw}s waiting for {crate} {version} at "
            f"{endpoint}. Remediation: confirm the exact version is visible on crates.io, "
            "then rerun this idempotent publisher."
        )
    time.sleep(min(interval, remaining))
    interval = min(maximum, interval * 2)
PY
}

registry_sha256() {
    python3 -B - "$1" "$VERSION" <<'PY'
import json
import os
import string
import sys
import urllib.parse
import urllib.request

crate, version = sys.argv[1:]
api_base = os.environ.get("CRATES_IO_API_BASE", "https://crates.io").rstrip("/")
url = "{}/api/v1/crates/{}/{}".format(
    api_base, urllib.parse.quote(crate, safe=""), urllib.parse.quote(version, safe="")
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
api_base = os.environ.get("CRATES_IO_API_BASE", "https://crates.io").rstrip("/")
escaped_crate = urllib.parse.quote(crate, safe="")
escaped_version = urllib.parse.quote(version, safe="")
headers = {"User-Agent": f"keyhog-release-gate/{version} (security@santh.dev)"}
metadata_url = f"{api_base}/api/v1/crates/{escaped_crate}/{escaped_version}"
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

url = f"{api_base}/api/v1/crates/{escaped_crate}/{escaped_version}/download"
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
    CARGO_PROFILE_DEV_DEBUG=0 CARGO_TARGET_DIR="$PACKAGE_TARGET/registry-build" cargo build \
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
' "$SOURCE_ROOT/Cargo.toml")
if [[ -z "${VERSION}" ]]; then
    echo "error: missing workspace.package.version in $SOURCE_ROOT/Cargo.toml" >&2
    exit 2
fi

preflight() {
    require_clean_tree
    require_complete_publish_order
    echo "==> verifying canonical license files in publishable crate roots"
    package_license_gate
    PACKAGE_TARGET="$(mktemp -d "${TMPDIR:-/tmp}/keyhog-publish-package.XXXXXX")"
}

package_current_archive() {
    local crate="$1"
    local archive="$2"
    echo "==> packaging $crate in isolated target $PACKAGE_TARGET"
    rm -f -- "$archive"
    CARGO_PROFILE_DEV_DEBUG=0 CARGO_TARGET_DIR="$PACKAGE_TARGET" cargo package \
        --locked \
        --all-features \
        --jobs "$PACKAGE_BUILD_JOBS" \
        --package "$crate"
    if [[ ! -f "$archive" ]]; then
        echo "error: cargo package did not create expected archive $archive" >&2
        return 1
    fi
}

package_and_verify() {
    local crate="$1"
    local archive="$PACKAGE_TARGET/package/${crate}-${VERSION}.crate"
    local remote_archive="$PACKAGE_TARGET/registry/${crate}-${VERSION}.crate"
    local downloaded_digest
    local packaged_digest
    local remote_digest
    local download_status
    mkdir -p "$(dirname "$archive")" "$(dirname "$remote_archive")"
    echo "==> checking crates.io for an existing $crate v$VERSION archive"
    if downloaded_digest="$(download_registry_archive "$crate" "$remote_archive")"; then
        remote_digest="$(registry_sha256 "$crate")"
        if [[ "$downloaded_digest" != "$remote_digest" ]]; then
            echo "error: downloaded $crate archive checksum does not match crates.io metadata" >&2
            printf 'Downloaded SHA-256: %s\nRegistry SHA-256:   %s\n' \
                "$downloaded_digest" "$remote_digest" >&2
            return 1
        fi
        echo "==> verifying immutable crates.io archive for already-published $crate v$VERSION"
        verify_registry_archive_build "$crate" "$remote_archive"
        package_license_gate "$remote_archive"
        package_current_archive "$crate" "$archive"
        packaged_digest="$(archive_sha256 "$archive")"
        if [[ "$packaged_digest" != "$downloaded_digest" ]]; then
            echo "error: tagged source archive for already-published $crate differs from crates.io" >&2
            printf 'Tagged source SHA-256: %s\nRegistry SHA-256:      %s\n' \
                "$packaged_digest" "$downloaded_digest" >&2
            return 1
        fi
        ALREADY_PUBLISHED["$crate"]=1
    else
        download_status=$?
        if [[ "$download_status" -ne 4 ]]; then
            return "$download_status"
        fi
        package_current_archive "$crate" "$archive"
    fi
    package_license_gate "$archive"
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
    local published_now=0
    require_clean_tree
    if [[ ! -s "$digest_file" ]]; then
        echo "error: missing verified package digest for $crate" >&2
        return 1
    fi
    verified_digest="$(<"$digest_file")"
    echo
    if [[ "${ALREADY_PUBLISHED[$crate]:-0}" == "1" ]]; then
        echo "==> $crate already at this version on crates.io; verified without republishing."
    else
        # Unpredictable per-crate log path: a fixed path is a symlink-TOCTOU
        # target and collides between concurrent publication runs.
        log="$(mktemp "${TMPDIR:-/tmp}/publish-${crate}.XXXXXX")"
        echo "==> cargo publish --locked --registry crates-io -p $crate"
        if CARGO_REGISTRY_TOKEN="$REGISTRY_TOKEN" \
            CARGO_PROFILE_DEV_DEBUG=0 CARGO_TARGET_DIR="$PACKAGE_TARGET" cargo publish \
            --locked --jobs "$PACKAGE_BUILD_JOBS" --registry crates-io --no-verify -p "$crate" 2>&1 | tee "$log"; then
            rm -f -- "$log"
            echo "==> $crate published."
            published_now=1
        else
            echo "==> ERROR: $crate publish failed." >&2
            rm -f -- "$log"
            return 1
        fi
    fi
    # The earlier `cargo package` already performed Cargo's build verification.
    # `--no-verify` keeps this credential-bearing Cargo invocation from executing
    # tagged build scripts. Cargo still rebuilds the upload archive; bind that
    # rebuild to the same isolated target, verify its license payload again, and
    # require both byte identity with the prechecked archive and the checksum
    # crates.io records for the uploaded object.
    package_license_gate "$archive"
    packaged_digest="$(archive_sha256 "$archive")"
    if [[ "$packaged_digest" != "$verified_digest" ]]; then
        echo "error: cargo publish produced different archive bytes for $crate" >&2
        printf 'Prechecked SHA-256: %s\nPublished SHA-256:  %s\n' \
            "$verified_digest" "$packaged_digest" >&2
        echo "The upload may already have completed. Stop the release and inspect crates.io." >&2
        return 1
    fi
    if [[ "$published_now" == "1" ]]; then
        remote_digest="$(wait_for_registry_version "$crate" "$packaged_digest")"
    else
        remote_digest="$(registry_sha256 "$crate")"
    fi
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
validate_poll_configuration

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
package_license_gate \
    --require-all-archives "${PACKAGE_ARCHIVES[@]}"
for crate in "${PUBLISH_TIER_4[@]}"; do
    publish "$crate"
done

echo
echo "==> All v${VERSION} crates published."

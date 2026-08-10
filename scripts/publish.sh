#!/usr/bin/env bash
# Publish the current workspace version after CI has passed.

set -euo pipefail

if [[ -z "${CARGO_REGISTRY_TOKEN:-}" ]]; then
    echo "error: CARGO_REGISTRY_TOKEN is required" >&2
    exit 2
fi

ROOT="$(cd -P -- "$(dirname -- "$0")/.." && pwd -P)"
cd "$ROOT"
if ! VERSION="$(python3 -B - <<'PY'
import pathlib
import tomllib
document = tomllib.loads(pathlib.Path("Cargo.toml").read_text())
print(document["workspace"]["package"]["version"])
PY
)"; then
    echo "error: missing workspace.package.version in Cargo.toml" >&2
    exit 2
fi
CRATES=(keyhog-profile keyhog-core keyhog-verifier keyhog-sources keyhog-scanner keyhog)

crate_visible() {
    python3 -B - "$1" "$VERSION" <<'PY'
import sys
import urllib.error
import urllib.parse
import urllib.request

crate, version = sys.argv[1:]
url = "https://crates.io/api/v1/crates/{}/{}".format(
    urllib.parse.quote(crate, safe=""), urllib.parse.quote(version, safe="")
)
request = urllib.request.Request(url, headers={"User-Agent": "keyhog-auto-release"})
try:
    with urllib.request.urlopen(request, timeout=30) as response:
        raise SystemExit(0 if response.status == 200 else 1)
except urllib.error.HTTPError as error:
    raise SystemExit(1 if error.code == 404 else 2)
PY
}

wait_until_visible() {
    local crate="$1"
    local delay=1
    local elapsed=0
    while ! crate_visible "$crate"; do
        if (( elapsed >= 300 )); then
            echo "error: timed out waiting for $crate $VERSION on crates.io" >&2
            return 1
        fi
        sleep "$delay"
        elapsed=$((elapsed + delay))
        if (( delay < 15 )); then
            delay=$((delay * 2))
            if (( delay > 15 )); then delay=15; fi
        fi
    done
}

publish_crate() {
    local crate="$1"
    local attempt
    local delay=2

    if crate_visible "$crate"; then
        echo "==> $crate $VERSION already published"
        return 0
    fi

    for attempt in 1 2 3; do
        echo "==> publishing $crate $VERSION (attempt $attempt/3)"
        if cargo publish --locked --no-verify --registry crates-io -p "$crate"; then
            wait_until_visible "$crate"
            return
        fi

        # The upload can succeed even when the client loses the response.
        # Visibility makes a rerun idempotent without parsing Cargo's prose.
        if crate_visible "$crate"; then
            echo "==> $crate $VERSION became visible after the failed upload response"
            return 0
        fi
        if (( attempt < 3 )); then
            echo "warning: $crate $VERSION upload failed; retrying in ${delay}s" >&2
            sleep "$delay"
            delay=$((delay * 2))
        fi
    done

    echo "error: failed to publish $crate $VERSION after 3 attempts" >&2
    echo "error: rerun this release workflow; already-visible crates will be skipped" >&2
    return 1
}

for crate in "${CRATES[@]}"; do
    publish_crate "$crate"
done

echo "Published KeyHog $VERSION to crates.io."

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
CRATES=(keyhog-core keyhog-verifier keyhog-sources keyhog-scanner keyhog)

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

for crate in "${CRATES[@]}"; do
    if crate_visible "$crate"; then
        echo "==> $crate $VERSION already published"
        continue
    fi
    echo "==> publishing $crate $VERSION"
    cargo publish --locked --no-verify --registry crates-io -p "$crate"
    wait_until_visible "$crate"
done

echo "Published KeyHog $VERSION to crates.io."

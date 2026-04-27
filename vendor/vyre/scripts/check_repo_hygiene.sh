#!/usr/bin/env bash
# Repo hygiene and contribution discipline.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

failed=0

require_file() {
    local path="$1"
    if [[ ! -f "$path" ]]; then
        echo "FAIL: required repository file missing: $path" >&2
        failed=1
    else
        echo "  ✓ $path"
    fi
}

require_dir_file_count() {
    local dir="$1"
    local glob="$2"
    local min_count="$3"
    local count
    count="$(find "$dir" -maxdepth 1 -type f -name "$glob" 2>/dev/null | wc -l | tr -d ' ')"
    if [[ "$count" -lt "$min_count" ]]; then
        echo "FAIL: $dir needs at least $min_count '$glob' files; found $count" >&2
        failed=1
    else
        echo "  ✓ $dir has $count '$glob' files"
    fi
}

require_file README.md
require_file CONTRIBUTING.md
require_file CODE_OF_CONDUCT.md
require_file SECURITY.md
require_file CHANGELOG.md
require_file LICENSE-APACHE
require_file LICENSE-MIT
require_file CODEOWNERS
require_file .github/CODEOWNERS
require_file .github/PULL_REQUEST_TEMPLATE.md
require_file .github/dependabot.yml
require_file .github/workflows/ci.yml
require_file .github/workflows/gpu-parity.yml
require_file .github/workflows/architectural-invariants.yml
require_dir_file_count .github/ISSUE_TEMPLATE '*.md' 3

if grep -RInE 'no-gpu|gpu-feature|vyre-driver-wgpu/no-gpu' \
    --include='*.yml' --include='*.yaml' --include='Cargo.toml' \
    --exclude-dir=target --exclude-dir=.git \
    .github vyre-driver-wgpu/Cargo.toml 2>/dev/null; then
    echo "FAIL: no-GPU feature escape hatch found in CI or WGPU manifest" >&2
    failed=1
else
    echo "  ✓ no no-GPU CI or manifest escape hatch"
fi

FORBIDDEN_EXTS='\.(rlib|so|dylib|exe|o|a|bin|dll|lib|pdb|pyd|whl|tgz|tar\.gz|zip|old|backup|orig|bak)$'
tracked_binaries="$(git ls-files | grep -E "$FORBIDDEN_EXTS" 2>/dev/null)"
if [[ -n "$tracked_binaries" ]]; then
    echo "FAIL: binary/backup files tracked:" >&2
    echo "$tracked_binaries" | head -10 >&2
    failed=1
else
    echo "  ✓ no tracked binaries"
fi

tracked_build="$(git ls-files | grep -E '(^|/)(target|node_modules|__pycache__|\.venv|\.next|dist)(/|$)' 2>/dev/null)"
if [[ -n "$tracked_build" ]]; then
    echo "FAIL: build-output tracked:" >&2
    echo "$tracked_build" | head -5 >&2
    failed=1
else
    echo "  ✓ no tracked build-output"
fi

if [[ -f .github/workflows-paused/gpu-parity.yml ]]; then
    echo "FAIL: GPU parity workflow is paused; it must be active under .github/workflows/" >&2
    failed=1
else
    echo "  ✓ GPU parity workflow is active"
fi

silent_gpu_skips="$(
    grep -RInE 'no GPU.*skipp|skipp.*no GPU|adapter missing.*skipp|skipp.*adapter missing' \
        --include='*.rs' \
        --exclude-dir=target \
        --exclude-dir=.git \
        . 2>/dev/null || true
)"
if [[ -n "$silent_gpu_skips" ]]; then
    echo "FAIL: silent GPU skip language found:" >&2
    echo "$silent_gpu_skips" >&2
    failed=1
else
    echo "  ✓ no silent GPU skip language"
fi

if [[ "$failed" -ne 0 ]]; then
    exit 1
fi

exit 0

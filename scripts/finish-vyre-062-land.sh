#!/usr/bin/env bash
#
# keyhog-side completion of the engine-refactor landing (tasks #12 + #14).
#
# PRECONDITION (NOT done by this script): the maintainer has approved and the
# vyre 0.6.2 release train has PUBLISHED the vyre crates to crates.io
#   (cd ../../libs/performance/matching/vyre && set VYRE_RELEASE_APPROVED=… &&
#    scripts/publish-release.sh   — see that repo's RELEASE.md §39).
#
# Given that, this script does the part keyhog owns:
#   1. verify vyre 0.6.2 is actually on crates.io (fail closed otherwise),
#   2. swap the dev path-override pins to `=0.6.2` registry pins (#12),
#   3. prove the published-crate build is green: release build + the test gate
#      + the differential bench gate (#13),
#   4. print the exact push to land all local commits on origin (#14).
#
# It deliberately does NOT run `git push` itself: the push moves the commits
# stacked on 78046450 ("[LOCAL — DO NOT PUSH yet]") to origin, so that final,
# irreversible step stays an explicit human action.

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

TARGET_VERSION="0.6.2"
CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-/mnt/FlareTraining/santh-archive/cargo-target}"
export CARGO_TARGET_DIR

die() { printf 'finish-vyre-062-land: %s\n' "$1" >&2; exit 1; }

# ── 1. Fail closed unless vyre 0.6.2 is published ──────────────────────────
# Query the crates.io sparse index for vyre-libs; the pin must never go in
# ahead of the publish (that would leave keyhog unbuildable for everyone).
have_version() { # crate, version
  curl -fsS --max-time 15 "https://index.crates.io/${1:0:2}/${1:2:2}/$1" 2>/dev/null \
    | grep -q "\"vers\":\"$2\""
}
for crate in vyre-libs vyre-core vyre-runtime vyre-driver-wgpu vyre-driver-cuda; do
  have_version "$crate" "$TARGET_VERSION" \
    || die "crate '$crate' $TARGET_VERSION is NOT on crates.io yet. Fix: approve + run the vyre release train (vyre repo: VYRE_RELEASE_APPROVED=… scripts/publish-release.sh) BEFORE pinning."
done
echo "✓ vyre $TARGET_VERSION is published on crates.io"

# ── 2. Swap the path-override pins to registry pins (#12) ───────────────────
# Only touches lines that carry the live-source vyre path override; bumps the
# exact pin and strips the path clause. Idempotent: a no-op once already pinned.
sed -i -E '/libs\/performance\/matching\/vyre\//{
  s/"=0\.6\.1"/"='"$TARGET_VERSION"'"/
  s/, path = "[^"]*vyre[^"]*"//
}' Cargo.toml

# Post-conditions: no vyre path override survives, and the pins are =0.6.2.
if grep -nE 'path = "[^"]*vyre[^"]*"' Cargo.toml; then
  die "a vyre path override survived the rewrite (see lines above). Fix: inspect Cargo.toml [workspace.dependencies] vyre* entries."
fi
grep -qE '^vyre = \{ version = "='"$TARGET_VERSION"'"' Cargo.toml \
  || die "expected 'vyre = { version = \"=$TARGET_VERSION\"' after rewrite; Cargo.toml shape changed — pin by hand."
echo "✓ vyre pins rewritten to =$TARGET_VERSION (path override dropped)"

# ── 3. Prove the published-crate build is green (#13) ──────────────────────
echo "→ release build against published vyre $TARGET_VERSION …"
cargo build --release -p keyhog --bin keyhog || die "release build failed against published vyre $TARGET_VERSION."

echo "→ scanner test gate …"
cargo test -p keyhog-scanner --no-default-features --features ci-lean --test all_tests \
  || die "scanner all_tests regressed against published vyre $TARGET_VERSION."

echo "→ differential bench gate …"
( cd benchmarks && KEYHOG_BIN="$CARGO_TARGET_DIR/release/keyhog" \
    python3 -m bench gate --corpus mirror --scanners keyhog,trufflehog \
      --baseline baselines/mirror-keyhog-baseline.json --epsilon 0.01 ) \
  || die "bench gate regressed against published vyre $TARGET_VERSION."

# ── 4. Hand the final, deliberate push to the human (#14) ──────────────────
COMMITS_AHEAD="$(git rev-list --count origin/main..HEAD)"
cat <<EOF

✓ keyhog is green against published vyre $TARGET_VERSION.
  Pin (#12) applied; correctness + bench gates (#13) pass.

LAST STEP (#14) — land $COMMITS_AHEAD local commits on origin. Review, then run:

    git -C "$REPO_ROOT" add Cargo.toml Cargo.lock
    git -C "$REPO_ROOT" commit -m "deps: pin vyre =$TARGET_VERSION, drop dev path override"
    git -C "$REPO_ROOT" push origin main

This push moves the stack built on 78046450 ("[LOCAL — DO NOT PUSH yet]") to
origin; run it only once the vyre release is intentionally public.
EOF

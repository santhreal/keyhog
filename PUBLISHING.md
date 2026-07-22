# crates.io publishing

Registry state below was verified on 2026-07-22. The complete published crate
chain is `0.5.44`; the source tree prepares `0.5.45`. The v0.5.44 GitHub release
did not publish because the signer addressed its draft through a tag endpoint
that exposes only published releases. Version 0.5.45 addresses draft mutation
and validation by immutable release ID. The v0.5.43 GitHub release failed in
the Windows GPU literal artifact generator, and v0.5.42 failed in the Windows
portable build. The v0.5.41 publication stopped after four libraries reached
crates.io because its immutable `keyhog-sources` archive failed under the CLI
feature graph. No `keyhog` v0.5.41 CLI or GitHub tag was published.

## What's live on crates.io

| crate | version |
| --- | --- |
| `keyhog`         | 0.5.44 |
| `keyhog-core`    | 0.5.44 |
| `keyhog-scanner` | 0.5.44 |
| `keyhog-sources` | 0.5.44 |
| `keyhog-verifier`| 0.5.44 |

Current source directly pins `vyre`, `vyre-libs`, `vyre-driver-wgpu`,
`vyre-driver-cuda`, and `vyre-runtime` at `=0.6.5`. Their transitive dependency
graph is resolved by Cargo and locked in `Cargo.lock`; it is not a second
KeyHog-owned publish list.

## Publish chain

The KeyHog workspace pins all five runtime VYRE crates (`vyre`, `vyre-libs`,
`vyre-driver-wgpu`, `vyre-driver-cuda`, and `vyre-runtime`) at `=0.6.5` from
crates.io. The repository carries no VYRE source snapshot. Nothing in the build
resolves through a repository vendor tree.

To cut a KeyHog release:

1. Bump the workspace package version and exact KeyHog dependency versions in
   `Cargo.toml`.
2. Run the prerelease suite against the release commit.
3. Run `scripts/publish.sh`. The script packages and builds every crate with all
   features before its tier uploads. It downloads and verifies immutable
   registry archives when you resume a partial run.
   Verification builds use one job and omit development debug metadata by
   default to bound peak memory. Set `PACKAGE_BUILD_JOBS` only when the release
   host can sustain wider builds.
4. Tag the exact published commit (`git tag v0.5.X && git push origin v0.5.X`).
   The tag starts the signed GitHub release workflow used by `install.sh`.

## If VYRE bumps minor

If a new VYRE minor is required, publish the needed VYRE chain from the upstream
repo first, then bump the five KeyHog `vyre*` pins in root `Cargo.toml`, run
`python3 scripts/gates/vyre_pin_consistency.py`, and publish KeyHog.

## Rate limits

crates.io enforces new-crate burst limits. KeyHog only needs the five published
runtime crates listed above; unrelated optional/support crates do not block its
publish chain.

## Stale `keyhog 0.2.1` on crates.io

The pre-VYRE `keyhog 0.2.1` is superseded by 0.5.40. If it remains unyanked,
registry owners can yank that exact version with `cargo yank keyhog --version
0.2.1`; yanking does not remove existing downloads or lockfile resolutions.

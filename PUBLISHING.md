# crates.io publishing

Registry state below was verified on 2026-07-12. The source tree is `0.5.41`;
all five public KeyHog crates remain at `0.5.40` until this publish chain
completes. KeyHog pins the five VYRE runtime dependencies to the published
`=0.6.5` release. Development-only or unrelated VYRE crates do not participate
in the KeyHog publish chain.

## What's live on crates.io

| crate | version |
| --- | --- |
| `keyhog`         | 0.5.40 |
| `keyhog-core`    | 0.5.40 |
| `keyhog-scanner` | 0.5.40 |
| `keyhog-sources` | 0.5.40 |
| `keyhog-verifier`| 0.5.40 |

Current source directly pins `vyre`, `vyre-libs`, `vyre-driver-wgpu`,
`vyre-driver-cuda`, and `vyre-runtime` at `=0.6.5`. Their transitive dependency
graph is resolved by Cargo and locked in `Cargo.lock`; it is not a second
KeyHog-owned publish list.

## Publish chain (for the next cut)

The KeyHog workspace pins all five runtime VYRE crates (`vyre`, `vyre-libs`,
`vyre-driver-wgpu`, `vyre-driver-cuda`, `vyre-runtime`) at `=0.6.5` from
crates.io. The repository carries no VYRE source snapshot and nothing in the
build resolves through a repository vendor tree.
To cut a new KeyHog release:

1. **Bump the workspace version** in `Cargo.toml` (`[workspace.package] version`).
2. **Run `cargo publish` in dependency order.** Do not start a dependent publish
   until crates.io has indexed the exact dependency version:
   ```sh
   cargo publish -p keyhog-core
   cargo publish -p keyhog-verifier   # depends on keyhog-core
   cargo publish -p keyhog-sources    # depends on keyhog-core + keyhog-verifier
   cargo publish -p keyhog-scanner    # depends on keyhog-core + vyre crates
   cargo publish -p keyhog            # depends on all four
   ```
3. **Tag the release** (`git tag v0.5.X && git push origin v0.5.X`) so
   `install.sh` can resolve the matching GitHub Release assets.

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

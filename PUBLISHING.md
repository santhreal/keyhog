# crates.io publishing

> Status (2026-06-17): the Keyhog workspace is pinned to published Vyre `0.6.2`
> registry crates. `vyre-debug` is not a Keyhog dependency and does not block the
> Keyhog publish chain. The last public Keyhog cut remains `0.5.37` until the
> package publish steps below run.

## What's live on crates.io

| crate | version |
| --- | --- |
| `keyhog`         | 0.5.37 |
| `keyhog-core`    | 0.5.37 |
| `keyhog-scanner` | 0.5.37 |
| `keyhog-sources` | 0.5.37 |
| `keyhog-verifier`| 0.5.37 |

Current source builds against published `vyre 0.6.2` plus the supporting Vyre
crates Keyhog needs: `vyre-spec`, `vyre-foundation`, `vyre-lower`,
`vyre-primitives`, `vyre-self-substrate`, `vyre-driver`, `vyre-emit-naga`,
`vyre-runtime`, `vyre-emit-ptx`, `vyre-driver-cuda`, `vyre-driver-wgpu`,
`vyre-harness`, and `vyre-libs`.

## Publish chain (for the next cut)

The keyhog workspace pins all five runtime `vyre*` crates (`vyre`, `vyre-libs`,
`vyre-driver-wgpu`, `vyre-driver-cuda`, `vyre-runtime`) at `=0.6.2` from
crates.io. The `vendor/vyre/` snapshot is a read-only reference copy
(`vendor/README.md`, MC-11); nothing in the build resolves through it.
To cut a new Keyhog release:

1. **Bump the workspace version** in `Cargo.toml` (`[workspace.package] version`).
2. **Run `cargo publish` in dependency order** (each step waits for crates.io to
   index the previous, usually ~30 seconds):
   ```sh
   cargo publish -p keyhog-core
   cargo publish -p keyhog-verifier   # depends on keyhog-core
   cargo publish -p keyhog-sources    # depends on keyhog-core
   cargo publish -p keyhog-scanner    # depends on keyhog-core + vyre crates
   cargo publish -p keyhog            # depends on all four
   ```
3. **Tag the release** (`git tag v0.5.X && git push origin v0.5.X`) so install.sh's
   GitHub-release-download path picks it up.

## If vyre bumps minor

If a new Vyre minor is required, publish the needed Vyre chain from the upstream
repo first, then bump the five Keyhog `vyre*` pins in root `Cargo.toml`, run
`python3 scripts/gates/vyre_pin_consistency.py`, and publish Keyhog.

## Rate limits

crates.io enforces new-crate burst limits. The Vyre `0.6.2` cut hit those limits
while publishing optional/support crates; Keyhog only needs the already-published
runtime crates listed above.

## Stale `keyhog 0.2.1` on crates.io

The pre-vyre `keyhog 0.2.1` is superseded by 0.5.37. To stop new `cargo install keyhog`
from picking up 0.2.1 by default, the user can yank it; doing so is not automated.

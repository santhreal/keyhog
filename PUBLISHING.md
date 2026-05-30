# crates.io publishing

> Status (2026-05-29): **DONE.** vyre 0.6.1 and keyhog 0.5.37 are live on crates.io.
> `cargo install keyhog` source-builds from registry. `install.sh` (signed prebuilt) stays
> the recommended path for end users; see [README.md](./README.md) for the trade-off.

## What's live on crates.io

| crate | version |
| --- | --- |
| `keyhog`         | 0.5.37 |
| `keyhog-core`    | 0.5.37 |
| `keyhog-scanner` | 0.5.37 |
| `keyhog-sources` | 0.5.37 |
| `keyhog-verifier`| 0.5.37 |

Built against published `vyre 0.6.1` (+ 13 supporting crates: vyre-spec, vyre-foundation,
vyre-lower, vyre-primitives, vyre-self-substrate, vyre-driver, vyre-emit-naga,
vyre-runtime, vyre-emit-ptx, vyre-driver-cuda, vyre-driver-wgpu, vyre-harness,
vyre-libs).

## Publish chain (for the next cut)

The keyhog workspace pins `vyre = "=0.6.1"` via pure-registry references (no `path =`
override; the `vendor/vyre/` tree stays on disk for offline work). To cut a new release:

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

If a new vyre (e.g. 0.6.2) is required, publish the full vyre chain from the upstream
repo first (`libs/performance/matching/vyre/`, 14 crates in topo order rooted at
`vyre-spec`), then bump the keyhog `vyre*` pins to match, then publish keyhog. The
detailed vyre publish order is committed in vyre's own changelog.

## Rate limits

crates.io enforces ~5 new-crate publishes per ~10-minute burst. The keyhog cut here is
five new versions of existing crates (lower limit, 30/week, very forgiving). The vyre
0.6.1 cut tripped the new-crate limit at version 6 (vyre-libs); waited ~9 minutes and
retried successfully.

## Stale `keyhog 0.2.1` on crates.io

The pre-vyre `keyhog 0.2.1` is superseded by 0.5.37. To stop new `cargo install keyhog`
from picking up 0.2.1 by default, the user can yank it; doing so is not automated.

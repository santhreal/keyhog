# crates.io publishing

> Status (2026-05-29): **blocked on upstream vyre 0.6.1 not being on crates.io.**
> Canonical install today is `install.sh` / GitHub Releases. See below for
> the unblock path.

## State of the registry

| crate | crates.io max | workspace HEAD | gap |
| --- | --- | --- | --- |
| `keyhog`         | 0.2.1 | 0.5.37 | 35 versions, pre-vyre era |
| `keyhog-core`    | 0.5.4 | 0.5.37 | 33 versions |
| `keyhog-scanner` | 0.2.1 | 0.5.37 | 35 versions |
| `keyhog-sources` | 0.5.4 | 0.5.37 | 33 versions |
| `keyhog-verifier`| 0.5.4 | 0.5.37 | 33 versions |

The stale `keyhog 0.2.1` is what the dropped crates.io README badge
used to point at. README + docs now link `cargo install --git` instead;
see commit `7da6af8d`.

## Blocker: vyre 0.6.1 isn't on crates.io

Workspace pins vyre at `=0.6.1` via vendored path deps:

```
vyre              = { version = "=0.6.1", path = "vendor/vyre/vyre-core" }
vyre_libs         = { version = "=0.6.1", path = "vendor/vyre/vyre-libs" }
vyre-driver-wgpu  = { version = "=0.6.1", path = "vendor/vyre/vyre-driver-wgpu" }
vyre-driver-cuda  = { version = "=0.6.1", path = "vendor/vyre/vyre-driver-cuda" }
vyre-runtime      = { version = "=0.6.1", path = "vendor/vyre/vyre-runtime" }
```

At publish time Cargo strips `path` and keeps `version`, so the published
manifests will require these versions on crates.io. crates.io has:

| vyre crate | published max |
| --- | --- |
| `vyre`              | 0.4.1 |
| `vyre-libs`         | **NOT PUBLISHED** |
| `vyre-driver-wgpu`  | **NOT PUBLISHED** (`vyre-wgpu 0.1.0` is the old name) |
| `vyre-driver-cuda`  | **NOT PUBLISHED** |
| `vyre-runtime`      | **NOT PUBLISHED** |
| `vyre-foundation`   | 0.4.1 |
| `vyre-macros`       | 0.6.1 |
| `vyre-primitives`   | 0.4.1 |

`cargo publish --dry-run -p keyhog-core --allow-dirty` confirms the
failure:

```
error: failed to prepare local package for uploading
Caused by: no matching package named `vyre-libs` found
```

## Unblock path

1. **Publish vyre 0.6.1 from the upstream vyre repo**
   (`/media/mukund-thiru/SanthData/Santh/libs/performance/matching/vyre`;
   `vendor/vyre/` in this checkout is a frozen snapshot, the canonical
   source lives in the standalone vyre repo). The dep chain is deeper
   than the keyhog-facing crates would suggest. Confirmed via
   `cargo publish --dry-run -p vyre-foundation`:

   ```
   error: failed to prepare local package for uploading
   Caused by: failed to select a version for the requirement `vyre-spec = "^0.6.1"`
   candidate versions found which didn't match: 0.4.1, 0.1.1, 0.1.0
   ```

   So the full publish order (leaf → root) is roughly:

   ```
   vyre-spec 0.6.1            (crates.io has 0.4.1)
   vyre-foundation 0.6.1      (crates.io has 0.4.1)
   vyre-macros 0.6.1          (already on crates.io at 0.6.1)
   vyre-primitives 0.6.1      (crates.io has 0.4.1)
   vyre-reference 0.6.1       (crates.io has 0.4.1)
   vyre-lower 0.6.1           (crates.io has 0.4.1)
   vyre-intrinsics 0.6.1      (crates.io has 0.4.1)
   vyre-self-substrate 0.6.1  (crates.io has 0.4.1)
   vyre-conform 0.6.1         (crates.io has 0.1.0)
   vyre (= vyre-core) 0.6.1   (crates.io has 0.4.1)
   vyre-driver 0.6.1          (crates.io has 0.4.1)
   vyre-libs 0.6.1            (NOT PUBLISHED)
   vyre-runtime 0.6.1         (NOT PUBLISHED)
   vyre-driver-wgpu 0.6.1     (NOT PUBLISHED; old name was vyre-wgpu 0.1.0)
   vyre-driver-cuda 0.6.1     (NOT PUBLISHED)
   ```

   That's 14 publishes per release cut, each requiring its own
   `cargo publish` + ~30 s crates.io index wait + the CLAUDE.md
   "read every file + run every test" gate. This is a multi-hour
   focused vyre-publish session, not a side-task of a keyhog session.

2. **Bump the keyhog workspace** if vyre publishes anything different
   from 0.6.1 (e.g. 0.6.2), then re-run the dry-run below.

3. **Publish keyhog crates** in dependency order, one tag bump per
   round (the workspace pins `=X.Y.Z`, so all five crates ship at the
   same version):
   ```sh
   cargo publish -p keyhog-core
   # wait ~30s for crates.io to index
   cargo publish -p keyhog-verifier   # depends on keyhog-core
   cargo publish -p keyhog-sources    # depends on keyhog-core
   cargo publish -p keyhog-scanner    # depends on keyhog-core
   cargo publish -p keyhog            # depends on all four
   ```

4. **Verify**:
   - `cargo install keyhog` (no `--git`) downloads + builds + runs.
   - Update the README install snippet from `cargo install --git ...`
     back to `cargo install keyhog` (revert commit `7da6af8d`'s install
     path block; the badge swap stays).

## Why we keep `install.sh` after the publish lands

Even with crates.io publishing working, a fresh `cargo install keyhog`
on Linux source-builds Hyperscan and the GPU stack — ~3 minutes on a
hosted runner. The prebuilt binary from `install.sh` is ~20 MB
downloaded in ~1 s, signed with minisign, and warm-starts in 500 ms.
`install.sh` stays the recommended path; `cargo install` is for
developers who want a source build.

## What does NOT publish

- `crates/cli` is the workspace package named `keyhog`. The composite
  GitHub Action (`.github/actions/keyhog/`) and the docs site live
  outside the publishable surface.
- `vendor/vyre/` is excluded from the workspace already
  (`exclude = ["vendor/vyre", "vendor/shared"]` in `Cargo.toml`); no
  vyre crate is published from this checkout.
- Examples and benches don't ship in the published tarball
  (`exclude` + `include` directives in each crate's `Cargo.toml`).

## Stale `keyhog 0.2.1` on crates.io

The 0.2.1 version predates the vyre integration and the current
detector corpus. It works (technically) but reports stale detector
counts, missing decoders, and lacks the precision fixes from 0.3 →
0.5.37. Options:

- **Leave it.** Anyone running `cargo install keyhog` gets 0.2.1, which
  is functional but five versions behind. README + docs already direct
  users to `cargo install --git`.
- **Yank 0.2.1.** Stops new `cargo install keyhog` from picking it up;
  the crate's page stays. Requires explicit ownership + confirmation
  per CLAUDE.md "Don't take risky/destructive actions without
  confirmation."
- **Publish 0.5.37** once vyre is on crates.io. This is the canonical
  fix.

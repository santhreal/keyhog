# `vendor/` — read-only reference snapshots (MC-11 policy)

**Nothing in the keyhog build compiles anything under `vendor/`.** These are
frozen reference copies of upstream crates, kept on disk for offline diffing and
local inspection only. They are NOT a second build path, NOT a fallback, and NOT
a source of truth.

## The contract

1. **Never edit a `vendor/<dep>` tree.** Edits are *inert*: the build resolves
   the dependency from the registry or a live-source path override (see below),
   never from `vendor/`, so any change here is silently clobbered on the next
   re-vendor and never reaches a binary. To change a vendored dependency, edit
   its **source repo** and publish a release that flows back to the consumer.
2. **Expect drift.** Because nothing builds these, they *will* fall behind the
   real dependency. That is acceptable precisely because they are reference-only.
   Do not trust a `vendor/` tree to reflect what ships — read the live source or
   the pinned registry version instead.
3. **Excluded from the workspace.** Each vendored crate that carries its own
   `Cargo.toml` is listed in the root `Cargo.toml` `[workspace] exclude` so it
   can never be pulled in as a member, even under a future glob-members change.

## The trees

### `vendor/vyre/`
Snapshot of the vyre matching engine (GPU/SIMD). The keyhog build resolves the
`vyre*` crates from a **live-source path override** — `[workspace.dependencies]`
in the root `Cargo.toml` points each at
`../../libs/performance/matching/vyre/<crate>`, pinned `=0.6.1`, because the
megakernel path consumes the unreleased
`vyre_libs::scan::build_regex_dfa_unanchored` /
`scan_presence_by_region` (see `docs/GPU_DETECTION_REWRITE.md`). That override is
a deliberate build config, not a silent fallback. The **source of truth is the
live tree** at `/media/mukund-thiru/SanthData/Santh/libs/performance/matching/vyre`
(remote `santhsecurity/vyre`, branch `main`) — never this snapshot. Once the
needed APIs ship in a published vyre release, the path override is replaced by a
plain `version = "=0.6.x"` registry pin and this snapshot can be dropped.

### `vendor/bogon/`
Snapshot of the bogon / non-public-IP classifier. It is **orphaned**: keyhog's
live SSRF policy uses the in-tree module `crates/verifier/src/bogon.rs`
(`keyhog_verifier::bogon::ip_addr_is_bogon`), composed with the fast
reserved-range checks in `keyhog_verifier::ssrf`. No build path references this
vendored copy. Kept only as a historical reference for the classifier table.

## Precedent: how a vendored tree is retired

`codewalk` used to live under `vendor/codewalk` for a Windows-stable
symlink-identity fix. When that fix shipped in `codewalk =0.2.5` (2026-05-03),
the vendored tree was deleted and the dependency became a registry pin (see the
comment near `codewalk` in the root `Cargo.toml`). `vendor/vyre` follows the same
path once its megakernel APIs are published. Dropping a snapshot is a deliberate,
operator-approved cleanup — do not delete one as a side effect of other work.

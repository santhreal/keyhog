# Local patches applied on top of the vendored vyre snapshot

`scripts/vendor-vyre.sh` replaces each `vyre-*` subdirectory **wholesale**
on every refresh. Anything edited in-place inside one of those subtrees
will be silently obliterated the next time the script runs.

This file is the ledger of those in-tree patches so they can be
re-applied (or, better, upstreamed) after every vendor refresh. Audit
with `git log -- vendor/vyre/vyre-*/` and append new entries here
whenever you commit a hand-edit inside the vendor tree.

## Refresh workflow

1. **Inventory before** — `git diff <last-vendor-commit>..HEAD -- vendor/vyre/`
   should equal the list below.
2. **Run** `scripts/vendor-vyre.sh --ref <new-upstream-sha>`.
3. **Re-apply** each patch below, prefer upstreaming over re-patching.
4. **Validate** — `cargo test -p keyhog-scanner` + the macOS lane.
5. **Update** the `Vendored:` header below with the new upstream SHA.

> Vendored: cc0c480d14 (2026-05-21, "vyre-libs(classic_ac): add
> use_subgroup_coalesce selector for CUDA compat")

---

## Active patches (must survive vendor refresh)

### 1. macOS / Windows `GpuStream` PhantomData fix

- **Files**: `vendor/vyre/vyre-runtime/src/lib.rs`
- **Commits**: `a6db92e` ("ci: cuda opt-in, lfs:true for fmt,
  PhantomData<'a> for non-Linux GpuStream"), follow-up in `641f2b1`.
- **Why it exists**: `GpuStream<'a>` carries a `uring` field that is
  Linux-only. On macOS / Windows the lifetime parameter becomes
  unused, which the compiler rejects. Patch adds:
  ```rust
  #[cfg(not(target_os = "linux"))]
  _phantom: std::marker::PhantomData<&'a ()>,
  ```
- **Loss symptom**: `cargo build` on macOS / Windows fails with
  "parameter `'a` is never used". The CI macOS lane catches this if
  the patch is removed.

### 2. Megakernel planner hardening (bitmap fusion + barriers + provenance)

- **Files**: `vendor/vyre/vyre-runtime/src/megakernel/planner/barriers.rs`
  and adjacent planner files under `vendor/vyre/vyre-runtime/src/megakernel/`.
- **Commits**: `afd8eaf` ("vendor/vyre: bitmap-accelerated fusion
  selection and planner hardening"), `641f2b1` ("fix(vyre): repair
  synced planner code and add adversarial corpus tests").
- **Why it exists**: the upstream planner had latent bitmap / barrier
  bugs that surfaced once keyhog wired vyre into the multi-detector
  GPU scan path. Local repairs are not yet upstreamed.
- **Loss symptom**: megakernel-path scans either dispatch the wrong
  kernel order, miss findings, or hit assertion failures in
  `vyre-runtime/src/megakernel/dispatch.rs`. Smoke test: run
  `keyhog scan /benchmark-harness/repos/django --backend gpu` and
  compare finding counts vs `--backend simd`.

### 3. `vyre-aot/Cargo.toml` local dependency trimming + version bumps

- **Files**: `vendor/vyre/vyre-aot/Cargo.toml`
- **Commit**: `3319bb2` ("build: refresh vendored vyre to 0.4.2
  (cc0c480d14) + lint/fmt sweep") and subsequent maintenance.
- **Why it exists**: keyhog only consumes a subset of vyre-aot's
  upstream feature surface. Local Cargo.toml drops unused deps that
  would otherwise pull wgpu/CUDA backends into every keyhog build.
- **Loss symptom**: workspace build time regresses by 60-90s on cold
  rebuild; `cargo deny check` flags new MPL-2.0 / duplicate-version
  warnings.

---

## Patches considered but rejected

(none yet — add entries here when a tempting in-tree edit is decided
against in favor of an upstream PR.)

---

## What does NOT need re-applying

Anything outside `vendor/vyre/vyre-*/` survives the refresh because
the script only manages `vyre-*` subdirs. The keyhog-local
`vendor/vyre/Cargo.toml` workspace manifest, `vendor/vyre/AGENTS.md`,
`vendor/vyre/weir/`, `vendor/vyre/shared/`, and this `PATCHES.md` are
all safe.

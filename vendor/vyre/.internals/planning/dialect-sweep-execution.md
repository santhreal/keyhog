# Dialect Sweep — One Gemini, 16 Commits, ~30 min

**Status:** execution plan. Hand to Gemini 3.1-pro in Antigravity once the
current 8-phase plan has landed its remaining phases.

**Rule zero:** no parallel writers on this workspace during the sweep.
Every past partial migration has reverted. One agent, one branch, 16
atomic commits that all must land.

**Folded in:** persistent GPU buffers (formerly "D3", which the prior
standalone codex attempt failed — landed only a cosmetic test-helper
rename) now lives as **C5b** atop the vyre-wgpu reshape in C5. The
zero-copy Cat C intrinsics (`io.dma_from_nvme`, `mem.zerocopy_map`,
etc.) land as **C5c** right after, consuming the `GpuBufferHandle`
type C5b introduces. Both additions exercise the dialect architecture
as it lands instead of fighting the old `OpSpec::intrinsic` allocator
path — which is why they reverted every time they were attempted
standalone.

---

## Commits

### C1 — Foundation types (dual-path mode)

Add alongside the existing `OpSpec` — do NOT delete anything yet.

- `vyre-core/src/dialect/op_def.rs` — `OpDef`, `Signature`, `TypedParam`,
  `AttrSchema`, `AttrType`, `Category::{A, B, C}`.
- `vyre-core/src/dialect/lowering.rs` — `LoweringTable` with fields
  `naga_wgsl: Option<fn(&Ctx) -> naga::Module>`, `naga_spv`, `ptx`,
  `metal_ir`, and the required `cpu_ref`.
- `vyre-core/src/dialect/dialect.rs` — `Dialect { id, version, ops,
  validator, backends_required }` + `DialectId: u16`, `InternedOpId: u32`.
- `vyre-core/src/dialect/registry.rs` — global `DialectRegistry` with
  `intern_op(dialect, op) -> InternedOpId`, `lookup(InternedOpId) ->
  &OpDef`, `get_lowering(op, target) -> fn`.
- `vyre-core/src/dialect/interner.rs` — string interner backed by FxHashMap.
- `vyre-core/tests/dialect_types.rs` — smoke test that builds a fake
  dialect with one op and round-trips an InternedOpId.

**Verify:** `cargo check -p vyre && cargo test -p vyre --test dialect_types`.
**Commit:** `C1: dialect foundation types (OpDef + LoweringTable + registry)`.

---

### C2 — Migrate Cat C intrinsics (the flaw fix)

Every `OpSpec::intrinsic(..., wgsl_only, ...)` + sibling `.wgsl` asset
today. List by ID:

- `workgroup.queue_fifo`
- `workgroup.queue_priority`
- `workgroup.stack`
- `workgroup.hashmap`
- `workgroup.union_find`
- `workgroup.typed_arena`
- `workgroup.string_interner`
- `workgroup.state_machine`
- `workgroup.visitor_walk`
- Plus every codec formatter under `ops/decode/` that writes raw WGSL.

For each:
1. Read the current `.wgsl` asset.
2. Reconstruct it as a `naga::Module` builder function in a new `lowering`
   submodule next to the op's spec.rs. Same bindings, same entry point,
   same workgroup size, same SSA structure.
3. Register via `OpDef { category: Category::Intrinsic, lowerings: LoweringTable {
   naga_wgsl: Some(build_naga_module), cpu_ref, ..Default::default() },
   ... }`.
4. Invoke the migration shader-parity test (see Claude's C2 tooling
   below) with the op ID; it asserts byte-exact `naga::back::wgsl::
   write_string` output matches the archived `.wgsl` asset.
5. Delete the `.wgsl` asset.

**Verify:** `cargo test -p vyre --test migration_shader_parity` —
every migrated op matches its original shader byte-for-byte.
**Commit:** `C2: migrate Cat C intrinsics to naga::Module builders
(shader-parity verified)`.

---

### C3 — Migrate primitive Cat A ops

- `primitive.math.*` (add, sub, mul, div, mod, abs, neg, min, max, ...)
- `primitive.bitwise.*` (and, or, xor, not, shl, shr, rotl, rotr, ...)
- `primitive.compare.*` (eq, ne, lt, le, gt, ge)
- `primitive.logical.*` (and, or, nand, nor, xor, not, literal_true,
  literal_false)
- `primitive.float.*` (fabs, fsqrt, fmin, fmax, fmul, fadd, ...)

Each becomes an `OpDef` with `Category::Intrinsic` and a `LoweringTable` whose
`naga_wgsl` builder wraps the existing IR lowering path. The composed
Expr tree is unchanged.

**Verify:** `cargo test -p vyre --test kat_parity` — all 82 KATs still
pass. Known-failures list unchanged.
**Commit:** `C3: migrate primitive.* Cat A ops to OpDef`.

---

### C4 — Remaining built-in ops

- `atomics.*`
- `compression.*` (gzip_decompress, zlib_decompress, deflate_decompress,
  zstd, lz4)
- `hash.*` (sha256, blake3, entropy)
- `string_matching.*` (aho_corasick_scan, dfa_scan, regex_scan)
- `decode.*` (base64, base32, hex, hex_decode_strict, url_percent,
  utf8_validate, unicode)

Each converted to `OpDef`. Cat assignment per op:
- Cat A when composed from other vyre ops
- Cat B when backend-specific behavior varies
- Cat C when hardware intrinsic

**Verify:** `cargo test -p vyre` full unit suite green.
**Commit:** `C4: migrate remaining built-in ops to OpDef`.

---

### C5 — vyre-wgpu consumes LoweringTable

Drop every `OpSpec::intrinsic` read path. Backend walks `OpDef ->
LoweringTable.naga_wgsl` to build the `naga::Module`, then emits via
`naga::back::wgsl::write_string`. Register
`supports_dialect("core@1", "math@1", "io@1", "workgroup@1", "pattern@1")`
in BackendRegistration.

**Verify:** `cargo test -p vyre-wgpu` green.
**Commit:** `C5: vyre-wgpu dispatches via LoweringTable (drop wgsl_only
path)`.

---

### C5b — Persistent GPU tier (D3, folded into sweep)

Prior codex attempts at D3 standalone reverted because they had to fight
the old `OpSpec::intrinsic` allocation path. Now that C5 has just
reshaped vyre-wgpu around `LoweringTable`, persistent buffers slot in
cleanly on top.

- `vyre-wgpu/src/buffer/handle.rs` — `GpuBufferHandle` wrapping
  `Arc<wgpu::Buffer>` + byte length + element count + `BufferUsages`.
  Constructors: `upload(&device, &queue, &[u8], usage)`,
  `alloc(&device, len, usage)`, `readback(&device, &queue, &mut Vec<u8>)`.
  `Clone` is cheap (Arc).
- `vyre-wgpu/src/buffer/pool.rs` — `BufferPool { device, queue,
  free: Mutex<Vec<FreeEntry>>, stats }`. `acquire(len, usage)` returns a
  power-of-two-rounded buffer from the pool or allocates fresh.
  `release(handle)` returns it. LRU eviction once VRAM retention > 1 GiB.
- `vyre-wgpu/src/pipeline.rs` — add persistent entry point alongside
  the legacy `dispatch(&[u8])`:
  ```rust
  pub fn dispatch_persistent(
      &self,
      inputs: &[GpuBufferHandle],
      outputs: &mut [GpuBufferHandle],
      params: Option<&GpuBufferHandle>,
      workgroups: [u32; 3],
  ) -> Result<(), BackendError>;
  ```
  BindGroup cached by `(pipeline_hash, binding_signature)` for reuse
  across repeated dispatches with the same handle layout. Batching API
  `dispatch_persistent_batched(&[DispatchItem])` collapses many
  dispatches into one `queue.submit`.
- Fold the DFA double round-trip: the match-ops dispatch path currently
  does count-matches → readback → alloc → extract-matches → readback.
  Collapse to a single submission that allocates output sized to
  `workload × max_matches_per_element` (with an atomic-append overflow
  check; re-dispatch with doubled capacity on overflow) and does one
  readback.
- Legacy `dispatch(&[u8])` becomes a thin wrapper that uploads on
  demand, so existing callers keep working.
- `vyre-wgpu/tests/persistent_dispatch.rs`:
  (a) compile XOR, upload input once, dispatch 1000×, assert allocation
      count ≤ (1 input + 1 output + 1 params + 1 readback + pool reuse
      overhead) via pool stats;
  (b) assert BindGroup cache hit ratio ≥ 99% after first dispatch;
  (c) change one input bit → cache miss;
  (d) oversized pool → LRU eviction honored.

**Verify:** `cargo test -p vyre-wgpu --test persistent_dispatch` on
the RTX 5090. `cargo clippy -p vyre-wgpu --all-targets -- -D warnings`
clean.
**Commit:** `C5b: persistent GPU tier — GpuBufferHandle + BufferPool + BindGroup cache (folds D3)`.

---

### C5c — Cat C IO intrinsics (depend on C5b's GpuBufferHandle)

Add a fresh `io` dialect at `vyre-core/src/dialect/io/`:

- `io.dma_from_nvme(fd: RawFd, offset: u64, length: u64) -> GpuBufferHandle`
  — GPUDirect Storage / io_uring→VRAM path.
- `io.write_back_to_nvme(handle: GpuBufferHandle, fd: RawFd, offset: u64)`
  — reverse direction.
- `mem.zerocopy_map(fd: RawFd) -> GpuBufferHandle` — IOMMU + PCIe BAR
  mapping; userspace writes land directly in VRAM.
- `mem.unmap(handle: GpuBufferHandle)` — paired teardown.

Every op registers an `OpDef` whose `LoweringTable` has all target
fields `None` plus a `cpu_ref` that returns
`BackendError::Unsupported`. Backend opt-in is per-backend: a Linux +
Nvidia wgpu backend registers `supports_op("io.dma_from_nvme")` via
inventory with a real lowering fn. The default wgpu backend does not.
Capability negotiation (Law C) surfaces the unsupported-op error
before dispatch — the consumer pattern is:

```rust
if backend.supports("io.dma_from_nvme") {
    let buf = backend.dispatch(io::dma_from_nvme(fd, 0, 50 << 30))?;
    scan(buf);
} else {
    // userspace upload fallback
}
```

No io_uring plumbing yet — just the op signatures and capability
skeleton. An opt-in implementation crate (similar to
`vyre-dialect-crypto`) can land in a follow-up and inventory-register
the real fn pointers without touching vyre-core.

**Verify:** `cargo test -p vyre` passes. A Program calling
`io.dma_from_nvme` against a non-supporting backend fails Law-C
validation cleanly (structured error, no panic).
**Commit:** `C5c: io dialect — Cat C zero-copy intrinsics (backend opt-in)`.

---

### C6 — vyre-reference same treatment

Reference interpreter invokes `LoweringTable.cpu_ref(...)` instead of
the legacy `structured_intrinsic_cpu` path.

**Verify:** `cargo test -p vyre-reference && cargo test -p vyre --test
kat_parity`.
**Commit:** `C6: vyre-reference dispatches via LoweringTable.cpu_ref`.

---

### C7 — Expr/Node fully open, variant-match removed

Every `match expr { ... }` and `match node { ... }` in vyre-core,
vyre-reference, vyre-wgpu gains a real `Opaque(_) => ...` arm that
forwards to the trait-object's own method. Zero `_ => unreachable!()`
left. Interpreter dispatches via `OpDef` lookup, not variant match.

This closes F4 (generic interpreter) and D2 (open IR) in one move.

**Verify:** full workspace test; zero clippy warnings on `unreachable!`
or `unimplemented!`.
**Commit:** `C7: open Expr/Node — every match site handles Opaque; interpreter dispatches through OpDef`.

---

### C8 — Backend trait split (F8)

```rust
trait Executable { fn execute(...) -> ...; }
trait Compilable { type BackendIR; fn compile(...) -> Self::BackendIR; }
trait Streamable { fn stream_in(...); fn stream_out(...); }
trait Backend: Executable {}  // legacy blanket impl
```

**Verify:** backends compile; existing callers work via blanket.
**Commit:** `C8: Backend split into Executable/Compilable/Streamable`.

---

### C9 — Progressive lowering (F10)

`vyre-wgpu` introduces `WgpuIR` (naga::Module + bindings). Lowering:
`Program → WgpuIR → WGSL text`. Each step testable in isolation. Same
shape reused when SPIR-V / PTX backends land.

**Verify:** `cargo test -p vyre-wgpu`. Integration test exercises each
lowering stage independently.
**Commit:** `C9: Progressive lowering (Program → BackendIR → Target)`.

---

### C10 — Wire format rev 3 (F3)

- `SCHEMA_VERSION: u32 = 3;`
- Program encodes `[magic][schema_version][dialect_manifest][ops...]`.
- `dialect_manifest` = `Vec<(dialect_name, semver)>` so a Program
  records its dialect footprint.
- Op payload format: `(u16 dialect_id, u32 op_id, u32 attr_blob_len,
  attr_blob_bytes)`. Decoder interns `(dialect_name, op_name) ->
  InternedOpId` via the global registry.
- `WireError::VersionMismatch { expected, found }`.
- `WireError::UnknownDialect { name, requested_version }`.
- Round-trip test: build a program, encode, decode, compare. Assert
  dialect manifest survives.

**Verify:** `cargo test -p vyre --test wire_format_rev3`.
**Commit:** `C10: wire format rev 3 — schema version + dialect manifest + interned op handles`.

---

### C11 — Delete legacy + Law B shader-asset extension

- Delete `OpSpec` struct + `OpSpec::intrinsic` + `wgsl_only` fn + every
  `structured_intrinsic_cpu` call site + `IntrinsicDescriptor`.
- Delete every `.wgsl`, `.spv`, `.ptx`, `.metal` asset file under
  `vyre-core/src/ops/**` and `vyre-wgpu/src/ops/**`.
- Extend `scripts/check_no_string_wgsl.sh` (and rename to
  `check_no_shader_assets.sh`) to fail if ANY `.wgsl/.spv/.ptx/.metal`
  file exists under `src/ops/**` or `src/dialect/**`.
- Update `scripts/rebuild_status.sh` dashboard to show the new law.

**Verify:** `bash scripts/rebuild_status.sh` — all laws green. `cargo
check --workspace` — zero errors. No legacy type referenced anywhere.
**Commit:** `C11: delete OpSpec + shader asset files; Law B bans shader assets under src/ops`.

---

### C12 — TOML dialect loader + reference external dialect

- `vyre-core/src/dialect/toml_loader.rs` — reads a dialect.toml +
  ops/*.toml and produces a `Dialect` registration.
- Env var `VYRE_DIALECT_PATH=dir1:dir2` searched at startup.
- Parse errors are structured: `DialectLoadError::UnknownAttrType`,
  `SignatureMismatch`, etc., with "Fix: ..." messages.
- A runtime-only dialect can ship ops whose lowering is a Rust
  function pointer found via `(dialect_name, op_name) -> fn_ptr` lookup
  into the main inventory table.
- New sibling crate (NOT under libs/performance/matching/vyre —
  elsewhere in the workspace) that inventory-submits a
  `dialect-crypto` with `crypto.hmac_sha256`, `crypto.md5`,
  `crypto.argon2id`. Integration test loads it, runs one op through
  vyre-wgpu, verifies output.

**Verify:** integration test passes; `VYRE_DIALECT_PATH=/tmp/fake
cargo test` loads a TOML-declared dialect from disk.
**Commit:** `C12: TOML dialect loader + external dialect-crypto reference crate`.

---

### C13 — Documentation

- `THESIS.md` — sections "Dialects, ops, lowerings" + "Extending vyre:
  the 5-minute new-op path".
- `ARCHITECTURE.md` — updated crate topology (still one vyre crate
  plus satellites), dialect registration flow diagram, wire format
  rev 3 spec, Law list updated.
- `VISION.md` — millions-of-ops scenario described concretely.
- `docs/dialect-cookbook.md` — copy-paste recipes: "add an op",
  "add a dialect", "add a backend".
- Per-dialect READMEs (`core`, `math`, `io`, `workgroup`, `pattern`)
  with op tables.
- `CHANGELOG.md` entry under Unreleased noting the dialect migration.

**Verify:** `RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps`
clean.
**Commit:** `C13: docs for dialect architecture`.

---

### C14 — Close the parity gaps

- Fix `primitive.bitwise.shl[1]` engine drift (shl lowering bug).
- Register the 7 missing-program KATs (primitive.math.avg_floor,
  primitive.math.wrapping_neg, primitive.logical.{and,nand,or,nor,xor})
  now that their dialect entries exist.
- Empty `KNOWN_FAILURES` in `vyre-core/tests/kat_parity.rs`.
- Run `bash scripts/publish-dryrun.sh` → READY TO PUBLISH.

**Verify:** `cargo test -p vyre --test kat_parity` 82/82 green with
zero known failures. `bash scripts/publish-dryrun.sh` green.
**Commit:** `C14: close parity gaps — shl fix + 7 KAT ops registered + publish gate green`.

---

## What Claude does while Gemini sweeps (not watching)

The dispatch is serial — one Gemini agent — but Claude is NOT idle.
Concrete parallel work, **zero overlap with Gemini's edit surface**:

1. **Pre-write `tests/migration_shader_parity.rs`** before Gemini
   starts. The test walks `src/ops/**/*.wgsl` (pre-migration snapshot
   in `target/pre-sweep-shaders/`), invokes the op's new naga-builder,
   diffs `naga::back::wgsl::write_string` output byte-for-byte.
   Without this tool, C2 is unverifiable.

2. **Pre-write `scripts/check_no_shader_assets.sh`** so C11 has it
   ready to enable.

3. **Pre-write `scripts/check_dialect_coverage.sh`** — new law: every
   Cat C intrinsic in a dialect manifest must have at least one
   target-lowering populated. Gemini runs this during C5/C6 to
   verify.

4. **Snapshot current shader output** to `target/pre-sweep-shaders/`
   so C2's parity test has a reference. Single bash script, 5 min.

5. **Write the `vyre-dialect-crypto` scaffold** — Cargo.toml,
   skeleton lib.rs, one op signature (`crypto.hmac_sha256`). Gemini
   fills in the lowering during C12 but the skeleton is ready.

6. **Parallel perf work on OTHER libs** — codex-5505623d is on
   vyre-wgpu, Gemini is on vyre-core/vyre-reference/vyre-wgpu, so
   Claude works on:
   - `libs/performance/matching/matchkit/` — review and tidy the
     public surface against the soon-to-exist vyre OpDef API.
   - `libs/performance/matching/dfajit/` — same review.
   - `libs/performance/matching/simdsieve/` — same.
   - These crates will consume vyre as a dialect-hosting substrate
     once the sweep lands. Surface review now means their
     integration commit is clean.

7. **Review every commit as it lands.** 14 commits × ~2 min review
   each = ~30 min of review budget over the 30-min sweep. Look for:
   - Semantic bugs Gemini's grep didn't catch (off-by-one in attr
     schemas, missing inventory::submit! lines).
   - Accidental scope creep into `libs/performance/*` crates.
   - Any `unreachable!()` / `todo!()` / `#[allow(dead_code)]` slip.

8. **Repair if needed, don't redispatch.** Per CLAUDE.md fix-agent
   pattern: if Gemini's commit has a small breakage, Claude edits
   the fix directly and commits on top, Gemini continues from there.
   Never restart the whole sweep.

---

## What happens if the sweep stalls mid-commit

If commit N fails CI or introduces a visible regression:
- Claude investigates (not Gemini — Gemini stays on-task).
- Either (a) Claude lands a fix commit and Gemini resumes at N+1,
  or (b) the sweep is paused and we decide.
- Never revert past commits. Fix forward. The 14-commit train is
  atomic at the *branch* level, not the commit level — we merge the
  whole branch or we don't.

---

## Success criteria

- `cargo check --workspace` zero errors.
- `cargo test --workspace` green (including the new
  `dialect_types`, `migration_shader_parity`, `wire_format_rev3`,
  `kat_parity` 82/82 no KNOWN_FAILURES, `persistent_dispatch`).
- `bash scripts/rebuild_status.sh` — every law green including the
  new `check_no_shader_assets.sh` and `check_dialect_coverage.sh`.
- `bash scripts/publish-dryrun.sh` — READY TO PUBLISH.
- `rg 'OpSpec::intrinsic|wgsl_only' --type rust` returns zero
  matches.
- `find . -name '*.wgsl' -path '*/src/ops/*'` returns zero files.
- An external crate can inventory-register a new dialect and its
  ops run through vyre-wgpu without touching vyre-core source
  (`vyre-dialect-crypto` proves this).
- A Program calling `io.dma_from_nvme` fails cleanly against a
  non-supporting backend via Law-C structured error (no panic), and
  a backend that opts in via inventory-registered lowering succeeds.
- `dispatch_persistent` allocates O(1) buffers across a 1000-iter
  dispatch loop; BindGroup cache hit ratio ≥ 99%.

Merge branch → main only when every item on this list is green.

# Sweep Plan — Gemini A: Ops & Dialects

**Agent:** Gemini 3.1-pro, launched in Antigravity, unlimited.
**Peer:** Gemini B is running in parallel on a different tree (backends +
perf). Claude is running the substrate (types, workspace-wide match rewrite,
wire format, deletion, docs, parity). You do not talk to B; you read the
git log for handshake points.

**Scope lock:**
- You may edit: `vyre-core/src/ops/**`, `vyre-core/src/dialect/<stdlib>/**`,
  `vyre-wgpu/src/ops/**`, `vyre-dialect-crypto/**`, `rules/kat/**` (only to
  register new primitive programs).
- You may NOT edit: `vyre-core/src/ir/**`, `vyre-core/src/backend/**`,
  `vyre-core/src/optimizer/**`, `vyre-core/src/runtime/**`,
  `vyre-core/src/dialect/{op_def,lowering,dialect,registry,interner}.rs`
  (these are Claude's substrate files), `vyre-wgpu/src/{pipeline,buffer,
  runtime,engine,lowering,backend}/**` (these are Gemini B's), or anything
  in `vyre-reference/**` or `vyre-primitives/**`.

**Handshake — when to start each step:**
- **Start immediately.** You own step A-B0 (dialect foundation types)
  — there is no pre-handshake. Launch as soon as you get this plan.
- **After A-B0 lands:** Gemini B can start B-B1, and Claude starts
  A-C1b onwards. All three agents proceed in parallel.
- **Step A-C7 pause:** after your A-B3 commit lands, if you are ready
  to start A-B4 (stdlib dialect reorg) you MAY — but your A-B4 must
  not delete any file Gemini B still imports. Use a
  `pub use vyre::ops::*` compatibility shim at the old path until
  Claude's A-C7 lands the workspace-wide import rewrite.

**Commit prefix:** every commit subject must begin with `A-B<step>:` so
Claude and Gemini B can find your commits in the log. `A` means "Gemini A",
`B<n>` is the step in this doc.

**Rules of engagement:**
- Direct to main. No branches, no worktrees.
- Narrow `cargo check -p vyre` during iteration. Full workspace check only
  at step end.
- No `todo!()`, `unimplemented!()`, `panic!("not implemented")`,
  "documented limitation" comments, or test-weakening.
- No `#[cfg(not(feature="gpu"))]` fallbacks — GPU is always present (RTX 5090).
- Every doc change you make lands in your commit; don't leave stale prose.

---

## Canonical op directory layout (MANDATORY — Claude's A-C11c enforces this)

Every op you migrate or create in A-B1 through A-B4 MUST land under
`vyre-core/src/dialect/<dialect>/<op>/` with this exact file set:

```
vyre-core/src/dialect/<dialect>/<op>/
├── op.rs            # OpDef construction + inventory::submit! registration
├── cpu_ref.rs       # CPU reference implementation (fn CpuRef signature)
├── wgsl.rs          # naga::Module builder for WGSL target
├── spv.rs           # naga::Module builder for SPIR-V (if lowering present)
├── ptx.rs           # PTX builder (rare; future)
├── metal.rs         # Metal builder (rare; future)
├── tests.rs         # unit tests + KAT driver for this op
└── README.md        # one paragraph: what this op does
```

Rules:
- `op.rs` is ≤ 100 lines. It declares the `OpDef` and submits it to
  inventory. Nothing else.
- `cpu_ref.rs` is the fn ptr named in `LoweringTable::new(cpu_ref)`.
- `wgsl.rs` exports `pub fn build_<op>_naga(ctx: &LoweringCtx) -> naga::Module`.
- `tests.rs` has `#[test]` cases covering the op's algebraic laws
  (property tests auto-generate more in A-B4c).
- `README.md` is 1 paragraph: what the op does + a `## Laws` subsection
  listing the algebraic laws it obeys.
- No `utils.rs`, `helpers.rs`, `common.rs`, `misc.rs`, `shared.rs`
  inside op directories. If you need a helper, put it one level up at
  `dialect/<dialect>/_support/helper_name.rs` — and the underscore
  prefix means "not a publicly visible op".

Dialect directory layout:
```
vyre-core/src/dialect/<dialect>/
├── mod.rs           # ≤ 80 lines, declares ops + DIALECT: Dialect = ...
├── README.md        # table of every op in this dialect
├── <op1>/           # canonical shape above
├── <op2>/
└── _support/        # optional; dialect-private helpers (underscore prefix)
```

`mod.rs` is trivial: `pub mod add; pub mod sub; ...` + the
`DIALECT: Dialect` constant with its inventory::submit. If it's doing
real work, move that work into a named sub-file.

Depth cap: max 4 levels from `vyre-core/src/`. `src/dialect/math/add/wgsl.rs`
is 4 levels, fine. `src/dialect/math/binary/arithmetic/add/wgsl.rs` is
5 levels, banned.

Every dialect directory and every op directory gets a README. A-C11c
has `check_readmes.sh` gating this.

---

## Step A-B0 — Dialect foundation types (you land this first, unblocks everyone)

You own the types. No waiting on anyone.

### Files to create under `vyre-core/src/dialect/`

- `mod.rs` — re-exports the public surface.
- `op_def.rs` — `OpDef`, `Signature`, `TypedParam`, `AttrSchema`,
  `AttrType { U32 | I32 | F32 | Bool | Bytes | String | Enum(&'static [&'static str]) | Unknown }`,
  `Category { A, B, C }`.
- `lowering.rs` — `LoweringCtx<'a>`, `NagaBuilder`, `SpirvBuilder`,
  `PtxBuilder`, `MetalBuilder`, `CpuRef`, `LoweringTable` (with
  `cpu_ref` required, all target builders Option, constructor
  `LoweringTable::new(cpu_ref)`).
- `dialect.rs` — `Dialect { id, version, parent, ops, validator,
  backends_required }`, `default_validator`, `BackendRegistration`,
  inventory::collect! for `OpDefRegistration`, `DialectRegistration`,
  `BackendRegistration`.
- `registry.rs` — `DialectRegistry` with `intern_op`, `lookup`,
  `get_lowering`, `coverage_matrix`, `load_runtime`. `Target` enum
  (Wgsl, Spirv, Ptx, MetalIr, CpuRef).
- `interner.rs` — `InternedOpId(u32)`; interner backed by
  `once_cell::OnceLock<Mutex<StringInterner>>`.

### Placeholder types for future targets

`PtxModule { asm: String, version: u32 }` and
`MetalModule { ast: Vec<u8>, entry: String }` as small structs (not
empty enums) so external crates that implement those targets don't
break when they land.

### Wire into `vyre-core/src/lib.rs`

Add `pub mod dialect;` at the appropriate spot. Follow the `automod`
convention the crate uses; don't hand-roll if automod already walks the
directory.

### Tests

`vyre-core/tests/dialect_types.rs` — smoke:
- Construct a fake `OpDef` with `cpu_ref` that returns bytes.
- Register via test-only `inventory::submit!`.
- `DialectRegistry::global().intern_op("test.noop")` returns stable
  `u32` across two calls.
- `get_lowering(id, Target::CpuRef)` returns `Some`.

### Verification

- `cargo check -p vyre` → 0 errors.
- `cargo test -p vyre --test dialect_types` → passes.
- `rg 'mod dialect' vyre-core/src/lib.rs` → one match.

### Commit

`A-B0: dialect foundation types (OpDef + LoweringTable + DialectRegistry + InternedOpId + Diagnostics surface)`

After this lands, Gemini B starts its B-B1 and Claude starts A-C1b.
You proceed to A-B1 without waiting on anyone.

---

## Step A-B1 — Migrate Cat C intrinsics to naga::Module builders

Every `OpSpec::intrinsic(..., wgsl_only, ...)` + sibling `.wgsl` asset file
becomes an `OpDef` with a `LoweringTable.naga_wgsl` builder function.
Sibling `.wgsl` asset files are deleted.

### Ops to migrate (exhaustive list)

Under `vyre-core/src/ops/`: every workgroup queue, stack, hashmap,
union-find, arena, string-interner, state-machine, and visitor-walk
intrinsic, plus every file under
`vyre-core/src/ops/security_detection/catalog/*.wgsl`
  (detect_ssrf, detect_hex_run, detect_jwt, detect_obfuscated_js, detect_xxe,
  detect_command_injection, detect_packed_binary, detect_sql_injection,
  detect_xss, detect_lfi, detect_email, detect_path_traversal, detect_uuid,
  detect_pem_block, detect_ipv6, detect_rfi, detect_high_entropy_window,
  detect_ipv4, detect_base64_run, file_magic_detect). 20+ security
  detectors, each currently shipped as a hand-typed WGSL file.
- every decode/codec op that currently has a hand-typed shader:
  the decode/codec/format.rs path Gemini previously flagged as a blocker.
  Enumerate via `find vyre-core/src/ops -name "*.wgsl" -print` — there are
  91 total and every one of them is owned by you in this step.

### Per-op procedure (canonical layout, per the top of this doc)

1. Create the op directory at `vyre-core/src/dialect/<dialect>/<op>/`
   with the six canonical files (`op.rs`, `cpu_ref.rs`, `wgsl.rs`,
   `spv.rs` if present, `tests.rs`, `README.md`).
2. Read the existing `.wgsl` asset and reconstruct it as a
   `naga::Module` builder function in `wgsl.rs`. Use `naga::Module`,
   `naga::Handle<Expression>`, `naga::Handle<Statement>`,
   `naga::Function`, `naga::EntryPoint`, `naga::GlobalVariable`.
   Follow `vyre-wgpu/src/lowering/naga_emit.rs` as a template.
3. Register the op in `op.rs`:
   ```rust
   inventory::submit! {
       vyre::dialect::OpDefRegistration::new(|| OpDef {
           id: "workgroup.queue_fifo",
           dialect: "workgroup",
           category: Category::Intrinsic,
           signature: Signature { /* typed from INPUTS/OUTPUTS */ },
           lowerings: LoweringTable {
               naga_wgsl: Some(build_queue_fifo_naga),
               cpu_ref: cpu_queue_fifo,
               ..LoweringTable::empty()
           },
           laws: &[],
           ..Default::default()
       })
   }
   ```
4. Invoke `migration_shader_parity` for this op:
   ```rust
   inventory::submit! {
       vyre::test_migration::MigrationEntry {
           op_id: "workgroup.queue_fifo",
           snapshot_path: "target/pre-sweep-shaders/<flattened>.wgsl",
           emit: || {
               let module = build_queue_fifo_naga(&LoweringCtx::default());
               let info = naga::valid::Validator::new(
                   naga::valid::ValidationFlags::all(),
                   naga::valid::Capabilities::empty(),
               ).validate(&module).unwrap();
               naga::back::wgsl::write_string(
                   &module, &info, naga::back::wgsl::WriterFlags::empty()
               ).unwrap()
           },
       }
   }
   ```
5. Run `cargo test -p vyre --test migration_shader_parity -- --ignored`.
   Must pass. Byte-for-byte match (whitespace-normalized) against the
   archived `.wgsl` snapshot.
6. Delete the `.wgsl` asset file.

### Verification

- `cargo check -p vyre` → 0 errors.
- `cargo test -p vyre --test migration_shader_parity -- --ignored` → all
  migrated ops pass.
- `find vyre-core/src/ops -name "*.wgsl" | wc -l` decreases by the number
  of ops you migrated. At end of A-B1 the count should be ≤ the ops NOT
  in the step-A-B1 list above (there should be zero, actually — A-B1
  covers all 91).

### Commit

`A-B1: migrate every Cat C intrinsic to naga::Module builders (91 ops, zero shader assets remain)`

---

## Step A-B2 — Migrate primitive Cat A ops

All ops under `vyre-core/src/ops/primitive/` move to `OpDef`.

Domains:
- `primitive.math.*` (add, sub, mul, div, mod, abs, neg, min, max, avg_floor, wrapping_neg, ...)
- `primitive.bitwise.*` (and, or, xor, not, shl, shr, rotl, rotr, popcount, clz, ctz, byte_swap, ...)
- `primitive.compare.*` (eq, ne, lt, le, gt, ge, is_zero)
- `primitive.logical.*` (and, or, nand, nor, xor, not, literal_true, literal_false, implies)
- `primitive.float.*` (fabs, fsqrt, fmin, fmax, fmul, fadd, fsub, fdiv, fma, is_nan, is_inf, is_finite, ceil, floor, round, trunc)

### Per-op procedure

Cat A ops are composed from other vyre ops — they do not hand-build
naga::Modules. Their `LoweringTable.naga_wgsl` is the existing IR builder
(wraps the existing `Program`-returning function in an adapter that goes
through the generic lowering). Just register the `OpDef`; the lowering is
a one-line adapter.

### Register missing programs for known-absent KATs

The `kat_parity` test already surfaces 7 KATs with no registered program:
- `primitive.math.avg_floor`
- `primitive.math.wrapping_neg`
- `primitive.logical.and`
- `primitive.logical.nand`
- `primitive.logical.or`
- `primitive.logical.nor`
- `primitive.logical.xor`

Each either has existing implementation code that lost its registry entry,
or was never implemented. Implement + register each.

### Verification

- `cargo test -p vyre --test kat_parity` — 82/82 pass. `KNOWN_FAILURES`
  shrinks by 7 (the missing-program list becomes empty).
- `cargo check -p vyre` → 0 errors.

### Commit

`A-B2: migrate primitive Cat A ops + register 7 missing-program KATs`

---

## Step A-B3 — Migrate remaining built-in ops

All remaining `OpSpec` call sites under:
- `vyre-core/src/ops/atomics/**` — atomic.load, .store, .add, .sub, .and, .or, .xor, .min, .max, .exchange, .compare_exchange
- `vyre-core/src/ops/compression/**` — gzip_decompress, zlib_decompress, deflate_decompress, zstd, lz4
- `vyre-core/src/ops/hash/**` — sha256, blake3, entropy
- `vyre-core/src/ops/string_matching/**` — aho_corasick_scan, dfa_scan, regex_scan
- `vyre-core/src/ops/decode/**` — base64, base32, hex, hex_decode_strict, url_percent, utf8_validate, unicode

For each:
- Cat A if composed from other vyre ops → adapter lowering (same pattern
  as A-B2).
- Cat B if backend-specific behavior varies across targets → `LoweringTable`
  with per-target builders.
- Cat C if hardware intrinsic → follows the A-B1 pattern (naga::Module
  builder, `.wgsl` asset deleted if one still exists).

### Verification

- `cargo check -p vyre` → 0 errors.
- `cargo test -p vyre --lib` green.
- `cargo test -p vyre --test kat_parity` — 82/82 pass.

### Commit

`A-B3: migrate atomics/compression/hash/string_matching/decode to OpDef`

---

## Step A-B4 — Stdlib dialect module structure

After A-B1-3 lands ALL ops as `OpDef`s but they're scattered. Organize into
stdlib dialects under `vyre-core/src/dialect/`:

- `vyre-core/src/dialect/core/` — literal, cast, load, store, invocation_id,
  workgroup_id, local_id, barrier, return
- `vyre-core/src/dialect/math/` — primitive.math.*
- `vyre-core/src/dialect/bitwise/` — primitive.bitwise.*
- `vyre-core/src/dialect/compare/` — primitive.compare.*
- `vyre-core/src/dialect/logical/` — primitive.logical.*
- `vyre-core/src/dialect/float/` — primitive.float.*
- `vyre-core/src/dialect/atomics/` — all atomics
- `vyre-core/src/dialect/compression/` — compression ops
- `vyre-core/src/dialect/hash/` — hash ops
- `vyre-core/src/dialect/string_matching/` — string-matching ops
- `vyre-core/src/dialect/decode/` — codec decoders
- `vyre-core/src/dialect/workgroup/` — SRAM data structures
- `vyre-core/src/dialect/security_detection/` — 20+ detectors
- `vyre-core/src/dialect/pattern/` — pattern matching helpers

Each dialect directory follows the canonical layout spelled out at the
TOP of this doc. Re-read that section before you start A-B4 — it's the
ground truth. Summary:
- `mod.rs` ≤ 80 lines: declarations + the `DIALECT: Dialect = ...`
  const + its `inventory::submit!`. No real code.
- `README.md` with a table of every op in this dialect.
- One directory per op, each with the six canonical files
  (`op.rs`, `cpu_ref.rs`, `wgsl.rs`, `spv.rs` when present,
  `tests.rs`, `README.md`).
- `_support/` (underscore prefix) for dialect-private helpers if any;
  banned at the op level.
- Max depth 4 from `vyre-core/src/`. Never go deeper.

The old `vyre-core/src/ops/` directory disappears. Files move, imports
get fixed up. Claude's A-C11c commits the CI law scripts that enforce
every constraint above — if you deviate, the script fails the PR.

### Verification

- `cargo check -p vyre` → 0 errors.
- `find vyre-core/src/ops -type f 2>/dev/null | wc -l` → 0.
- `bash scripts/laws/check_layout.sh` passes (when it exists — may land
  concurrently via A-C11c; re-run after it lands).
- Every Program in test suites continues to compile — `cargo test -p vyre
  --lib`.

### Commit

`A-B4: reorganize ops under vyre-core/src/dialect/<name>/; per-dialect READMEs, one op per file`

---

## Step A-B4b — Per-dialect feature flags

A minimal vyre binary should not have to link `dialect-security_detection`
if the user isn't scanning. Turn every stdlib dialect into a Cargo
feature.

### Changes

- `vyre-core/Cargo.toml`:
  ```toml
  [features]
  default = ["dialect-core", "dialect-math", "dialect-bitwise",
             "dialect-compare", "dialect-logical", "dialect-float",
             "dialect-atomics", "dialect-compression", "dialect-hash",
             "dialect-string-matching", "dialect-decode",
             "dialect-workgroup", "dialect-pattern"]
  dialect-core = []
  dialect-math = []
  # one feature per stdlib dialect
  dialect-security-detection = []    # not default — opt-in
  dialect-io = []                    # not default — opt-in
  ```

- Each stdlib dialect module is gated:
  ```rust
  #[cfg(feature = "dialect-math")]
  pub mod math;
  ```

- `inventory::submit!` calls inside each dialect are naturally inert
  when the feature is off because the whole module is excluded.

- `cargo check --no-default-features --features dialect-core,dialect-math`
  produces a minimal build that still compiles and passes a narrowed
  `kat_parity`.

### Verification

- `cargo check -p vyre --all-features` → 0 errors.
- `cargo check -p vyre --no-default-features` → compiles (no ops
  registered but the substrate types are present).
- `cargo check -p vyre --no-default-features --features dialect-core,dialect-math`
  → compiles with math-only op set.

### Commit

`A-B4b: per-dialect feature flags (minimal vyre builds ship only the dialects needed)`

---

## Step A-B4c — Per-dialect conformance tests + property-test engine

Dialects are testable in isolation. One test file per dialect, one
property-test engine driven by declared laws.

### Changes

For each dialect `<name>` in `vyre-core/src/dialect/<name>/`:

- Add `vyre-core/tests/conformance_<name>.rs` — runs only that
  dialect's KAT vectors against every available backend.
  `cargo test -p vyre --test conformance_math` passes in isolation.

- Add `vyre-core/tests/properties_<name>.rs` — proptest-driven. For
  every op in the dialect, read the op's declared `laws` and generate
  the corresponding proptest assertion:
  - `AlgebraicLaw::Commutative { }` → `prop_assert_eq!(op(a, b), op(b, a))`
  - `AlgebraicLaw::Associative { }` → `prop_assert_eq!(op(op(a, b), c), op(a, op(b, c)))`
  - `AlgebraicLaw::Identity { element }` → `prop_assert_eq!(op(a, element), a)`
  - `AlgebraicLaw::Idempotent { }` → `prop_assert_eq!(op(a, a), a)`
  - `AlgebraicLaw::SelfInverse { result }` → `prop_assert_eq!(op(a, a), result)`
  - `AlgebraicLaw::Absorbing { element }` → `prop_assert_eq!(op(a, element), element)`
  - `AlgebraicLaw::Bounded { lo, hi }` → `prop_assert!(op(a, b) >= lo && op(a, b) <= hi)`
  - `AlgebraicLaw::ZeroProduct { holds: true }` → `prop_assert!(op(a, b) != 0 || a == 0 || b == 0)`
  Laws-driven — the test engine is generic; each op's assertions come
  from its own `laws: &[...]` declaration. No hand-coded proptest per
  op.

- A shared engine module `vyre-core/tests/properties_engine.rs` holds
  the generic driver fn used by every `properties_<name>.rs`.

### Verification

- `cargo test -p vyre --test conformance_math` passes.
- `cargo test -p vyre --test properties_math` passes (proptest runs
  8192 cases per law by default).
- Every stdlib dialect has both test files.

### Commit

`A-B4c: per-dialect conformance + laws-driven property tests (one test file per dialect)`

---

## Step A-B4d — Op-ID stability catalog

Op IDs are public API. Renaming one silently breaks the world.

### Changes

- Generate `docs/op-id-catalog.md` at build time via an xtask:
  walks the dialect registry, emits a sorted table of every op's
  `(id, dialect, version, category, signature_hash)`. The
  signature_hash is blake3 of the canonical signature bytes — changes
  when inputs/outputs/attrs change.

- Add `scripts/check_op_id_stability.sh`:
  generates the catalog fresh, diffs against committed
  `docs/op-id-catalog.md`. Fail on any diff.

- To rename an op, the contributor must:
  1. Add the new op as a v2 with the new id.
  2. Add a migration entry (see Claude A-C2 wire-format migration table).
  3. Deprecate the old op id (keeps working but warns).
  4. Update `docs/op-id-catalog.md` with the new row.

- `scripts/rebuild_status.sh` includes the stability check in its
  law dashboard.

### Verification

- `bash scripts/check_op_id_stability.sh` passes after A-B4 lands.
- Breaking the catalog by hand (rename an op) causes the script to
  fail.

### Commit

`A-B4d: op-ID stability catalog + CI gate (renames require explicit migration)`

---

## Step A-B5 — TOML dialect loader + external dialect proof

Wire the TOML runtime path:

1. `vyre-core/src/dialect/toml_loader.rs` — `DialectLoader::from_path(dir)`
   reads `<dir>/dialect.toml` + `<dir>/ops/*.toml` and produces a `Dialect`.
   Errors are structured: `DialectLoadError::UnknownAttrType`,
   `SignatureMismatch`, `MissingLowering`, etc., each with a "Fix: ..."
   message.
2. Env var `VYRE_DIALECT_PATH=dir1:dir2` searched at startup by
   `DialectRegistry::load_runtime()`.
3. A TOML-declared dialect may pair its signatures with Rust-compiled
   lowering fns via inventory: dialect.toml says
   `op = "crypto.hmac_sha256"`, a separate Rust crate does
   `inventory::submit! { LoweringRegistration { op: "crypto.hmac_sha256",
   target: "wgsl", fn_ptr: ... } }`. The loader joins the two halves at
   resolution time.

4. Fill in `vyre-dialect-crypto` — Claude pre-scaffolded the crate, you
   populate:
   - `src/lowering.rs` — naga::Module builders for `crypto.hmac_sha256`,
     `crypto.md5`.
   - `src/cpu.rs` — reference implementations using `sha2` and the
     existing md5 crate.
   - `crypto.argon2id` — CPU-only for now (GPU argon2 is a bigger fight).
   - Enable the `dialect_v1` feature by default in Cargo.toml.
   - Integration test: `cargo test -p vyre-dialect-crypto` — builds a
     Program that calls `crypto.hmac_sha256`, runs through the CPU
     reference, verifies against a known test vector (RFC 4231 §4.1).

5. Runtime loader integration test: `vyre-core/tests/dialect_loader.rs`
   creates a temp dir with a fake `demo.toml` declaring one op, points
   `VYRE_DIALECT_PATH` at it, constructs a Program that references the op,
   asserts the DialectRegistry resolves it.

### Verification

- `cargo test -p vyre-core --test dialect_loader` passes.
- `cargo test -p vyre-dialect-crypto` passes (HMAC-SHA256 against RFC 4231 vectors).
- `VYRE_DIALECT_PATH=/tmp/fake cargo test -p vyre --lib` still passes (loader
  tolerates invalid paths by warning, not panicking).

### Commit

`A-B5: TOML dialect loader + vyre-dialect-crypto proves the external-dialect path`

---

## Legendary bar for Gemini A

When you are done:
- Zero `.wgsl`/`.spv`/`.ptx`/`.metal`/`.msl` files anywhere under
  `vyre-core/src/ops/**` or `vyre-core/src/dialect/**`.
- Zero `OpSpec::intrinsic(...)` calls remain in the source (Claude deletes
  the type itself in step A-C11; you just stop using it).
- Every op lives in exactly one `vyre-core/src/dialect/<name>/` module,
  one file per op, every file ≤ 500 lines, zero `// section ---`
  comments, with a matching `<name>/README.md`.
- Every op's `LoweringTable` has `cpu_ref` populated AND at least one
  target lowering (`naga_wgsl` for everything, plus `naga_spv` for any op
  Gemini B's SPIR-V backend pass covers).
- Every stdlib dialect is a Cargo feature; `--no-default-features`
  produces a valid library shell; minimal `math`-only builds work.
- `migration_shader_parity` is green for every Cat C intrinsic.
- `kat_parity` is 82/82 with zero known failures.
- Each dialect has `tests/conformance_<name>.rs` + `tests/properties_<name>.rs`;
  property tests are laws-driven, not hand-coded.
- `docs/op-id-catalog.md` is committed and matches the current registry
  byte-for-byte (CI gate via `scripts/check_op_id_stability.sh`).
- `vyre-dialect-crypto` on crates.io is proof a 3rd-party can add a
  dialect in a separate crate without editing vyre.

Commit subjects all start `A-B<n>:` or `A-B4<letter>:`. No other prefix.

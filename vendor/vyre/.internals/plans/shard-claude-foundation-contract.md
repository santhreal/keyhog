# SHARD CLAUDE — Foundation + Shared Contract

11 tasks from `.internals/planning/LEGENDARY.md`. The serial spine — files
that every other shard reads, so must be single-owner to avoid merge churn.

## Global invariants (same as every shard)

1. **Zero runtime cost on the dispatch hot path.** No locks after init, no
   per-call allocations, no per-call hashing beyond one FxHash. Build time
   and abstraction depth are free.
2. **No stubs (LAW 1).** Never `todo!()`, `unimplemented!()`, empty match
   arms. Don't delete functionality that's still useful — rewire instead.
3. **IEEE-754 strict math.** No approximations, no `_vyre_fast_*`.
4. **Every commit compiles.** Monotonically decrease the 88-error baseline
   — never increase.

## Known issues (mine, folded into tasks below)

- **RuleCondition closed enum** (`vyre-core/src/ops/rule/ast.rs`) → #3 §1.3
- **DataType wire tags closed match table** → #5 §12 (Opaque tag `0x80+ext_id`)
- **node_kind.rs dead code** (0 usages in compiler) → #3 §1 (visitor
  migration rewires or deletes after migration is complete)
- **ExprVisitor ignored by compiler transforms** (0 usages) → #3 §1.6/1.7
- **1,073 .rs files in vyre-core** → #25 §11 (physical split)
- **Dangling conform test refs in vyre-spec/src/invariants.rs** → #5 §12
  cleanup (audit vyre-spec for conform references; move to conform crates
  or delete if orphaned)
- **automod unused in source** → #25 §11 (remove automod dep; it was
  scaffolding for the split that never wired in. See
  `feedback_dont_delete_implement` — confirm it's truly unused, not just
  unreferenced on the current branch, before removing.)

## Owned files

- `vyre-core/src/dialect/registry.rs`, `migration.rs`, `op_def.rs`,
  `enforce.rs`, `mutation.rs`, `interner.rs`, `lowering.rs`, `dialect.rs`,
  `mod.rs`, `io.rs`, `core_indirect.rs`
- `vyre-core/src/ir/**` — all of it: `model/**`, `validate/**`, `serial/**`,
  `visit/**`, `transform/inline/**`, `transform/visit.rs`,
  `transform/compiler/**`, `transform/parallelism.rs`, `ir.rs`,
  `ir/extension.rs`, `ir/engine/**`, `ir/memory_model.rs`
- `vyre-core/src/ops/metadata.rs`, `cpu_op.rs`, `cpu_references.rs`,
  `fixtures.rs`, `fixtures/**`, `ops.rs`, `ops/rule/**` (not covered by
  Codex's OpDefRegistration delete — `ops/rule/ast.rs` is mine)
- `vyre-core/src/backend.rs`, `backend/**`
- `vyre-core/src/diagnostics.rs`, `error.rs`, `routing.rs`, `routing/**`,
  `pipeline.rs`, `test_migration.rs`, `match_result.rs`,
  `introspection.rs`, `lib.rs`, `lower.rs`, `cert.rs`, `cert/**`
- `vyre-spec/**` (everything — Expr/Node/DataType/BinOp/UnOp/AtomicOp
  data types, invariants.rs)
- `vyre-macros/**` (proc macros, `define_op!`)
- `docs/ARCHITECTURE.md`, `THESIS.md`, `VISION.md`, `semver-policy.md`,
  `wire-format.md`, `wire-format-v2.md` (new), `inventory-contract.md`
  (new), `error-codes.md` (new), `composition-algebra.md` (coordinate with
  Agent-B §10/#8 — I own the file, Agent-B writes the proof content),
  `memory-model.md`, `targets.md`, `frozen-traits/**` (new —
  signature snapshots per §30)
- `scripts/check_no_closed_ir_enums.sh`, `check_no_shader_assets.sh`,
  `check_no_string_wgsl.sh`, `check_no_parse_str.sh`,
  `check_architectural_invariants.sh`, `check_trait_freeze.sh`,
  `check_registry_consistency.sh`, `check_capability_negotiation.sh`,
  `check_unsafe_justifications.sh`, `check_expect_has_fix.sh`,
  `check_dialect_coverage.sh`, `check_no_hot_path_inventory.sh` (new),
  `check_no_opspec_tokens.sh` (new)
- Workspace `Cargo.toml`, `vyre-core/Cargo.toml`, `vyre-spec/Cargo.toml`,
  `vyre-macros/Cargo.toml`
- `CHANGELOG.md` (workspace root — release entries), `vir0-spec.md`
- `benches/registration_overhead.rs` (new — #1 overhead bench only; other
  benches are Agent-A's)
- `RELEASE.md`, `scripts/publish-dryrun.sh`

## Forbidden files — don't touch

- `vyre-core/src/dialect/<dialect_name>/**` (Agent-A owns per-dialect
  subdirs — math/, logical/, hash/, string_matching/, security_detection/,
  stats/, buffer/, decode/, encode/)
- `vyre-core/src/ops/*/reference/**`, `ops/*/cpu_ref.rs`,
  `ops/*/reference.rs` (Agent-B — moving to vyre-reference)
- `vyre-core/src/optimizer/passes/**`, `scheduler.rs`, `rewrite.rs`,
  `tests.rs`, `fusion_cert.rs` (Agent-A)
- `vyre-core/src/lower/**` (Agent-A — IEEE math emit)
- `vyre-wgpu/**`, `backends/photonic/**`, `backends/spirv/**` (Agent-A)
- `vyre-reference/**` (Agent-B)
- `conform/**` (Agent-B)
- `examples/**`, `demos/**` (Agent-B for examples, untouched for demos)
- `benches/**` except `benches/registration_overhead.rs` (Agent-A)
- `.github/workflows/**` (Agent-B owns; I write new `scripts/check_*.sh`
  and Agent-B wires them into architectural-invariants.yml)
- `vyre-build-scan/**` (Agent-B deletes)
- `xtask/**` (Agent-B)
- `rust-toolchain.toml`, `.cargo/config.toml` (Agent-B)
- Every `README.md` except the workspace root (Agent-B) — I may edit
  workspace `README.md` but defer the full rewrite to Agent-B's #29

## My 11 tasks

### #1 — §4 Inventory contract (IN PROGRESS — mostly landed)

**Status:** `vyre-core/src/dialect/registry.rs` rewrite is committed. Frozen
index, zero runtime cost, `Option<&'static OpDef>` on the hot path. Remaining:

- [ ] `ARCHITECTURE.md §82` updated to describe the frozen-index model.
  (Done.)
- [ ] `docs/inventory-contract.md` — new file naming every inventory
  collection (OpDefRegistration, BackendRegistration, PassRegistration,
  ExtensionRegistration, MigrationRegistration), iteration-order guarantees
  (none — consumers must sort), and the hot-path prohibition.
- [ ] `scripts/check_no_hot_path_inventory.sh` — forbids `inventory::iter`
  in `vyre-core/src/backend/**`, `vyre-wgpu/src/pipeline*.rs`,
  `vyre-wgpu/src/engine/**`, `vyre-core/src/ir/transform/**` runtime paths,
  `vyre-core/src/dialect/registry.rs` outside the `global()` init closure.
- [ ] Extend `scripts/check_architectural_invariants.sh` to scan
  `vyre-macros/src/**` — blind spots are bugs.
- [ ] `benches/registration_overhead.rs` — criterion bench with two targets:
  cold first-access ≤100µs, warm lookup = sub-ns (pointer chase). Wire
  into `benches/budgets.toml` (Agent-A owns the budgets file overall; I add
  my rows via a commit message request if they blow up — but these rows are
  new so I add them).

**Success:** `cargo bench --bench registration_overhead` shows warm lookup
≤5 ns per call. CI grep gate green.

### #2 — §3 Single registry (finish after Codex)

**Codex in-flight:** `codex-c6cfb73b` is migrating `pub const SPEC: OpDefRegistration`
sites to `OpDefRegistration::new` (via `define_op!`). When it commits, my
residual work:

- [ ] Verify every `OpDefRegistration` / `OpDefRegistration` / `DIALECT_REGISTRY` /
  `inventory::submit!` token is gone from workspace. Any remaining site is
  mine to migrate manually.
- [ ] `scripts/check_no_opspec_tokens.sh` — fails on any of those tokens.
- [ ] `vyre-core/src/ir/transform/inline.rs` — confirm it resolves compose
  via `DialectRegistry::global().lookup(op_id).and_then(|d| d.compose)` (no
  OpDefRegistration residue).
- [ ] `vyre-core/src/ops/metadata.rs` — verify `Compose::{Composition,
  Intrinsic}` is collapsed to `Option<fn()->Program>` on `OpDef`. Delete
  the enum.
- [ ] Delete `vyre-core/src/ops/spec.rs`, `ops/registry/registry.rs`,
  `ops/registry/static_generated/walked_ops.rs` + the build-time codegen
  that produces it.

**Success:** workspace grep `OpDefRegistration|OpDefRegistration|DIALECT_REGISTRY|inventory::submit!`
returns zero hits. `cargo check --workspace --all-features` green.

### #3 — §1 IR openness (Opaque variants + visitor migration) — BIGGEST

**Where:** `vyre-spec/src/data_type.rs`, `bin_op.rs`, `un_op.rs`,
`atomic_op.rs`; `vyre-core/src/ops/rule/ast.rs`, `ops/rule/builder.rs`;
`vyre-core/src/ir/visit/**`, `vyre-core/src/ir/transform/**`,
`vyre-core/src/ir/validate/**`, `vyre-core/src/ir/model/**`,
`vyre-core/src/backend.rs`, `vyre-core/src/ir/serial/wire/**`.

**What:**
1. Add `Opaque` variants to DataType, BinOp, UnOp, AtomicOp — each carries an
   `ExtensionXxxId(u32)` PLUS a cached `&'static dyn ExtensionXxxTrait`
   pointer resolved ONCE at IR construction time (not per-eval). This is
   non-negotiable for zero runtime cost.
2. Extension payload registration via
   `inventory::collect!(ExtensionDataTypeRegistration)` etc. First-access
   builds a `LazyLock<FxHashMap<ExtensionXxxId, &'static dyn
   ExtensionXxxTrait>>`. IR node construction resolves the pointer via this
   map once.
3. Wire tag `0x80 + u32 extension_id` (done via §12 / #5 too — but #3
   defines the Opaque variant shape).
4. Implement `size_bytes / min_bytes / max_bytes / is_float_family /
   is_host_shareable` via the registered trait.
5. `RuleCondition::Opaque(Arc<dyn RuleConditionExt>)` in `ops/rule/ast.rs`.
   Replace hardcoded six `BufferDecl` in `ops/rule/builder.rs` with
   `RuleConditionExt::required_buffers() -> Vec<BufferDecl>`.
6. `Backend` enum (`vyre-core/src/ops/metadata.rs:41`) → `struct
   BackendId(Arc<str>)`. Every `match b { Backend::... }` becomes
   `BackendRegistry::get(&id)`. The registry is frozen-after-init; lookup
   returns `&'static dyn VyreBackend` (no allocation).
7. Property test: `ExprNode::stable_fingerprint` injectivity — two distinct
   ExprNode impls produce distinct fingerprints w.h.p. Test:
   `vyre-core/tests/extension_fingerprint_injective.rs`.
8. **Visitor migration — the 14 sites:**
   - `ir/transform/optimize/cse/impl_exprkey.rs`
   - `ir/transform/optimize/cse/impl_csectx.rs`
   - `ir/transform/optimize/dce/collect_expr_refs.rs`
   - `ir/transform/optimize/dce/expr_has_effect.rs`
   - `ir/transform/dead_buffer_elim/*.rs`
   - `ir/validate/expr_type.rs` (confirm path — might be `expr_rules.rs`)
   - `ir/validate/binop_rules.rs`
   - `ir/validate/comparison_rules.rs` (confirm — might be inside
     `typecheck.rs`)
   - `ir/transform/inline/expand/*.rs`
   - `ir/serial/wire/encode/put_expr.rs`
   - `ir/serial/wire/decode/impl_reader.rs`
   - `vyre-wgpu/src/lowering/naga_emit.rs` — **Agent-A owns.** Coordinate:
     I add the visitor trait; Agent-A migrates the matcher in naga_emit.rs
     under #17.

   Each site loses its closed `match Expr { ... }` and uses
   `expr.visit(&mut visitor)`.
9. `scripts/check_no_closed_ir_enums.sh` ratchets down on every migrated
   site. Baseline at plan start: audit this — I'll log in the commit.
10. `Expr::Call` inlining routes through the visitor. Post-inline validate
    rejects Call variants.
11. Remove `_ =>` wildcards on Node matches. `_ => Err(...)` at
    `eval_expr.rs:74` (per BRUTAL_CRITIQUE.md) — that file is
    `vyre-reference`'s, Agent-B owns. Commit `§1-REQUEST: replace _ =>` via
    commit message.
12. Add `vyre-core/tests/extension_round_trip.rs` covering: custom
    ExprNode + custom NodeNode + custom ExtensionDataType + custom
    RuleConditionExt — each (a) registers via inventory, (b) round-trips
    `to_wire`/`from_wire` byte-identical, (c) survives CSE+DCE+fusion
    unchanged, (d) validates without violating `validate_extension()`.
13. Audit `node_kind.rs` — 0 usages. Either wire into the visitor dispatch
    (rename to `NodeKind` trait for open-Node) or delete if truly orphaned
    after migration. Default: wire into dispatch, don't delete.

**Success:** `scripts/check_no_closed_ir_enums.sh` returns 0. Extension
round-trip tests green. 14 visitor sites migrated. No `_ =>` wildcard on
Expr/Node matches in vyre-core.

### #4 — §2 Substrate-neutral vocabulary purge

**Where:** every file in `vyre-core/src/**`, `vyre-spec/src/**`,
`docs/**`. Cross-shard-blast: touches Agent-A's per-dialect subdirs.

**Strategy:** I do the API/core-type renames. Agent-A does the
backend-side rename in owned files (WGSL is WGSL — backend-local words stay).

**What:**
- `workgroup_size` field + method on `Program` → `parallel_region_size`.
  Keep `workgroup_size` as a backend-facing alias **inside vyre-wgpu
  only** — Agent-A owns adding the alias.
- `WorkgroupId` Expr variant → `ParallelRegionId(axis: ParallelAxis)`.
- `LocalId` Expr variant → `InvocationLocalId`.
- `Node::Barrier` — name stays (already abstract).
- Every WGSL reference in `vyre-core/src/**` comments + docs becomes
  "the default backend shader" or names the backend directly.
- WGSL-named tests in `vyre-core/tests/` move to `vyre-wgpu/tests/`
  (I coordinate the move with Agent-A).
- `scripts/check_architectural_invariants.sh` (Law H) grows a vocabulary
  check: grep `vyre-core/src` for
  `\bworkgroup\b|\bsubgroup\b|\bwarp\b|\bwgsl\b|\bptx\b|\bmsl\b` with
  allowlist for `// WORD-OK:` comments. Fails on hits outside allowlist.
- `docs/memory-model.md` and `targets.md` already use neutral vocabulary.
  Whitelist paths in `scripts/check_no_string_wgsl.sh`.

**Success:** Law H grep returns zero in `vyre-core/src/**`. Public API
renames compile clean. Backend-local files (Agent-A's) still use
`workgroup`, `wgsl` freely.

### #5 — §12 Wire format v2 (VIR0)

**Where:** `vyre-core/src/ir/serial/wire/encode/**`,
`serial/wire/decode/**`, `serial/wire/tags.rs`, `serial/wire/framing/**`,
`vyre-core/src/dialect/migration.rs` (new v1→v2 migration),
`docs/wire-format.md`, `docs/wire-format-v1.md` (archived),
`docs/wire-format-v2.md` (current).

**What:**
1. Encoder `serial/wire/encode/put_expr.rs` grows `Expr::Opaque` branch —
   emits tag `0x80`, `extension_id: u32`, `payload_len: u32`, bytes from
   `ExprNode::encode()`. Same for Node::Opaque.
2. Decoder `serial/wire/decode/impl_reader.rs` tag `0x80` dispatches
   through `inventory::iter::<ExtensionRegistration>`. On miss:
   `DecodeError::UnknownExtension { extension_id, kind, payload_bytes }`.
   Payload preserved so caller can install extension + re-decode.
3. `BufferDecl.bytes_extraction` wire-encodes as flag bit in `memory_hints`
   u8. Bump wire version to 2.
4. Migration `v1 → v2` in `dialect::migration`: v1 blob sets
   `bytes_extraction: false` on every buffer.
5. Deterministic encoding contract: sorted metadata map keys (lex),
   canonical f32 (no NaN payload bits), canonical int (fixed-width
   big-endian for IDs, LEB128 for lengths).
6. **DataType wire tags** — close the `match DataType` table in encoder by
   adding Opaque handling + `#[non_exhaustive]` safe wildcard. This
   eliminates the known "DataType wire tags closed match table" issue.
7. CI test: round-trip contract — encoded → decoded → re-encoded =
   byte-identical across full KAT corpus.
8. Wire spec split: `docs/wire-format-v1.md` (archived, frozen),
   `docs/wire-format-v2.md` (current). `vir0-spec.md` points to current.
9. Wire security caps (§37 / #24 territory but I land them here):
   `MAX_NESTING_DEPTH` (existing), `MAX_PROGRAM_BYTES = 64 MiB`. No
   `as usize` without bound check. Extension payloads bounded by
   `ExprNode::max_encoded_bytes()`.
10. **Audit dangling conform refs in vyre-spec/src/invariants.rs** — if
    conform references exist, move to conform crates (coordinate with
    Agent-B) or delete if orphaned.

**Success:** CI round-trip test green over KAT corpus. Wire v1 blobs
still decode (migration path). New v2 blobs round-trip identity.

### #6 — §30 Frozen traits snapshot

**Where:** `docs/frozen-traits/*.txt` (new), `scripts/check_trait_freeze.sh`
(existing — extend).

**What:** snapshot byte-for-byte signatures of 7 frozen traits:
- `VyreBackend` — `vyre-core/src/backend.rs`
- `ExprVisitor` — `vyre-core/src/ir/visit/expr.rs`
- `NodeVisitor` — `vyre-core/src/ir/visit/node.rs`
- `Lowerable` — grep to find current home
- `AlgebraicLaw` — `vyre-core/src/ops/mod.rs` or `ops/metadata.rs`
- `EnforceGate` — `conform/vyre-conform-enforce/src/lib.rs` (READ-ONLY for
  me — I don't edit conform, but I can snapshot)
- `MutationClass` — `vyre-core/src/dialect/mutation.rs`

`scripts/check_trait_freeze.sh` reads the trait via `syn`, emits canonical
signature bytes, diffs against snapshot. Any diff = frozen-trait violation.

Document "extend = new trait + default impl delegating to old" policy in
`docs/semver-policy.md`.

**Success:** `check_trait_freeze.sh` green across all 7 traits. Snapshot
files committed.

### #15 — §7 [REASSIGNED TO AGENT-A]

Originally in my pile; moved to Agent-A's shard because the validation
cache lives in `vyre-wgpu/src/pipeline.rs` (Agent-A territory) and is
tightly coupled to `CompiledPipeline`. I remain responsible for the
`verify_program_certificate` function itself and the blake3 key derivation
from `Program::to_wire()`.

**My piece:** ensure `verify_program_certificate` is content-addressable —
pure function, no hidden state, keyed by `blake3(program.to_wire())`. Keep
the function in `vyre-core/src/cert.rs`. Agent-A wraps with the
`DashMap<[u8;32], Certified>` cache.

### #20 — §14 + §29 Diagnostics + error code registry

**Where:** `vyre-core/src/diagnostics.rs`, `error.rs`,
`vyre-core/src/ir/validate/err.rs`, `validation_error.rs`,
`vyre-core/src/backend/error.rs`, `docs/error-codes.md` (new).

**What:**
- Grow E-*/W-*/V### catalog across wire decode errors, per-variant
  BackendError, conform verdicts (read-only — Agent-B owns conform
  variants, I spec the codes), validation codes.
- LSP JSON serialization: every Diagnostic serializes to
  `PublishDiagnosticsParams` shape.
- rustc-style render: `error[E-IR-003]: primary msg\n  --> file:line:col\n
  |\n  | ...`. Zero-learning-curve ergonomics.
- Mandatory `Fix:` prose per variant. CI lint rejects new Diagnostic
  variants without `Fix:`.
- `source_span` optional; when present, renderer highlights; when absent,
  renderer names `op_id`.
- `BackendError` — no string-only variants. Every variant named with
  structured fields.
- `docs/error-codes.md` lists every code with meaning + Fix template.
  Append-only; renames are migrations.

**Success:** every error produced by `vyre-core` carries a code + `Fix:`
prose. CI lint green.

### #24 — §28 + §37 + §32 Input validation + wire security + unsafe discipline

**Where:** `vyre-core/src/ir/serial/wire/decode/**`, `serial/wire/framing.rs`,
`vyre-core/src/backend.rs`, every `pub fn` accepting bytes in `vyre-core`,
`vyre-core/src/lib.rs`.

**What:**
- Every `pub fn` accepting user bytes (`dispatch(inputs: &[Vec<u8>])`,
  `from_wire(bytes: &[u8])`, `Program::deserialize(...)`) validates
  alignment + length + reasonable size before bytemuck/naga.
  `bytemuck::try_cast_slice` with structured error.
- `DispatchConfig::max_output_bytes` honored — typed error on overflow.
- `MAX_INPUT_BYTES = 4 GiB`. Opt-out via `DispatchConfig::unbounded = true`.
- Wire: `MAX_NESTING_DEPTH` (existing) + `MAX_PROGRAM_BYTES` (64 MiB).
  No `as usize` without prior bound check.
- `Reader::leb_len` typed max.
- `Expr::Opaque` extension payloads bounded by
  `ExtensionExprTrait::max_encoded_bytes()`.
- `#![forbid(unsafe_code)]` on vyre-core (add if absent — currently may
  have unsafe for inventory; audit). Every remaining unsafe block has
  `// SAFETY: <invariant>` comment (Law D).
- No `unwrap` / `expect` in wire decoder. Every malformed byte sequence
  returns `DecodeError`.
- `cargo-deny` + `cargo-audit` in CI (Agent-B wires workflow; I supply
  `deny.toml`).

**Success:** `deny.toml` covers banned crates/licenses/git URLs.
`cargo-audit` green. Wire decoder fuzz target (Agent-B's #23) never
panics on arbitrary input.

### #25 — §11 Physical workspace split — BIG

**Where:** workspace-level `Cargo.toml`, every ops-façade
`ops-facades/vyre-ops-*/src/lib.rs`, `git mv` orchestration.

**What:**
- `vyre-core` keeps: `ir/`, `dialect/{registry,op_def,enforce,mutation,
  interner,lowering,dialect,migration}.rs`, `optimizer/` (scheduler only —
  passes move out), `backend/{trait,error,config,registration}.rs`,
  `validate/`, `serial/wire/`, `lower/` (trait defs only), crate-level docs.
- Split ops per existing façades:
  - `ops/primitive/` → `vyre-ops-primitive/src/`
  - `ops/hash/` → `vyre-ops-hash/src/`
  - `ops/string/`, `string_matching/`, `string_similarity/` →
    `vyre-ops-string/src/`
  - `ops/security_detection/` → `vyre-ops-security/src/`
  - `ops/compression/` + `ops/decode/` + `ops/encode/` →
    `vyre-ops-compression/src/`
  - `ops/graph/` → `vyre-ops-graph/src/`
  - `ops/workgroup/` → `vyre-ops-workgroup/src/`
  - `ops/data_movement/`, `reductions/`, `sort/`, `scan/`, `stats/`,
    `match_ops/` — decide per domain.
- `git mv` preserves history. Update every `use vyre::ops::foo::...`.
- Façade `src/lib.rs` becomes the owner of the module, not a re-export.
- Passes split from `vyre-core::optimizer::passes::` into own crates via
  `PassRegistration` inventory (coordinate with Agent-A — Agent-A owns
  the passes today; together we define the split).
- **1,073 .rs file count** drops below 400 in `vyre-core/src/**`.
- **automod unused in source** — verify truly unused across branches; if
  so, remove dep. If used by a non-current branch / agent script, preserve.
- Workspace members list fixed ordering: specs + macros + core + refs +
  ops + backends + conform + demos + examples + xtask.

**Success:** `vyre-core/src/` has <400 .rs files. Each domain lives in its
own crate. `cargo check --workspace` green. `git log --follow` still
threads through every moved file.

### #30 — §27 + §38 [REASSIGNED TO AGENT-B]

Originally in my pile; moved to Agent-B because coverage-matrix generation
is a script + docs/catalogs job, which fits B's territory. I retain
ownership of the underlying script
`scripts/check_registry_consistency.sh` (already exists) — Agent-B's new
`gen_coverage_matrix.sh` reads it.

### #32 — §20 Publish

**Where:** `scripts/publish-dryrun.sh`, every
`ops-facades/*/Cargo.toml`, `backends/*/Cargo.toml`,
`conform/*/Cargo.toml`, workspace `Cargo.toml`.

**What:**
- Verify publish order + every crate has README (pointer) + LICENSE-MIT +
  LICENSE-APACHE + description + keywords + categories + repository +
  homepage. Coordinate with Agent-B (they own per-crate READMEs).
- Squat-defend crate names on crates.io: `vyre-ops-primitive`,
  `vyre-ops-hash`, `vyre-ops-string`, `vyre-ops-security`,
  `vyre-ops-compression`, `vyre-ops-graph`, `vyre-ops-workgroup`,
  `vyre-conform-{spec,generate,enforce,runner}`, `vyre-spirv`,
  `vyre-photonic`. Publish v0.0.1 placeholders before legendary ships.
- First publish: core v0.5.0, new crates v0.1.0.
- `docs/semver-policy.md` — every API-visible Opaque variant additive-only;
  new inventory collection = minor bump; changing an existing collection's
  struct shape = major bump.
- Per-crate `CHANGELOG.md` = pointer to workspace CHANGELOG.
- `docs.rs` config: `[package.metadata.docs.rs] all-features = true,
  rustdoc-args = ["--cfg", "docsrs"]`. `#[cfg(docsrs)]` feature-gates
  all-features-only pieces.

**Success:** `scripts/publish-dryrun.sh` green. Every crate publishable
(metadata complete). CHANGELOG unified.

### #33 — §39 Legendary sign-off

Last task. Gate on every other task being done. Acceptance test:

- External extension crate <200 LOC adds `tensor.gather` + custom
  `DataType` + custom backend; CI passes; zero core edits.
- wgpu + spirv byte-identical across full primitive corpus.
- Zero reference code in `vyre-core`.
- Every op has signed cert byte-identical across machines.
- Real reproducible bench numbers in `benches/RESULTS.md`.
- `vyre-core/src/` <400 files. Each domain own crate + CHANGELOG pointer.
- Every `expect` starts with `Fix:`, every `pub` item has real rustdoc.
- 7 frozen traits byte-stable.
- New backend = one crate + `inventory::submit!`. Period.

Then tag `v1.0.0`. Commit message: `vyre v1.0.0 — legendary`.

## Coordination

- **Codex** (`codex-c6cfb73b`) is finishing §3 OpDefRegistration delete. Do not touch
  ops/spec.rs, ops/registry/, OpDefRegistration until it commits. Then I finish
  #2.
- **Agent-A** owns backend perf + per-dialect subdirs + optimizer passes +
  benches. My #3 §1.7 visitor migration touches `vyre-wgpu/src/lowering/naga_emit.rs`
  — I define the visitor trait, Agent-A migrates the match sites in their
  file under their #17.
- **Agent-B** owns reference + conform + tests + CI + docs + cleanliness.
  My #5 §12 wire format touches `vyre-spec/src/invariants.rs` if dangling
  conform refs exist there. Coordinate via commit message.

## Commit protocol

- Prefix: `vyre §<N>: <one-line summary>` or `vyre §<N> (partial): ...`.
- Every commit compiles. Never raise the 88-error baseline.
- `*-REQUEST:` commits signal cross-shard needs. Agents read recent log.

Go.

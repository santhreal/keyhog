# Agent 1 — Core + Reference + Conform + Docs

**Exclusive ownership (zero overlap with Agent 2):**
- `vyre-core/**`
- `vyre-spec/**`
- `vyre-reference/**`
- `conform/**`
- `ops-facades/**`
- `backends/photonic/**`
- `examples/**`
- `demos/**`
- `docs/**`, `scripts/**`
- Root-level files (`Cargo.toml`, `README.md`, scratch files, etc.)

**Forbidden paths (belong to Agent 2):** `vyre-wgpu/`, `backends/spirv/`, `benches/`, `xtask/`, `tests/` (root-level), `vyre-macros/`.

**Do not coordinate. Do not wait. Commit directly to `main`.**

---

## A. Open-IR load-bearers

### A1. Restore frozen visitor traits
- Create `vyre-core/src/ir/visit/mod.rs`, `expr.rs`, `node.rs`, `traits.rs`.
- Define `ExprVisitor`, `NodeVisitor`, `Lowerable` with visit methods for every variant PLUS `visit_opaque(id)` fallback.
- Snapshot signatures into `docs/frozen-traits/{ExprVisitor,NodeVisitor,Lowerable}.md` byte-for-byte.
- Make `scripts/check_trait_freeze.sh` pass (currently errors: "Frozen contract source missing").
- Re-export from `vyre-core/src/ir.rs` so downstream sees them.

### A2. Migrate 17 closed-match transform sites to visitors
Each file below: replace `match expr { ... _ => ... }` with an `ExprVisitor`/`NodeVisitor` impl. Add `visit_opaque` fallback that is conservative (bail the optimization, preserve correctness).

- `vyre-core/src/ir/transform/visit.rs:144`
- `vyre-core/src/ir/transform/visit.rs:277`
- `vyre-core/src/ir/transform/optimize/dce/const_truth.rs:5`
- `vyre-core/src/ir/transform/optimize/dce/collect_expr_refs.rs:8`
- `vyre-core/src/ir/transform/optimize/dce/expr_has_effect.rs:7`
- `vyre-core/src/ir/transform/optimize/cse/impl_exprkey.rs:9`
- `vyre-core/src/ir/transform/optimize/cse/impl_csectx.rs:158`
- `vyre-core/src/ir/transform/optimize/cse/impl_csectx.rs:159`
- `vyre-core/src/ir/transform/optimize/cse/impl_csectx.rs:169`
- `vyre-core/src/ir/transform/optimize/cse/impl_csectx.rs:194`
- `vyre-core/src/ir/transform/optimize/cse/expr_has_effect.rs:9`
- `vyre-core/src/ir/transform/inline/expand/impl_calleeexpander/primitive.rs:8`
- `vyre-core/src/ir/transform/inline/expand/impl_calleeexpander/primitive.rs:158`
- `vyre-core/src/ir/transform/inline/expand/impl_calleeexpander/composition.rs:82`
- `vyre-core/src/ir/transform/inline/impl_inlinectx.rs:99`
- `vyre-core/src/ir/transform/inline/impl_inlinectx.rs:195`
- `vyre-core/src/ir/transform/parallelism.rs:135`

### A3. Wire `Node::Opaque` into the wire format
- Assign tag `0x80` in `vyre-core/src/ir/serial/wire/tags/` for `Node::Opaque`.
- Encode path in `vyre-core/src/ir/serial/wire/encode/**`, decode path in `vyre-core/src/ir/serial/wire/decode/from_wire.rs`.
- Round-trip proptest + fingerprint stability test.
- Bump wire version from 1 → 2; author `docs/wire-format-v1.md` freeze + `docs/wire-format-v2.md` additive delta; write v1→v2 migration helper.

### A4. Delete OpSpec legacy shim
- Migrate callers:
  - `vyre-core/src/ops/hash/fnv1a32.rs` (uses `OpSpec::composition`)
  - `vyre-core/src/ops/compression/gzip_decompress/implementation/kernel.rs`
  - `vyre-core/src/ops/hash/entropy/kernel/spec.rs`
- Delete `OpSpec`, `OpSpecEntry`, `BYTES_TO_U32_OUTPUTS`, `BYTES_TO_BYTES_INPUTS`, `BYTES_TO_BYTES_OUTPUTS` if no longer used.
- Every op registers via `OpDefRegistration` only.
- `scripts/check_no_opspec_tokens.sh` green.

### A5. Resolve `node_kind.rs` dead code
- `vyre-core/src/ir/model/node_kind.rs` has zero usages in compiler.
- Either (a) wire it into dispatch as an enum discriminant table, or (b) delete it.
- One decision, one commit. LAW 9: no documented-limitation purgatory.

### A6. Fix `vyre-spec/src/invariants.rs` dangling conform references
- Current file points at non-existent conform test files.
- Regenerate manifest from `conform/**` live tree.
- Add CI check: manifest paths must exist on disk.

---

## B. Law-B string-WGSL purge inside core

### B1. New naga-builder trait in vyre-core
- Create `vyre-core/src/lower/naga_builder.rs` — trait `NagaBuilder` that `vyre-wgpu` implements (vyre-core defines, vyre-wgpu owns).
- Declares methods for constructing naga::Module pieces: `emit_workgroup_var`, `emit_storage_binding`, `emit_compute_entry_point`, `emit_binop`, etc.
- Core holds only the trait; no naga types leak out beyond opaque handles.

### B2. Delete string WGSL from `ops/workgroup`
- `vyre-core/src/ops/workgroup/queue_priority/lowering.rs:41-43` — remove `var<workgroup> heap_values/heap_priorities/heap_len` string emission; call `NagaBuilder` instead.
- `vyre-core/src/ops/workgroup/stack/lowering.rs:43-44` — same for `stack_values`, `stack_len`.

### B3. Delete 84 `naga::front::wgsl::parse_str` sites in `dialect/security_detection`
For every file matching `vyre-core/src/dialect/security_detection/*/wgsl.rs`:
- Replace `let wgsl = format!(r#"..."#); naga::front::wgsl::parse_str(wgsl).expect("valid wgsl")` with a call to a `NagaBuilder` fixture.
- Confirmed hot sites: `detect_url/wgsl.rs:28`, `detect_xxe/wgsl.rs:78`, `detect_xss/wgsl.rs:71`, `detect_ipv4/wgsl.rs:27`, `detect_base64_run/wgsl.rs:31`, `detect_path_traversal/wgsl.rs:17`, `file_magic_detect/wgsl.rs:23`, `detect_ssrf/wgsl.rs:78`, `detect_uuid/wgsl.rs:21`, `detect_lfi/wgsl.rs:81`, … (74 more under `dialect/security_detection/**` and related dialect trees).
- Zero `.expect("valid wgsl")` left in `vyre-core/src`.
- `scripts/check_no_string_wgsl.sh` green.
- `scripts/check_no_parse_str.sh` green.

---

## C. Reference interpreter

### C1. Remove scheduler simulation from `vyre-reference/src/workgroup.rs`
- Trim or remove `LocalSlots::visit_nodes` (`:144-186`) and `visit_expr` (`:188-241`) — both have `_ => {}` wildcards that silently drop `Opaque` variants.
- Rewrite using the new `ExprVisitor`/`NodeVisitor` from A1.
- Make `sequential.rs` the canonical path; `workgroup.rs` should not simulate schedules, only model invocation identity.

### C2. Intern `Memory` keys
- `vyre-reference/src/workgroup.rs:42-43` — `HashMap<String, Buffer>` on hot path.
- Intern buffer names to `u32 BufferId` at program-compile time.
- Replace with `FxHashMap<BufferId, Buffer>` or `SmallVec<[(BufferId, Buffer); 8]>` (most programs have ≤8 buffers).

### C3. Move 13 reference files out of `vyre-core/src/ops`
- Legendary-signoff §7 reports 13 `.rs` files in `vyre-core/src/ops` that are CPU reference code. They belong in `vyre-reference/`.
- `git mv` each one, update imports, update `Cargo.toml` members if needed.
- `scripts/check_legendary_signoff.sh` "reference interpreter isolation" gate goes green.

---

## D. Crate split + org

### D1. Split core files > 500 lines
Use `splitrs` (see `~/.claude/projects/-home-mukund-thiru/memory/rust-module-tooling.md`) — do NOT hand-roll.
- `vyre-core/src/ir/model/expr.rs` (643)
- `vyre-core/src/ir/model/program.rs` (617)
- `vyre-core/src/diagnostics.rs` (564)
- `vyre-core/src/dialect/migration.rs` (534)
- `vyre-core/src/ir/serial/wire/decode/from_wire.rs` (516)
- `vyre-reference/src/hashmap_interp.rs` (922)
- `vyre-reference/src/eval_expr.rs` (750)
- `vyre-reference/src/typed_ops.rs` (485)
- `vyre-reference/src/workgroup.rs` (502)

Target `vyre-core` file count < 400 (currently 1244).

### D2. Feature-gate ops-facades
- Convert `ops-facades/vyre-ops-{primitive,hash,string,security,compression,graph,workgroup}` from 7 publishable crates into `[features]` on `vyre-core/Cargo.toml`: `hash = []`, `string = []`, `primitive = []`, `security = []`, `compression = []`, `graph = []`, `workgroup = []`.
- `default-features` enables all.
- `git rm -r ops-facades/` and remove from workspace members in root `Cargo.toml`.
- Update any downstream import paths.

### D3. Reconcile photonic + three_substrate_parity
- `backends/photonic` is a stub with `supports_dispatch=false`. Either:
  - (a) Implement a CPU-emulated photonic backend that actually dispatches (any real math, even trivial), OR
  - (b) `git rm -r backends/photonic/`, remove from workspace members, rename `examples/three_substrate_parity` → `examples/two_substrate_parity`, update docs.
- `examples/external_ir_extension` does not yet exist — create it or remove the THESIS.md reference.

### D4. Root hygiene
- Move to `.internals/scratch/`: `scratch.rs`, `test_if.wgsl`, `check.log`, `build_tree.py`, `migrate_inventory.py`, `migrate_inventory2.py`.
- `CODE_OF_CONDUCT.md`, `CITATION.cff`, `SECURITY.md`, `CODEOWNERS` — verify current + correct.
- Root README must build a first-time-user example in < 30 lines.

---

## E. Error / panic discipline (core-only)

### E1. Sweep `.unwrap()` in core `src/`
Files with `.unwrap()`:
- `vyre-core/src/pipeline.rs` (12 sites)
- `vyre-core/src/dialect/io.rs`, `dialect/migration.rs`, `dialect/toml_loader.rs`
- `vyre-core/src/dialect/logical/{nand,xor,and,nor,or}/op.rs`
- `vyre-core/src/dialect/string_matching/{wildcard_match,substring_find_all,aho_corasick_scan,kmp_find,substring_contains}/op.rs`
- `vyre-core/src/dialect/buffer/{byte_swap_u64,memcmp,memset,memchr}/op.rs`
- `vyre-core/src/dialect/workgroup/{state_machine,string_interner}/op.rs`
- `vyre-core/src/diagnostics.rs` (3 sites)
- `vyre-core/src/routing.rs` (2 sites)
- `conform/vyre-conform-runner/src/cert.rs` (2 sites)

Replace each with `?` propagation or `.expect("Fix: <actionable reason>")`. Zero raw `.unwrap()` in non-test core source.

### E2. Author `scripts/check_no_raw_unwrap.sh`
Referenced in legendary-signoff as missing. Enforce 0 raw `.unwrap()` in `**/src/**`. Add `.expect("Fix: ...")` requirement (the `check_expect_has_fix.sh` gate exists; wire it).

### E3. Delete `catch_unwind` in conform runner
Per completion audit: conform hides panics. Remove — let the harness process exit non-zero so CI catches them.

### E4. `#![forbid(unsafe_code)]` on each core crate
Workspace-level `unsafe_code = "deny"` is set, but per-crate forbid is stronger + boundary-enforced. Add to each of: `vyre-core/src/lib.rs`, `vyre-spec/src/lib.rs`, `vyre-reference/src/lib.rs`, `conform/*/src/lib.rs`, `ops-facades/*/src/lib.rs` (before merging into features).

---

## F. Config surface

### F1. `vyre-core/src/config.rs` + `vyre.toml` schema
Absorb hardcoded constants:
- `MAX_WORKGROUP_BYTES` (`vyre-reference/src/workgroup.rs:17`)
- `DEFAULT_MAX_MATCHES`, `MAX_DFA_MATCHES` (from vyre-wgpu, but expose via core config)
- Any other Tier-A knob scattered across core/reference.

Tier-A config per CLAUDE.md: compiled defaults → `vyre.toml` → CLI. Ship example `vyre.toml.example`.

---

## G. Capability negotiation + gates

### G1. Fix `scripts/check_capability_negotiation.sh:54`
Syntax error: `command substitution: line 54: syntax error near unexpected token '('`. Fix the bash; make the gate functional (currently aborts, masquerading as a failure).

### G2. Verify every `BackendRegistration` advertises `supported_ops`
Audit all `inventory::submit!(BackendRegistration{..})` in `backends/**`, ops-facades, and conform — every one must set `supported_ops`.

### G3. Consolidate composite gates
- Merge `scripts/check_base_monument.sh` (9 prereqs) into `scripts/check_legendary_signoff.sh`.
- Delete the redundant composite.

---

## H. Conform pipeline scale-up

### H1. Expand cert generation
- `conform/vyre-conform-runner` currently only produces xor-1M three-substrate parity cert.
- Iterate: every `OpDefRegistration` × every backend (wgpu, spirv) × every `AlgebraicLaw` in `vyre-spec/src/algebraic_law.rs` × every `WitnessSet`.
- Emit `.internals/certs/<backend>/<op_id>.json` with ed25519 signature.
- Target: 10,000+ certs. Add `witness_set_hash` field to every cert so witness-set revisions invalidate certs automatically.

### H2. Cert schema versioning
- `cert_schema_version: 1` field.
- Any field addition bumps schema; keep a migration helper in `conform/vyre-conform-spec/`.

### H3. Signing key hygiene audit
- No committed private keys anywhere.
- Document key rotation in `docs/cert-signing.md`.

---

## I. Publish hygiene (core-owned crates only)

### I1. Per-crate metadata
For each of `vyre-core`, `vyre-spec`, `vyre-reference`, `conform/*` (after ops-facades removal):
- `[package.metadata.docs.rs]` with `all-features = true`, `rustdoc-args = ["--cfg", "docsrs"]`.
- README.md.
- LICENSE-MIT, LICENSE-APACHE.
- CHANGELOG.md.

### I2. `[patch.crates-io]` rename resolution
Root `Cargo.toml:123-130` aliases `vyre` → `vyre-core` for in-workspace. For external `cargo add vyre`, the crates.io rename must publish cleanly. Run `cargo publish --dry-run` per crate; commit output under `.internals/release/`.

### I3. Squat-defense
- Verify each crate name is claimed on crates.io by the Santh org.
- Don't publish placeholders — only publish when real code ships (per global rule).

---

## J. Execution rules for Agent 1

- Commit directly to `main`. No worktrees.
- No `todo!()`, `unimplemented!()`, `// TODO`, `// FIXME` left behind. LAW 1 + LAW 9.
- No weakening of tests. If a test fails, fix the engine.
- Run `bash scripts/check_legendary_signoff.sh` after each task; goal is 17/17.
- Do NOT touch any file under `vyre-wgpu/`, `backends/spirv/`, `benches/`, `xtask/`, `tests/`, `vyre-macros/`. Those are Agent 2.
- If a change in your territory forces a signature break in a file Agent 2 owns, STOP — write a brief note to `.internals/coordination/agent1-to-agent2-api-break.md` and pick a different task. Never edit across boundaries.

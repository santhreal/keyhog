# Gemini 3.1-pro Execution Plan — Vyre Workspace, 2026-04-18

You are Gemini 3.1-pro operating inside Antigravity with **unlimited usage** on the vyre workspace at
`/media/mukund-thiru/SanthData/Santh/libs/performance/matching/vyre`.

You are working **alongside Claude** (the human's primary orchestrator). Claude is handling:
- Parity test maintenance (`vyre-core/tests/kat_parity.rs`)
- Compile-break triage as you go
- Final publish gate

You own **everything else** on this plan. Commit directly to `main` after each phase completes. **No worktrees, no shims, no `todo!()`, no "documented limitation" comments, no test-weakening, no function bodies that lie.** If you hit a real blocker on a phase, commit partial progress tagged `WIP <phase>: <exact blocker sentence>` and move to the next phase — do not stall.

---

## Current workspace truth (read first)

- `cargo check -p vyre` → clean as of commit `parity test + quiet pre-existing churn`
- Pre-existing engine drift: `primitive.bitwise.shl[1]` produces `01000000` but KAT says `00000000`. Tracked in `vyre-core/tests/kat_parity.rs` KNOWN_FAILURES allowlist. Fix the shl lowering in Phase 5.
- 5 `vyre-conform-*` crates are being **deleted** in Phase 0 (below). The workspace `Cargo.toml` already has them removed from `members`; the crate directories still exist on disk and may have lingering references in non-conform crates.
- Codex agent `codex-5505623d` is concurrently executing Phase 4 (D3 persistent GPU buffers) inside `vyre-wgpu/`. Do NOT touch `vyre-wgpu/src/pipeline.rs`, `vyre-wgpu/src/buffer/`, or anything that obviously overlaps with the persistent-buffer work until that commit lands.

---

## Phase 0 — Conform deletion (finish what Claude started)

The workspace `Cargo.toml` already drops the 5 conform members. You need to:

1. **Delete on disk:**
   ```
   git rm -r vyre-conform
   git rm -r vyre-conform-spec
   git rm -r vyre-conform-enforce
   git rm -r vyre-conform-generate
   git rm -r vyre-conform-runner
   ```

2. **Scrub non-conform references.** Run `rg "vyre[-_]conform" --type rust --type toml` at the workspace root. For every hit outside the 5 deleted directories, rewrite to not depend on conform. Expect to touch:
   - `vyre-sigstore/src/lib.rs` — drop any conform re-exports; sigstore should be pure signing.
   - `vyre-spec/src/*.rs` — spec is self-contained; rip conform-specific traits/types.
   - `vyre-build-scan/src/conform*.rs` — the conform-specific build-scan helpers die with conform. Delete those files entirely (`git rm -r vyre-build-scan/src/conform*`). Update `vyre-build-scan/src/lib.rs` to drop the re-exports.
   - `vyre-reference/src/eval_expr.rs` — probably imports a conform error type; swap to a local one.
   - `vyre-wgpu/src/ext.rs` — any conform hook dies; route through core.
   - `xtask/src/**` — `cmd_generate_tests.rs`, `cmd_mutation_gate.rs`, `cmd_coverage_check.rs`, `cmd_conform_verify.rs`, `paths/conform_root.rs`. **Delete these xtask subcommands and their paths helper**; xtask stays lean.
   - `xtask/src/main.rs` + `xtask/Cargo.toml` — drop the removed subcommands from the clap tree + `[dependencies]`.
   - `demos/rust_lexer_gpu/src/lib.rs`, `demos/rust_parser_gpu/src/lib.rs` — demos that import `vyre_conform` lose that import; they should still parse/lex and expose a public API via vyre/vyre-reference directly.
   - `vyre-core/src/ops/registry/gate.rs` — any conform coupling dies.
   - `vyre-core/src/bin/vyre_new_op/*.rs` — op-scaffold generator should not generate conform spec files anymore. Strip.
   - `README.md`, `ARCHITECTURE.md`, `THESIS.md`, `VISION.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, all `docs/**.md` — update prose to reflect that conformance = `scripts/check_*.sh` + `vyre-core/tests/kat_parity.rs`, not a separate crate.

3. **Delete the audit backlog entries that conform deletion resolves.** Open `docs/audits/CONSOLIDATED_FINDINGS_2026-04-18.md` and update `status: closed_by_deletion` for every finding whose scope is one of the 5 deleted crates. Add a note at the top: "Conform deletion 2026-04-18 closed N findings in bulk."

4. **Commit.** Message:
   ```
   Delete conform framework: 5 crates, 15K+ LoC

   The conform framework cost more attention than vyre itself for a
   negative ROI. What actually earned its keep — CPU↔registered-program
   parity across the 82 primitive KAT vectors — now lives as a plain
   integration test at vyre-core/tests/kat_parity.rs, and the Laws A–H
   are standalone CI scripts under scripts/check_*.sh.

   Deleted crates: vyre-conform, vyre-conform-spec, vyre-conform-enforce,
   vyre-conform-generate, vyre-conform-runner.

   All non-conform references scrubbed. Audit backlog entries scoped to
   these crates marked closed_by_deletion.
   ```

**Success criteria for Phase 0:**
- `rg "vyre[-_]conform" --type rust --type toml` returns zero matches.
- `cargo check --workspace` returns 0 errors.
- `cargo test -p vyre --test kat_parity` passes (81/82, one allowlisted).
- `bash scripts/rebuild_status.sh` runs all 6 laws and reports cargo health green.

---

## Phase 1 — D4: Remove vyre-build-scan syn reliance

`vyre-build-scan` currently parses 1100+ Rust source files with `syn` during `cargo build` to emit static registries into `OUT_DIR`. This destroys incremental compile caching and breaks cross-compilation. After Phase 0, the only remaining consumer of build-scan is registry generation for `vyre-core` (and maybe a handful of other crates that still `include!` generated registries).

1. **Audit every consumer.** `rg "vyre_build_scan::" --type rust` — enumerate every `build.rs` that calls it.

2. **Replace each generated registry with `inventory::submit!`.**
   - For each source file that currently has `pub const REGISTERED: Foo = Foo;`, replace with `inventory::submit! { Foo::new_constant() }` (adjust to match the trait-object shape). Follow the existing `NodeKindRegistration` pattern in `vyre-core/src/ir/model/node_kind.rs` — it's the template.
   - The `include!("../generated/foo_registry.rs")` lines in consumer files become direct `inventory::iter::<_>().collect::<Vec<_>>()` calls inside the consumer code. Cache the Vec in a `OnceLock` if the caller is hot-path.
   - Delete every `build.rs` that was only scanning for registries. For each crate whose `build.rs` is now empty (`fn main() {}`), just delete the `build.rs` file and remove the `[build-dependencies]` section from `Cargo.toml`.

3. **Prune `vyre-build-scan` itself.**
   - After (2), `vyre-build-scan` has no consumers left. Delete the crate entirely: `git rm -r vyre-build-scan` + remove from workspace members. Drop the workspace-dep entry if any Cargo.toml still lists it.
   - If (2) leaves a genuine callsite that *does* need dynamic scanning (e.g., xtask commands the human wants to keep), extract just that one function into the xtask that uses it and delete the crate wrapper.

4. **Verify incremental compile wins.** `touch vyre-core/src/lib.rs && time cargo check -p vyre` — should be ≤2 s. Before this change, that used to be 30 s+ because every rebuild re-parsed 1100 files.

5. **Commit.** Message:
   ```
   D4: drop vyre-build-scan — static inventory::submit! registration only

   Previously every cargo build parsed 1,100+ Rust files with syn to
   emit static registries. Incremental compile was destroyed and
   cross-compilation broke. All registries now use inventory::submit!
   in-file, consumers call inventory::iter::<_>() at their point of
   use, and build.rs scripts are gone.

   vyre-build-scan crate deleted.
   ```

---

## Phase 2 — D1: Commit to naga AST only

The `check_no_string_wgsl.sh` script already catches `push_str`/`format_args!` with WGSL tokens outside `vyre-wgpu/`. Verify it's complete and close any remaining leaks.

1. **Run** `bash scripts/check_no_string_wgsl.sh`. Expected: pass. If it fails, fix each call site to build the corresponding `naga::Module` / `naga::Handle<Expression>` instead of concatenating strings. The emission path is `vyre-wgpu/src/lowering/naga_emit.rs`.

2. **Tighten the guard.** The current script allows ≤3 `push_str` calls with WGSL tokens inside `vyre-wgpu/`. Tighten to **zero** — every shader token in vyre-wgpu must come from `naga::back::wgsl::write_string`. Search vyre-wgpu/ for any residual manual WGSL strings (fallback paths, helper preludes, hand-written entrypoint wrappers). Port each to naga AST.

3. **Delete any "wrap_shader" / "prelude_for_config" helpers that emit WGSL text.** These were tripwire shortcuts. Replace with naga AST nodes that produce the same final WGSL via `naga::back::wgsl::write_string`.

4. **Commit.** Message:
   ```
   D1: vyre compiles exclusively through the naga AST

   check_no_string_wgsl.sh now enforces ZERO push_str/format_args!
   with WGSL tokens anywhere in the workspace including vyre-wgpu.
   Every lowering path constructs naga::Module / Handle<Expression>
   nodes and emits text only via naga::back::wgsl::write_string.
   ```

---

## Phase 3 — D2: Open the IR (Expr + Backend)

This is the biggest architectural move. **Think hard before coding** — the enum-vs-trait-object question isn't cosmetic, and post-Phase-0 the practical blast radius is much smaller.

1. **`pub enum Expr` in `vyre-core/src/ir/model/expr.rs`.** It already has an `Opaque(Arc<dyn ExprNode>)` escape hatch (that's what closed Law A in the hybrid allowance). The question is whether the enum stays as the ergonomic default with Opaque as the extension point, or whether Expr disappears entirely into `Arc<dyn ExprNode>` everywhere.
   - Option A (hybrid): keep as-is, document `Opaque` as the only way to add a new expression kind in a downstream crate, and delete the `[allow_pattern]` from Law A's script so the structural check catches only enums that *don't* have an extension hatch. **Score: low disruption, preserves ergonomics, honest about open-world. Recommended.**
   - Option B (fully trait-object): every `Expr` becomes `Arc<dyn ExprNode>`. Every consumer pattern-match becomes a dispatch call. ~500 call sites touched. Preserves the architectural purity of THESIS.md but costs a week of churn on a codebase that will keep churning anyway.
   - **Pick Option A.** Execute: ensure every IR consumer (optimizer passes, validators, wire encode/decode, reference interpreter, wgpu lowering) includes an explicit `Expr::Opaque(_)` arm with correct behaviour (forward to trait-object methods, not a silent no-op). No `_ => unreachable!()`, no `_ => panic!()`. The Opaque arm is real.

2. **`pub enum Backend` in `vyre-core/src/ops/metadata.rs`.** Currently `Wgsl | Cuda | SpirV | Metal | Extension(ExtensionBackend)`. The Extension variant makes it nominally open. Inspect `ExtensionBackend` — does it carry the trait-object? If yes, Backend already is hybrid-open. If no, introduce `ExtensionBackend(Arc<dyn BackendKind>)` where `BackendKind: Debug + Send + Sync + 'static { fn name(&self) -> &str; fn id(&self) -> BackendId; ... }`. Every match site gets an `Extension(kind) => kind.something()` arm.

3. **Document the extension contract.** Update `ARCHITECTURE.md` with a new section "Adding a new Expr kind" and "Adding a new Backend" — include a minimal working example (`Arc<dyn ExprNode>` impl + `impl ExprNode for MyNode` + usage), and link from THESIS.md.

4. **Tests.** Add `vyre-core/tests/open_ir.rs` that:
   - Constructs a custom `ExprNode` impl in the test, wraps as `Expr::Opaque`, runs it through the reference interpreter, asserts correct output.
   - Constructs a custom `BackendKind` impl, registers via inventory, looks it up by id, dispatches a trivial program through it.

5. **Commit.** Message:
   ```
   D2: open the IR — document the extension hatch as the sole path

   Expr and Backend keep their ergonomic enum surface but every match
   site now handles Opaque / Extension with real behaviour, not a
   wildcard panic. ARCHITECTURE.md documents the full extension
   contract with a working example, and tests/open_ir.rs exercises a
   custom ExprNode + BackendKind end-to-end.
   ```

---

## Phase 4 — D3 wait-point

Codex is executing D3 (persistent GPU buffers) in `vyre-wgpu/`. Let Codex finish. Do NOT touch `vyre-wgpu/src/pipeline.rs`, `vyre-wgpu/src/buffer/`, or the new `persistent_dispatch.rs` test until Codex commits.

Once Codex's D3 commit lands on main (watch `git log --oneline`), run these verification steps:
- `cargo test -p vyre-wgpu --test persistent_dispatch` passes on the RTX 5090
- The BindGroup cache hit ratio assertion passes
- Allocation count assertion is met

If Codex's commit is broken, fix the smallest thing and re-run. Do not rewrite the whole feature.

---

## Phase 5 — Engine work (post-conform)

After Phase 0-4 the architecture is clean. Now fix the engine drift that parity surfaced and the F-fixes that are still real (some were conform-coupled and died with Phase 0).

1. **Fix the `primitive.bitwise.shl[1]` drift.**
   - Vector: input `0100000000000000` (LE u32 pair 1 and 0) → expected `00000000` (shl 1 << 0 by 0 bits = 1 << 0 — wait, verify). Trace the discrepancy:
     - Look at `vyre-core/src/ops/primitive/bitwise/shl.rs` or wherever the shl program is constructed.
     - Run the reference interpreter on the exact input bytes, print intermediate expression values.
     - The bug is either in the IR construction or in the reference evaluator's BinOp::Shl handling.
   - Fix the bug, **then remove the entry from `KNOWN_FAILURES`** in `vyre-core/tests/kat_parity.rs`. The allowlist self-audits: an entry that no longer fails must be dropped.
   - Commit: `shl: fix primitive.bitwise.shl[1] drift; remove from KNOWN_FAILURES`.

2. **F3 — wire-format schema versioning + op-id-keyed decoder registry.**
   - Add `SCHEMA_VERSION: u32 = 2;` constant in `vyre-core/src/ir/serial/wire/mod.rs`.
   - Encoder: emits `[magic][schema_version][flags][...]`.
   - Decoder: reads the version word; if not 2, returns `WireError::VersionMismatch { expected: 2, found: x }`.
   - Op-id-keyed payload deserialize: each `NodeKind` registers its decoder via `inventory::submit!` alongside its encoder. `from_wire` looks up the decoder by op_id, calls it with the payload slice.
   - Tests: encode→decode round-trip for 50 programs. Mismatched version asserts `WireError::VersionMismatch`. Unknown op_id asserts a distinct `WireError::UnknownOp { op_id }`.
   - Commit: `F3: wire-format schema version + op-id-keyed decoder registry`.

3. **F4 — `NodeKind::interpret` method.**
   - Add `fn interpret(&self, ctx: &mut InterpContext) -> Result<(), Error>;` to the `NodeKind` trait.
   - Migrate `vyre-reference/src/interp.rs` and `hashmap_interp.rs` to walk by `node.interpret(&mut ctx)` instead of matching on variants.
   - Commit: `F4: NodeKind::interpret trait-driven interpreter`.

4. **F8 — split Backend capability traits.**
   - Split current `Backend` into `Executable` (can dispatch a compiled artifact), `Compilable` (can lower a Program), `Streamable` (can pipe data in chunks).
   - Blanket-impl the legacy `Backend` for `T: Executable + Compilable` so existing callers don't break.
   - Update `vyre-wgpu` to impl all three where appropriate; `vyre-reference` impls Executable only.
   - Commit: `F8: split Backend into Executable/Compilable/Streamable`.

5. **F10 — progressive lowering.**
   - Define `BackendIR` as an associated type on `Compilable`.
   - `vyre-wgpu` introduces `WgpuIR` (wraps a `naga::Module` plus resource bindings) as its `BackendIR`.
   - Lowering becomes: `Program → BackendIR::lower(program) → BackendIR::emit() → Target`. Each stage is independently testable.
   - Commit: `F10: progressive lowering — Program → BackendIR → Target`.

6. **DUP-24 — absorb `PipelineCache` into `TieredCache`** (in vyre-wgpu; coordinate with Codex's D3 if in flight).

7. **DUP-30 — unify the `Value` enums.** Currently vyre-core, vyre-reference, and the (now-deleted) conform each had their own `Value`. After Phase 0 there are at most two left; merge them into `vyre-spec::Value` (or wherever the canonical lives) and delete duplicates.

8. **DUP-32 — delete free-fn `run()` in favor of explicit trait usage.**

---

## Phase 6 — Remaining audit drain

The consolidated findings tracker at `docs/audits/CONSOLIDATED_FINDINGS_2026-04-18.md` still has open entries that survived Phase 0. Pick every one tagged `status: open` whose scope is:
- `vyre-core`
- `vyre-wgpu`
- `vyre-reference`
- `vyre-primitives`
- `vyre-sigstore`
- `vyre-spec`
- `vyre-macros`
- `vyre-std`

For each finding, implement the fix from the `suggested:` field. Update status to `fixed` with commit SHA. Commit per finding or per tight batch (≤5 closely-related). The doctruth audit (`docs/audits/AUDIT_2026-04-18_doctruth.md`) has 25 findings that are pure prose fixes — burn through those first, they're cheap and deflate the backlog fast.

---

## Phase 7 — API terseness façade

Acceptance test: the following must be the full user-facing code to run a XOR program on the GPU:

```rust
use vyre::prelude::*;

fn main() {
    let out = vyre::xor(&[0xFF, 0x00, 0xFF, 0x00], 0xA5).run_gpu();
    println!("{:02x?}", out);
}
```

To get there:
1. Create `vyre-core/src/prelude.rs` re-exporting the 10–15 types a 90th-percentile user needs.
2. Add a `vyre::xor(input, key)` top-level helper that builds the Program.
3. Add `impl Program { fn run_gpu(&self) -> Vec<u8> }` and `fn run_cpu(&self) -> Vec<u8>` methods that hide the backend construction, dispatch, and readback.
4. Tests: `examples/hello_vyre/src/main.rs` or a doctest in `vyre-core/src/lib.rs` that demonstrates the 3-line XOR.

Commit: `API: 3-line XOR façade — vyre::xor(...).run_gpu() works out of the box`.

---

## Phase 8 — Final gate

Run the full pre-publish gate Claude rewrote: `bash scripts/publish-dryrun.sh`. It must return `READY TO PUBLISH`. Fix every failure before that line is green. Do not skip any gate.

Commit: `vyre: full pre-publish gate green — ready for crates.io release`.

---

## Rules of engagement (apply everywhere above)

- **Commit direct to main.** No worktrees, no branches, no PRs.
- **Narrow `cargo check -p <crate>`** during iteration — workspace check is for end-of-phase verification only. The dispatch wrapper times out at 124 s; narrow checks finish in 5–30 s.
- **Never silence a warning with `#[allow]` as an excuse not to fix it.** The fix is the point.
- **Never delete functionality you can't reimplement.** When in doubt, rewire instead of delete. Deleting ~500 LoC of engine code because "it looked dead" has happened twice this project — the answer was always "it was load-bearing, rewire to the new API."
- **No placeholder test assertions.** No `let _ = result`. Every test asserts something meaningful.
- **When you write new code, treat it as production code.** Doc comments on every public item. Error messages in "Fix: ..." format. `# Errors` and `# Panics` sections where relevant.
- **GPU is always present.** Do not write `#[cfg(not(feature = "gpu"))]` fallback branches that silently pretend there's no GPU. The fleet has RTX 5090 (32 GB), RTX 4090, and more. `nvidia-smi` confirms.

---

## Progress reporting

After each phase, print:
```
Phase N complete — committed as <SHA>. Next: Phase N+1.
```

If you hit a blocker, print:
```
Phase N BLOCKED — <one-sentence cause>. Committed WIP as <SHA>. Proceeding to Phase N+1.
```

Do not pause for approval between phases. Execute the whole plan.

---

## File that already exists as your starting point

`vyre-core/tests/kat_parity.rs` is the new parity test. Don't rewrite it. If you need to change the `KNOWN_FAILURES` allowlist (Phase 5.1 removes the shl entry), keep the allowlist self-audit logic intact — that's the feature.

Good luck. Claude is watching the git log and will step in if something goes structurally wrong.

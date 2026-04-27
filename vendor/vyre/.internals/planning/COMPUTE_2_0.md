# Vyre Compute 2.0 — Master Architectural Blueprint

Long-horizon plan. Does not need to execute this week. Exists so every
future decision can be measured against it. If a commit makes the shape
below harder to reach, the commit is wrong.

---

## 0. What this document is

A durable architectural blueprint for transitioning vyre from a
1,244-file tangled monocrate into a zero-abstraction compiler foundation
for Compute 2.0 — an execution model where the CPU is a receptionist and
the GPU dictates its own dispatch schedule against data that never
entered userspace.

This document addresses two problems simultaneously, because the two are
inseparable:

1. **Folder scatter.** 1,244 `.rs` files in vyre-core, 479 under `dialect/`,
   426 under `ops/`, 12 top-level modules in `lib.rs`, application
   semantics mixed with IR primitives mixed with driver-layer caching.
2. **Dependency tangle.** The layering is a cyclic DAG disguised as a
   module tree. Foundation-shaped files (`ir/transform/compiler/`)
   import from application-shaped files (`ops::AlgebraicLaw`). Dialect
   and ops cross-reference each other with no hierarchy. Nothing in
   core is extractable as its own crate because every file reaches
   sideways.

Both must be fixed. Re-shuffling folders without untangling imports
produces neat-looking scatter. Untangling imports without restructuring
folders produces 1,244 clean files nobody can navigate.

---

## 1. The Vision — Compute 2.0

Vyre is not a library. It is an operating execution layer with these
properties:

- **CPU as receptionist.** Tokio handles accept(), memory allocation,
  OS setup. It does not enter the compute loop. No userspace memcpy
  in the hot path.
- **Zero-copy ingestion.** NVMe → `io_uring` (`wireshift`) → kernel-mapped
  Vulkan external memory (`kernelkit`) → GPU-visible buffer (`mempool`).
  A byte read from SSD touches kernel DMA engines only; it never
  lands in userspace heap.
- **Indirect execution.** Orchestration thread (`fusedpipe`) fires one
  `dispatch_workgroups_indirect`. From there the GPU reads the next
  dispatch shape from a memory array it itself produced. CPU polls
  completion but never authors the inner loop.
- **Persistent megakernel.** A long-running compute shader reads work
  items from a GPU-side ring buffer and writes results to another
  ring. Scan-rate throughput, PCIe dispatches counted per-scan not
  per-input.
- **Branchless SIMT where it matters.** The IR keeps `if`/`loop` for
  authorial clarity. An optimizer pass lowers divergent control flow
  to `select` + predicated execution where cost analysis says that
  wins. Never a blanket rule; always an earned transformation.

Each of these requires a compiler foundation that does not know what
malware scanning is.

---

## 2. What's wrong now — measured

### 2.1 Folder scatter

```
vyre-core/src/
├── lib.rs                  12 top-level pub mods — no layering
├── ir/                     114 files    (foundation-shaped; partially)
├── ops/                    426 files    (mixed primitive + application)
├── dialect/                479 files    (application semantics)
├── optimizer/               12 files    (buried, overlaps with ir/transform)
├── backend/                  4 files    (should be a driver crate)
├── lower.rs                  1 file     (contract; OK)
├── pipeline.rs             274 lines    (backend caching — wrong layer)
├── routing.rs              219 lines    (runtime PGO — wrong layer)
├── cert.rs + cert/           1 file     (conform concern, not core)
├── diagnostics.rs          564 lines    (LSP rendering; borderline)
├── introspection.rs                     (coverage-matrix tooling; meta)
├── test_migration.rs                    (temporary scaffolding in prod)
├── routing/                  1 file
├── fuzz/                     4 files
└── bin/                     17 files    (codegen binaries inside the lib crate)
```

Out of 1,244 files in vyre-core:
- ~75% belong in a stdlib layer that doesn't exist as a crate
- ~10% belong in a driver/runtime layer that doesn't exist as a crate
- ~5% is meta-level tooling (introspection, test_migration, bin) that
  doesn't belong in a shipped library at all
- ~10% is actual foundation

### 2.2 Dependency tangle — the reverse imports

Measured by `grep -rn "use crate::X" Y/`:

- **IR → ops (foundation importing application primitives):**
  - `ir/transform/compiler/dominator_tree.rs:15` uses `ops::AlgebraicLaw`
  - `ir/transform/compiler/typed_arena.rs:13` uses `ops::AlgebraicLaw`
  - `ir/transform/compiler/dataflow_fixpoint.rs:14` uses `ops::AlgebraicLaw`
  - `ir/transform/compiler/recursive_descent.rs:13` uses `ops::AlgebraicLaw`
  - `ir/transform/compiler/string_interner.rs:14` uses `ops::{AlgebraicLaw, IntrinsicDescriptor}`
  - `ir/transform/compiler/visitor_walk.rs:13` uses `ops::AlgebraicLaw`
  - `ir/engine/token_match_filter.rs:9` re-exports `ops::string::tokenize_gpu::TokenType`

  **Read this as:** the IR transformation layer (CSE, DCE, compiler
  primitives) cannot exist without knowing what application ops claim
  about algebraic laws. An IR-level pass should not care that the op it
  is folding is "string tokenization" vs "arithmetic add."

- **Ops ↔ dialect (no hierarchy between two sibling trees):**
  - `ops/registry/lookup.rs:1` uses `dialect::registry::DialectRegistry`
  - `ops/registry/lookup.rs:2` uses `dialect::interner::intern_string`
  - 96 files under `dialect/` reach into `ir/`, `ops/`, or `optimizer/`

  **Read this as:** `ops/` and `dialect/` are two trees claiming the
  same responsibility. There is no single answer to "where does a new
  primitive go" because both trees exist.

- **Wrong-layer residents at vyre-core/src/ root:**
  - `pipeline.rs` — compiled-pipeline caching. This is driver/runtime
    concern. Core IR should not know what a backend is.
  - `routing.rs` + `routing/` — runtime profile-guided variant selection.
    Runtime concern; belongs in driver.
  - `cert.rs` + `cert/` — ed25519 certificate signing. Conform concern;
    belongs in `vyre-conform-*`.
  - `diagnostics.rs` — 564 lines of LSP-shaped renderers. Tooling layer,
    not IR.
  - `introspection.rs`, `test_migration.rs` — meta-level, don't belong
    in a shipped library at all.

### 2.3 Why this blocks innovation

- **New execution model (megakernel, persistent, indirect):** requires
  edits in `ops/`, `dialect/`, `ir/engine/`, `backend/`, and
  `pipeline.rs`. No single place owns "what running means." Every
  execution-model experiment is a 5-module cascade.
- **New lowering target (PTX, Metal, Photonic):** `dialect/`'s 479 files
  each declare their own lowering hooks. Adding a target means visiting
  all 479 plus `lower.rs` plus the naga pipeline in `vyre-wgpu`. One
  day of typing, not one day of thinking.
- **New frontend consumer (pyrograph, surgec, warpscan):** cannot depend
  on a slim "IR-only" library. Consuming vyre pulls blake3, inventory,
  naga, every dialect, every CVE detector. Bloat by construction.
- **Replace a dialect:** cannot be done surgically. The dialect
  intermingles with ops which intermingles with the IR transformation
  layer. A security-detection redesign means editing files the CSE
  pass imports from.

Each of these is a symptom of the same root: **there is no layering
rule that the compiler enforces.** Module visibility in a single crate
(`pub(crate)`) is a social contract. Crate boundaries are the only
structural enforcement Rust gives you. Vyre uses none of them.

---

## 3. The Layering Rule

Exactly four layers. A strict DAG. Cross-layer imports go DOWN only.
Violations are compile errors, not review findings.

```
                 ┌───────────────────────────────────────────┐
                 │   applications      (surgec, pyrograph)    │
                 │   consumers, no layer name                 │
                 └────────────────┬──────────────────────────┘
                                  │ depends on
                 ┌────────────────▼──────────────────────────┐
                 │   stdlib                                   │
                 │   exiled dialects: pattern, hash, dataflow│
                 │   crypto, compression, security, graph    │
                 │   each = one crate, one responsibility     │
                 └────────────────┬──────────────────────────┘
                                  │ depends on
                 ┌────────────────▼──────────────────────────┐
                 │   driver                                   │
                 │   registry, lowering, runtime, pipeline   │
                 │   wgpu, spirv, pipeline-wireshift etc.    │
                 └────────────────┬──────────────────────────┘
                                  │ depends on
                 ┌────────────────▼──────────────────────────┐
                 │   foundation                               │
                 │   IR, type system, memory model,           │
                 │   hardware intrinsics, visit traits, wire │
                 │   ZERO application semantics              │
                 └───────────────────────────────────────────┘
```

Enforcement rules (machine-checkable):

- **R1.** `vyre-foundation-*` crates have zero deps on `vyre-driver-*`,
  `vyre-stdlib-*`, or `vyre-*` consumers. CI: `cargo metadata` walk.
- **R2.** `vyre-driver-*` crates have zero deps on `vyre-stdlib-*`.
  Drivers dispatch programs; they do not know the algorithms.
- **R3.** `vyre-stdlib-*` crates depend on `vyre-foundation-*` only.
  They do not depend on each other. Two stdlib crates share concepts
  via foundation types or not at all.
- **R4.** No workspace member re-exports from a layer it shouldn't name.
  (A stdlib crate cannot re-export a driver type.)
- **R5.** `vyre-reference` depends on `vyre-foundation-*` only. The
  oracle knows IR; it does not know wgpu, registry, or dialects.
- **R6.** `vyre-conform-*` depends on foundation + reference, not
  stdlib. Certs are foundation-level proofs.

These rules make the 10-year test automatic: a structure that passes R1–R6
cannot accidentally tangle, because every mis-import is `cargo build`
saying no.

---

## 4. Target crate graph

```
vyre-foundation/                     [FOUNDATION]
├── vyre-foundation-ir               Expr / Node / BasicBlock / Program
├── vyre-foundation-type             u8..u64, i8..i64, f16..f64, ptr, vec2-4
├── vyre-foundation-memory           std430 layout, buffer decl, align rules
├── vyre-foundation-intrinsics       add/sub/mul/div, bitwise, atomics, subgroup
├── vyre-foundation-visit            ExprVisitor, NodeVisitor, Lowerable (frozen)
├── vyre-foundation-wire             binary wire format encode/decode
├── vyre-foundation-validate         structural validation (no dialect knowledge)
└── vyre-foundation-extension        Opaque IDs, inventory collection point

vyre-optimizer/                      [FOUNDATION-TIER passes]
├── vyre-optimizer-cse               common-subexpression elimination
├── vyre-optimizer-dce               dead-code elimination
├── vyre-optimizer-inline            call inlining
├── vyre-optimizer-branch-flatten    if/else → select where profitable
├── vyre-optimizer-vectorize         scalar → vec lowering
└── vyre-optimizer-validate          semantic validation (math/memory rules)

vyre-driver/                         [DRIVER]
├── vyre-driver-registry             DialectRegistry, frozen-index lookup
├── vyre-driver-lowering             LoweringTable, per-target dispatch
├── vyre-driver-runtime              device acquisition, buffer pool, cache
├── vyre-driver-pipeline             compiled-pipeline persistence (today's pipeline.rs)
├── vyre-driver-routing              runtime PGO variant selection
├── vyre-driver-naga                 foundation IR → naga::Module
├── vyre-driver-wgpu                 wgpu backend, dispatch, buffer pool
├── vyre-driver-spirv                SPIR-V emitter
├── vyre-driver-indirect             indirect dispatch + GPU-side work queue
├── vyre-driver-megakernel           persistent-kernel mode
└── vyre-driver-diagnostics          LSP-shaped error rendering

vyre-pipeline/                       [DRIVER-TIER, Compute 2.0]
├── vyre-pipeline-wireshift          io_uring binding
├── vyre-pipeline-mempool            NUMA-aware zero-copy ring
├── vyre-pipeline-kernelkit          Vulkan external memory mapping
├── vyre-pipeline-fusedpipe          stage-graph lifecycle
└── vyre-pipeline                    GpuStream = SSD → GPU → results

vyre-stdlib/                         [STDLIB]
├── vyre-stdlib-pattern              DFA scan, Aho-Corasick, regex-lite
├── vyre-stdlib-hash                 blake3, fnv1a, xxhash, entropy
├── vyre-stdlib-string               substring find, wildcard, KMP
├── vyre-stdlib-crypto               chacha20, ed25519, sha256
├── vyre-stdlib-compression          gzip, lz4, base64
├── vyre-stdlib-dataflow             bitset fixpoint, BFS reachability, dominator
├── vyre-stdlib-graph                CSR graph, adjacency traversal
├── vyre-stdlib-math                 transcendentals, vector algebra
├── vyre-stdlib-logical              and/or/xor compositions
├── vyre-stdlib-workgroup            workgroup-scoped primitives
└── vyre-stdlib-security             YARA-style detector composites

vyre-reference/                      [ORACLE]
vyre-conform-spec/                   [PROOFS]
vyre-conform-runner/                 [PROOFS]
vyre-spec/                           [frozen data contracts]
vyre-macros/                         [proc macros]

surgec/                              [consumer — rule compiler]
pyrograph/                           [consumer — taint frontends + stdlib-dataflow impl]
warpscan/                            [consumer — supply chain scanner]
```

Total: ~40 crates instead of one 1,244-file god-crate. Each crate
< 500 LoC average, most < 300. Each has a README, CHANGELOG, docs.rs
metadata, independent semver.

---

## 5. Folder discipline within each crate

Each crate follows the same template so a Fortune-500 engineer opens
any one and sees the same shape:

```
vyre-<layer>-<name>/
├── Cargo.toml                       layer-appropriate deps only
├── README.md                        one paragraph + example
├── CHANGELOG.md
├── LICENSE-{MIT,APACHE}
├── src/
│   ├── lib.rs                       pub use re-exports ONLY
│   ├── <primary-concept>.rs         ≤ 300 lines
│   ├── <secondary-concept>.rs
│   └── <submodule>/
│       ├── mod.rs                   ≤ 50 lines, re-exports
│       └── <piece>.rs               ≤ 300 lines
├── tests/
│   ├── unit/
│   ├── adversarial/
│   ├── property/
│   └── gap/
├── benches/
│   └── <primary-concept>.rs
└── docs/
    └── frozen/                      byte-stable contract snapshots
```

No file over 500 lines. No `bin/` inside a library crate. No
`test_migration.rs` in prod. No `introspection.rs` mixing meta-tooling
with runtime. Meta tools live in `xtask/`, not in shipped crates.

---

## 6. Primitive taxonomy — what goes where

The line between foundation and stdlib is the question that matters.
Rule: **a primitive is foundation iff it can be defined without naming
a domain.**

**Foundation** (can be defined in pure math/hardware terms):
- Arithmetic: add, sub, mul, div, mod, fma
- Bitwise: and, or, xor, not, shl, shr, popcount, clz, ctz
- Atomics: atomic_add, atomic_or, atomic_xchg, compare_exchange
- Subgroup: ballot, broadcast, reduce, scan, shuffle
- Memory: load, store, atomic_load, atomic_store
- Control: select, loop (bounded), barrier, indirect_dispatch
- Structure: CSR traversal (graph-agnostic), bitset fixpoint (dataflow-agnostic)
- Dispatch: async_load, async_wait, persistent_megakernel_loop

**Stdlib** (names an application domain):
- Aho-Corasick scan, DFA scan (pattern matching)
- BLAKE3, FNV1a, xxhash (hashing algorithms)
- KMP, substring find, wildcard match (string algorithms)
- ChaCha20, SHA-256, ed25519 (cryptography)
- gzip, lz4, base64 (compression/encoding)
- detect_xss, detect_ssrf, detect_url (security detectors)
- YARA-style rules (detector composites)

**Borderline cases resolved:**
- **Taint dataflow fixpoint** → foundation (`vyre-stdlib-dataflow` wraps
  it for consumers, but the primitive itself is domain-free: reaching
  definitions, liveness, and taint all reduce to the same bitset
  fixpoint over a CSR).
- **String interner** → foundation (hash table on GPU is a primitive;
  strings being the payload is incidental).
- **Typed arena** → foundation (region allocator; generic over element
  type).
- **Recursive descent** → stdlib (parsing is a domain with grammars;
  the primitive is `vyre-stdlib-pattern` or `vyre-stdlib-parse`).
- **Category combination tables** (source × sink → dangerous) → stdlib,
  data-driven via TOML, lives in `vyre-stdlib-security` or pyrograph.

---

## 7. Branchless SIMT — the honest semantics

Not "IR forbids branches." That destroys authorial clarity and doesn't
match how GPU compilers actually work (naga, DXC, spirv-cross all
handle both shapes).

The IR keeps `Node::If`, `Node::Loop`, `Expr::Select`. The optimizer
pass `vyre-optimizer-branch-flatten` runs BEFORE lowering:

- **Uniform branches stay as if.** Naga emits `if` in WGSL; wavefront
  uniformity is preserved.
- **Divergent branches with small bodies** convert to `select` +
  predicated side-effects. Cost model: both-sides-always-executed
  cost < expected divergence cost × divergence probability.
- **Divergent branches with large bodies** stay as `if`. Warps pay the
  divergence tax; the bodies were too expensive to always-run.
- **Loop-carried divergent branches** get special treatment — often
  flatten to masked iteration + early-exit via ballot.

The pass emits per-node metadata (`branch_flattenable: bool`,
`uniformity_proven: bool`, `estimated_divergence: f32`) so backends
can make informed decisions. The CPU reference doesn't care; lane
uniformity is a GPU concept.

Result: rule authors write `if score >= 80 { critical }`. Backends
emit whichever GPU shape is fastest for that exact branch. No author
effort; no perf regression.

---

## 8. Phase plan

Each phase ends with a buildable, shippable workspace. No phase leaves
the repo broken.

### Phase 0 — Stabilize current vyre

Delivered by the existing AGENT1/AGENT2 plans in `.internals/plans/`.
Prereq for everything below:
- vyre-core builds green
- `compute_fixpoint` wired, visitor traits restored, OpSpec purged
- No wrong-direction imports in `ir/transform/compiler/`
- Workspace-level `cargo build` succeeds

### Phase 1 — Cut the reverse imports

Targets the 7 IR-into-ops violations directly:
1. Move `AlgebraicLaw` out of `ops/` into `vyre-spec` (it's already
   a contract, not an application concept).
2. Move `IntrinsicDescriptor` into foundation.
3. Delete `ir/engine/token_match_filter.rs::TokenType` re-export; the
   token match filter is a pattern concept, move the whole file to
   `vyre-stdlib-pattern`.
4. `ops/registry/lookup.rs` merges into `dialect/registry.rs`, then
   becomes `vyre-driver-registry`.

Done when: `grep "use crate::ops::" vyre-core/src/ir/` returns empty.
`grep "use crate::dialect::" vyre-core/src/ops/` returns empty.

### Phase 2 — Extract vyre-foundation

New workspace member. Move:
- `vyre-core/src/ir/model/` → `vyre-foundation-ir/src/`
- `vyre-core/src/ir/visit/` → `vyre-foundation-visit/src/`
- `vyre-core/src/ir/serial/wire/` → `vyre-foundation-wire/src/`
- `vyre-core/src/ir/validate/` → `vyre-foundation-validate/src/`
- `vyre-core/src/memory_model.rs` → `vyre-foundation-memory/src/`
- `vyre-core/src/ir/extension.rs` → `vyre-foundation-extension/src/`

vyre-core keeps `pub use vyre_foundation_*::*` for back-compat during
transition. Every downstream consumer migrates one at a time.

Acceptance: `cargo build -p vyre-foundation-ir` with zero deps on
`naga`, `wgpu`, `inventory`, `blake3`. Only `serde`, `thiserror`,
`tracing`, `smallvec`.

### Phase 3 — Extract vyre-optimizer

New crates for each pass. Move:
- `vyre-core/src/ir/transform/optimize/cse/` → `vyre-optimizer-cse/src/`
- `vyre-core/src/ir/transform/optimize/dce/` → `vyre-optimizer-dce/src/`
- `vyre-core/src/ir/transform/inline/` → `vyre-optimizer-inline/src/`
- NEW: `vyre-optimizer-branch-flatten/` (didn't exist before)
- NEW: `vyre-optimizer-vectorize/`

Each depends on `vyre-foundation-*` only.

### Phase 4 — Extract vyre-driver

Move:
- `vyre-core/src/dialect/registry.rs` + `op_def.rs` + `lowering.rs` +
  `dialect.rs` + `interner.rs` → `vyre-driver-registry/src/`
- `vyre-core/src/backend/` → `vyre-driver-backend-trait/src/`
- `vyre-core/src/pipeline.rs` → `vyre-driver-pipeline/src/`
- `vyre-core/src/routing.rs` + `routing/` → `vyre-driver-routing/src/`
- `vyre-core/src/diagnostics.rs` → `vyre-driver-diagnostics/src/`
- `vyre-wgpu/` → `vyre-driver-wgpu/` (rename for layer consistency)
- `backends/spirv/` → `vyre-driver-spirv/`

`vyre-wgpu/src/megakernel.rs` becomes `vyre-driver-megakernel/` with
a real implementation (it's a 1-file stub today).

### Phase 5 — Exile stdlib dialects

One crate per dialect, migrated in order of independence:
1. `vyre-stdlib-logical` (nothing depends on it)
2. `vyre-stdlib-math`
3. `vyre-stdlib-hash`
4. `vyre-stdlib-string`
5. `vyre-stdlib-pattern` (depends on -string)
6. `vyre-stdlib-graph`
7. `vyre-stdlib-dataflow` (depends on -graph; pyrograph uses this)
8. `vyre-stdlib-crypto`
9. `vyre-stdlib-compression`
10. `vyre-stdlib-workgroup`
11. `vyre-stdlib-security` (depends on many; goes last)

Each crate: registers its ops via `inventory::submit!` to `vyre-driver-registry`.
vyre-core becomes a meta-crate re-exporting stdlib for back-compat,
then deletes when consumers finish migrating.

Move `cert/` out to `vyre-conform-spec`. Move `introspection.rs`,
`test_migration.rs`, `bin/` out to `xtask/`.

### Phase 6 — Wire Compute 2.0 pipeline crates

- `vyre-pipeline-wireshift/` — binds to existing `libs/io/wireshift`
- `vyre-pipeline-mempool/` — binds to existing `libs/memory/mempool`
- `vyre-pipeline-kernelkit/` — binds to existing `libs/kernel/kernelkit`
- `vyre-pipeline-fusedpipe/` — binds to existing `libs/pipeline/fusedpipe`
- `vyre-pipeline/` — composes the above into `GpuStream`

Consumer surface: one type.
```rust
let stream = vyre_pipeline::GpuStream::new(source_path, program);
for result in stream { /* ... */ }
```

CPU involvement in the inner loop: zero. Memcpy from userspace: zero.

### Phase 7 — Persistent megakernel mode

Real implementation of `vyre-driver-megakernel/`:
- GPU-side work-item ring buffer (atomic head/tail pointers)
- Persistent compute shader dispatch (one kernel, runs for the
  entire scan)
- Consumer crates (warpscan, surgec-runtime) opt into megakernel
  mode via `DispatchConfig::execution_model = ExecutionModel::Persistent`

Benchmark target: 1000× reduction in PCIe dispatch count vs the
per-input dispatch model. Chart committed to `docs/performance.md`.

### Phase 8 — Delete vyre-core

After every consumer migrates away from `vyre` (which is now a
re-export shim), delete the crate. Update the `[patch.crates-io]`
rename resolution. The workspace ends as ~40 layered crates with
a strict dependency DAG.

---

## 9. Migration rules (how to do this without scars)

- **R7.** Every phase is one PR. No multi-phase commits; each PR must
  land the workspace in a green, testable state.
- **R8.** During migration, old paths are `#[deprecated]` not deleted.
  Consumers migrate at their own pace. Deletion happens when
  `cargo build` says no caller references the old path.
- **R9.** No consumer edits during a Phase N move. If moving
  `vyre-core::ir::X` to `vyre-foundation-ir::X`, consumers get a
  re-export in vyre-core until Phase 8. Surgec/pyrograph never see a
  broken morning.
- **R10.** CI must enforce R1–R6 starting Phase 2. Write
  `scripts/check_layering.sh` that does `cargo metadata` + a
  layer-DAG check. A PR that adds a wrong-direction dep fails CI.
- **R11.** Wire format, visitor trait signatures, and `VyreBackend`
  trait are frozen contracts during the migration. Layer rearrangement
  cannot change them. If a layer move would change a frozen contract,
  it's a semver-major event and gets its own RFC.
- **R12.** Dialect registrations use `inventory::submit!` from the
  stdlib crate. The symbol resolution stays link-time; runtime
  behavior is byte-identical pre- and post-migration. Conform certs
  remain valid.

---

## 10. What this unlocks

- **New execution model (megakernel, persistent, indirect).** One crate
  to touch: `vyre-driver-megakernel/`. Everything else oblivious.
- **New lowering target (PTX, Metal, Photonic).** One crate to add:
  `vyre-driver-ptx/`. Stdlib and foundation unchanged. No visiting
  479 files.
- **New frontend consumer.** Depends on `vyre-foundation-ir` only.
  Doesn't pull naga, wgpu, any dialect, any CVE detector. Compile
  time measured in seconds, not minutes.
- **Replace a stdlib dialect.** Fork `vyre-stdlib-pattern`, publish
  `my-better-pattern` with the same extension IDs. Consumers swap
  one line of Cargo.toml. Nothing else moves.
- **Community contribution.** External org writes `vyre-stdlib-fpga`
  for custom hardware. Registers through `vyre-foundation-extension`.
  Ships as a crate. Never asks permission.
- **Security audit.** Auditor reads `vyre-foundation-*` in one
  afternoon. 40 small crates instead of 1,244 entangled files.
  Respect earned in the first commit opened.
- **Compute 2.0 experimentation.** `vyre-pipeline-wireshift` swaps
  backends without affecting IR. Try `vyre-pipeline-dpdk` next week.
  Nothing else changes.

---

## 11. What this does NOT do

- Does not commit to a timeline. This is topology, not a schedule.
- Does not replace the existing two-agent vyre-stabilization plans —
  those deliver Phase 0 and are prerequisite.
- Does not solve what "legendary" means — that's taste + review, not
  structure. But it removes the structural excuses for not being
  legendary.
- Does not demand all-or-nothing. Phases 1+2+3 alone already buy
  enormous clarity. Phase 6–7 can wait until someone wants Compute 2.0.
- Does not preclude experimental crates. A new `vyre-experimental-*`
  tier can exist outside the layer DAG for spike work; it just can't
  be a dep of any shipped crate.

---

## 12. The 10-year test

Open `vyre-foundation-ir/src/lib.rs` in 2036. If it reads like an
LLVM-style IR crate — nodes, types, visit traits, wire format, and
nothing else — the blueprint held. If it mentions malware, scanning,
taint, regex, hashing, or any product concept, the blueprint failed
and rework is cheap because the layering is clean.

Open `vyre-stdlib-pattern/src/lib.rs` in 2036. It reads like a pattern
library. It does not know what a `wgpu::Device` is. It does not know
what `io_uring` is. It does one thing.

Open `vyre-pipeline/src/lib.rs` in 2036. It reads like a streaming
pipeline. It does not know what an `Expr` is. It composes four
infrastructure crates and exposes `GpuStream`.

If these three files read correctly in 2036, every downstream
consumer — surgec, pyrograph, warpscan, the ones that don't exist yet —
inherits a foundation a senior engineer respects.

---

## 13. Execution trigger

This plan executes when ALL of the following hold:

1. Phase 0 is complete: vyre-core builds green, the 18-defect list is
   closed, visitor traits restored, `compute_fixpoint` wired.
2. The team has a 2-week uninterrupted window for Phase 1+2+3. The
   layering extraction is mechanical but unforgiving of partial state.
3. Every current consumer (surgec, pyrograph) has a test suite green
   against vyre-core so regression detection is automatic during
   extraction.
4. The frozen contracts (wire, visitor, VyreBackend, AlgebraicLaw,
   EnforceGate, MutationClass) have snapshot drift tests. Migration
   cannot silently change them.

Until all four hold, the plan lives here, not in code. Any session
that moves any of the four closer counts as progress against this
plan without needing to mention it.

---

## 14. Anti-goals

- This is NOT a reason to start extracting things early. Extracting
  before Phase 0 completes produces scars that take longer to repair
  than the extraction saved.
- This is NOT an invitation to write 40 skeleton crates "for later."
  Empty crates are evasion (LAW 9). Each crate is created the day
  code is actually moving into it.
- This is NOT a rewrite. Every file moves; no file is rewritten unless
  it was already slated for a rewrite pre-migration.
- This is NOT a reason to delete `vyre-core` early. The re-export
  shim is what lets consumers migrate gradually. Delete it only at
  Phase 8 when `cargo build` proves nobody imports it.

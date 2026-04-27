# vyre — Vision

## The missing stack

CPUs evolved a natural stack of abstractions over fifty years:

```
transistors → gates → microcode → ISA → assembly → C → Python
```

Each layer genuinely forgets the one below it. You write Python without knowing about register allocation. You write C without knowing about TLB shootdowns. You write a web server without knowing about cache coherency protocols. The abstraction holds because someone built the stratum that hides the layer below, and verified that the hiding was honest.

GPUs never got that stack. They started as fixed-function pipelines, became programmable shaders, and stayed stuck at "parallel assembly with hardware-visible details." CUDA *looks* like C but leaks warps, divergence, shared memory banks, occupancy, and barrier semantics everywhere. WGSL is slightly prettier assembly. Triton is tiled assembly. There is no layer where you can say "give me a stack" or "give me a hashmap" and the hardware details are genuinely hidden.

**Vyre is the missing stratum.** The point in the GPU stack where you can write "I need a state machine" or "I need a fixed-point dataflow solver" and the answer does not require understanding workgroup topology. Same way `malloc` does not require understanding TLB shootdowns.

That is not just a software engineering convenience. It is a **cognitive offload mechanism.** A human brain (or model context window) cannot simultaneously hold "what is a register allocator" and "what is a warp divergence penalty" and "what is a memory coherency model" in working memory. So it approximates, and the approximation is brittle. The CPU abstraction stack solved this by letting each generation of programmers forget what the previous generation had to know. Vyre does the same for GPU compute.

---

## The After Effects architecture

Think of a video editor using After Effects. When a user drags a "Brightness" slider, they use a highly domain-specific abstraction so they don't have to do millions of matrix math operations in their head. But underneath, the GPU rendering engine (OpenGL/Metal) does not have a `gl_BrightnessSlider` primitive baked into its core. The frontend translates that slider into raw vector math *before* it hits the GPU. The GPU remains dumb, hyper-generic, and incredibly fast.

Vyre operates identically:

- **Frontend** owns domain concepts — `RuleCondition::FileSizeGt`, `PatternExists`, `borrow_check`, `type_unify`. Infinite domain-specific abstractions.
- **Core** owns generic compute primitives — `Expr::gt`, `Expr::and`, stack push, hashmap insert, barrier, atomic. Dumb, fast, frozen.
- **Backend** owns hardware translation — WGSL, SPIR-V, PTX, Metal, photonic instruction sets. Substrate-specific, swappable.

Frontends translate domain concepts into generic math *before* hitting core. Core never knows what a "rule", a "file", or a "borrow checker" is. It only understands fundamental math. By stacking domain concepts purely in the frontend, vyre provides a pristine developer experience while keeping the compilation core infinitely extensible and fiercely optimized.

The core is frozen. The frontends are infinite. That is the architecture.

---

## Four tiers, one registration mechanism

The architecture above only holds if there is a rule for where each op
lives. vyre locks it at four tiers, all of which register through the
same `inventory::submit!(OpEntry { … })` mechanism and pass the same
universal harness:

- **Tier 1** — `vyre-foundation` / `vyre-spec` / `vyre-core`: the IR
  model, wire format, frozen contracts. No ops.
- **Tier 2** — `vyre-intrinsics`: the frozen core surface.
  `hardware/` (Cat-C intrinsics, one hardware instruction each) +
  `primitive/` (arithmetic, bitwise, compare) + `composite/` (Cat-A
  stdlib). Every op has a size cap of ≤ 200 top-level Nodes. Every
  op is hand-audited. Every op has a CPU reference byte-identical to
  its documented spec.
- **Tier 3** — `vyre-libs-<domain>` crates: unbounded domain
  libraries. `vyre-libs-nn` (DL), `vyre-libs-crypto` (full crypto
  rounds), `vyre-libs-regex` (DFA compilers), `vyre-libs-parse`
  (whole-grammar parsers as Cat-A). Each its own crates.io identity.
  Depends on Tier 2. Never on another Tier-3 crate.
- **Tier 4** — external community packs via `vyre-libs-extern`.
  Published outside the santht org, registered via `ExternDialect`,
  verified to live under the `vyre-libs-` naming prefix.

Op IDs encode the tier: `vyre-intrinsics::...` (T2), `vyre-libs-nn::...`
(T3), `<dialect>::...` (T4). A grep tells you exactly where any op
lives.

**The Region chain invariant** keeps this auditable. Every op wraps
its body in `Node::Region { generator, source_region, body }`. When
an op is built by composing another registered op, the `source_region`
points back. `cargo xtask print-composition <op_id>` walks the chain
from any public op down through every intermediate composition to
the hardware intrinsic leaves. This is what prevents Tier-3 crates —
an attention block, a full regex DFA compiler, a whole-language
parser — from becoming black boxes.

Full spec:
- [`docs/library-tiers.md`](docs/library-tiers.md) — the five-tier rule.
- [`docs/region-chain.md`](docs/region-chain.md) — the composition-chain invariant.
- [`docs/parsing-and-frontends.md`](docs/parsing-and-frontends.md) — why source parsers stay on CPU and what connects them to GPU ops.

---

## Substrate neutrality

Substrate neutrality is not the thesis; it is a **consequence** of the architecture. If the core is generic enough to not know what a "brightness slider" is, it is also generic enough to not care whether the backend is WGSL, CUDA, or a photonic accelerator.

The IR speaks in abstract parallel concepts, not hardware-specific words:

- **parallel regions** — a group of threads that share a fast memory tier
- **memory tiers** — abstract hierarchy: invocation-local → shared → global
- **sync events** — barrier, fence, acquire, release; not `barrier()`
- **pure data operations** — arithmetic, bitwise, compare, memory ops

Words like *workgroup*, *subgroup*, *warp*, *WGSL*, *PTX* live only in backend crates. If they appear in `vyre-core/`, that is a bug.

If in 2030 a photonic accelerator ships with wildly different synchronization primitives, the change to vyre is: add a backend crate that implements the `VyreBackend` trait. Nothing in the IR changes. Nothing in the standard library changes. Nothing in the conformance harness changes. The conform gate certifies the new backend the same way it certifies wgpu — by diffing against the reference interpreter across the same witness set the existing backends pass.

That is the single test of whether the design is right. Every decision in this codebase should be evaluated against: "does this make it easier or harder to add the photonic backend in 2030?"

---

## Honest verification

Abstraction without verification is theater. If you tell a developer "don't worry about warps" but the backend silently produces different results on NVIDIA vs AMD, the abstraction has lied. The developer now has to care about warps.

Vyre's conform gate makes the abstraction bargain possible by ensuring backends cannot lie:

- **Property-based verification** over bounded witness domains with stratified boundary sampling (0, 1, MAX, MAX-1, ±0, ±Inf, NaN, subnormal, MSB-set, MSB-clear).
- **Counterexample extraction** — every failing property reports the smallest input that violates it.
- **Algebraic-law composition verification** — if op A satisfies commutativity and op B satisfies commutativity, the conform gate proves that `compose(A, B)` still satisfies commutativity for the composed witness domain. Not Coq. Not SMT. Bounded-witness algebra.

The certificate is a structured, signed artifact — not prose. It lists which laws were verified, which witness domain was covered, and the commit hash of the reference interpreter. Two backends that produce the same certificate are exchangeable.

Vyre does not claim formal verification it does not have. The conform gate is rigorous property testing, not a proof assistant. The claims are honest, bounded, and reproducible.

---

## Network effects

The architecture creates compounding value:

- Every new frontend (surgec, keyhog, gossan, compiler demos) makes vyre more valuable by proving the abstraction stack works for a new domain.
- Every new backend (CUDA, Metal, photonic) makes every frontend more valuable by making it portable to new hardware without code changes.
- Core never widens; it stays frozen. The network effect happens at the edges, not the center.

This is the Linux property applied to GPU compute: the substrate has more leverage than the vendor. If NVIDIA wanted to add a CUDA backend tomorrow, they could — one trait, one conformance run, one certificate. No coordination with vyre maintainers. If AMD does the same independently, both produce identical bytes for every input because the spec is unambiguous and the conformance suite is the arbiter. The cost of not being on vyre is higher than the cost of contributing to it.

---

## Open hierarchies

Vyre IR is designed around extension, not closure. `Expr`, `DataType`, `Backend`, and `RuleCondition` expose trait-based extension seams (`ExprVisitor`, `Lowerable`, `Evaluatable`) so external crates can add new IR constructs and new backends without editing the core enum. Node traversal stays concrete and explicit — dead trait indirection is not part of the contract.

The extension mechanism is real and wired end-to-end:

- `Expr::Opaque(Arc<dyn ExprNode>)` with `wire_payload()`
- `Node::Opaque(Arc<dyn NodeExtension>)` with `wire_payload()`
- `DataType::Opaque(Arc<dyn DataTypeExt>)` with full serialization
- `BinOp::Opaque(u32)` / `UnOp::Opaque(u32)` with dedicated CSE keys to prevent unrelated extensions from merging
- `RuleCondition::Opaque(Arc<dyn RuleConditionExt>)` with `#[non_exhaustive]`

This is a genuine open/closed design, not a facade.

---

## Reference owns execution

The reference interpreter owns the CPU reference for every op. Core owns the IR and the op declarations (the contract). Backends compile the contract to their target. Reference implementations live in `vyre-reference`, not in the public API shim.

Reference is not fallback. `vyre-reference` is a test oracle, not a runtime path. If a backend lacks a Category C hardware intrinsic, it returns `UnsupportedByBackend`; it does not fall back to slow CPU code.

---

## No runtime theater

Every claim in vyre's public surface is either provably true or honestly labeled:

- Benchmarks compare against real, hand-written baselines — not self-comparison. When we can't produce a hand-written baseline, the bench is marked "single-backend measurement, no comparator."
- Error types are structured enums with machine-readable codes. Strings are for humans, not code.
- Panics happen only on invariant violations that would produce undefined behavior. Every expect() starts with "Fix:".

---

## Conform is load-bearing, not parasitic

The conformance harness is essential. It is also bounded: split into four small crates (`-spec`, `-enforce`, `-generate`, `-runner`), each under 10k LOC. No crate depends on the others transitively in a way that forces a rebuild cascade. Core compiles without conform. Tests in core use a mock backend, not wgpu.

---

## One source of truth

One README at the workspace root. One CHANGELOG at the workspace root. One VISION.md (this file). Crate-level docs live in `rustdoc`, not in separate markdown files. If a concept lives in two places, one of them is wrong.

Plan and audit precedence is governed by
[`docs/DOCUMENTATION_GOVERNANCE.md`](docs/DOCUMENTATION_GOVERNANCE.md).
That file exists to keep historical plans and internal archives visible
without letting them compete with the active release gate.

---

## The wrapper namespace and its closed-set rule

`vyre-*` is a **closed namespace** — substrate only. Every crate prefixed `vyre-` is part of vyre's internals (foundation, primitives, driver, driver-wgpu, driver-spirv, runtime, libs, harness, intrinsics, spec, core, macros, reference, conform, std). No wrapper that builds *on top of* vyre ever uses the `vyre-*` prefix.

Capabilities that build on vyre live in their own real-word-named crates, each owning **one** capability:

```
vyre-*       CLOSED — substrate

Wrappers (each consumes vyre, owns ONE capability):
  weir       GPU-resident dataflow primitives (extracted 2026-04-26 from
             vyre-libs::dataflow). SSA, IFDS, reaching defs, points-to,
             callgraph, slice, escape, summary, loop_sum, range.
  writ       CPU symbolic execution + exploit witness construction
             (Z3-backed). Class 1 finding upgrade for surgec.
  scry       GPU-resident symbolic execution. Vyre-native research stub.
             NO CPU primitives ever. NO Z3 dependency. Long-term moat.
  ambit      Context evaluation. Entrypoint reachability, auth-dominator,
             rate-limit-dominator, validation-dominator, deploy-graph
             membership. Composes the per-finding severity vector.

Future wrappers (split when ready, never vyre-*):
  decode wrapper, matching wrapper, binary frontends (PE/ELF/Mach-O/DEX),
  YARA-rule transpiler, CodeQL-rule transpiler, Semgrep-rule transpiler.
```

Reasoning: anything that wraps vyre wants its own version axis, its own publishing cadence, its own community, and (for `scry`) its own substrate constraints. Feature-flagging a CPU symbolic executor and a GPU symbolic executor inside one crate would let CPU primitives leak into GPU code paths — exactly the failure mode the substrate-neutrality guarantee is meant to prevent. The same logic generalizes: every wrapper is a separate crate.

A new capability that doesn't fit an existing wrapper does not get added to `vyre-libs` and does not get a `vyre-` prefix. It becomes a new wrapper crate with a real-word name.

---

## The shape of the codebase

```
vyre/
├── vyre-core/            Umbrella crate — stable public API
├── vyre-foundation/      IR, serialization, validation, transform, optimizer
│   ├── src/ir_inner/     Expr, Node, DataType, Program, visit traits
│   ├── src/serial/       VIR0 wire format encode/decode
│   ├── src/validate/     Program validation (V### error codes)
│   ├── src/transform/    Optimization passes
│   └── src/lower.rs      Lowerable trait definitions
├── vyre-intrinsics/      Tier 2 — frozen hardware-mapped intrinsics
│   ├── hardware/         subgroup, barrier, fma, popcount, bit_reverse,
│   │                     inverse_sqrt (dedicated Naga + reference arms)
│   └── …
├── vyre-primitives/      Tier 2.5 — LEGO compositional primitives
│   ├── graph/ bitset/ reduce/ label/ predicate/ fixpoint/
│   └── text/ matching/ math/ nn/ hash/ parsing/ (feature-gated)
├── vyre-driver/          Backend traits, registry, routing, diagnostics
│   ├── backend/          VyreBackend, Executable, Streamable
│   ├── registry/         DialectRegistry, OpDefRegistration
│   └── routing/          Backend auto-picker
├── vyre-driver-wgpu/     wgpu/WGSL backend (primary production path)
├── vyre-driver-spirv/    SPIR-V backend (Vulkan direct)
├── vyre-spec/            Frozen data contracts
├── vyre-macros/          Proc-macros for op declarations
├── vyre-reference/       CPU reference interpreter (the oracle)
├── vyre-runtime/         Persistent megakernel, replay, io_uring native ingest
├── conform/              Split conformance crates (spec, generate, enforce, runner)
├── xtask/                Release tooling, benchmarks, quick-check
├── benches/              Criterion benchmarks
├── docs/                 Architecture, memory model, targets, wire format
└── rules/                Community-contributed detection rules
```

What's gone:

- `vyre-tree-gen` — source-parsing codegen that lost control of the module tree. Deleted.
- `build_scan` — 1000-line build.rs filesystem scanner. Inlined. Gone.
- `vyre-sigstore` — orphan crate. Deleted or folded into conform.
- Every build.rs that parsed crate source with `syn`. Gone.
- Duplicate READMEs, CHANGELOGs, THESIS.md references.

What's open for extension without editing core:

- New IR nodes → implement `ExprNode` or `NodeExtension` in a downstream crate, wrap in `Expr::Opaque` / `Node::Opaque`.
- New backends → implement `VyreBackend`, register via inventory.
- New op specs → `inventory::submit!` at declaration site.
- New algebraic laws → implement `AlgebraicLaw` trait, plug into conform.
- New rule conditions → implement `RuleCondition` trait.

---

## The forcing function

Backend neutrality is verified by the backend contract, not by carrying a
dummy crate. If adding a new substrate such as CUDA, Metal-direct, or future
photonic hardware requires editing `vyre-foundation`, the abstraction has
leaked. The correct integration point is one backend crate implementing
`VyreBackend`, registering through inventory, and passing the same conformance
lenses as wgpu.

---

## Non-goals

- Vyre is not a shading language. It emits WGSL / PTX / MSL; it does not define one.
- Vyre is not a formal-verification framework. The conform gate is rigorous property testing over bounded witness domains, not Coq.
- Vyre is not a runtime. Backends own device, queue, memory. Vyre owns the contract.
- Vyre is not a frontend. Frontends (Karyx, Soleno, and future ones) produce vyre IR; vyre executes it.

---

## What done looks like

1. A new photonic backend can be added by authoring one crate, registering it via inventory, and passing the conform suite. No edits to core.
2. A new IR node (e.g., `Node::Speculate`) can be added in a downstream crate by extending the concrete node-lowering surface alongside `Lowerable`. Core does not know about it; passes that understand it route through the explicit lowering boundary.
3. A new frontend author never edits core. They compose ops, define domain types, and lower to vyre IR. The frontend is a separate crate with a separate release cycle.
4. Every public function in core has either a test that proves its invariant or a doc-comment explaining why the invariant is unprovable.
5. Every benchmark has a named comparator baseline. No self-comparison.
6. Every certificate is a structured, signed artifact. Byte-identical across machines that produced it from the same inputs.

This is the bar.

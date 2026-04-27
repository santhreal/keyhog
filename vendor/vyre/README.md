# vyre

![vyre architecture](docs/architecture.svg)

**Vyre is the abstraction layer GPUs never got.**

CPUs evolved a natural stack of abstractions over fifty years. You write Python without knowing SIMD. You write C without knowing TLB shootdowns. You write a web server without knowing cache coherency protocols. Each layer genuinely forgets the one below it.

GPUs never got that stack. CUDA looks like C but leaks warps, divergence, shared memory banks, and barrier semantics everywhere. WGSL is slightly prettier assembly. Triton is tiled assembly. There is no layer where you can say "I need a stack" or "I need a hashmap" and the hardware details are genuinely hidden.

Vyre is that missing stratum. It provides workgroup-local stacks, queues, hashmaps, state machines, typed arenas, string interners, dominator trees, union-find structures, visitor walks, and fixed-point dataflow engines as first-class primitives. Each primitive lowers to the shader a hand-optimizer would write, and the conformance gate rejects any backend that diverges by even one bit.

A Python developer uses `numpy.dot` without knowing SIMD. A vyre consumer calls `vyre::compile(program)` without knowing lowering, WGSL, GPU dispatch, or conformance. Each layer is sealed, composable, and never refactored. Adding capability is always additive: new file, new trait impl, new backend. Never modifying an existing frozen contract.

## The 10-second pitch

Every GPU framework handles the embarrassingly parallel case. That problem is solved. Vyre ships what nobody else does: compiler-grade sequential logic on GPU, with workgroup-local coordination and a machine-verified conformance gate. Think MLIR composability, plus property-based verification over bounded witness domains with counterexample extraction, plus SQLite engineering discipline.

Vyre unblocks the workloads every other GPU stack punts to CPU: lexers, parsers, borrow checkers, type solvers, regex engines, and fixed-point dataflow analyzers. You compose ops. Vyre parity tests prove that the backend reproduces the reference bit-for-bit.

Vyre is not another GPU IR competing with SPIR-V. SPIR-V is a compilation target. Vyre is a semantic contract system that compiles to SPIR-V, WGSL, Metal, or DXIL as a backend detail. Vyre is not an ML framework; ML kernels are one of the simpler things it expresses. Vyre is not a replacement for CUDA or wgpu; it is the layer above them that makes their hand-tuned code surface addressable from high-level IR without losing performance. Vyre is not a language; humans write Rust, and vyre absorbs the mechanical GPU-specific concerns.

Vyre must become the standard for expressing GPU computation. Not by decree, but by being so correct, so composable, and so well-tested that building a GPU project without vyre is obviously more expensive than building with it. The ecosystem compounds. Every contributed operation makes vyre more valuable. Every backend makes adoption easier. Every parity suite proves the ecosystem works. Forking is suicide; contributing is the only rational strategy.

## The vyre crates

| Crate | Purpose | Audience |
|-------|---------|----------|
| `vyre` | IR, ops, lowering, `VyreBackend` trait — the core compiler surface every consumer imports | end user |
| `vyre-spec` | Frozen data contracts (5-year SemVer) — stable enum tags, wire constants, schema types shared across vyre crates | end user |
| `vyre-reference` | Pure-Rust CPU reference interpreter; the oracle every backend must match byte-for-byte | end user |
| `vyre-driver-wgpu` | wgpu-backed GPU backend implementing `VyreBackend` (primary production backend today) | end user |
| `vyre-foundation` | IR, serialization, validation, transform, optimizer — the core compiler substrate | maintainer |
| `vyre-driver` | Backend traits (`VyreBackend`, `Executable`, `Compilable`), registry, routing, diagnostics | maintainer |
| `vyre-intrinsics` | Hardware-mapped intrinsic ops — subgroup, barrier, FMA, bit manipulation | end user |
| `vyre-runtime` | Persistent megakernel (GPU-as-bytecode-interpreter) + Linux `io_uring` zero-copy NVMe → GPU streaming | end user |
| `vyre-primitives` | Tier 2.5 LEGO substrate shared by multiple Tier-3 dialects | end user |
| `vyre-macros` | Proc-macro crate (`#[vyre_pass]`, registration helpers) used by `vyre` at compile time | maintainer |
| `vyre-driver-spirv` | SPIR-V emitter — reuses naga IR to emit SPIR-V for Vulkan-compute runners outside wgpu | end user |
| `vyre-libs` | Category A composition ecosystem — `math`, `nn`, `matching`, `hash`, `decode`, `parsing`, `security` modules as pure vyre IR over `vyre-intrinsics` + `vyre-primitives` (no shader source) | end user |
| `xtask` | Workspace task runner (release, publish, audit helpers) invoked via `cargo xtask …` | maintainer |

## The five-tier rule — where every op lives

vyre ops live at exactly one tier. The tier is encoded in the op ID
prefix and determines stability, size cap, and audit requirements.
Full rule in [`docs/library-tiers.md`](docs/library-tiers.md).

| Tier | Crate(s) | What lives here | Size cap |
| --- | --- | --- | --- |
| **1** | `vyre-foundation`, `vyre-spec`, `vyre-core` | IR model, wire format, frozen contracts. No ops. | — |
| **2** | `vyre-intrinsics` | Cat-C hardware-mapped intrinsics — ops that need a dedicated Naga emitter arm + dedicated `vyre-reference` eval arm (subgroup_*, barrier, fma, popcount, bit_reverse, inverse_sqrt). | frozen 9-op surface |
| **2.5** | `vyre-primitives` | Reusable LEGO substrate shared by multiple Tier-3 dialects — bitset, graph, reduce, predicate, fixpoint, text, matching, math, hash, parsing, nn. | Gate 1 budget |
| **3** | `vyre-libs` today; domain crates later when justified | Every product-facing `fn(...) -> Program` composition — math, hash, logical, nn, matching, rule, text, parsing, security. | no cap |
| **4** | External community crates | Tier-3-shaped packs outside the santht org, registered via `vyre-libs-extern` + `ExternDialect` | no cap |

**Op ID tells you the tier**: `vyre-intrinsics::hardware::fma_f32` is T2,
`vyre-primitives::graph::reachable` is T2.5, `vyre-libs::hash::fnv1a32`
is T3, `<community-dialect>::foo` is T4.

**Dependency direction is enforced**: T2 depends on T1 only;
T2.5 depends on T1 plus narrowly-approved intrinsics; T3 depends on
T2.5+T2+T1; T4 depends on T3+T2.5+T2+T1. Never upward. CI gate
`cargo xtask check-tier-deps` rejects violations.

**Region chain invariant**: every op at every tier wraps its body
in `Node::Region` and — when built from another registered op —
populates `source_region` so `cargo xtask print-composition <op_id>`
can walk the decomposition chain from public surface down to hardware
intrinsics. Spec in [`docs/region-chain.md`](docs/region-chain.md).

**Frontends stay outside core**. vyre is a GPU IR; source-language
frontends live in Tier-3 crates or downstream tools, generate grammar
tables / packed AST buffers, and feed GPU-side ops that walk those
buffers. Full spec + throughput math in
[`docs/parsing-and-frontends.md`](docs/parsing-and-frontends.md).

## How to navigate the docs

Every significant surface in vyre has a canonical doc. When onboarding:

| You want | Read this |
| --- | --- |
| Architectural thesis + layering | `docs/ARCHITECTURE.md`, `docs/THESIS.md`, `VISION.md` |
| **Which tier does my op belong to?** | `docs/library-tiers.md` |
| **Composition chain — how ops stay auditable** | `docs/region-chain.md` |
| **Source parsers — where frontends live** | `docs/parsing-and-frontends.md` + **`docs/PARSING_EXECUTION_PLAN.md`** (phases, tests) |
| Documentation precedence | `docs/DOCUMENTATION_GOVERNANCE.md` |
| Current release gate | `audits/LEGENDARY_GATE.md` |
| Historical plans | `docs/V7_LEGENDARY_PLAN.md`, `.internals/audits/from-docs-audits/MASTER_PLAN*.md` |
| **Ops catalog — full surface at 0.6** | `docs/ops-catalog.md` |
| **Santh-wide Cat‑A building blocks + testing program (roadmap)** | `docs/OP_MASTER_PLAN_BUILDING_BLOCKS_AND_QA.md` |
| **Execution status + op inventory refresh** | `docs/EXECUTION_STATUS.md`, `docs/generated/OP_INVENTORY.md` |
| Writing a new op (contract + review checklist) | `docs/library-tiers.md` + `docs/region-chain.md` — **no raw WGSL ever; the whole contract is here** |
| Wire format + 0.6 tag reservations | `docs/wire-format.md` + `docs/wire-format-0.6-reservations.md` |
| Backend contract (capability queries, lifecycle hooks, sealing) | `vyre-driver/BACKEND_CONTRACT.md` |
| OpDef field audit (primitive / hardware / composite / tensor-core) | `vyre-spec/OPDEF_CONTRACT.md` |
| Frozen trait surfaces (5-year SemVer) | `docs/frozen-traits/*.md` |
| Memory model + ordering | `docs/memory-model.md` |
| Error-code catalog (stable u32 ids) | `docs/error-codes.md` |
| SemVer + API-stability policy | `docs/semver-policy.md` |
| Observability (tracing spans + stats schema) | `docs/observability.md` |
| Security disclosure + threat model | `SECURITY.md` + `docs/threat-model.md` |
| Release playbook (publish order, alpha soak) | `RELEASE.md` |
| 0.7 RFCs (Region inline, autodiff, quantization, collectives, megakernel) | `docs/rfcs/000*.md` |
| Persistent megakernel + `io_uring` NVMe streaming (Linux) | `vyre-runtime/README.md` |
| Testing standard + 6 category skills | `.internals/skills/testing/SKILL.md` |
| Per-crate test contract | `<crate>/tests/SKILL.md` |
| In-flight legendary-bar gap contracts | `contracts/legendary.md` |
| Benchmark baselines | `benches/RESULTS.md` + `docs/BENCHMARKS.md` |
| Public-API snapshots (diff gate) | `<crate>/PUBLIC_API.md` |

## Try it in 2 minutes

```sh
cargo add vyre vyre-reference vyre-driver-wgpu
```

Build a program, serialize it to text, and run the reference interpreter:

```rust
use vyre::ir::{BufferDecl, DataType, Expr, Node, Program};
use vyre_reference::{run, value::Value};

fn main() {
    // Construct an IR program that XORs two u32 buffers element-wise.
    let program = Program::wrapped(
        vec![
            BufferDecl::read("a", 0, DataType::U32),
            BufferDecl::read("b", 1, DataType::U32),
            BufferDecl::read_write("out", 2, DataType::U32),
        ],
        [1, 1, 1],
        vec![
            Node::let_bind("idx", Expr::u32(0)),
            Node::store(
                "out",
                Expr::var("idx"),
                Expr::bitxor(
                    Expr::load("a", Expr::var("idx")),
                    Expr::load("b", Expr::var("idx")),
                ),
            ),
        ],
    );

    println!("{}", program.to_text().expect("text serialization failed"));

    let inputs = &[
        Value::Bytes(vec![0xAA, 0x00, 0x00, 0x00].into()),
        Value::Bytes(vec![0x55, 0x00, 0x00, 0x00].into()),
        Value::Bytes(vec![0x00; 4].into()),
    ];
    let outputs = run(&program, inputs).expect("reference interpreter failed");
    println!("output: {:?}", outputs);
}
```

Run the same program on the GPU via the wgpu backend:

```rust
use vyre::VyreBackend;
use vyre_driver_wgpu::WgpuBackend;

let backend = pollster::block_on(WgpuBackend::acquire()).expect("no GPU");
let inputs: &[&[u8]] = &[
    &[0xAA, 0x00, 0x00, 0x00],
    &[0x55, 0x00, 0x00, 0x00],
    &[0x00; 4],
];
let outputs = backend.dispatch_borrowed(&program, inputs, &Default::default())
    .expect("dispatch failed");
```

The wire format provides lossless binary transport: `program.to_wire()` serializes, `Program::from_wire()` reconstructs, and round-trip equality is invariant I4. The former general-purpose bytecode VM was removed in v0.4.0-alpha.2. The NFA-scan micro-interpreter was removed in v0.5.0 — every detection primitive (string scanning, taint flow, AST motif, decode chain, binary structural, neural suspicion filter, exploit-graph reconstruction, …) composes from vyre ops. No interpreter surface remains anywhere in core. Surgec's full detection engine (scan, taint, decode, parse, fixpoint, graph, neural) composes in vyre IR. See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for architecture, [docs/wire-format.md](docs/wire-format.md) for the wire format, and [docs/inventory-contract.md](docs/inventory-contract.md) for the extension model.

## Standard library

The Layer 1 primitives live in `vyre` (core) and are organized into domains:

- **Primitive ops** — bitwise, arithmetic, and logical operations with exhaustive edge-case coverage and algebraic law verification.
- **Byte/text scan ops** — Aho–Corasick, substring find-all, multi-way scanners with real WGSL kernels (one ingredient inside larger programs).
- **Workgroup coordination primitives** — stack, FIFO queue, priority queue, hashmap, state machine, typed arena, string interner, visitor walk, recursive descent, dataflow fixed-point, dominator tree, and union-find.
- **Compiler primitives** — DFA engines, parser combinators, dataflow solvers, and tree-walk abstractions composed from workgroup primitives.

Composition-inlineable helpers live inside `vyre`'s own `ops::` tree alongside their primitives:

- **DFA/regex compilation pipeline** — `regex_to_nfa` (Thompson) → `nfa_to_dfa` (subset construction) → `dfa_minimize` (Hopcroft) → `dfa_pack` (Dense or EquivClass) → `dfa_assemble` (composite entry).
- **Aho-Corasick construction** — CPU reference + WGSL kernel + 5 GOLDEN samples + 20 KAT vectors.
- **Content-addressed compilation cache** — skips the pipeline when the same pattern set has already been compiled.
- **Arithmetic helpers** — ~80 typed compositional ops (saturating, wrapping, clamp, lerp, midpoint, abs_diff, div_ceil/round/floor).

## Benchmarks

The primitive showcase benchmark runs every registered `primitive.*` op at 1,024, 10,240, 102,400, and 1,048,576 elements. CPU numbers are direct Rust scalar kernels. GPU numbers are timed WGSL dispatch through `wgpu` after input buffers have already been prepared. The timed GPU loop includes dispatch, readback, and map; it excludes input buffer upload and bind-group preparation because `prepare_inputs` is hoisted outside the measured loop. Kernel-only timings are captured in [benches/RESULTS.json](benches/RESULTS.json).

| op_id | N=1K CPU | N=1K GPU | N=10K CPU | N=10K GPU | N=100K CPU | N=100K GPU | N=1M CPU | N=1M GPU | crossover |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| primitive.bitwise.and | 1.12 | 52.7 | 1.07 | 6.36 | 1.07 | 2.46 | 1.07 | 2.03 | >1048576 |
| primitive.bitwise.clz | 1.12 | 40.6 | 1.07 | 5.39 | 1.06 | 1.77 | 1.07 | 1.46 | >1048576 |
| primitive.bitwise.ctz | 1.12 | 41.3 | 1.07 | 5.56 | 1.06 | 1.78 | 1.07 | 1.63 | >1048576 |
| primitive.bitwise.extract_bits | 1.30 | 49.4 | 1.25 | 6.15 | 1.25 | 2.37 | 1.25 | 2.29 | >1048576 |
| primitive.bitwise.insert_bits | 1.48 | 50.1 | 1.42 | 6.21 | 1.42 | 2.31 | 1.42 | 2.04 | >1048576 |
| primitive.bitwise.not | 1.14 | 49.3 | 1.07 | 5.70 | 1.06 | 1.86 | 1.07 | 1.44 | >1048576 |
| primitive.bitwise.or | 1.12 | 51.6 | 1.07 | 6.45 | 1.07 | 2.35 | 1.07 | 2.36 | >1048576 |
| primitive.bitwise.popcount | 1.14 | 42.1 | 1.09 | 5.56 | 1.08 | 1.91 | 1.10 | 1.84 | >1048576 |
| primitive.bitwise.reverse_bits | 1.32 | 42.3 | 1.25 | 5.84 | 1.25 | 1.91 | 1.25 | 1.61 | >1048576 |
| primitive.bitwise.rotl | 1.13 | 133 | 1.07 | 7.79 | 1.07 | 2.56 | 1.08 | 2.37 | >1048576 |
| primitive.bitwise.rotr | 1.38 | 51.4 | 1.07 | 6.29 | 1.07 | 2.45 | 1.10 | 2.15 | >1048576 |
| primitive.bitwise.shl | 1.14 | 48.0 | 1.08 | 6.61 | 1.08 | 2.37 | 0.91 | 2.30 | >1048576 |
| primitive.bitwise.shr | 1.14 | 49.2 | 1.08 | 6.30 | 1.07 | 2.31 | 1.07 | 2.33 | >1048576 |
| primitive.bitwise.xor | 1.44 | 58.0 | 0.90 | 6.10 | 0.89 | 3.12 | 1.08 | 2.16 | >1048576 |
| primitive.compare.eq | 1.13 | 48.3 | 1.07 | 6.09 | 1.07 | 2.37 | 1.08 | 2.20 | >1048576 |
| primitive.compare.ge | 1.19 | 52.0 | 1.12 | 6.16 | 1.12 | 2.40 | 1.13 | 2.06 | >1048576 |
| primitive.compare.gt | 1.17 | 46.5 | 1.13 | 6.15 | 1.12 | 2.36 | 1.14 | 2.07 | >1048576 |
| primitive.compare.le | 1.12 | 49.2 | 1.06 | 6.12 | 1.06 | 2.36 | 1.07 | 2.13 | >1048576 |
| primitive.compare.logical_not | 1.13 | 42.2 | 1.08 | 12.8 | 1.07 | 1.91 | 1.07 | 1.48 | >1048576 |
| primitive.compare.lt | 1.14 | 52.8 | 1.07 | 6.10 | 1.07 | 2.41 | 1.07 | 2.03 | >1048576 |
| primitive.compare.ne | 1.13 | 50.5 | 1.07 | 6.27 | 1.07 | 2.40 | 1.07 | 2.15 | >1048576 |
| primitive.compare.select | 1.13 | 48.5 | 1.08 | 6.17 | 1.07 | 2.28 | 1.07 | 2.09 | >1048576 |
| primitive.float.f32_abs | 1.12 | 40.4 | 1.07 | 5.51 | 1.06 | 1.74 | 1.07 | 1.42 | >1048576 |
| primitive.float.f32_add | 1.13 | 46.3 | 1.07 | 6.73 | 0.89 | 2.25 | 1.07 | 2.02 | >1048576 |
| primitive.float.f32_cos | 1.35 | 43.1 | 1.33 | 5.54 | 1.32 | 1.80 | 1.40 | 1.44 | >1048576 |
| primitive.float.f32_div | 1.13 | 47.3 | 1.07 | 6.09 | 1.07 | 2.28 | 1.07 | 2.01 | >1048576 |
| primitive.float.f32_mul | 1.13 | 50.7 | 1.07 | 6.07 | 1.07 | 2.26 | 0.89 | 1.95 | >1048576 |
| primitive.float.f32_neg | 1.12 | 40.2 | 1.07 | 5.41 | 1.06 | 1.90 | 1.08 | 1.42 | >1048576 |
| primitive.float.f32_sin | 2.39 | 48.5 | 1.32 | 5.59 | 1.32 | 1.93 | 1.39 | 1.44 | >1048576 |
| primitive.float.f32_sqrt | 1.13 | 50.1 | 1.07 | 5.38 | 1.07 | 1.83 | 1.07 | 1.57 | >1048576 |
| primitive.float.f32_sub | 0.96 | 51.0 | 0.90 | 6.20 | 0.89 | 2.27 | 1.07 | 2.08 | >1048576 |
| primitive.math.abs | 1.12 | 43.8 | 1.07 | 5.71 | 1.07 | 2.38 | 1.07 | 1.45 | >1048576 |
| primitive.math.abs_diff | 1.12 | 48.5 | 1.07 | 6.20 | 1.07 | 2.37 | 1.07 | 2.16 | >1048576 |
| primitive.math.add | 1.18 | 55.7 | 1.47 | 8.10 | 1.07 | 3.17 | 1.07 | 2.14 | >1048576 |
| primitive.math.add_sat | 1.14 | 50.7 | 1.08 | 6.14 | 1.07 | 2.20 | 1.08 | 1.95 | >1048576 |
| primitive.math.clamp | 1.13 | 53.1 | 1.07 | 6.22 | 1.07 | 2.42 | 1.08 | 1.97 | >1048576 |
| primitive.math.div | 1.13 | 55.7 | 1.07 | 6.48 | 1.07 | 2.27 | 1.08 | 2.10 | >1048576 |
| primitive.math.gcd | 30.2 | 54.4 | 31.7 | 6.76 | 32.8 | 2.41 | 32.3 | 1.83 | 10240 |
| primitive.math.lcm | 22.5 | 50.7 | 27.1 | 6.28 | 28.2 | 2.51 | 28.6 | 2.02 | 10240 |
| primitive.math.max | 1.12 | 48.3 | 1.07 | 6.24 | 1.06 | 2.45 | 1.07 | 2.06 | >1048576 |
| primitive.math.min | 1.12 | 57.5 | 1.48 | 6.86 | 1.07 | 2.38 | 1.07 | 2.03 | >1048576 |
| primitive.math.mod | 1.12 | 50.2 | 1.07 | 6.24 | 1.07 | 2.32 | 1.07 | 2.01 | >1048576 |
| primitive.math.mul | 1.12 | 49.1 | 1.07 | 6.27 | 1.07 | 2.43 | 1.08 | 2.02 | >1048576 |
| primitive.math.neg | 1.13 | 39.9 | 1.07 | 5.52 | 1.06 | 1.72 | 1.07 | 1.52 | >1048576 |
| primitive.math.negate | 1.13 | 40.5 | 1.07 | 5.52 | 1.07 | 1.84 | 1.07 | 1.47 | >1048576 |
| primitive.math.sign | 1.13 | 40.5 | 1.07 | 5.51 | 1.07 | 2.05 | 1.08 | 1.81 | >1048576 |
| primitive.math.sub | 0.95 | 49.1 | 1.25 | 17.1 | 1.07 | 2.37 | 1.08 | 1.99 | >1048576 |
| primitive.math.sub_sat | 1.13 | 47.3 | 1.07 | 6.31 | 1.08 | 2.28 | 1.07 | 1.99 | >1048576 |

See [benches/RESULTS.md](benches/RESULTS.md) for the full 48-row primitive table.
Auto-registration is handled by link-time `inventory::submit!` registrations. Dialect operation files submit `OpDefRegistration` values, backend crates submit `BackendRegistration` values, and optimizer passes submit `PassRegistration` values. The registries are collected with `inventory::iter` at runtime and sorted where deterministic order matters. Adding a new dialect op, backend, or pass requires a new registration item, not a generated build-scan crate or a central hand-edited list.

Versioning follows the substrate pattern. `vyre-spec` publishes rarely and every release is an event: new data types, never removals, aggressive `#[non_exhaustive]`. `vyre` publishes patch releases frequently for optimizations and new lowerings. Backend crates publish on their own cadence after passing their parity suites. A community contributor can depend on `vyre-spec` alone without linking any backend.

## The Cat A / Cat B / Cat C discipline

Vyre organizes every operation into exactly one of three categories. This is not metadata decoration; it is an architectural gate that determines what code can exist and what code is forbidden.

**Category A — Pure composition.** A Cat A op is built entirely from existing ops. It introduces no new backend code, no new shader kernel, and no unsafe hardware assumption. Correctness propagates by construction: if the primitives are certified, the composition is certified. Most user programs and high-level library ops live here.

A new Cat A op ships as a focused builder under `vyre-libs/src/<domain>/`
or, when it becomes shared substrate, under `vyre-primitives/src/<domain>/`.
It introduces no backend-specific lowering and no hidden interpreter. The
filesystem is still the registry boundary: one domain, one responsibility,
and no central hand-edited list.

**Category B — Forbidden CPU coupling.** Cat B is the immune system's reject list. No general runtime interpretation engine, stack-machine evaluator, or CPU-fallback dispatch path may exist in vyre. The `nfa_scan` micro-interpreter was removed in v0.5.0 — those scans are expressed as composed ops in vyre IR and lower to GPU. Any construct that forces the host CPU to step into the execution loop of a GPU program is a Category B violation and is rewritten or deleted.

CI enforces this with tripwire gates that scan for forbidden patterns: `typetag`, `#[ctor]`, `Any::downcast`, dynamic async futures, pub-use globs, stub functions with `todo!()`, and frozen trait signature edits. These patterns break the black-box invariant, so their absence is load-bearing. `inventory::submit!` is the sanctioned link-time registration mechanism; it is not a runtime dispatch path. This keeps the abstraction stack sealed: GPU programs run on GPU, full stop. If a backend lacks a Category C hardware intrinsic, it returns `UnsupportedByBackend`; it does not fall back to slow CPU code. Reference is not fallback; `vyre-reference` is a test oracle, not a runtime path.

**Category C — Hardware intrinsic with a contract.** A Cat C op declares a
dedicated backend lowering path, a pure-Rust CPU reference oracle, a set of
algebraic laws, and engine invariants such as determinism, atomic
linearizability, barrier safety, and subnormal preservation. It has no
software fallback; unsupported hardware returns an error rather than silently
degrading.

Every Cat C op must pass the parity gate before it ships. The gate runs exhaustive edge cases on the u8 domain, property-based witnesses on the u32 domain, adversarial mutations from the mutation catalog, and backend-oracle parity checks across archetypes. The algebraic laws include commutativity, associativity, identity, self-inverse, distributivity, DeMorgan, and op-specific identities. The engine invariants include deterministic output, atomic linearizability, workgroup invariance, subnormal preservation for strict ops, and declared ULP bounds for approximate float ops.

The zero-overhead claim is load-bearing. The benchmark track in `benches/vs_cpu_baseline.rs` compares vyre-dispatched primitives against a direct hand-written `wgpu` path and against CPU baselines on the same fixture. A Cat C op that loses to the hand-written path is a regression and is rejected. An op without a passing parity gate is a lie.

Determinism is achieved via restriction, not elimination. Strict IEEE 754 operations remain as two roundings; the backend cannot fuse them into FMA. Reductions are ordered sequentially or as a canonical binary tree. Subnormals are preserved for strict ops. Transcendentals such as `sin` and `cos` are approximate ops today: the reference path uses Rust `f32` math and the WGSL backend uses shader builtins, so their contract is a declared ULP tolerance rather than correctly rounded results. Approximate and strict never mix in the same certificate. You choose per operation, in the IR, visibly.

## Backend Parity

A backend passes only when it reproduces the reference bit-exactly across the entire op matrix, law suite, archetype corpus, adversarial mutation catalog, and enforcement gate battery. The gate battery includes:

- **Atomics safety** — every atomic operation is linearizable and race-free.
- **Barrier correctness** — control flow reconverges safely at every barrier.
- **Out-of-bounds detection** — buffer accesses stay within declared bounds.
- **Determinism enforcement** — identical inputs produce bit-identical outputs.
- **Wire-format validation** — round-trip serialization is lossless.
- **Architectural tripwires** — forbidden patterns are absent from the source tree.

A violation means the backend emitted a finding with an actionable fix hint that starts with `Fix: `. Every finding is critical; there is no severity field because at internet scale, a low-severity bug still corrupts billions of records.

The parity suite makes silent divergence structurally impossible. Green means conformant and shippable; red means stop and fix.

There are four contributor flows:

- Add a new op by copying the template and filling in the spec, laws, archetypes, and KAT vectors.
- Add a new gate by dropping a file in `enforce/gates/` with a `REGISTERED` const.
- Add a new oracle by dropping a file in `proof/oracles/` with a `REGISTERED` const.
- Add a new backend by implementing `VyreBackend` and running it through the parity suite.

Community knowledge that does not require Rust can be expressed as TOML rules. Drop a file in `rules/{category}/{name}.toml` and the tool auto-loads on the next scan. Every flow is additive. Nothing requires editing a central list. The architecture grows without refactoring.

## Who uses vyre

- **Santh security tools.** `surgec` compiles SURGE / CISB-style detectors into vyre programs and drives evaluation. `keyhog` runs regex engines, entropy detectors, and hash verifiers on GPU. `gossan` performs fingerprint matching, tech-stack detection, and DNS graph walks as workgroup-coordinated sequential logic. Every detector ships with a conform certificate.

Before vyre, these tools ran CPU-bound for the sequential parts of their pipelines. Every one of them was blocked by the same missing abstraction: workgroup-coordinated primitives without hand-written shader code. Vyre unblocks all of them simultaneously. Exhaustive text and binary scanning at internet scale becomes feasible because the primitives are proven correct and the backend is certified before deployment. A detector that passes `certify()` cannot silently produce the wrong answer on one vendor's driver while working on another.

- **Research compilers.** Teams building lexers, parsers, borrow checkers, and type solvers emit vyre IR instead of hand-writing WGSL. The compiler author never reasons about warps, thread IDs, barriers, or memory coherence; vyre's primitives absorb those concerns. The Rust lexer demo already carries workgroup-shaped token state through stack, interner, and arena primitives. The parser demo parses a Rust subset into a typed arena with recursive-descent and visitor-walk primitives.

The final-boss milestone is a minimal Rust compiler expressed entirely as a vyre program: lexer, parser, resolver, trait solver, borrow checker, MIR builder, and codegen, all composed from vyre ops, all certified before execution. Not cross-compile. Not emit GPU backend code from CPU. The compiler author writes sequential logic; vyre absorbs every concurrency primitive they do not know how to reason about.

When that runs, it proves the thesis: GPU compute can have the same abstraction bargain CPUs have. You can write a compiler without knowing what a warp is.

- **GPU-first applications.** Any workload that needs zero-overhead abstraction on GPU with a machine-verified semantic contract. Video enhancement pipelines validate workgroup coordination at production scale. Scientific simulators rely on strict IEEE 754 determinism. Rule-evaluation engines lower to the same IR and run through the same gate, regardless of backend vendor.

`flare-native` is the in-house consumer that validates vyre's workgroup-coordination primitives at production scale for video enhancement. It is not a compiler workload, but it exercises the same stack, queue, and barrier primitives that compilers need. If it works for video frames at 4K60, it works for token streams at millions of lines per second.

If NVIDIA wanted to add a CUDA backend tomorrow, they could: an engineer reads the spec, implements one trait (`VyreBackend`), runs the conformance suite, gets a certificate. No communication with the vyre maintainers needed. If AMD wants to do the same independently, they can. Both backends produce identical bytes for every input, not because they coordinated, but because the spec is unambiguous and the conformance suite is the arbiter. This is the Linux property applied to GPU compute: the substrate has more leverage than the vendor. The cost of not being on vyre is higher than the cost of contributing to it.

## Contributing

Review boundaries are strict. Maintainers own law declarations, reference semantics, certificate format, and the gates. Contributors can propose changes there, but review will be stricter. Append-only paths such as corpora, regressions, and golden evidence should grow, not shrink. The project standard is simple: no stubs, no fake returns, no decorative laws, no swallowed errors, no dead code, and no contribution that only makes the suite quieter without making it truer.

## Links

- [Architecture](docs/ARCHITECTURE.md) — workspace layout, frozen contracts, CI laws
- [Wire format](docs/wire-format.md) — VIR0 binary serialization spec
- [Inventory contract](docs/inventory-contract.md) — link-time registration and extension rules
- [Semver policy](docs/semver-policy.md) — normative version contract
- [Error codes](docs/error-codes.md) — canonical registry of stable diagnostic codes
- [Vision](VISION.md) — the missing abstraction stack, After Effects architecture, network effects
- [Thesis](docs/THESIS.md) — technical axioms and where vyre beats existing options
- [crates.io/crates/vyre](https://crates.io/crates/vyre)
- [github.com/santhsecurity/vyre](https://github.com/santhsecurity/vyre)
- [License: MIT](LICENSE-MIT) / [Apache-2.0](LICENSE-APACHE)

If it passes parity, it ships. Binary verdict, always.

# vyre Thesis

## One-line

**vyre is the abstraction layer GPUs never got.** The IR speaks in abstract parallel concepts. Backends translate to whatever hardware can run parallel computation — today wgpu-targeted GPUs, tomorrow SPIR-V/Vulkan, CUDA/PTX, Metal/MSL, FPGAs, photonics.

CPUs evolved a natural stack of abstractions over fifty years. You write Python without knowing SIMD. You write C without knowing TLB shootdowns. GPUs never got that stack. CUDA looks like C but leaks warps, divergence, shared memory banks, and barrier semantics everywhere. WGSL is slightly prettier assembly. Triton is tiled assembly. There is no layer where you can say "give me a hashmap" and the hardware details are genuinely hidden.

Vyre is that missing stratum. The point in the GPU stack where you can write "I need a stack" or "I need a state machine" and the answer does not require understanding workgroup topology.

## The question every decision answers

*"Does this make it easier or harder to add a photonic backend in 2030?"*

A photonic accelerator with fundamentally different synchronization primitives should require one new crate at `backends/photonic/` implementing `VyreBackend`. Nothing in the IR changes. Nothing in the standard library changes. Nothing in the conformance harness changes. The conform gate certifies the new backend the way it certifies wgpu — by differential testing against the reference interpreter on the same witness set every existing backend passes.

If adding the photonic backend ever needs edits to `vyre-core`, the standard library, or the conformance harness, the design is wrong.

## Why this matters

Every successful compiler infrastructure of the last thirty years — LLVM, MLIR, WebAssembly — won by **being the stable contract between frontends and backends**. Frontends don't target C; they target LLVM IR. Backends don't implement "a C compiler"; they implement "an LLVM backend." One contract in the middle, many producers on one side, many consumers on the other.

vyre does this for parallel compute. LLVM assumed sequential execution was the ground truth and bolted parallelism on top (OpenMP, vector types, intrinsics). That choice permeates every pass, every verifier rule, every optimization. A truly parallel-first IR is not "LLVM plus parallel annotations." It is a different IR.

But the deeper reason this matters now is that **the compression ratio is wrong.** No human brain can simultaneously hold "what is a register allocator" and "what is a calling convention" and "what is a peephole optimizer" in working memory. The reason we don't have this problem on CPU is that the abstraction stack exists — junior developers write web servers without knowing cache lines. There is no equivalent stack on GPU.

Vyre provides the primitives so developers write lexers, parsers, borrow checkers, and type solvers on GPU without reasoning about warps, thread IDs, barriers, memory coherence, or control-flow divergence. The final-boss milestone — a minimal Rust compiler expressed entirely as a vyre program, entirely on GPU, zero CPU fallback — proves the thesis: GPU compute abstractions can be zero-overhead AND provably correct AND expressive enough to encode a real compiler.

## Core axioms

Each axiom maps to a layer in the abstraction stack:

1. **The IR speaks in abstract parallel concepts**, not hardware-specific words. *Parallel regions*, *memory tiers*, *sync events*. Not *workgroup*, *subgroup*, *warp*. Words like those live in backend crates. If they appear in `vyre-core/`, that is a bug.
   > *This is the C layer: a portable language that forgets the CPU underneath.*

2. **Open hierarchies.** `Expr`, `Node`, `DataType`, `Backend`, `RuleCondition` expose trait-based visitor APIs (`ExprVisitor`, `NodeVisitor`, `Lowerable`). External crates can add new IR constructs and new backends without editing core. Every traversal over the IR goes through the visitor API — adding a variant is a localized change.
   > *This is the libc layer: extensible without recompiling the kernel.*

3. **Honest verification.** The conform gate performs property-based verification over bounded witness domains with stratified boundary sampling (0, 1, MAX, MAX-1, ±0, ±Inf, NaN, subnormal, MSB-set, MSB-clear), counterexample extraction, and **algebraic-law composition verification**: if op A satisfies commutativity and op B satisfies commutativity, conform proves `compose(A, B)` satisfies commutativity on the composed witness domain. Not Coq. Not SMT. Bounded-witness algebra. The certificate is a signed structured artifact — two backends that produce the same certificate are exchangeable.
   > *This is the test/QA layer that makes forgetting safe. Without it, abstraction is theater.*

4. **Reference owns execution.** The reference interpreter (`vyre-reference`) owns the CPU reference for every op. `vyre-core` owns the IR and the op declarations (the contract). Backends compile the contract to their target.
   > *This is the reference manual: the ground truth that every implementation must match.*

5. **No runtime theater.** Every claim in vyre's public surface is provably true or honestly labeled. Benchmarks compare against real hand-written baselines — not self-comparison. Error types are structured enums with machine-readable codes. Panics happen only on invariant violations that would otherwise produce undefined behavior.
   > *This is the engineering culture layer: no marketing in the code.*

6. **Conform is load-bearing.** The conformance harness is essential. It is also bounded: split into four small crates (`vyre-conform-spec`, `-enforce`, `-generate`, `-runner`), each under 10 kLOC. Core compiles without conform. Tests in core use a mock backend, not wgpu.
   > *This is the CI layer: the gate that keeps quality automatic.*

7. **One source of truth.** One `README.md` at the workspace root. One `CHANGELOG.md` at the workspace root. One `VISION.md`. This file. Crate-level docs live in rustdoc. If a concept lives in two places, one is wrong.
   > *This is the documentation layer: if you have to ask which doc is right, both are wrong.*

8. **Zero-cost domain abstractions.** Frontend rule builders can expose infinite domain abstractions (`RuleCondition::FileSizeGt`, `PatternExists`). Those abstractions compile strictly into generic compute primitives (`Expr::gt`, `Expr::and`) before reaching the `Backend` registry. The execution substrate does not know what a "pattern" or a "file size" is. It only understands fundamental math.
   > *This is the compiler optimization layer: the frontend pays nothing at runtime for its expressiveness.*

## Where vyre beats the existing options

| System | Why it's not enough | Abstraction leakage |
|--------|---------------------|---------------------|
| **LLVM IR** | CPU-assumption baked in: undef, poison, signed integer semantics, sequential fallthrough. Parallel work is annotations on top, not the primary. | Leaks sequential memory model, undefined behavior, register pressure. |
| **SPIR-V** | Vulkan-and-friends-specific. No substrate-neutral story for CPU / photonics / novel hardware. No conformance certificate. No algebraic-law verification. | Leaps Vulkan memory model, descriptor sets, execution model. |
| **MLIR** | Dialects are first-class, but cross-backend parity is left to the user. No canonical CPU reference, no witness certificate. | Leaks dialect boundaries; backend lowering is user-defined and unverified. |
| **WebGPU Shading Language** | A shader language, not an IR. Source text, not structured form. No verifier, no optimizer pipeline. | Leaks workgroups, subgroups, bind groups, texture formats. |
| **CUDA** | NVIDIA-only. Leaks warps, divergence, shared memory banks, occupancy, barrier semantics. No verification, no cross-vendor portability. | Leaks everything: warps, divergence, shared memory layout, occupancy, PTX version. |
| **Triton** | Tiled assembly with Python sugar. Leaks tile sizes, memory coalescing, and thread-block layout. No verification beyond manual testing. | Leaks tile sizes, memory coalescing patterns, block layouts. |

vyre's novel contribution — the piece no existing system has — is **algebraic-law composition verification** (axiom 3). Given a library of ops that each satisfy a set of laws, the conform gate *composes the laws* and proves the composition holds on a composed witness domain. That is a primitive-level proof of correctness preservation under program construction. Not formal verification, but rigorous enough to act as a cert.

## Non-goals

- vyre is **not a shading language.** It emits WGSL / PTX / MSL; it does not define one.
- vyre is **not a formal-verification framework.** The conform gate is rigorous property testing over bounded witness domains, not Coq.
- vyre is **not a runtime.** Backends own device, queue, memory. vyre owns the contract.
- vyre is **not a frontend.** Frontends produce vyre IR; vyre executes it.

## What done looks like

1. A new photonic backend can be added by authoring one crate, registering it via inventory, and passing the conform suite. No edits to `vyre-core`.
2. A new IR node (`Node::Speculate`) can be added in a downstream crate by implementing `NodeVisitor` and `Lowerable`. Core does not know about it; passes that understand it route via the visitor.
3. Every public function in core has either a test proving its invariant or a doc-comment explaining why the invariant is unprovable.
4. Every benchmark has a named comparator baseline. No self-comparison.
5. Every certificate is a structured signed artifact. Byte-identical across machines that produced it from the same inputs.

This is the bar.

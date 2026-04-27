# Op Categories — A, C, and the forbidden B

vyre operations fall into exactly two permitted categories. A third
category is forbidden.

## Category A — Compositional, zero-overhead

**Definition:** The op is expressed as a composition of other vyre ops.
When lowered to target code, it inlines completely — every sub-op is
expanded in place, the resulting shader is identical to what a human
would write by hand for the same computation.

**Property:** The abstraction exists at IR construction time. It
vanishes at shader emission time. There is no runtime cost for the
abstraction — the generated GPU code is flat and optimal.

**How the lowering achieves this:**

1. The contributor writes `program()` as an IR tree with `Call`,
   `BinOp`, `UnOp`, `Load`, `Store`, etc.
2. The lowering walks the tree. Every `Call(op_id, args)` is
   substituted with the callee's IR body, with argument values inlined.
3. Every IR node maps to a WGSL construct directly.
4. The WGSL compiler (Tint / Naga / SPIRV-Cross) sees the flat shader
   and performs register allocation, dead code elimination, constant
   folding as if the program were hand-written.
5. The resulting GPU code has no function-call overhead, no dispatch
   tables, no runtime abstraction markers.

**Examples:** `xor`, `add`, `popcount`, `bfs`, `dfa_scan`, `matmul`,
`softmax`, `layer_norm`, `prefix_sum`, `sort`, every compound and
engine op. 95%+ of vyre ops.

**The test:** if `lower(op.program())` produces WGSL that is
semantically equivalent to hand-written WGSL of the same computation,
the op is Category A.

## Category C — Hardware intrinsic

**Definition:** The op maps 1:1 to a specific hardware instruction that
software composition cannot match in performance. The op's IR form is
itself an intrinsic — when lowered, it emits exactly one hardware
instruction (or a short inline sequence that is the hardware's exposed
way of accessing the unit).

**Property:** Still zero-overhead. There is no abstraction to eliminate
because the op IS the hardware instruction at the IR level. The
"overhead" of Category C is the cost of the hardware instruction itself
— unavoidable, because it's what the hardware does.

**Why Category C exists:** some hardware units perform operations that
no software composition can match. A warp shuffle exchanges data
through a dedicated crossbar in one cycle. A tensor core MMA does
`m16n16k16` matrix multiply in a handful of cycles. A texture sampler
does bilinear filtering in 1-2 cycles. An RT core does ray-BVH
traversal in ~10ns. Simulating these in scalar software is 10×-1000×
slower.

**The per-backend availability requirement:** every Category C op MUST
declare which backends support it and which do not. A backend that
supports the op's hardware intrinsic lowers it to the intrinsic. A backend
that does **not** support the hardware refuses the program and returns
`Error::UnsupportedByBackend { op, backend }`. There is **no fallback
composition**. There is no degraded path. There is no performance
loss, ever.

This is **not** how LLVM handles `llvm.ctpop` or `llvm.nvvm.wmma.*`. LLVM
provides portable CPU substitutions because LLVM is a CPU-first substrate where
"works everywhere, sometimes slowly" is an acceptable tradeoff. vyre is a
GPU compute substrate where performance degradation is unacceptable and a
fallback path would destroy the zero-abstraction-cost property that makes
vyre worth building on. If the hardware isn't there, the op isn't there.
A program that needs `TensorCoreMatMul` compiles and runs on RDNA only if
you declare the intrinsic available via a wgpu extension — otherwise the
program is rejected at dispatch time with a structured error, and the
caller must pick a different backend or express the computation as a
Category A composition of primitives (which is its own program the author
writes explicitly, not a hidden fallback the runtime substitutes).

**Examples:**

| Op | Hardware instruction (NVIDIA) | Backends that support it |
|----|-------------------------------|--------------------------|
| `SubgroupShuffle` | `shfl.sync` | CUDA, wgpu + `SHADER_SUBGROUP`, SPIR-V with `SubgroupShuffleKHR` |
| `SubgroupReduce(Sum)` | `redux.sync` | CUDA, wgpu + `SUBGROUP_REDUCE`, SPIR-V |
| `SubgroupBallot` | `ballot.sync` | CUDA, wgpu + `SUBGROUP_BALLOT`, SPIR-V |
| `TensorCoreMatMul(m16n16k16,f16)` | `wmma.mma.sync` | CUDA on SM70+, wgpu + `COOPERATIVE_MATRIX` |
| `SampleImage(bilinear)` | `tex.sample` | CUDA, wgpu (universal on image types) |
| `AsyncCopyToShared` | `cp.async` | CUDA on SM80+ |
| `TraceRay` | `trace.ray` | CUDA on RT cores, wgpu + `RAY_TRACING` |

Every Category C op is as fast as the hardware allows on supporting
backends. On non-supporting backends, the op is unavailable — the program
that uses it is refused by that backend at dispatch time. A downstream
caller who wants cross-backend portability must either (a) constrain their
target backend set to ones that support all their Category C ops, or
(b) author a separate Category A composition over primitives that expresses
the same computation at the cost of the programmer's own explicit choice.
vyre will not make that choice silently.

## Category B — Forbidden

**Definition:** Any operation whose execution incurs runtime abstraction
cost. Virtual dispatch, interpreter loops, JIT compilation, reference
counting, boxed types, dynamic polymorphism, indirect function calls
that the compiler cannot prove to inline.

**Why forbidden:** runtime abstraction cost compounds. If 10 Category B
ops are composed, the cost is 10× the overhead. If 100 ops, 100×. vyre
compositions can be arbitrarily deep (Layer 1 primitives → Layer 2
compounds → Layer 3 engines → application programs). Runtime overhead
per layer means deeper compositions are slower. This breaks the "zero-
cost abstraction" property that makes vyre a usable substrate.

**What this means in practice:**

- No virtual dispatch between ops. The Op trait exists only at Rust
  compile time — `Box<dyn Op>` never appears at runtime in lowered code.
- No interpreter. The legacy bytecode eval shader has been removed because
  it was a Category B violation — it interpreted opcodes at runtime on
  the GPU with a switch statement. The word "bytecode" is retired from
  vyre; the binary serialization of a program is the IR wire format,
  which is decoded back to `ir::Program` before lowering (never
  interpreted).
- No JIT. vyre programs are lowered ahead of dispatch, not during
  dispatch.
- No runtime type checks. Type checking happens during `ir::validate`
  before lowering, never during shader execution.
- No runtime error recovery. Errors are caught at validation time,
  not during GPU execution.

**The test for a proposed op:** can it lower to code that matches
either:
(a) the output of `lower::wgsl::lower(composition_of_existing_ops)`
    for some composition (Category A), or
(b) a single hardware intrinsic or a short inline sequence the hardware
    provides (Category C)?

If yes to either, the op is acceptable. If no — if the op requires any
form of runtime abstraction to function — it is rejected. Category B
does not exist in vyre.

## Planned Layer 2 Rule Domain

`ops/rule/` is planned as the seventh Layer 2 domain. It will migrate rule
condition evaluation from the old parallel-evaluation path into Category A IR
compositions over Layer 1 primitives and existing Layer 2 matching, string,
hash, graph, decode, and compression operations.

The rule domain will not introduce a runtime evaluator, bytecode VM, dynamic
dispatch table, or hidden fallback. Each rule operation must still satisfy the
same Category A test as every other Layer 2 domain: `program()` returns a
complete `ir::Program`, every `Expr::Call` is inlined before lowering, and the
emitted backend code contains no Category B abstraction cost.

No `ops/rule/` source files exist until the H5 migration lands. This section is
a preview of the domain boundary so the operation model remains coherent while
the implementation is staged.

## Why this rule is non-negotiable

vyre's whole value proposition depends on composability without cost.
An integer XOR composed into a hash function composed into a DFA
composed into a scanner composed into a malware detection engine must
lower to shader code that is as fast as a hand-written malware detection
engine would be. If any layer of that stack carries runtime overhead,
the whole stack is slower than the hand-written version, and users who
care about performance write the hand-written version instead. vyre
becomes the middle-tier option — better than writing from scratch,
worse than the serious alternative. Middle tier is the worst place to
be.

Category A + C eliminates this possibility by construction. Every op in
vyre, at every layer, lowers to either inlined composition or direct
hardware access. A stack of 20 ops is as fast as a hand-written version
because after lowering it IS a hand-written version. The composition is
where the abstraction lives; the shader is where the hardware executes.
These never meet at runtime.

Serious users get as-fast-as-possible code for free. Easier users get
high-level abstractions that are as fast as low-level code. The tradeoff
between ease and performance is eliminated — there is no tradeoff. Both
groups use the same substrate.

This is the property that makes vyre worth building on.

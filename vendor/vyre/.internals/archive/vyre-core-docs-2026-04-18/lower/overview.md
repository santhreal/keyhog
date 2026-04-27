# Lowering — the compiler

## What lowering is

Lowering is the step that turns an `ir::Program` into executable
code. It is a compiler. Not a wrapper, not a translator, not a
code generator — a compiler. The distinction matters because a
compiler has obligations that wrappers and translators do not.

A wrapper passes through. A translator rearranges. A compiler
*preserves semantics under transformation*. The input has meaning
(the IR). The output has meaning (the shader). The compiler's job
is to ensure both meanings are identical — not similar, not close,
not equivalent-for-practical-purposes, but byte-identical in
observable output for every valid input.

This is the hardest job in vyre. The IR is clean: deterministic
integer semantics, defined OOB behavior, defined division-by-zero,
explicit atomics, no undefined behavior. The target is dirty: WGSL
has vendor-specific shader compiler optimizations, GPU hardware has
vendor-specific behavior for edge cases, and the space between "what
the WGSL spec says" and "what the GPU actually does" is where
miscompilation bugs live.

The lowering's job is to bridge that gap. It must emit target code
that *forces* the GPU to produce the result the IR specifies, even
when the GPU's natural behavior would differ. Division by zero must
return zero, not `u32::MAX` — so the lowering emits a guard:
`select(a / b, 0u, b == 0u)`. Shift amounts must be masked — so
the lowering emits `a << (b & 31u)` even though some GPUs already
mask internally (because other GPUs do not, and the lowering must
be correct on all of them). Out-of-bounds loads must return zero —
so the lowering emits bounds checks or relies on WebGPU's Robust
Buffer Access guarantee (and documents which).

Every one of these guards is a place where a missing guard produces
a miscompilation — a wrong result that looks right, passes
superficial testing, and corrupts data silently. The testing book's
"failure mode 1" chapter is entirely about this. The lowering is
where miscompilation is born or prevented.

## The pipeline

```text
Program
  → validate()        reject malformed IR before any work
  → optimize()        IR-to-IR rewrites (constant fold, dead code, fusion)
  → lower()           IR to target code (WGSL, SPIR-V, PTX, MSL)
  → compile()         target code to GPU pipeline (wgpu, driver)
  → dispatch()        launch invocations
  → readback()        read output buffers
  → compare()         verify against CPU reference (in conformance suite)
```

Validation is mandatory. A Program that fails validation must not
reach the lowering. The lowering may assume every Program it
receives is valid — buffers are declared, bindings are unique,
variables are bound before use, axes are in range.

Optimization is optional for correctness. A lowered unoptimized
Program produces the same bytes as a lowered optimized Program. The
optimization exists for performance: constant folding eliminates
dead branches, dead-code elimination removes unused computations,
and fusion merges adjacent ops into one. But the bytes must not
change. An optimization that changes observable bytes is a
miscompilation, not an optimization.

Lowering is mandatory. A backend that claims to support vyre must
lower every valid Program in its claimed spec surface. A backend
that cannot lower a valid Program is non-conforming for that
Program.

## The reference lowering

WGSL is the reference lowering target because vyre's reference
implementation uses wgpu, which consumes WGSL. "Reference" means
this is the lowering against which conformance is first verified.
It does NOT mean WGSL has privileged semantics.

If the WGSL lowering produces output bytes that disagree with the
CPU reference, the WGSL lowering is wrong. Not the CPU reference.
Not the IR specification. The lowering. The CPU reference and the
ground truth spec are the authority. The lowering is the
implementation that must conform to them.

This is a critical distinction. In many GPU frameworks, the shader
is the de facto specification — "whatever the shader does is what
the framework does." In vyre, the IR is the specification, and the
shader is an implementation that is tested against it. The test is
the parity harness: same input, same Program, GPU result vs. CPU
result, byte-for-byte. Any divergence is a lowering bug.

## Future lowerings

SPIR-V, PTX (CUDA), and MSL (Metal) are expected future lowering
targets. Each must:

1. Accept every valid `ir::Program` in its claimed spec surface.
2. Produce output bytes identical to the CPU reference for every
   valid input.
3. Return structured errors for Programs that exceed the target's
   resource limits.
4. Handle every `Node` and `Expr` variant in its claimed spec level.
5. Never panic on any input.

Future lowerings may choose different code shapes. A SPIR-V lowering
might use different register allocation, different helper function
structure, different control flow representation. A PTX lowering
might exploit CUDA-specific features (warp shuffles, shared memory
bank conflict avoidance). These choices are implementation freedom.
They do not extend to semantic freedom: integer arithmetic, atomics,
OOB behavior, shift masking, division-by-zero — these must match
the IR specification exactly, regardless of the target.

A future lowering that disagrees with the WGSL lowering on any
Program is a finding. Either the new lowering has a bug, or the
WGSL lowering has a bug that the new lowering exposed. Both are
tested against the CPU reference to determine which is wrong.

## Semantics preservation — the complete list

A lowering preserves semantics when the GPU produces byte-identical
output to the CPU reference for every valid input. "Byte-identical"
covers every observable effect:

| Effect | What the lowering must preserve |
|--------|-------------------------------|
| Buffer writes | Every `Store` writes the correct value at the correct index. |
| Atomic return values | Every `Atomic` returns the value that existed before the operation. |
| Atomic accumulation | Multiple `AtomicAdd` to the same location produce the correct final sum. |
| Early returns | `Return` stops the invocation from executing subsequent statements. |
| Barriers | `Barrier` synchronizes workgroup invocations and makes writes visible. |
| Integer wrapping | `add(u32::MAX, 1) = 0`. Not 1, not `u32::MAX`, not undefined. |
| Division by zero | `div(x, 0) = 0`. Not `u32::MAX`, not trap, not undefined. |
| Modulo by zero | `mod(x, 0) = 0`. |
| Shift masking | `shl(x, 32) = shl(x, 0) = x`. Mask is `b & 31`. |
| Boolean encoding | `true = 1`, `false = 0`. Not `0xFFFFFFFF`, not `-1`. |
| OOB loads | Return zero. Not stale data, not adjacent buffer data, not undefined. |
| OOB stores | No-op. No write to any location. |
| OOB atomics | Return zero, no modification. |
| Invocation IDs | `InvocationId.x = WorkgroupId.x * workgroup_size[0] + LocalId.x`. |
| Loop bounds | `from` is inclusive, `to` is exclusive. `from >= to` means zero iterations. |
| Scoping | `Let` bindings are visible until end of enclosing block. No shadowing. |

Every row in this table is a potential miscompilation site. The
lowering contract doc ([contract.md](contract.md)) specifies the
obligations formally. The WGSL lowering doc ([wgsl.md](wgsl.md))
specifies the exact WGSL construct emitted for each IR node and
expression.

## What makes lowering hard

Lowering a single `BinOp::Add` is trivial: emit `left + right`.
Lowering a complete Program is hard because the hard cases are
combinations:

**Division inside a loop with an induction variable as divisor.**
The divisor is zero when the induction variable is zero. The lowering
must emit the zero-guard for every division, not just "most"
divisions. Missing one guard in a rarely-taken branch is a
miscompilation that passes 99.9% of tests.

**Atomic inside a conditional.** If the conditional is
invocation-dependent (some invocations take the branch, some don't),
the lowering must not lift the atomic out of the conditional. An
atomic that fires for all invocations when it should fire for some
corrupts the count.

**Barrier inside a loop.** Every invocation in the workgroup must
reach the same barrier. If the loop has an early-exit condition that
varies by invocation, the barrier is illegal. The validator should
catch this (V010), but the lowering must not silently emit code that
deadlocks if the validator has a gap.

**Nested `Select` with atomics.** `Select` evaluates both branches.
If one branch contains an atomic, the atomic fires even when the
condition is false. The lowering must preserve this — it must not
optimize `Select` into a short-circuit `If` that skips the atomic.

**Cast chains.** `U32 → I32 → U64` involves a bitcast followed by
a sign-extension. The lowering must perform these in order:
bitcast first (reinterpret the bits), then sign-extend (propagate
the sign bit to 64 bits). Reversing the order produces a different
result.

Each of these cases has a specific test in the lowering test
category. The mutation catalog includes mutations that break each
case (remove a zero-guard, hoist an atomic, short-circuit a Select,
reorder a cast chain). The tests must kill those mutations.

## The relationship to testing

The lowering is the component most likely to have bugs. It is the
component that translates abstract semantics into concrete hardware
instructions, and the translation is where every subtle assumption
mismatch becomes a wrong result.

The testing book devotes an entire failure mode chapter to
miscompilation (failure mode 1) and an entire test category to
lowering (`tests/integration/lowering/`). The lowering category
includes:

- **Expression coverage.** Every `Expr` variant has at least one
  test that exercises it through lowering.
- **Node coverage.** Every `Node` variant has at least one test.
- **BinOp coverage.** Every `BinOp` variant.
- **WGSL syntax validation.** Every lowered shader compiles on wgpu.
- **Bounds check coverage.** Every buffer access in the lowered
  shader has a bounds check.
- **Shift mask coverage.** Every shift in the lowered shader has a
  mask.
- **Mutation gate.** `LowerRemoveBoundsCheck` and
  `LowerRemoveShiftMask` mutations must be killed.

The lowering is not a place where "it probably works" is acceptable.
The lowering is the place where "it provably works" is required,
because every Program that every user will ever write passes through
it.

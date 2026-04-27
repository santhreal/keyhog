# LLVM IR

LLVM IR is a mature, typed, SSA-based compiler IR. It is the shared target for
frontends such as Clang and Rust, and it supports many CPU and accelerator
backends through a large optimization pipeline. Its core model is a general
compiler substrate: modules contain functions, functions contain basic blocks,
and instructions express control flow, memory access, arithmetic, vector
operations, and calls.

LLVM is not vyre's direct replacement target. LLVM solves the problem of
compiling language-level programs into machine code across a broad hardware
matrix. vyre solves a smaller problem: expressing deterministic GPU compute
programs as an IR that lowers to backend shader or kernel languages and carries
a standard operation library.

## Where LLVM is stronger

LLVM has decades of production optimization work. It has mature alias analysis,
loop optimizers, vectorizers, register allocation, debug info support, object
emission, target-specific instruction selection, and toolchain integration.
For CPU language implementation, LLVM is the default answer because it gives a
frontend a path to many architectures.

LLVM also has a huge ecosystem around IR transforms. A compiler can run
canonicalization, scalar replacement, inlining, dead-code elimination,
interprocedural analysis, and target-specific passes without owning those
implementations. vyre should not attempt to match that surface.

## Where vyre differs

vyre is GPU-native by scope. A vyre `Program` is a compute dispatch: buffers,
workgroup size, and entry nodes. It does not need to represent general CPU
process semantics, function ABI details, exception models, stack frames, or
object-file linkage. That restriction is intentional. It makes the IR easier to
validate exhaustively and easier to lower to shader languages such as WGSL.

vyre has no CPU execution path. LLVM often supports an execution spectrum:
compile ahead of time, JIT, interpret in tools, or lower to multiple target
families. vyre does not accept a slow CPU fallback for runtime semantics. If a
backend cannot implement an operation, that is an unsupported-backend result,
not permission to reinterpret the program somewhere else.

vyre's Category C intrinsics are explicit hardware contracts with no fallback.
LLVM intrinsics often model target-specific operations and may participate in
legalization or lowering to alternative instruction sequences. vyre's Category C
rule is stricter: an intrinsic exists only when the backend declares support for
the hardware unit. Otherwise the operation is unavailable. This keeps
performance cliffs visible.

vyre's wire format is a stable, lossless serialization of the same semantic IR.
`Program::from_wire(program.to_wire())` must reconstruct the same program. LLVM
has textual `.ll` and bitcode forms, but LLVM bitcode is a compiler interchange
format tied to LLVM's IR evolution and toolchain compatibility rules. vyre's
wire format is part of the product contract for downstream tools that store,
transport, and replay GPU compute programs.

## Where vyre should not compete

vyre should not grow into a general compiler framework, CPU optimizer, JIT, or
object emitter. If downstream users need language frontend infrastructure, they
can still use LLVM before or after vyre depending on the product. vyre's leverage
comes from being a small, deterministic GPU compute contract with conformance
tests, not from becoming another all-purpose compiler platform.

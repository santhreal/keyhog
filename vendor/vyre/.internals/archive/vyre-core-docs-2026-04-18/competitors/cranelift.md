# Cranelift

Cranelift is a code generator designed for fast, secure machine-code generation.
It is best known through Wasmtime and other JIT or ahead-of-time compilation
contexts where compilation latency, sandboxing, and predictable code generation
matter. Its IR is lower level than a source language but still targets CPU
machine code through instruction selection and register allocation.

vyre is not a CPU code generator. It is a GPU compute IR and operation library.

## Where Cranelift is stronger

Cranelift is designed to generate native CPU code quickly. It owns the backend
problems vyre deliberately avoids: calling conventions, register allocation,
stack slots, CPU instruction selection, relocations, traps, and integration with
runtime systems such as WebAssembly engines.

Cranelift also has an explicit security story for untrusted code generation.
That matters for WebAssembly hosts where code is compiled at runtime and then
executed on the CPU under sandbox constraints.

## Where vyre differs

vyre's target unit is a GPU compute dispatch, not a CPU function. The public
program model contains buffers, a workgroup size, and entry nodes. The reference
lowering emits WGSL. Future backends can emit CUDA, SPIR-V, PTX, or MSL, but
they still implement the same GPU compute semantics rather than CPU ABI
semantics.

vyre also bakes in a domain operation library. Primitive arithmetic, hash,
decode, graph, compression, and match operations are part of the crate's
standard surface as IR compositions or Category C intrinsics. Cranelift does not
try to ship a malware-scanning DFA operation, a rolling hash domain, or a URL
decode operation as codegen primitives. Those belong above a CPU compiler. In
vyre they are central because the project is building the missing substrate for
GPU workloads.

Cranelift can be used as a backend for many language runtimes. vyre should not
become such a runtime. There is no stack-machine evaluator, opcode loop, or CPU
fallback. Downstream products construct or import vyre programs and lower them
to GPU backends.

## Comparison summary

Use Cranelift when the goal is fast CPU machine-code generation. Use vyre when
the goal is deterministic GPU compute expression with a conformance-gated
operation library. They may coexist in a larger product, but they occupy
different layers.

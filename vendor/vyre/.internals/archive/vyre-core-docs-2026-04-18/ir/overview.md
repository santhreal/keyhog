# IR Overview

vyre IR is the stable language of GPU compute in this project. Frontends produce
IR, optimizers transform IR, lowerings translate IR to target code, runtimes
execute lowered code, and conformance checks the result against the ground truth
semantics. The IR is the shared contract between all of those parts.

## Program At A Glance

A vyre `Program` is a complete GPU compute dispatch:

```rust
Program {
    buffers: Vec<BufferDecl>,
    workgroup_size: [u32; 3],
    entry: Vec<Node>,
}
```

`buffers` declares every externally supplied memory object the program may read
or write. `workgroup_size` declares the local invocation shape for the compute
entry point. `entry` is the ordered statement body executed by each invocation.

The program is self-contained at the IR layer. It does not depend on a GPU
device, shader language, runtime cache, host allocator, or backend-specific
handle. A backend that understands the IR can validate, optimize, lower, and
execute the program independently.

## Why IR First

IR-first design gives vyre one semantic authority. Without IR, every operation
would need its own WGSL, CUDA, Metal, CPU reference, serializer, optimizer, and
test harness. That duplicates behavior and guarantees drift.

With IR, each operation emits one `Program`. Every lowering must preserve that
program's semantics. Every optimizer must transform one valid program into an
equivalent valid program. Every conformance test can compare independent
backends against the same CPU reference. The abstraction exists at design time
and vanishes at execution time after lowering and optimization.

## Relationship To Other Modules

`ir/` has zero external dependencies and no feature gates. It defines pure data:
types, expressions, statements, programs, validation, and visitors. It is the
constitution of vyre because all other layers are judged against it.

`ops/` depends on `ir/` and provides the standard operation library. An op is a
named, versioned producer of an `ir::Program` plus metadata such as signature
and dependencies.

`lower/` depends on `ir/` and translates valid programs to target code. The
reference lowering is WGSL. Future lowerings such as SPIR-V, PTX, and MSL must
accept the same valid programs and produce equivalent outputs.

`engine/` composes ops and runtime execution into complete pipelines such as
DFA matching, evaluation, scatter, and dataflow. Engines do not define new IR
semantics; they orchestrate programs built from the lower layers.

## Zero Dependencies

The IR data model must remain usable without a GPU and without wgpu. A
program can be constructed in tests, serialized to the IR wire format,
audited, optimized, and validated on any machine with no accelerator.
Execution, however, is GPU-only: a program is run by lowering it to a GPU
backend (WGSL, CUDA, SPIR-V, MSL, or future targets) and dispatching the
result. vyre has **no CPU runtime path** — the reference interpreter that
implements the semantic spec lives in the `vyre-conform` crate as a test
oracle, not as a vyre runtime. GPU support belongs in runtime and backend
modules, not in the IR.

## The Constitution Metaphor

The IR is called the constitution because it constrains every implementation.
An optimizer cannot delete a store if that changes observable bytes. A WGSL
lowering cannot choose a different division-by-zero result. A backend cannot
ignore an unknown expression variant. The constitution is small, explicit, and
stable so that independent implementors can build against it without hidden
agreement.

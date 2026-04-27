# Execution Model

## Overview

A vyre Program executes as a GPU compute dispatch. The runtime launches N
invocations organized into workgroups. Each invocation executes the Program's
entry point body independently. Invocations within a workgroup can synchronize
via barriers. Invocations in different workgroups cannot communicate.

## Invocations

A dispatch creates `dispatch_x * dispatch_y * dispatch_z` workgroups. Each
workgroup contains `workgroup_size[0] * workgroup_size[1] * workgroup_size[2]`
invocations. The total invocation count is the product of both.

Each invocation has a unique identity:
- `InvocationId { axis }` — the global invocation index. Axis 0 (x) ranges
  from 0 to `dispatch_x * workgroup_size[0] - 1`. Same for y and z.
- `WorkgroupId { axis }` — the workgroup index. Ranges from 0 to
  `dispatch_{axis} - 1`.
- `LocalId { axis }` — the invocation's position within its workgroup. Ranges
  from 0 to `workgroup_size[axis] - 1`.
- Relationship: `InvocationId = WorkgroupId * workgroup_size + LocalId`.

## Execution Order

### Within an invocation

Statements execute sequentially in the order they appear in `entry`. `Let`
binds before subsequent `Assign` or `Var` references. `If` evaluates the
condition, then executes exactly one branch. `Loop` iterates from `from` to
`to` (exclusive), executing the body each time. `Return` exits the entry point
immediately. `Block` executes its contents sequentially.

There is no parallelism within a single invocation. A statement that appears
after another statement observes all effects of the earlier statement.

### Across invocations

Invocations execute independently. There is **no ordering** between statements
in different invocations unless explicitly synchronized.

Two invocations may execute their entry points in any order, interleaved in any
way, on any hardware thread, at any speed. A conforming backend may execute all
invocations sequentially, all in parallel, or any mix.

### Barriers

`Barrier` synchronizes invocations within a workgroup. When an invocation
reaches a `Barrier`:
1. It waits until every invocation in the same workgroup reaches the same
   `Barrier`.
2. All storage buffer writes performed by any invocation in the workgroup
   before the barrier become visible to all invocations in the workgroup
   after the barrier.
3. Execution resumes.

Barriers do NOT synchronize invocations in different workgroups. There is no
mechanism for cross-workgroup synchronization in vyre. If a program requires
global synchronization, it must use multiple dispatches.

**Every invocation in a workgroup must reach the same `Barrier`.** A `Barrier`
inside an `If` branch that not all invocations take is undefined behavior in
WGSL. vyre inherits this constraint: if `Barrier` appears inside a conditional,
the condition must evaluate to the same value for all invocations in the
workgroup.

## Memory Visibility

### Without barriers

Writes to storage buffers from one invocation are NOT guaranteed to be visible
to other invocations until a barrier. Two invocations writing to the same
non-atomic storage location without synchronization produce an indeterminate
result (not undefined — the value is one of the written values, but which one
is unspecified).

### With barriers

After a `Barrier`, all storage writes from all invocations in the workgroup
that occurred before the barrier are visible. This is equivalent to WGSL's
`storageBarrier()`.

### Atomics

Atomic operations (`Expr::Atomic`) provide synchronization without barriers.
An `AtomicAdd` to `buf[i]` from two invocations is well-defined: both additions
happen, in some order, and the final value is the sum. The return value of each
atomic is the value that existed immediately before that invocation's operation.

Atomics are sequentially consistent: the results of all atomic operations on a
given location are consistent with some sequential ordering of all invocations.

## Data Races

A data race occurs when two invocations access the same non-atomic storage
location, at least one access is a write, and there is no barrier between them.

**Data races produce indeterminate (not undefined) results.** The read
invocation gets one of the values that was written, but which one is
unspecified. The program does not crash, does not corrupt other memory, and does
not exhibit undefined behavior. This is a deliberate constraint — GPU programs
must not crash on any input.

However, data races make program output non-deterministic. The conformance suite
detects non-determinism by running the same input multiple times and comparing
results. A program with data races will fail conformance testing.

**Best practice:** avoid data races entirely. Use atomics for concurrent writes
to the same location. Use barriers for phased computation within a workgroup.
Use separate buffer regions for independent invocations.

## Dispatch Lifecycle

1. **Validation.** The runtime validates the Program (see validation.md).
   Invalid programs are rejected with a structured error before any GPU work.

2. **Lowering.** The Program is lowered to target code (e.g., WGSL). The
   lowered code is compiled into a GPU pipeline.

3. **Buffer allocation.** The runtime allocates GPU buffers for each
   `BufferDecl`. Input data is uploaded to read-only buffers.

4. **Dispatch.** The runtime dispatches the compute shader with the specified
   workgroup count. All invocations execute.

5. **Readback.** The runtime reads back output buffers (ReadWrite) and returns
   the result bytes.

Between dispatches, buffer contents are NOT preserved unless the runtime
explicitly supports buffer reuse. A program must not depend on buffer state
from a previous dispatch.

## Determinism Guarantee

A conforming vyre program (no data races, no dependence on invocation ordering)
produces **identical output bytes** for identical input bytes on every
conforming backend, on every GPU vendor, on every run.

This is possible because:
- **Integer arithmetic is bit-exact by definition** (no accumulator
  ambiguity, no vendor rounding).
- **Float arithmetic is bit-exact under the strict IEEE 754 rules** vyre
  enforces at the IR level: no FMA fusion, no reduction reordering, no
  subnormal flush, correctly-rounded transcendentals, no silent tensor
  core precision downgrade. See `types.md` → "Float Semantics".
- Data race freedom is enforced (no scheduling nondeterminism).
- Out-of-bounds access is defined (returns 0, not undefined — see
  out-of-bounds.md).
- Atomic operations are sequentially consistent (see above).

If a program produces different results on different runs or different backends,
either the program has a data race or the backend has a bug.

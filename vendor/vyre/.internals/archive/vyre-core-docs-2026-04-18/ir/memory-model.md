# Memory Model

## Address Spaces

vyre programs operate on two address spaces:

### Storage

Storage buffers (`BufferAccess::ReadOnly` and `BufferAccess::ReadWrite`) are
in global GPU memory. They are visible to all invocations across all
workgroups.

- **ReadOnly** buffers can be read by any invocation. Writes are forbidden
  (validation error).
- **ReadWrite** buffers can be read and written by any invocation.
- **Uniform** buffers are a fast-path subset of ReadOnly. They are small
  (typically 64KB), read-only, and cached aggressively. Use for parameters
  that are the same across all invocations.

### Workgroup

Workgroup-shared memory (`BufferAccess::Workgroup`) is visible only to
invocations within the same workgroup. It is faster than storage but smaller
(typically 32-48KB).

Workgroup buffers are declared with a static element `count`. They do not use
a binding slot. `Load` and `Store` are allowed; `Atomic` is not (validation
error). Out-of-bounds access on workgroup memory returns zero for loads and is
a no-op for stores, matching the overall vyre OOB policy.

## Visibility Rules

### Within a single invocation

All reads and writes by a single invocation are ordered. A `Store` followed
by a `Load` to the same buffer and index returns the stored value. This is
guaranteed.

### Across invocations — without synchronization

Writes to storage buffers from one invocation are **NOT visible** to other
invocations until:
- A `Barrier` is executed (within a workgroup), or
- The dispatch completes (across workgroups).

A `Load` from one invocation may see a stale value written by another
invocation if no synchronization has occurred. The value is not garbage — it
is either the initial value or a value written by some invocation — but
WHICH value is indeterminate.

### Across invocations — with Barrier

After all invocations in a workgroup reach a `Barrier`:
- All `Store` operations performed by any invocation in the workgroup BEFORE
  the barrier are visible to all invocations in the workgroup AFTER the
  barrier.
- This applies to both storage buffers and (future) workgroup buffers.

Barriers do NOT synchronize across workgroups. There is no cross-workgroup
synchronization in vyre. Programs that need global synchronization must use
multiple dispatches.

### Across invocations — with Atomics

Atomic operations (`Expr::Atomic`) provide per-element synchronization without
barriers. An `AtomicAdd` to `buf[i]` is immediately visible to subsequent
atomic operations on `buf[i]` by other invocations.

Atomics are sequentially consistent: all invocations observe the same order of
atomic operations on a given location.

Non-atomic reads of a location that was atomically written may see stale values
unless a barrier intervenes. The rule: if you write with atomics, read with
atomics (or use a barrier).

## Data Races

A data race occurs when:
1. Two invocations access the same storage location.
2. At least one access is a non-atomic write.
3. There is no barrier between the accesses.

Data races produce **indeterminate** results. The read may return any value
that was written to that location by any invocation, or the initial value.
The program does not crash. Memory is not corrupted. Other locations are not
affected.

However, data races make output non-deterministic. The conformance suite
detects this and reports it as a failure.

**Best practice:** partition the output buffer by invocation ID so each
invocation writes to a unique location. This eliminates data races by
construction.

## Initial Buffer Contents

- **ReadOnly** buffers are initialized by the host before dispatch. Their
  contents are defined by the input data.
- **ReadWrite** buffers are initialized to zero before dispatch unless the
  host explicitly provides initial data. A conforming backend MUST zero-fill
  output buffers (or provide a mechanism for the host to do so).
- **Uniform** buffers are initialized by the host.

Programs must NOT depend on ReadWrite buffer contents from a previous dispatch.
Buffer contents between dispatches are NOT preserved unless the runtime
explicitly guarantees it (which is a runtime feature, not an IR guarantee).

## Buffer Lifetime

Buffers exist for the duration of a dispatch. After readback, the buffer may
be reclaimed by the runtime. A Program cannot reference buffers from a
previous dispatch.

## Permanence

The memory model described here is permanent. Storage visibility rules, barrier
semantics, atomic ordering (sequentially consistent), data race behavior
(indeterminate, not undefined), and initial-value guarantees will not change.

# Out-of-Bounds Behavior

## Decision

**Out-of-bounds loads return zero. Out-of-bounds stores are no-ops.**

This is permanent. It will never change.

## Definition

A `Load { buffer, index }` is out-of-bounds when the evaluated index is greater
than or equal to the element count of the buffer (as returned by
`BufLen { buffer }`).

A `Store { buffer, index, value }` is out-of-bounds under the same condition.

An `Atomic { buffer, index, expected, value, .. }` is out-of-bounds under the same
condition. Out-of-bounds atomics are no-ops and return zero.

## Rationale

### Why not undefined behavior?

Undefined behavior is the source of most security vulnerabilities in C/C++ and
most divergence bugs in GPU compute. If out-of-bounds access is undefined, two
conforming backends can produce different results for the same input. One
returns zero, another returns stale memory, a third crashes. This makes the
conformance suite meaningless — it can only test inputs that don't go OOB, but
the inputs that go OOB are exactly the ones where bugs hide.

vyre has **zero undefined behavior**. Every input to every operation produces
exactly one correct output. Two engineers implementing backends independently
produce identical bytes for identical inputs. This property is non-negotiable.

### Why zero?

Zero is the only value that is:

1. **Deterministic.** Every backend on every GPU vendor will return zero for
   the same OOB access. There is no vendor-specific behavior.

2. **Hardware-supported.** WGSL's Robust Buffer Access (mandated by the WebGPU
   spec) already returns zero for OOB loads and ignores OOB stores. We are not
   inventing new behavior — we are formalizing existing behavior.

3. **Safe.** An OOB read of zero will not leak information from other buffers
   or other invocations. It cannot be used as a side channel.

4. **Composable.** Zero is the additive identity, the absorbing element of
   multiplication, and the neutral element of OR. In most computations, an
   OOB read of zero produces a benign result (a missed match, a zero
   contribution, a false condition).

### Why not clamp?

Clamping (`buf[min(index, len-1)]`) is surprising. `buf[100]` on a 10-element
buffer returning `buf[9]` silently gives wrong results that are hard to
distinguish from correct results. Zero is obviously wrong — it stands out in
debugging. Clamp hides the bug.

### Why not trap?

Trapping (aborting the invocation) is catastrophic in GPU compute. One bad
invocation kills the workgroup. The entire dispatch produces no output. For a
scanner processing millions of files, one malformed input kills the batch. Zero
is graceful — the OOB invocation produces a benign result, the rest of the
batch succeeds.

## Formal Specification

For any `Load { buffer: B, index: I }` where `B` resolves to a declared buffer
with element count `N`:

```
if eval(I) < N:
    result = buffer_contents[eval(I)]
else:
    result = 0
```

For any `Store { buffer: B, index: I, value: V }`:

```
if eval(I) < N:
    buffer_contents[eval(I)] = eval(V)
else:
    // no effect
```

For any `Atomic { op, buffer: B, index: I, expected: E, value: V }`:

```
if eval(I) < N:
    old = buffer_contents[eval(I)]
    buffer_contents[eval(I)] = atomic_apply(op, old, eval(V))
    result = old
else:
    result = 0
    // no effect on buffer
```

## Implications

### For program authors

Programs SHOULD bounds-check before accessing buffers:

```
let idx = InvocationId { axis: 0 };
if idx < BufLen("output") {
    Store("output", idx, compute(idx));
}
```

This is not required — OOB access is defined, not undefined. But it is best
practice because:
- It documents intent (the reader knows which invocations are active).
- It avoids silent zeros in output buffers.
- It matches the pattern used in every GPU compute tutorial.

### For backend implementors

The backend MUST ensure OOB loads return zero and OOB stores are no-ops. On
WGSL/WebGPU, this is automatic (Robust Buffer Access). On CUDA, the backend
must emit bounds checks or use hardware features that provide equivalent
behavior. On Metal, the backend must use `buffer_access::safe` or equivalent.

### For the conformance suite

The conformance suite MUST test OOB access explicitly:
- Load at index `N` (one past the end) must return 0.
- Load at index `u32::MAX` must return 0.
- Store at index `N` must not modify any buffer element.
- Atomic at index `N` must return 0 and not modify any buffer element.

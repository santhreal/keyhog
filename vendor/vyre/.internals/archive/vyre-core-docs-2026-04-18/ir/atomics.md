# Atomic Operations

## Overview

Atomic operations provide synchronized access to buffer elements across
invocations. They are the ONLY mechanism for safe concurrent writes to the
same buffer location (besides barriers, which synchronize phases, not
individual accesses).

All atomics:
- Operate on a single `u32` element in a `ReadWrite` storage buffer.
- Return the value that existed **before** the operation (the "old" value).
- Are **sequentially consistent**: the results of all atomic operations on a
  given location are consistent with some sequential ordering of all
  invocations.

## Operations

### AtomicAdd

**Semantics:** `old = buf[i]; buf[i] = (old + value) mod 2^32; return old`

Wrapping addition. If two invocations atomically add 1 to a location
containing 0, the final value is 2. One invocation gets `old = 0`, the other
gets `old = 1` (order is unspecified but both additions happen).

### AtomicOr

**Semantics:** `old = buf[i]; buf[i] = old | value; return old`

Bitwise OR. Commonly used for setting flag bits across invocations.

### AtomicAnd

**Semantics:** `old = buf[i]; buf[i] = old & value; return old`

Bitwise AND. Commonly used for clearing flag bits.

### AtomicXor

**Semantics:** `old = buf[i]; buf[i] = old ^ value; return old`

### AtomicMin

**Semantics:** `old = buf[i]; buf[i] = min(old, value); return old`

Unsigned minimum.

### AtomicMax

**Semantics:** `old = buf[i]; buf[i] = max(old, value); return old`

Unsigned maximum.

### AtomicExchange

**Semantics:** `old = buf[i]; buf[i] = value; return old`

Unconditional swap.

### AtomicCompareExchange

**Semantics:**
```
old = buf[i];
if old == expected {
    buf[i] = new_value;
}
return old;
```

The caller provides `expected` and `new_value` as distinct IR operands:
`Expr::Atomic { op: CompareExchange, expected: Some(expected), value:
new_value, .. }`. On failure (`old != expected`), the buffer element is left
unchanged.

**Note:** CompareExchange is the foundation of lock-free algorithms. The
returned `old` tells the caller whether the exchange happened (`old == expected`
means it did).

## Memory Ordering

All vyre atomics are **sequentially consistent**. This is the strongest
ordering guarantee. It means:

1. All invocations observe atomic operations on a given location in the same
   order.
2. The final value of a location after all invocations complete is the result
   of applying all atomic operations in some sequential order.
3. The return values are consistent with that order.

This is deliberately the strongest guarantee. Weaker orderings (relaxed,
acquire/release) are NOT exposed in the vyre IR. Reason: weaker orderings
are a source of subtle bugs that vary by hardware vendor. Sequential
consistency is correct everywhere. The performance difference is small for
GPU compute workloads (atomics are already expensive; the ordering overhead
is marginal).

## Out-of-Bounds Atomics

An atomic on an index beyond the buffer length is a **no-op that returns zero**.
See `out-of-bounds.md`. The buffer is not modified. The return value is 0.

## Concurrent Non-Atomic Access

Two invocations accessing the same non-atomic storage location, where at least
one is a write, is a **data race** (see `execution-model.md`). The result is
indeterminate. Use atomics or barriers instead.

## WGSL Mapping

| vyre Atomic | WGSL |
|-------------|------|
| `AtomicAdd` | `atomicAdd(&buf.data[i], value)` |
| `AtomicOr` | `atomicOr(&buf.data[i], value)` |
| `AtomicAnd` | `atomicAnd(&buf.data[i], value)` |
| `AtomicXor` | `atomicXor(&buf.data[i], value)` |
| `AtomicMin` | `atomicMin(&buf.data[i], value)` |
| `AtomicMax` | `atomicMax(&buf.data[i], value)` |
| `AtomicExchange` | `atomicExchange(&buf.data[i], value)` |
| `AtomicCompareExchange` | `atomicCompareExchangeWeak(&buf.data[i], expected, new_value).old_value` |

Note: WGSL requires `atomic<u32>` type for the buffer. The lowering must
declare atomic buffers with `array<atomic<u32>>` instead of `array<u32>`.

## Permanence

All atomic semantics are permanent. Sequential consistency is permanent.
Return-before semantics are permanent. OOB-returns-zero is permanent.

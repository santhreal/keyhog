# Invocation Model

## Dispatch Shape

A vyre Program is dispatched with a workgroup count `(gx, gy, gz)` determined
by the runtime. The Program declares `workgroup_size = [wx, wy, wz]`.

Total invocations: `gx * wx * gy * wy * gz * wz`.

Most programs use 1D dispatch: `workgroup_size = [W, 1, 1]`, dispatched with
`(ceil(N / W), 1, 1)` workgroups for N elements. 2D and 3D dispatch are
available for image/volume workloads.

## Identity Expressions

### InvocationId (global_invocation_id)

`Expr::InvocationId { axis }` returns the global invocation index.

| Axis | Range | WGSL |
|------|-------|------|
| 0 (x) | `[0, gx * wx)` | `global_invocation_id.x` |
| 1 (y) | `[0, gy * wy)` | `global_invocation_id.y` |
| 2 (z) | `[0, gz * wz)` | `global_invocation_id.z` |

This is the most commonly used identity. For a 1D dispatch of N elements:
`InvocationId { axis: 0 }` ranges from 0 to N-1 (approximately — the actual
range is `gx * wx` which may exceed N due to workgroup rounding).

### WorkgroupId (workgroup_id)

`Expr::WorkgroupId { axis }` returns the workgroup index.

| Axis | Range | WGSL |
|------|-------|------|
| 0 (x) | `[0, gx)` | `workgroup_id.x` |
| 1 (y) | `[0, gy)` | `workgroup_id.y` |
| 2 (z) | `[0, gz)` | `workgroup_id.z` |

### LocalId (local_invocation_id)

`Expr::LocalId { axis }` returns the invocation's position within its
workgroup.

| Axis | Range | WGSL |
|------|-------|------|
| 0 (x) | `[0, wx)` | `local_invocation_id.x` |
| 1 (y) | `[0, wy)` | `local_invocation_id.y` |
| 2 (z) | `[0, wz)` | `local_invocation_id.z` |

### Relationship

```
InvocationId.x = WorkgroupId.x * workgroup_size[0] + LocalId.x
InvocationId.y = WorkgroupId.y * workgroup_size[1] + LocalId.y
InvocationId.z = WorkgroupId.z * workgroup_size[2] + LocalId.z
```

This relationship is guaranteed by the spec. A backend that violates it is
non-conforming.

## Excess Invocations

When dispatching `ceil(N / W)` workgroups for N elements, the total invocation
count `ceil(N / W) * W` may exceed N. Invocations with `InvocationId.x >= N`
are "excess" invocations.

Excess invocations still execute. Their behavior is defined by the Program.
The standard pattern is an early-exit bounds check:

```
let idx = InvocationId { axis: 0 };
if idx >= BufLen("output") {
    Return;
}
// ... rest of computation
```

**The runtime does NOT automatically skip excess invocations.** It is the
Program's responsibility to handle them. This is deliberate: the Program
knows its own semantics. The runtime does not.

If an excess invocation reads from a buffer at index `idx` where
`idx >= buffer_length`, it gets zero (see `out-of-bounds.md`). If it writes,
the write is a no-op. No crash, no corruption. But the Program should still
bounds-check for clarity.

## Axis Validation

The axis parameter for InvocationId, WorkgroupId, and LocalId must be 0, 1,
or 2. Any other value is a validation error caught by `ir::validate`.

## Permanence

The identity relationships, ranges, and excess-invocation behavior are
permanent. `InvocationId.x = WorkgroupId.x * workgroup_size[0] + LocalId.x`
will never change.

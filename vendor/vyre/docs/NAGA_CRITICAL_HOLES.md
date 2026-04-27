# F-NAGA — Critical Naga Lowering Holes (tracking doc)

Tracks #171 F-NAGA. Supersedes ad-hoc notes across the audit train.
Companion to `docs/NAGA_LOWERING_STATUS.md` (shipped/open list)
and `docs/NAGA_LOWERING_AUDIT.md` (Loop/If/Region coverage).

## Critical holes (shipped fixes or explicit rejections)

| Hole | Status | Resolution |
|---|---|---|
| `Expr::Cast` target missing U64 arm | shipped rejection | Named error pointing at vec2 emulation (NAGA_DEEPER F53). |
| `emit_binop` on U64/I64 silently componentwise | shipped rejection | Arithmetic rejected; bitwise/equality allowed (NAGA_DEEPER F59). |
| `emit_bool_from_handle` rejecting F32 | shipped | `f32 != 0.0` path (NAGA_DEEPER F54). |
| Array stride silent default 4 | shipped | LoweringError naming buffer (NAGA_DEEPER F52). |
| Atomic element type hard-coded to u32 | shipped | Derived from op (NAGA_HOLES F06). |
| Node::AsyncLoad/Store/Wait silently skipped | shipped | Dedicated arms or explicit rejection (NAGA_HOLES F19). |
| Node::Trap/Resume silently skipped | shipped | Same (NAGA_HOLES F20). |
| Node::If missing bool condition check | shipped | Guard in emit_if (NAGA_HOLES F22). |
| AtomicOp::CompareExchangeWeak/FetchNand/Opaque rejected | shipped | Dedicated arms + extension dispatch (NAGA_HOLES F07/F08/F09). |

## Critical holes still open

Tracked in #171 F-NAGA; each requires structural naga emitter work.

| Hole | Reason open | Next step |
|---|---|---|
| Expr::SubgroupBallot / Shuffle / Add | Naga 24 feature-gates these; vyre-intrinsics still submits them unconditionally. | Feature-gate the intrinsics under `subgroup-ops` to match naga; re-admit on naga ≥ 25. |
| Expr::BufLen on workgroup buffer | ArrayLength invalid for workgroup (static-size only). | Read static count from `BufferDecl.count`; guarded by `is_workgroup()`. |
| Expr::Fma type-agnostic | Assumes F32 regardless of operand type. | Dispatch on operand dtype; route I32/U32 through a fallback. |
| Node::Barrier scope | Always emits combined STORAGE\|WORK_GROUP. | Add `scope: BarrierKind` parameter; map to exact naga flag (Workgroup/Storage/Subgroup). |
| Node::Loop double-evaluation of `to` | Bound expression re-evaluated each iteration. | Cache the bound in a naga local before entering the loop. |
| Node::Loop error-path body loss | Saved function body dropped if error mid-emit. | Restore body on error; propagate error. |

## Gate

`cargo test -p vyre-driver-wgpu --tests` must pass. Missing
`naga_deeper_regressions.rs` entries = a silent-correctness gap
re-opened; fix or document rejection path.

`gap_validation_cross_backend.rs` + `gap_determinism_contract.rs`
+ `gap_device_lost_recovery.rs` + `gap_dispatch_preemption.rs`
cover cross-cutting holes as they land.

## Operating rule

No IR variant ships without a naga path (emit arm OR named
rejection). Silent-correctness lowering bugs are always CRITICAL
regardless of the overt impact — downstream consumers relying on
"it compiled, it must be right" pay the bill.

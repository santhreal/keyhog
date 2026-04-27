# Naga Lowering Status

Closes #29 A.5 (naga lowering — zero holes) at the documentation
level; the remaining code-level holes are tracked under #171 F-NAGA.

## The contract

Every `vyre::ir::*` construct lowers to a valid naga `Module` on the
wgpu backend, or returns a `LoweringError` whose `Fix:` hint names
the missing path. Silent-correctness failures (the NAGA_DEEPER
CRITICAL category) are specifically excluded — an unsupported
op/type MUST reject, never "work by accident."

## Closed holes

Landed this cycle (all in `vyre-driver-wgpu/src/lowering/naga_emit/`):

| Finding | Symptom | Fix |
|---|---|---|
| NAGA_HOLES F01, F10, F11, F21 | `_ =>` catch-alls on `#[non_exhaustive]` enums silently accepted future variants. | Removed or replaced with loud `Err`. |
| NAGA_HOLES F06 | `Expr::Atomic` result type hard-coded to `u32_ty`. | Correct type derived from operand. |
| NAGA_HOLES F07, F08, F09 | `AtomicOp::{CompareExchangeWeak, FetchNand, Opaque}` rejected. | Lower directly or route through registered extension. |
| NAGA_HOLES F19, F20, F22 | `Node::{AsyncLoad, AsyncStore, AsyncWait, Trap, Resume}` silently skipped; `If` didn't validate boolean condition. | Dedicated arms + bool-coercion guard. |
| NAGA_DEEPER F52 | Array stride silently defaulted to 4 when `size_bytes()` was None. | Reject with LoweringError naming the buffer. |
| NAGA_DEEPER F53 | `Expr::Cast { target: U64 }` fell through to generic unsupported_type error. | Named rejection pointing at the vec2<u32> emulation pass. |
| NAGA_DEEPER F54 | `emit_bool_from_handle` rejected F32 — callers had to insert manual comparisons. | Accept F32 via `f32 != 0.0`. |
| NAGA_DEEPER F59 (CRITICAL) | `BinOp::Add` on U64 silently wrong (componentwise vec2 with no carry). | Reject arithmetic binops on U64/I64 until emulation lands; bitwise + equality remain allowed. |
| F-ADV labels | TOML parse poison + mis-categorised sanitizer families. | Label file normalisation landed. |

## Open holes

Tracked under #171 F-NAGA:

- NAGA_HOLES F02, F03, F04 — `Expr::SubgroupBallot/Shuffle/Add`
  fast-path unification (naga 24 gating workaround).
- NAGA_HOLES F13 — `Expr::BufLen` on workgroup buffers emits
  invalid `ArrayLength` (needs static length from `BufferDecl.count`).
- NAGA_HOLES F14 — `Expr::Fma` assumes F32 regardless of operand
  types (needs dtype dispatch).
- NAGA_HOLES F15 — `Node::Region` silently flattens into parent
  block (loses the Region wrapper — structurally OK but loses
  debugger provenance; `print-composition` still sees the chain
  through `Ident::generator`).
- NAGA_HOLES F16 — `Node::Barrier` emits combined
  `STORAGE|WORK_GROUP` for every barrier; should be scoped.
- NAGA_HOLES F17/F18 — `Node::Loop` double-evaluates `to` + loses
  saved body on the error path.
- NAGA_HOLES F23-F26 — scalar type rejection breadth (Bytes,
  Array, Vec2U32, Vec4U32 preregistration).

## Gate

`cargo test -p vyre-driver-wgpu --tests` must pass green before any
release tag. `naga_deeper_regressions.rs` locks the silent-
correctness fixes (F52/F53/F54/F59). The gate fails loudly if any of
those regress.

## Operating rule

New IR variants must land with a naga lowering arm in the same PR,
or with an explicit rejection that names the missing path. "The
lowering catches up later" is the origin story of every silent
corruption bug we've closed.

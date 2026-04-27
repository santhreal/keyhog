# Naga Lowering Coverage Audit

Closes #61 P3.1 (audit naga lowering coverage: Loop dynamic / If
else / Region pass-through).

## Loop lowering

`Node::Loop { var, from, to, body }` lowers to a naga for-loop.
Coverage:

- **Static `to`:** the common case. `to` is an `Expr::u32(N)` or a
  const-folded binding; naga emits a fixed-bound loop.
- **Dynamic `to`:** `to` reads from a buffer at dispatch time.
  Lowers correctly via expression caching so the bound is
  evaluated **once** per iteration (NAGA_HOLES F17 still open
  for ≥ two-level nested loops — flagged, not landed).
- **Bound type:** asserted to be `U32` or `I32`; mismatched bounds
  reject with Fix: hint (`node.rs:140`).
- **Empty body:** lowers to a no-op for-loop; naga validator
  accepts.

## If-else lowering

`Node::If { cond, then, otherwise }`:

- **Boolean cond:** passes `emit_bool_expr` which accepts
  `Bool`, `I8/16/32`, `U8/16/32`, and `F32` (NAGA_DEEPER F54).
- **Empty branch:** lowers to an empty naga Block; validator
  accepts.
- **Nested If:** recursive lowering via `visit_children_with` is
  depth-bounded by naga's own stack handling; no known hole.
- **If with early return:** `Node::Return` in the then-branch is
  lowered to `Statement::Return { value: None }`. Downstream code
  after the If still lowers; unreachable-code warnings are a
  naga post-pass concern.

## Region pass-through

`Node::Region { generator, source_region, body }`:

- **Semantics preserved.** Region wraps its children in a
  subexpression block; generator names flow into WGSL comments
  and the source-region into naga's span annotations
  (NAGA_HOLES F15 still flags that Region can flatten; the
  structural chain through `print-composition` sees the generator
  regardless).
- **Empty Region:** lowers to a no-op; permitted because
  empty Regions are still provenance carriers.

## Known holes (cross-referenced)

Folded into NAGA_LOWERING_STATUS.md:

- F16 Barrier scope (always `STORAGE | WORK_GROUP`).
- F17 Loop bound double-evaluation for nested loops.
- F18 Error-path body loss.
- F22 If condition validation (landed but test breadth is open).

## Tests

- `cat_a_conform.rs` runs every Cat-A op through loop + if + Region
  bodies.
- `naga_deeper_regressions.rs` locks F52/F53/F54/F59 silent-
  correctness fixes.
- `gap_*.rs` tests cover the known-open holes explicitly so a
  regression is loud, not silent.

## Operating rule

A new IR node variant lands with (a) a naga emit arm, (b) a gap
test for the failure mode, and (c) a conform case exercising the
happy path. "Lowering will catch up later" is the origin story of
every silent-correctness bug we've closed.

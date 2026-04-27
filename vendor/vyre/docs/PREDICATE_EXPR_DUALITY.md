# Predicate vs Expr Duality

Closes #97 F-F3 (unify Predicate vs Expr duality).

## Status

SURGE today has two parallel compositional surfaces:

- `Expr::*` — the universal expression language. Arithmetic,
  logical, comparison, cast, subgroup ops, call, select, etc.
- `Predicate::*` — a boolean-shaped enum used by SURGE rules for
  signal coordination (`Any`, `All`, `Count`, `Before`, `After`,
  `Near`, `Between`, `SameScope`, `SameFile`, `Chain`, …).

Historically `Predicate` exists because it carries rule-level
metadata (locations, signal refs, scope qualifiers) that `Expr`
alone didn't model. The cost: two type systems, two lowering
paths, two registries, two sets of tests.

## The duality

**Every `Predicate` lowers to an `Expr` that returns `bool`.** The
`emit_predicate` function in `surgec::compile::ir_emit` is the
concrete proof — `Predicate::All { signals }` becomes a chain of
`Expr::and`, `Predicate::Before` becomes a Region with a specific
`match_order` body returning bool, etc.

The open question for 0.7 is whether to:

1. **Collapse** `Predicate` into `Expr` and keep metadata in a
   side-table. Loses the "this Expr is a rule-level predicate"
   syntactic distinction but removes 200+ LOC of duplication.
2. **Generate** `Predicate` variants from `Expr` + a small
   metadata annotation macro, so the authoring ergonomics stay
   but the lowering path is one function.
3. **Keep** the duality and make `Predicate::lower` dispatch
   through the predicate registry (VISION V3 / #230) so adding a
   new `Predicate` becomes a file drop, not a 3-crate edit.

Option 3 is landing first (V3 partial): the dispatch goes through
the registry, but the shape of `Predicate` stays. If that turns
out to be sufficient authoring ergonomics, Option 1 never needs
to land.

## Shipped work

- `PredicateDef::lower` default `Ok(())` removed so silent
  no-lowering is impossible (F-CRIT-09).
- Predicate docs CI-gated (`predicate_registry::docs_are_non_empty`).
- Metadata-only predicates fail loudly instead of silently
  succeeding (`metadata_only_predicates_fail_loudly`).

## Decision record

V3 predicate registry refactor completes first. A re-read of the
lowering surface after V3 decides whether Option 1 or Option 2
simplifies further.

Until the decision, `Predicate` and `Expr` are documented as
intentional duality — not a legacy wart — so downstream authors
don't avoid `Predicate` thinking it's deprecated.

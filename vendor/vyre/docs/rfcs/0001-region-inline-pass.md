# RFC 0001 — Region inline pass

## Summary

Add an opt-in optimizer pass that unrolls `Node::Region` bodies into
their parent scope when the pass's cost model decides inlining
benefits the program.

## Motivation

`Node::Region` wraps library compositions (FlashAttention, Linear,
matmul) as opaque IR units so the optimizer walks them as single
nodes by default. This preserves source-mapping and makes
`tracing::trace_span` events useful. But some workloads benefit
from aggressive inlining — fused kernels, whole-program
optimization. Today inlining is all-or-nothing via caller choice.

## Design

One pass: `RegionInlinePass { policy: InlinePolicy }`.

`InlinePolicy` variants:
- `Always` — unroll every Region unconditionally
- `Never` — preserve every Region (default; existing behavior)
- `SizeThreshold(usize)` — inline when `body.len() <=`
- `LawGuided` — inline when algebraic-law optimizer passes would
  rewrite across the boundary
- `Callback(fn(&Region) -> bool)` — caller decides per-Region

The pass runs at `PassKind::Inline` phase, after CSE and before
fusion. Inlining a Region replaces the `Node::Region { body, .. }`
with `body`'s contents hoisted into the parent `Vec<Node>`. Source-
region metadata is preserved on a best-effort basis via a new
`Node::InlineMarker { origin: GeneratorRef }` sentinel that
stays in the stream for trace-mapping.

## Testing

- Property: `eval(p) == eval(inline(p))` for every valid `p`
- Bench: FlashAttention-shaped programs inline vs not-inlined,
  compare dispatch latency
- Adversarial: deeply nested Regions (A wraps B wraps C) must
  inline correctly

## Alternatives considered

- **Always-inline semantics.** Rejected: kills source-mapping +
  makes BackendError stacks useless.
- **No inlining, optimizer sees only Regions.** Rejected: leaves
  cross-Region optimization opportunities on the floor.
- **Inline at backend lowering.** Rejected: every backend
  re-implements the same inlining logic.

## Open questions

- How to preserve `source_region` through deep inlining chains.
- Whether `InlineMarker` becomes a first-class IR node or a
  comment-only optimizer artifact.

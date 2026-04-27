# vyre IR — Statement semantics (0.6 frozen)

> ⚠️ **Staleness warning (V7-CORR-002/003)**: this doc names
> `Node::Let`, `Node::Assign`, and `Node::forever` tag values that
> do not match the live wire format in
> `vyre-foundation/src/serial/wire/encode/put_node.rs` +
> `impl_reader.rs`. The authoritative tags live there.
>
> `Node::forever` is not a real variant; it is an aspiration for
> sugar over `Node::Loop { to: u32::MAX }`. Treat any mention here
> as future-tense until the variant lands in `vyre::ir::Node`, the
> encoder/decoder, the validator, and both interpreter paths.
>
> Full rewrite tracked in `audits/V7_STATUS.md` under V7-CORR-002/003.

This document is the canonical specification of every `Node` variant's
evaluation semantics. Backends (reference, wgpu, spirv, photonic) MUST
produce byte-identical output for every program whose execution
schedule these rules cover. Any divergence is a conformance bug per
the OCC registry (see `docs/occ.md`).

The rules below are frozen for the 0.6 series. Semver-major releases
may extend the node set; no existing variant's semantics may change.

## Variable lifecycle: `Let`, `Assign`, scope

`Node::Let { name, value }` introduces a new binding in the current
scope. The binding is live from the immediately-following statement
until the enclosing scope exits. **Shadowing is disallowed** — a
second `Let` with the same name anywhere in the visible scope chain
(current or enclosing) is a `V008` validation error. Pick unique
local names; the validator enforces this contract machine-checkably.

This rule is intentional: it keeps the statement-IR easy to reason
about, eliminates a class of SSA-conversion edge cases, and matches
WGSL's explicit no-shadowing discipline. Autodiff and canonical-form
passes rely on it — any pass that wants to rename must produce
globally unique names.

`Node::Assign { name, value }` mutates the most recent `Let` binding
of `name` in scope. It is an error (surfaced by the validator) to
`Assign` to a name that has not been `Let`-bound in scope.

**This is the contract every Cat-A composition depends on:**

- `Let(acc, 0)` then `Assign(acc, acc + x)` inside a loop accumulates
  across iterations (not a fresh binding per iteration).
- `Let(state, 0)` at the outer scope then a sequence of `Assign(state, …)`
  inside an inner scope observably mutates the outer binding from the
  perspective of every later statement in the outer scope.
- `Assign` does not create a new binding. A failed `Assign` (no prior
  `Let`) MUST return a `PipelineError::Validation` with code `V033`.

### Scope rules

| Construct | Opens new scope? | Inherits parent? |
| --- | --- | --- |
| `Node::Block` | yes | yes |
| `Node::Loop` | yes (per-iteration scope is child of loop header scope) | yes |
| `Node::If { then, otherwise }` | yes (one per branch) | yes |
| `Node::Region { body, … }` | **no** (transparent wrapper) | yes |

Region transparency is load-bearing: it means `Assign` from inside a
vyre-libs composition can mutate a binding the caller established
before wrapping the call in a `Region`. Composition-preserving
refactors (e.g. `region_inline`) are guaranteed not to change any
observable state by this rule.

### Why Assign exists at all

vyre IR is deliberately not SSA. Algebraic-law passes, autodiff
transform, and canonical-form normalization all run over a statement
IR whose mutation is local to a named binding. SSA can be derived on
demand via `transform::ssa::to_ssa`; it is not the canonical form.

**Future-proofing:**

- The validator freezes this contract in code. Any future pass that
  wants to assume immutability must call `transform::ssa::to_ssa`
  first.
- Wire format: `Node::Let` and `Node::Assign` have distinct tag bytes
  (`0x02` and `0x03`). The validator treats stray `Assign` as a hard
  error, not a warning, so downstream tools can trust the shape.
- The conformance runner generates proptest cases that exercise
  every combination of shadowing, scope exit, and Region wrapping,
  and every backend must match the CPU reference byte-for-byte.

## Execution order within a `Vec<Node>`

Statements execute top-to-bottom. Control-flow statements (`If`,
`Loop`, `Return`, `Barrier`) have their usual meaning. `Return`
unwinds all scopes and exits the current entry-point invocation.
`Barrier` is a workgroup synchronization point; passing through a
divergent barrier is `V010` (validation error).

## Iteration semantics for `Node::Loop`

`Node::Loop { var, from, to, body }` evaluates `from` and `to` once
at loop entry. The loop variable `var` is `from`, `from+1`, …,
`to-1` (half-open). The body runs once per iteration in a fresh
child scope; `Assign`s to the loop variable itself are `V011`
(loop variables are immutable — rename).

`Node::forever(body)` is sugar for `Loop { var: "__forever__",
from: 0, to: u32::MAX, body }`, chosen so existing passes process
it without a new variant.

## Region semantics recap

`Node::Region { generator, source_region, body }` is a pure
debug-wrapper. Evaluation is identical to `Node::Block(body)` — the
two fields are informational only and do not affect semantics. The
reference interpreter executes the body in the current scope; the
wgpu/spirv backends lower the body in place; `region_inline`
flattens it into the surrounding sequence when its node count is
below the inline threshold.

## `Node::Opaque` semantics

`Node::Opaque(extension)` delegates evaluation to the registered
`OpaqueNodeResolver` for `extension.extension_kind()`. If no
resolver is registered for that kind at dispatch time, the backend
returns `PipelineError::Backend` with a `B-CAP-003` code. The
resolver's evaluation MUST satisfy the same observable-state
contract as core nodes.

## Error codes introduced by this contract

| Code | Rule | Fix template |
| --- | --- | --- |
| `V033` | `Assign` to a name not `Let`-bound in the enclosing scope chain | Add a `Node::Let { name, value }` before the first `Assign { name, … }` in this scope or an enclosing scope. |

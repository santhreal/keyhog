# LEGO-BLOCK rule — composition is the architecture

This doc codifies the workspace-wide rule that every author + agent
MUST follow before adding a new sub-op.

## The rule

> **Before inventing a new sub-op, scan `vyre-primitives/src/<domain>/`
> (feature-gated: `text`, `matching`, `math`, `nn`, `hash`, `parsing`,
> `graph`) and `vyre-libs/src/{math,nn,hash,matching,parsing,text, security,logical}` for an existing primitive that does the work.
> Only invent a new sub-op when (a) nothing existing maps AND (b) the
> new sub-op will be reused by 2+ callers.**

The Gate 1 complexity budget (see `docs/primitives-tier.md`) is
enforced by *reuse*, not by bespoke splitting. When attention has 8
loops, the answer is not 4 new attention-private sub-ops; it is
"composes existing matmul + softmax + layer_norm primitives." When
blake3_compress has 601 nodes, the answer is not "split into 4
blake3-only chunks"; it is "extract the G mixing function and the
round permutation as `vyre-primitives-hash::blake3_g` /
`blake3_round`, reused by future `blake3_keyed`, `blake3_xof`, and
`blake3_tree_hash`."

## Why

Vyre's product claim is "compose perfect primitives, beat monolithic
kernels." That claim fails the moment a dialect crate reinvents a
primitive locally — the new caller doesn't benefit from the existing
one's hardening, the optimizer can't fuse across the boundary, and
the LEGO substrate fragments. Every primitive that lives in only one
op's source file is wasted leverage.

## Discovery checklist

Before writing a new sub-op:

1. **Search by name.** `rg -i 'fn <verb>' vyre-libs/src vyre-primitives-*/src` —
  if the work has a name (matmul, scan, hash, dfa_step), someone has
   probably written it.
2. **Search by op id.** `cargo xtask print-composition vyre-libs::`* —
  walks every registered op's region tree. If a target Region's
   `generator` reads like the work you're about to do, that's the
   primitive.
3. **Search by region chain.** Pick a sibling op (same domain, similar
  shape) and run `cargo xtask print-composition <sibling_op_id>`.
   The chain shows what primitives that sibling already composes —
   chances are 1+ apply to your op too.
4. **Ask Gate 1.** `cargo xtask gate1` reports per-op
  `composed_fraction`. If your sibling has a high composed_fraction,
   that's the playbook to follow.

## Promotion criteria (single-caller → primitive)

A `fn(...) -> Program` graduates from "private to one dialect" to
"public Tier 2.5 primitive" when ALL THREE conditions hold:

1. **Reusability.** ≥ 2 Tier-3 dialects (or one Tier-3 dialect +
  `xtask` / conform harness / a planned community pack) consume it.
2. **Stability.** The primitive's API has settled — argument list is
  small, named, no caller is asking for breaking changes.
3. **No domain glue.** The primitive does ONE concern. `matmul` does
  matmul, not "matmul plus a softmax for transformers." Domain
   compositions glue primitives together; the primitive itself is
   single-purpose (LAW 7).

If only ONE caller has a private helper, leave it alone — premature
promotion creates churn for no gain. The xtask `cargo xtask gate1`
will surface promotion candidates as composed_fraction trends down
across multiple dialects.

## Before / after example — `attention`

### Before (Gate 1 fails, 8 loops, composed_fraction=0%)

```rust
pub fn attention(q: &str, k: &str, v: &str, out: &str, d: u32, s: u32) -> Program {
    // bespoke 8-loop body that inlines:
    //   - q @ k^T computation         (would be `matmul`)
    //   - per-row max for stable softmax  (would be `reduce_max`)
    //   - per-row exp/sum/divide      (would be `softmax_step`)
    //   - score @ v                   (would be `matmul`)
    //   - residual norm               (would be `layer_norm`)
}
```

### After (Gate 1 passes via composition, 0 inline loops)

```rust
pub fn attention(q: &str, k: &str, v: &str, out: &str, d: u32, s: u32) -> Program {
    let scratch_scores = "scores_scratch";
    let scratch_norm = "norm_scratch";
    Program::wrapped(
        vec![/* ... declarations including scratches ... */],
        [s, 1, 1],
        vec![
            region::wrap_child(
                "vyre-libs::nn::attention",
                /* parent generator-ref */,
                vec![
                    // every step is a wrap_child INTO a registered primitive
                    region::wrap_child("vyre-primitives-math::matmul", /* ref */,
                        vec![/* call into matmul body */]),
                    region::wrap_child("vyre-primitives-nn::softmax_step", /* ref */,
                        vec![/* call into softmax_step body */]),
                    region::wrap_child("vyre-primitives-math::matmul", /* ref */,
                        vec![/* second matmul */]),
                    region::wrap_child("vyre-primitives-nn::layer_norm_step", /* ref */,
                        vec![/* residual norm */]),
                ],
            ),
        ],
    )
}
```

Gate 1 passes: 4 child regions, each a registered Tier 2.5 primitive,
composed_fraction=100%. The optimizer can still inline+fuse across
boundaries; the composition chain stays visible to
`print-composition` for audit.

The win: a future `linear_attention`, `multi_query_attention`, or
`flash_attention_v2` reuses the same matmul + softmax_step +
layer_norm_step primitives. No code duplication. No drift.

## Anti-patterns the rule rejects

- **"I'll factor it out later" inline helpers.** If you're writing a
`fn(...)->Program` that's local to one op file, ask the
Discovery-checklist questions first. If a primitive exists, use it.
- **Cross-dialect reach-around.** Tier 3 dialect `vyre-libs-nn`
importing private items from `vyre-libs-matching`. Lift to Tier
2.5 (`vyre-primitives-matching::dfa_step`) instead.
- **Bespoke split to satisfy Gate 1.** Splitting `attention` into
`attention_part_a` / `attention_part_b` private helpers passes the
loop count but fails the LEGO test — there's no reuse, just visual
surgery. Gate 1 enforcement detects this via composed_fraction.
- **Premature promotion.** Lifting a single-caller helper into a
Tier 2.5 crate before a second consumer materializes. Wait for the
second caller; promote when ≥ 2 want it.

## Workflow when the primitive doesn't exist yet

1. Write the primitive directly in the appropriate
  `vyre-primitives-<domain>/src/ops/<primitive>.rs` (NOT inside the
   consuming dialect).
2. Add an `inventory::submit!(OpEntry)` registration so the universal
  harness picks it up.
3. Add `test_inputs` + `expected_output` (use `cargo xtask trace-f32`
  for f32 ops).
4. Add the primitive's docstring + a one-line note in
  `docs/primitives-tier.md` recording who consumes it.
5. Now wire your high-level op to call into it via
  `region::wrap_child(<primitive_op_id>, ...)`.
6. Run `cargo xtask gate1` — your op should now pass via composed_fraction.

## Enforcement

- `cargo xtask gate1` runs in CI and fails on Gate 1 budget violations.
- `composition_discipline.rs::no_op_reinvents_another_registered_op` tests
scan for op bodies whose IR fingerprint matches an already-registered op
but isn't dispatching through it.
- Code review: every PR touching `vyre-libs/src/<domain>/.../*.rs` that
adds a new `fn(...)->Program` must include a one-line "Discovery
checklist" note in the commit body confirming nothing existing
applied.

## Before / after example — `visual` domain (Molten)

This is a real decomposition that occurred when adding GPU-accelerated
visual effects (blur, shadow, filter chains) for the Molten web engine.
It illustrates the full discovery process and how domain-level thinking
distills into existing primitives.

### Attempt 1: new Tier 2.5 domain `visual/` with 6 primitives

Initial plan created an entire `vyre-primitives/src/visual/` domain:

```
vyre-primitives/src/visual/
├── blur.rs            # two-pass Gaussian blur
├── shadow.rs          # box shadow with SDF falloff
├── filter_chain.rs    # brightness/contrast/saturate/invert
├── composite.rs       # Porter-Duff alpha over
├── gradient.rs        # CSS gradient rasterization
└── downsample.rs      # 2× box-filter downsample
```

Each file was a monolithic `fn(...) -> Program` — ~200 lines of inlined
IR with custom pixel unpacking, color math, and kernel loops. Gate 1
would have rejected every one of them on composed_fraction = 0%.

### Attempt 2: decompose into real primitives

Applied the discovery checklist. Proposed Tier 2.5 primitives:

- `visual::separable_conv` — 1D convolution along an axis
- `visual::pixel_pack` — RGBA u32 ↔ separate channels
- `visual::color_lerp` — interpolate between two colors
- `visual::sdf_rounded_rect` — signed distance to a rounded rect

### Attempt 3: dissolve into existing domains (correct answer)

Applied the checklist *again*. Each "visual primitive" collapsed into
something that already exists or belongs in `math/`:

| Proposed visual primitive | Actual home | Why |
|---|---|---|
| `separable_conv` | **`math::conv1d`** | 1D convolution is domain-neutral — used by signal processing, audio, NLP, and image processing. Not visual-specific. |
| `pixel_pack/unpack` | **Already Tier 1 IR** | `Expr::bitand`, `Expr::shr`, `Expr::shl`, `Expr::bitor` do this directly. No primitive needed. |
| `color_lerp` | **Already Tier 1 IR** | `lerp(a, b, t) = a + (b - a) * t` — three Expr ops. A color is just a value. |
| `sdf_rounded_rect` | **Private in Tier 3** | Only one consumer (`box_shadow`). By the promotion rule, stays inline until a second caller appears. |

**Result:** the `visual/` Tier 2.5 domain was deleted entirely. The only
new Tier 2.5 primitive is `math::conv1d` — a 1D separable convolution
that blur, signal processing, and future audio ops all compose from.

The domain-specific compositions (`blur`, `box_shadow`, `filter_chain`,
`glass`) live in `vyre-libs/src/visual/` as Tier 3 compositions over:

- `math::conv1d` (blur kernel)
- Existing IR expressions (pixel bit manipulation, lerp, clamp)
- Private helpers where only one caller exists (SDF)

### The lesson

**Domain thinking creates domain primitives. LEGO thinking dissolves
them into math.** When the discovery checklist says "nothing existing
maps," run it again — you're probably looking at the wrong abstraction
level. A "color interpolation" is marketing language for a multiply-add.
A "pixel unpack" is marketing language for a bit shift. The LEGO rule
forces you to see through the domain framing to the underlying
operation, which is almost always already in `math/`, `text/`, or the
IR itself.

# RFC 0002 — Reverse-mode autodiff as an IR transform

## Summary

Add an IR transformation pass that consumes a `Program` + a set of
output buffer names + a set of input buffer names, and emits a new
`Program` that computes the gradient of the outputs with respect to
the inputs (reverse-mode accumulation).

## Motivation

Every serious ML IR carries autodiff. JAX builds it on XLA; PyTorch
Inductor on its own graph; MLIR on the `enzyme` dialect. Vyre's
composition ecosystem (`vyre-libs::nn::{linear, attention, softmax}`)
cannot train models without gradient support. For 0.7 vyre needs to
be the IR ML frameworks target directly.

## Design

Two public entry points, both in `vyre-foundation::transform::autodiff`:

```rust
pub fn grad(program: &Program, outputs: &[&str], inputs: &[&str])
    -> Result<Program, AutodiffError>;

pub fn grad_with_pullback(program: &Program, outputs: &[&str], inputs: &[&str])
    -> Result<(Program, PullbackMap), AutodiffError>;
```

The second form returns both the forward-pass Program + a
`PullbackMap: HashMap<NodeId, Expr>` that captures the gradient
contribution per node — useful for checkpointed backprop (re-compute
instead of store).

Implementation sketch:
1. Walk the forward `Program` top-down, recording each `Expr`'s
   symbolic derivative rule (e.g. `d(a*b)/da = b`, `d(sin(x))/dx = cos(x)`).
2. Build the reverse graph: for each Node, emit gradient
   accumulation into a per-input gradient buffer.
3. Terminal outputs (the user's named outputs) get an implicit
   `1.0` seed in the gradient buffer.
4. The emitted Program declares fresh BufferDecls for each gradient
   buffer + reuses the forward Program's input buffers for the
   stored activations.

For now, every primitive op in `vyre-ops` needs a `d_forward`
companion function in its lowering table. Ops without a registered
derivative raise `AutodiffError::NotDifferentiable { op_id }` with
a clear `Fix: ` hint.

## Differentiable primitive coverage (0.7 target)

- `primitive.math.{add, sub, mul, div, neg, abs}` — trivial
- `primitive.bitwise.*` — NOT differentiable (raise error if hit)
- `primitive.compare.*` — NOT differentiable; surface error
- `logical.{and, or, not}` — NOT differentiable
- `math.{min, max, sqrt, exp, log, sin, cos}` — trivial
- `vyre-libs::nn::{linear, relu, softmax, layer_norm, attention}` —
  composed from differentiable primitives + their own derivatives

## Testing

- Property: `grad_fd(p, eps) ≈ grad(p)` (finite-difference check
  within ULP budget) for every differentiable op
- Conform: gradient Program produces byte-identical outputs on
  every backend
- Gap: every primitive that `vyre-libs::nn` depends on has a
  registered derivative; test fails if any dep is non-differentiable

## Alternatives considered

- **Source-to-source autodiff on Rust code.** Rejected: vyre's
  advantage is IR-level transforms; source-to-source (Enzyme
  style) loses that.
- **Numerical differentiation only.** Rejected: too slow for ML
  inference-training mix; symbolic is the standard.

## Open questions

- Checkpoint-vs-store policy for large-tensor intermediates.
- How to integrate with the upcoming quantization RFC (gradients
  in a quantized domain need scale tracking).

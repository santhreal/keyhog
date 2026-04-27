# The `vyre-std` crate

`vyre-std` is the Layer 2 standard library built compositionally from
the Layer 1 primitives that live in `vyre` core. Every op in this crate
is Category A: it lowers to the same IR nodes a hand-optimizer would
write, carries a CPU reference, and is certified byte-identical by the
conform gate.

## What ships today

- **Pattern compilation pipeline**: `regex_to_nfa` (Thompson),
  `nfa_to_dfa` (subset construction with dead-state pruning),
  `dfa_minimize` (Hopcroft), `dfa_pack` (Dense or byte-equivalence-class
  formats), `dfa_assemble` (composite entry).
- **Aho-Corasick construction**: `pattern::aho_corasick_build` holds
  the CPU reference, WGSL kernel, five GOLDEN samples, and twenty KAT
  vectors for regression anchoring.
- **Content-addressed compilation cache**: `pattern::cache` short-circuits
  the pipeline when the same pattern set has already been compiled. Bypass
  with `VYRE_NO_CACHE=1`.
- **Arithmetic helpers**: `arith::*` exposes 24 saturating + 24
  wrapping + 16 min/max/clamp + 4 midpoint + 4 abs_diff + 6 div helpers
  + 2 lerp = ~80 compositional helpers keyed by concrete type so every
  lowering is byte-explicit.

## Why Layer 2 is compositional

A Cat A op lowers to primitives that already live in Layer 1. Conform
proves the lowered output is byte-identical to the hand-written
composition on every witness. Consumers get expressiveness; the backend
gets simplicity; no runtime library sneaks in.

An op that needs a hardware intrinsic (subgroup shuffle,
dot-product-accumulate, texture sample) belongs in Layer 1 core as Cat
C, not here. The categorical fence is enforced by `enforce/category`.

## The 10-line consumer API

```rust
use vyre_std::pattern::{dfa_assemble, AssembleOptions, Pattern};

let patterns = [
    Pattern::Literal(b"GET /api"),
    Pattern::Literal(b"POST /api"),
    Pattern::Regex("PUT /api/v[0-9]+"),
];

let packed = dfa_assemble(&patterns, AssembleOptions::default())?;
// packed.bytes is ready for a wgpu::Buffer.
```

See [`GPU DFA assembly pipeline`](dfa-assembly.md) for the stage-by-stage
walkthrough.

## Relationship to rulefire

`rulefire` is the rule-engine frontend. It parses YARA/Sigma/Nuclei-style
rule DSLs, canonicalizes them, and emits `vyre::Program` via `vyre-std`'s
pattern pipeline. Consumers who want "rule sets in, match reports out"
install rulefire; consumers who want fine-grained GPU compute write
against `vyre-std` directly. See [Writing a rule frontend](../vyre-and-conform.md)
for the split.

# Library tiers — the long-term organization

This doc locks the rule that says which ops live in which crate. It is
the companion to `docs/primitives-tier.md` (Tier 2.5 rule) and
`docs/lego-block-rule.md` (the workspace-wide reuse policy that makes
Tier 2.5 self-enforcing).

## The governing rule

> **If you can write it as `fn(...) -> Program` using only `vyre::ir::*`
> types, it belongs in `vyre-libs` or a user package, NOT
> `vyre-intrinsics`.**

Any op that requires a dedicated Naga emitter arm (the backend has to
do something other than recurse over existing `Expr`/`Node` variants)
AND/OR a dedicated `vyre-reference` eval arm (the interpreter needs
bespoke logic) is an **intrinsic**. Everything else is a **library op**.

## The five tiers

> See `docs/primitives-tier.md` for the full Tier 2.5 spec.

| Tier | Crate(s) | What belongs here | Stability |
| --- | --- | --- | --- |
| 1 | `vyre-foundation`, `vyre-spec`, `vyre-core` | IR model, wire format, frozen contracts. No ops. | Frozen at minor versions. |
| 2 | `vyre-intrinsics` | Cat-C hardware intrinsics: ops that require dedicated Naga emission + dedicated interpreter handling. Current 0.6 surface: **9 ops** (see below). | Frozen surface; hand-audited. |
| **2.5** | **`vyre-primitives` (feature-gated per domain: `text`, `matching`, `math`, `nn`, `hash`, `parsing`, `graph`)** | **Shared `fn(...) -> Program` primitives reused by ≥ 2 Tier-3 dialects. ONE concern per domain folder; no domain glue. The LEGO substrate.** | **Per-domain feature gate; single crate semver.** |
| 3 | `vyre-libs-{nn,math,matching,hash,security,parse-c,parse-rust,…}` (currently the monolithic `vyre-libs`; splits in Phase K) | Domain-specific compositions over Tier 2.5 primitives. Public surface a downstream tool actually imports. | Per-dialect semver. |
| 4 | `vyre-libs-extern` + `ExternDialect` (third-party packs) | Same Tier-3 op shape; published and versioned independently. | Community-governed. |

## Tier 2 — `vyre-intrinsics` (9 ops today)

| Op | Hardware instruction | CPU reference |
| --- | --- | --- |
| `subgroup_add` | `subgroupAdd()` | single-lane wave reduction |
| `subgroup_ballot` | `subgroupBallot()` | single-lane wave ballot |
| `subgroup_shuffle` | `subgroupShuffle()` | single-lane wave shuffle |
| `workgroup_barrier` | `workgroupBarrier()` | no-op on serial interp |
| `storage_barrier` | `storageBarrier()` | no-op on serial interp |
| `bit_reverse_u32` | `reverseBits()` | `u32::reverse_bits` |
| `popcount_u32` | `countOneBits()` | `u32::count_ones` |
| `fma_f32` | `fma()` | `f32::mul_add` byte-exact |
| `inverse_sqrt_f32` | `inverseSqrt()` | `1.0 / f32::sqrt(x)` bit-exact |

The 3 subgroup ops are feature-gated behind `subgroup-ops` until the
Naga 25+ emitter arm lands (FINDING-PRIM-2).

Tier 2 is intentionally small. Every op here is reviewed by eye. New
entries require a dedicated Naga arm AND a dedicated vyre-reference
eval arm — both are boilerplate that can't be auto-generated from an
IR composition.

## Tier 3 — `vyre-libs` (every composition)

Current submodules (all live under `vyre-libs/src/`):

- `math/` — linear algebra (`linalg`, `broadcast`, `scan`),
  `avg_floor`, `wrapping_neg`, `clamp_u32`, `lzcnt_u32`, `tzcnt_u32`,
  plus `atomic/` (the 8 `atomic_*_u32` ops).
- `hash/` — `fnv1a32`, `fnv1a64`, `crc32`, `adler32`, `blake3_compress`.
- `logical/` — element-wise bool (and, or, xor, nand, nor).
- `nn/` — `relu`, `linear`, `softmax`, `layer_norm`, `attention`.
- `matching/` — `substring_search`, `aho_corasick`, `dfa_compile`.
- `rule/` — typed rule conditions and literal builders (feature `rule`;
  for compilers that lower boolean rule IR to vyre `Program` values).
- `text/` — byte classification, UTF-8 validation, line index
  (feeds parser pipelines such as the C11 front end).
- `parsing/` — `core/` (shared), `c/` (C11 lex / preprocess / parse / pipeline);
  grammar tables for table-driven stages are **host-generated** and loaded
  as `ReadOnly` buffers (see `libs/tools/surgec/grammar-gen`).
- `security/` — taint / flow / dominator-style compositions (composes
  `text` + `parsing` + `graph` primitives; feature-gated in concert with
  upstream callers).
- `hash` still re-exports from the deprecated `crypto` module path
  for one release cycle.

Everything here is a `fn(...) -> Program` over existing
`vyre::ir::Expr` / `Node` variants. No size cap, no dedicated emitter
arm. New ops land via a Write + an `inventory::submit!(OpEntry { ... })`
registration.

## Tier 3 will split (Phase K)

Before 0.7, `vyre-libs` decomposes into per-domain crates so each
becomes its own product with its own semver + community:

- `vyre-libs-nn` — matmul, attention, softmax, layer_norm, relu,
  linear, scan_prefix_sum, broadcast.
- `vyre-libs-crypto` — full BLAKE3 tree-hash, full SipHash, future
  SHA-2.
- `vyre-libs-regex` — DFA compiler, aho_corasick, regex_match,
  substring_search.
- `vyre-libs-parse` (or per-lang `vyre-libs-parse-c`, …) — whole-grammar
  parsers as Cat-A compositions (depends on which front ends are split out
  in Phase K).

Each splits cleanly because `vyre-libs` already organizes by module
boundary. The parent crate becomes a deprecation shim for one minor
version, then goes away.

## Tier 4 — community packs

Same mechanism as Tier 3, but the crate is **not** part of the main
Vyre version train. It registers via `ExternDialect` (see
`vyre-libs-extern`). The dialect name prefix (`vyre-libs-<name>`) tells
downstream tools where an op was defined.

## Op ID naming — tier encoded in the prefix

- `vyre-intrinsics::hardware::<name>` — Tier 2.
- `vyre-libs::<domain>::<name>` — Tier 3. Examples:
  - `vyre-libs::math::clamp_u32`
  - `vyre-libs::math::atomic::atomic_add_u32`
  - `vyre-libs::hash::fnv1a32`
  - `vyre-libs::logical::and`
- `<community-dialect>::<name>` — Tier 4.

A `grep` over the codebase tells you exactly which tier any op
belongs to — and, by extension, which audit / review / stability
guarantees apply.

## Dependency direction — enforced

- Tier 2 may depend on Tier 1. Never the reverse.
- Tier 3 may depend on Tier 2 + Tier 1. Never the reverse.
- Tier 4 may depend on Tier 3 + Tier 2 + Tier 1. Never the reverse.

Currently: `vyre-libs/Cargo.toml` does NOT depend on `vyre-intrinsics`.
Library ops that need a hardware intrinsic construct it by using the
base `Expr`/`Node` variant directly (e.g. `Expr::popcount`), not by
calling into the intrinsic crate. This keeps the dependency graph one-
directional and the two crates independently testable.

## Region chain — mandatory at every tier

Every op at every tier wraps its body in
`Node::Region { generator, source_region, body }`. When an op is
constructed by composing another registered op's builder, the outer
op's `source_region` points back via `GeneratorRef`. See
`docs/region-chain.md`.

`cargo xtask print-composition <op_id>` walks the Region tree from a
registered op down to its leaves — the audit tool that makes
the chain visible.

## What dissolves / what stays

| Former path | Current path | Why |
| --- | --- | --- |
| Legacy monolithic op crate | `vyre-intrinsics` (9 ops) | Scope locked to ops requiring dedicated emitter arms. |
| Legacy hardware-shaped math helpers (`clamp`, `lzcnt`, `tzcnt`) | `vyre-libs::math::*` | Pure IR compositions — library. |
| Legacy atomic helpers | `vyre-libs::math::atomic::*` | `Expr::Atomic` is an existing IR variant — library. |
| Legacy composite hash helpers | `vyre-libs::hash::*` | Hash/checksum ops are pure compositions. |
| `vyre-libs::crypto::*` | `vyre-libs::hash::*` | Consolidated per Migration 3. Old path is a deprecation shim. |
| `vyre-libs-extern` | unchanged | Tier-4 registration mechanism. |
| `vyre-libs-template` | unchanged | Template for Tier-3/4 packs. |

## Anti-patterns the rule rejects

- **Intrinsic with a composable body**: if you can write the op as
  `fn(...) -> Program` using existing `Expr`/`Node` variants, it does
  NOT belong in `vyre-intrinsics`. It goes to `vyre-libs` or a user
  crate.
- **Library op that requires a new `Expr` variant**: backwards —
  adding a new IR variant is a Tier-1 concern in `vyre-foundation`.
  If the new variant is for a hardware intrinsic, wrap it in a
  Tier-2 `vyre-intrinsics` op. Libraries use only existing variants.
- **Tier-3 crate depends on a Tier-3 crate**: allowed but requires
  review. Prefer lifting the shared primitive into Tier 2 or 1.
- **Tier-3 depends on a Tier-4 community pack**: banned. Community
  packs sit on top of the core Vyre stack, not vice versa.
- **Same op registered at two tiers** (e.g. both
  `vyre-intrinsics::hardware::X` AND `vyre-libs::math::X` both active
  in the inventory): banned. Each op has exactly one home. The
  `crypto → hash` shim in 0.6 is a re-export, not a dual registration.
- **`Node::Region { source_region: None }` at the root of a composed
  op**: allowed for anonymous inline construction (most stdlib ops),
  required-non-None when the body was built by calling another
  registered op. `cargo xtask print-composition` relies on this to
  render the chain.

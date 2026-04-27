# Tier 2.5 — `vyre-primitives` (the LEGO block layer)

This doc promotes shared primitive ops out of Tier 3 (`vyre-libs`) into
the `vyre-primitives` crate between intrinsics and library
compositions. It is a direct response to:

- **Gate 1 complexity budget violations** (e.g. `attention` 8 loops,
`blake3_compress` 601 nodes) that appear when a high-level op inlines
primitive work instead of composing it.
- **The LEGO-block thesis** — vyre's whole reason for existing is that
a composition of perfect primitives beats a monolithic kernel. That
thesis fails if every dialect crate reinvents matmul / softmax /
blake3-G / DFA-step locally.
- **Workspace-scaling concerns** as more domains land. With one giant
`vyre-libs` crate every consumer pulls every dialect; a shared
primitive substrate needs a stable home Tier 3 dialects can depend on.

The corresponding layout in `vyre-libs` (Tier 3) is:

- `parsing/core/` — language-neutral substrate: delimiters, shared
  AST node kinds, Shunting-yard and related **generic** table walkers.
- `parsing/c/` — **C11**-specific front end: DFA-oriented `lex/`, `preprocess/`,
  `parse/`, plus `pipeline/` (staged example programs and integration glue).

A second language reuses `parsing/core/` and adds `parsing/<lang>/` the
same way `c/` sits beside `core/`. The names in tree **match the source
files**; there is no separate `ast/`, `common/`, or `opt/` directory at
0.6 — that split was a planning sketch, not the on-disk shape.

## One crate, per-domain feature flags (not seven tiny crates)

Tier 2.5 is a single crate: `vyre-primitives`. Each domain is a folder
under `vyre-primitives/src/<domain>/` gated by a cargo feature:

```
vyre-primitives/
  src/
    lib.rs            # marker types (always on, zero deps)
    text/             # feature = "text"
      mod.rs
      ops/
        char_class.rs
        utf8_validate.rs
        line_index.rs
    matching/         # feature = "matching"
      mod.rs
      ops/
        bracket_match.rs
    math/             # feature = "math"       (scaffolded, empty)
    nn/               # feature = "nn"         (depends on math)
    hash/             # feature = "hash"
    parsing/          # feature = "parsing"    (depends on text + matching)
    graph/            # feature = "graph"
```

A Tier 3 dialect depends on `vyre-primitives` and enables only the
domains it consumes:

```toml
[dependencies]
vyre-primitives = { version = "0.6.0", features = ["text", "matching"] }
```

Separate `vyre-primitives-*` crates were considered and rejected —
publishing one crate with feature gates is cleaner for consumers than
seven tiny crates, and matches the existing `vyre-libs` shape.

## Five-tier model

`docs/library-tiers.md` is the canonical tier table. This section repeats the
shape locally because Tier 2.5 is the reason this document exists.

| Tier    | Crate(s)                                                          | What belongs here                                                                                                        | Stability                                         |
| ------- | ----------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------ | ------------------------------------------------- |
| 1       | `vyre-foundation`, `vyre-spec`, `vyre-core`                       | IR model, wire format, frozen contracts. No ops.                                                                         | Frozen at minor versions.                         |
| 2       | `vyre-intrinsics`                                                 | Cat-C hardware intrinsics: ops requiring dedicated Naga emission AND dedicated interpreter handling. 9 ops.              | Frozen surface; hand-audited.                     |
| **2.5** | `**vyre-primitives` (feature-gated per domain)**                  | **Shared `fn(...) -> Program` primitives reused by ≥ 2 Tier-3 dialects. ONE concern per domain folder; no domain glue.** | **Per-domain feature gate; single crate semver.** |
| 3       | **`vyre-libs` (0.6: one crate, `src/<domain>/` + `Cargo` features; 0.7+ may split to `vyre-libs-*`, see `library-tiers.md`)** | Domain-specific compositions over Tier 2.5 primitives. Public surface a downstream tool actually imports.                | Per-dialect semver.                               |
| 4       | Community packs (`vyre-libs-extern` + `ExternDialect`)            | Same Tier-3 op shape; published and versioned independently of the main crates.                                         | Community-governed.                               |


## Tier 2.5 — the seven domain folders


| Folder      | Feature                      | Responsibility                                                      | Reused by                                    |
| ----------- | ---------------------------- | ------------------------------------------------------------------- | -------------------------------------------- |
| `text/`     | `text`                       | `char_class`, `utf8_validate`, `line_index`, escape handling        | every parser, text-search, security tainting |
| `matching/` | `matching`                   | `bracket_match`, DFA driver, aho-corasick step, substring scanner   | regex dialect, parser lexers, literal sinks  |
| `math/`     | `math`                       | matmul, matmul_tiled, dot, scan_prefix_sum, broadcast, reduce, gemm, conv1d | nn, vision, security graph, Molten visual effects |
| `nn/`       | `nn` (→ math)                | softmax_step, layer_norm_step, attention_score, activations         | transformer/classifier dialects              |
| `hash/`     | `hash`                       | fnv1a32/64, crc32, adler32, blake3_g, blake3_round                  | hash dialect, fingerprinting, Tier-3 callers that need stable digests  |
| `parsing/`  | `parsing` (→ text, matching) | Shunting-yard, packed-AST allocator, table walker                   | every `parse-<lang>` dialect                 |
| `graph/`    | `graph`                      | DAG walks, dominator tree, topological sort, reachability           | security taint flow, optimizer, graph-IR     |


All folders are scaffolded. `text` + `matching` have their first
migrations landed (char_class, bracket_match, utf8_validate,
line_index). Remaining migrations follow Step 2 below.

## What promotes a `fn(...) -> Program` into Tier 2.5

Three conditions, all required:

1. **Reusability.** ≥ 2 Tier-3 dialects (or one Tier-3 + `xtask` /
  conform tooling / a planned community pack) actually want it.
2. **Stability.** The primitive's API has settled — small, named, no
  caller is asking for breaking changes.
3. **No domain glue.** `matmul` does matmul, not "matmul plus a softmax
  for transformers." Domain compositions glue primitives together in
   Tier 3; the primitive itself is single-purpose (LAW 7).

If a primitive only has ONE caller, leave it inside that Tier-3 dialect
until a second caller wants it. Premature promotion creates churn for
no gain.

## The Gate 1 enforcement loop

`cargo xtask gate1` walks every registered op's region tree:

1. Count nodes + loops in its expanded body.
2. If under raw budget (loops ≤ 4 AND nodes ≤ 200), pass.
3. If over budget, walk `Node::Region { source_region: Some(parent) }`
  children. Compute `composed_fraction = nodes_inside_child_regions /  total_nodes`. If `composed_fraction ≥ 0.6`, the op is composing
   primitives correctly — pass.
4. Otherwise fail with a structured diagnostic listing which inline
  sub-blocks would have been composeable as Tier 2.5 primitives.

This makes the LEGO rule mechanical. An author can't game Gate 1 by
wrapping a `Node::Region` around inlined code; the body has to call
into registered primitive ops.

## Migration plan

### Step 1 — scaffold (done)

Single `vyre-primitives` crate now owns the Tier 2.5 substrate.
Seven domain folders with feature gates. CI green at zero cost.

### Step 2 — first migrations per domain

Move ONE primitive into each domain folder from `vyre-libs/src/`.
Preferred candidates:

- `vyre-primitives::math::matmul` ← `vyre-libs/src/math/linalg/matmul.rs`
- `vyre-primitives::hash::blake3_g` (extract from `blake3_compress`)
- `vyre-primitives::matching::bracket_match` ← done (commit 46ce855c22)
- `vyre-primitives::text::char_class` ← done (commit 5ba1a0b0f2)
- `vyre-primitives::parsing::shunting_yard` (extract from `vyre-libs/src/parsing/core/ast/`)
- `vyre-primitives::graph::dominator_tree` (extract — security ops are inert today)
- `vyre-primitives::nn::softmax_step` (extract from `vyre-libs/src/nn/attention/softmax.rs`)

Keep `vyre-libs/` re-exports as OpEntry-registration shims (the op id
stays stable; only the builder moves).

### Step 3 — Gate 1 enforcement (done)

`cargo xtask gate1` implemented. Wired into CI as blocking gate.
Run against the workspace; every Gate 1 violation either composes
primitives or surfaces as a finding for the next migration cycle.

### Step 4 — split `vyre-libs` into `vyre-libs-`* (Phase K, pre-0.7)

With Tier 2.5 settled and Gate 1 enforced, splitting `vyre-libs` is
mechanical: each `vyre-libs/src/<domain>/` becomes its own crate
depending on the `vyre-primitives` domain feature it needs.

## Dependency direction (extends `library-tiers.md`)

- Tier 2.5 may depend on Tier 1 (IR types). Never on Tier 2
(intrinsics use the Naga arm path; primitives compose IR variants
directly).
- Tier 2.5 domain folders may depend on each other (`nn` → `math`,
`parsing` → `text` + `matching`) via feature composition. The graph
stays a DAG.
- Tier 3 (`vyre-libs-*`) may depend on Tier 2.5 + Tier 2 + Tier 1.
- Tier 4 same as today: depends on 3, 2.5, 2, 1.

## Anti-patterns the new tier rejects

- **Domain-specific code in a primitive folder.** `vyre-primitives::math:: attention_score` would be wrong — attention is the domain consumer,
the primitive is `matmul`. Domain glue belongs in Tier 3.
- **Single-caller "primitive."** A `fn(...) -> Program` with one
caller is a private helper, not a primitive. Inline it back until
a second caller appears.
- **Tier 3 reaching past 2.5 into a Tier 2.5 internal module.** Tier
2.5 publishes an API; Tier 3 uses the API.
- **Premature promotion.** Lifting a single-caller helper into Tier
2.5 before a second consumer materializes. Wait for the second
caller; promote when ≥ 2 want it.

## Why this matters for the composability thesis

The design goal is: **compose small vetted primitives, beat monolithic
kernels on audit surface and reuse.** Without a dedicated home for those
primitives, every dialect crate either (a) reinvents them locally —
defeating the claim — or (b) reaches into a sibling dialect's
internals — coupling the ecosystem. Tier 2.5 makes the shared substrate
explicit, versioned, and discoverable.

A community contributor writing `vyre-libs-vision` (image kernels)
imports `vyre-primitives` with `features = ["math", "hash"]` and
ships their image-specific compositions on top. They never have to
know `vyre-libs-nn` exists. That's the moat.

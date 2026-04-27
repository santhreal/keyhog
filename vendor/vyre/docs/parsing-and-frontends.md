# Parsing & frontends — where source-language parsers live

vyre is a strictly GPU-first IR and op catalog. **Front ends** (e.g. C11,
future Rust, Go, Python) are first-class *computations*: lexing,
preprocessing, structural parsing, and static analysis are expressed
as vyre `Program` values. This doc outlines the SIMT story, the
**packed-AST** buffer contract, and **where the code lives in 0.6.x** so
paths in other docs are not wrong.

Companion to:
- `docs/library-tiers.md` — where ops live.
- `docs/region-chain.md` — how compositional ops stay auditable.
- `docs/ops-catalog.md` §1 (graph / AST / dataflow) — the ops that
  operate on parsed ASTs.

## Why processing shifts to GPU natively

Historically, parsers were assumed to be fundamentally CPU-bound due to branch-heavy algorithms. The 1.0 architecture shatters this assumption by adopting parallel SIMT scanning principles:

- **Breaking Branch Dependencies**: Rather than heavy recursive branching, parsing is formulated as a parallel scan over maximal token DFAs, using parallel prefix-scan implementations.
- **Subgroup Contention Relief**: The VRAM bottleneck usually associated with GPU parsing is bypassed by using native subgroup intrinsics (`subgroup_ballot`, `subgroup_add`).
- **Parallel Substrate**: A fully native GPU path avoids shuffling token or
  AST data through a separate host parser on every pass (IPC, extra
  copies, and driver round-trips that dominate small inputs).

What this unleashes for vyre:

- Fully zero-copy memory pipelines across the engine.
- Construction of the packed AST entirely inside VRAM at extreme token throughput.
- A zero-CPU-in-the-loop **goal** for hot paths: raw bytes in VRAM →
  tokens / packed AST → IR-level analyses (e.g. dataflow, taint) without
  serializing back to a host tree on every file.

The pipeline: upload raw source bytes → GPU Lexer (DFA) → GPU Parser (parallel construction) → execute graph ops natively on the resulting `PackedAst` buffer.

## The packed AST buffer contract

Every frontend emits an AST in a uniform layout. vyre ops consume it
without knowing the source language.

### Layout (v0 — frozen at 0.7)

```
struct PackedAst {
    // Global header
    magic:        [u8; 4]  = b"VAST",
    version:      u16      = 0,
    source_lang:  u16,     // 0 = c, 1 = rust, 2 = go, 3 = python, ...
    node_count:   u32,
    file_count:   u32,

    // Per-node table, node_count entries
    nodes: [Node; node_count] = [
        Node {
            kind:        u16,   // language-specific kind
            parent_idx:  u32,   // u32::MAX for root
            first_child: u32,   // u32::MAX if leaf
            next_sibling:u32,   // u32::MAX if last
            src_file:    u32,   // index into files
            src_byte_off:u32,   // byte offset in source
            src_byte_len:u32,   // span length
            attr_off:    u32,   // offset into attr_blob for per-node metadata
            attr_len:    u32,
        }; node_count
    ],

    // Per-file metadata
    files: [FileEntry; file_count] = [
        FileEntry {
            path_off: u32, path_len: u32,   // into string_blob
            size:     u32,
        }; file_count
    ],

    // Variable-length string pool
    string_blob: [u8; …],

    // Variable-length per-node attribute blob (identifiers,
    // literals, type hints — frontend-specific)
    attr_blob:   [u8; …],
}
```

- Fixed-size Node record = direct indexed access, GPU-friendly.
- `parent_idx` + `first_child` + `next_sibling` gives a standard
  tree walk in constant stack.
- `src_byte_off/len` preserves mapping back to source for
  diagnostics.
- `kind` is opaque to vyre; it's a language-local tag the frontend
  documents. Ops that need semantic info (identifier names, type
  kinds) use the attr_blob side channel.

### What vyre ops can assume

An `ast_walk_preorder` dispatched over a `PackedAst` buffer:

1. Reads the Node table at packed offsets.
2. Walks via `first_child` / `next_sibling`.
3. Emits one u32 per visited node to the output buffer in walk order.

Nothing language-specific. Same op works for C, Rust, Go, Python — as
long as the frontend emitted a valid `PackedAst`.

## Where the code lives — **0.6.x (current tree)**

C11 work is **not** a separate `vyre-libs-parse-c` crate yet. It is Tier 3
**inside the monolithic `vyre-libs` crate**, gated by the `c-parser`
`Cargo` feature (off in default features until the surface stabilizes).

| Path | Role |
| --- | --- |
| `vyre-libs/src/parsing/core/` | Language-neutral: delimiters, shared AST pieces, Shunting-yard-style helpers. |
| `vyre-libs/src/parsing/c/` | C11: `lex/`, `preprocess/`, `parse/`, `pipeline/` (stages, examples, glue). |
| `vyre-libs/src/compiler/` | C11 **middle end** on vyre IR: CFG (`cfg`), regalloc, stack layout, object emission (`object_writer`, …), System V–style layout helpers (`types_layout`). Flat modules — file names match `pub mod` names. |
| `vyre-cc/` (workspace crate) | Small driver: enables `c-parser`, wires a backend + runtime; not the IR itself. |
| `surgec-grammar-gen/` (root workspace crate under `libs/tools/surgec/grammar-gen`) | Host-side table generation for grammar-driven GPU parsers; output is loaded as `ReadOnly` buffers. |

**Naming note (Tier 2.5 vs Tier 3):** `vyre-primitives` has a `matching/`
*feature* (bracket matching, etc.). `vyre-libs` has a *different* `matching/`
*module* (substring / DFA compositions). The words collide in English; the
crate path disambiguates.

## Planned layout — per-language Tier-3 **crates** (post–Phase K / 0.7+)

The long-term shape is one crate per major front end, e.g.
`vyre-libs-parse-c`, `vyre-libs-parse-rust`, each emitting `PackedAst` and
depending only on the `vyre-primitives` features it needs. The **0.6**
monolith is a staging step, not the final packaging.

Each such crate will: register `OpEntry` bodies composed from Tier 2.5
primitives (Gate 1), emit `PackedAst` into VRAM, and use subgroup-friendly
algorithms for reductions that would otherwise spam global atomics.

## Performance and Throughput Directives

Because parsing algorithms are traditionally $O(N)$ scalar loops, writing them naively in GPU kernels creates a catastrophic divergence and serialization traps.

**Strict Implementation Imperatives:**
1. **Never** increment global atomic counters natively for every single matched token or AST node. 
2. Use **Subgroup Scans** (e.g., `subgroup_add`, `subgroup_ballot`) to compute offsets simultaneously in a warp, dedicating exactly one thread per warp/workgroup to write to global atomics.
3. Replace linear list traversal algorithms with parallel Hash Tables resolved cleanly via FNV-1a routines operating natively on VRAM slices.
4. Compose modularly: use `vyre_lib::region::wrap_child` and Tier 2.5
   primitives from `vyre-primitives` instead of inlining large
   unregistered `Node::Loop` regions that break Gate 1.

Failure to uphold these paradigms results in a GPU parser that runs orders of magnitude slower than a 16-core CPU. By maintaining this discipline, vyre can realize its massive hardware throughput advantage.

## Front end → IR pipeline (logical)

```text
source file bytes
    │
    │  host: map / upload to storage buffer (any driver helper)
    ▼
raw byte buffer (device-visible)
    │
    │  GPU: vyre-libs::parsing::c::lex  (C11)  —  other langs: parsing::<lang>::…
    ▼
token stream (or preprocessed view)
    │
    │  GPU: vyre-libs::parsing::c::parse
    ▼
PackedAst buffer (per contract above)
    │
    │  GPU: graph / walk ops from vyre-libs::security, vyre-primitives::graph, …
    ▼
analysis buffers (taint, orderings, match hits, …)
    │
    │  host: readback for diagnostics / test oracles
    ▼
structured output
```

The intent is: **one IR**, **registered ops**, **Region chain** (see
`region-chain.md`). The exact `OpEntry` id for a walk or flow pass is
whatever the catalog and `vyre-libs` register — not a second shadow IR.

## Execution plan and current code status

- **Single roadmap** (phases, testing bar, innovation backlog):
  [`PARSING_EXECUTION_PLAN.md`](PARSING_EXECUTION_PLAN.md).
- **`PackedAst` / VAST** in this file is a **design** contract. A **shared
  Rust** `PackedAst` / `VastHeader` in `vyre-foundation` (or `vyre-libs`)
  is **Phase P2** in that plan — not yet the default handoff in code.
- **Grammar table blobs** produced by `surgec-grammar-gen` use wire magic
  **`SGGC`** (see `libs/tools/surgec/grammar-gen/src/wire.rs`); the lexer DFA comes
  from `c11_lexer::build_c11_lexer_dfa()` in the **default** `emit` path.

## Non-scope

- **GPU preprocessor** (#include resolution, macro expansion on GPU).
  Preprocessor is a Turing-complete macro interpreter on tiny
  inputs; GPU is wrong hardware.
- **General-purpose language runtimes** on the GPU (e.g. bytecode
  interpreters, goroutine schedulers) — out of scope; vyre models
  *specific* static or data-parallel passes as IR, not full VMs.
- **Round-trip from `PackedAst` back to source text.** The buffer
  carries byte spans pointing at the source, so diagnostic tools
  reopen the source file and slice — they do not reconstruct from
  the AST.

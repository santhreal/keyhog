# AST / parsing — execution plan (authoritative)

This is the **single** roadmap for **C11 → buffers → GPU analysis** in the
vyre tree. It ties together `parsing-and-frontends.md` (VAST / PackedAst
*design*), `vyre-libs::parsing`, and `surgec-grammar-gen` (table blobs).
Subagents and humans should work **only** from this + linked specs.

## Current reality (2026, audited)

| Piece | State |
|--------|--------|
| **`vyre-libs` C11 path** | **Feature** `c-parser` (WIP, **not** default). Lex + structural passes + shunting; **not** a standards-complete C11 front. |
| **Preprocessor** | `opt_conditional_mask` is below contract; A2 replaces it with table-backed preprocessing masks plus source maps. |
| **LR(1) tables** | `surgec-grammar-gen` ships `smoke_grammar`; A3-A6 replace smoke coverage with C declaration/expression/statement tables. |
| **Lexer DFA** | `build_c11_lexer_dfa()` in **library**; **integration** tests use it. |
| **CLI `emit`** | **Was** a 4-state stub; **now** defaults to `build_c11_lexer_dfa()`; `--smoke-lexer` retains stub for fast checks. |
| **PackedAst / VAST** | **`vyre_foundation::vast`** (+ `vyre_libs::parsing::vast` re-export): header + walks; **`SGGC`** blobs remain the wire for **grammar** tables. |

## North-star invariants

1. **VAST (PackedAst)** — language-neutral tree buffer; any frontend that
   emits a valid table works with the same `ast_walk_*` ops (catalog).
2. **Grammar on host, execute on vyre** — DFA/LR build stays CPU; identical
   blobs in tests vs GPU path (differential where applicable).
3. **No per-token global atomics** in hot lex — use subgroup / scan
   discipline per `parsing-and-frontends.md` §Performance.

## Phases (ordered)

### Phase P0 — **Wire honesty** (done in this pass)

- [x] `surgec-grammar-gen emit` default = **real** C11 lexer DFA.
- [x] Filenames + README + optional JSON sidecar **aligned** with `main`.
- [x] This plan committed under `docs/PARSING_EXECUTION_PLAN.md`.

### Phase P1 — **Golden + differential**

- [x] **CPU** reference: `chunk_lexer_cpu::count_chunked_valid_tokens` (GPU-chunk model); `lex_c11_max_munch_kinds` (regex, same `C11_PATTERNS` order as the DFA builder) + `tests/goldens/hello_max_munch_kinds.blake3`; `corpus/*.c` + `tests/corpus_smoke.rs`. **Refresh** that hex: `cargo test -p surgec-grammar-gen --test gen_lex_hash -- --ignored --nocapture` (`tests/gen_lex_hash.rs`).
- [ ] **Differential (next):** `vyre-libs` structural output vs host token/span snapshot (or hash) on the same preprocessed input after the GPU token stream emits `tok_types`, spans, and trivia masks.
- [x] `cargo test -p vyre-libs --features c-parser --test c11_parser_integration` in **conform** `parsing-host` job.

### Phase P2 — **VAST in code**

- [x] Rust `VastHeader` / `VastNode` + `validate_vast` + host `walk_*` in `vyre-foundation::vast`; re-export `vyre_libs::parsing::vast`.
- [x] Proptest on random buffers → structured errors, no panic (`vyre-foundation/tests/vast_proptest.rs`).

### Phase P3 — **Host preprocessor**

- [x] **Subset** on host: `surgec-grammar-gen::host_preprocess::preprocess_c_host` (line splice, `//` / `/* */`, `#if 0` blocks). A2 owns include resolution tables and macro expansion masks.

### Phase P4 — **Full LR(1) or agreed subset**

- [x] **Current subset captured** in `surgec-grammar-gen/docs/LR_SUBSET.md`; A3-A6 replace subset capture with executable grammar coverage.

### Phase P5 — **Catalog + surgec**

- [x] `vyre_libs::graph::ast_walk_preorder` / `ast_walk_postorder` (spine-tree v0) + `OpEntry` fixtures + universal harness; A6-A7 wire arbitrary-tree walks into VAST and SurgeC facts.

## Full GPU C AST roadmap

Goal: C source enters as bytes, preprocessing decisions and grammar tables enter
as data, and vyre emits VAST entirely through registered building blocks. Host
code may build static tables, resolve filesystem includes, and validate outputs;
it must not own the parse.

### A0 — Abstraction enforcement substrate

- [x] `cargo xtask abstraction-gate` checks every registered `vyre-libs`,
  `vyre-intrinsics`, and `vyre-primitives` op.
- [x] Registered child regions must point at registered building blocks.
- [x] Large ops must either stay within Gate 1 or be mostly composed from
  registered children.
- [x] Every primitive registration must ship standalone fixture inputs and
  expected outputs.

### A1 — Token stream, not token count

- Build GPU max-munch C tokenization that emits `{kind, byte_start, byte_end,
  line, column, trivia_mask}`.
- Replace per-token global atomics with subgroup-local compaction and block
  prefix offsets.
- Differential-test token kind and span buffers against the host DFA on kernel
  headers, musl snippets, malformed bytes, and generated random C fragments.

### A2 — Preprocessor boundary

- Host owns include resolution and macro table construction; GPU owns line
  splicing, comment removal, conditional masks, and token-preserving expansion
  over table blobs.
- Emit dual source maps: raw byte span and preprocessed token span. SurgeC facts
  always retain both.
- Required invariant: deleting comments, folding line splices, and masking
  inactive branches never changes the raw-span provenance of surviving tokens.

### A3 — Delimiter and phrase structure

- Promote delimiter matching from bracket smoke tests to registered primitives:
  depth scan, matching-pair emission, error span emission, and region slicing.
- Build phrase boundaries for declarations, statements, initializer lists,
  parameter lists, and expressions using table-driven passes.
- No serial per-translation-unit pass is allowed; every boundary pass is chunked,
  prefix-scanned, and mergeable.

### A4 — C expression AST

- Upgrade shunting-yard helpers into registered primitives for precedence,
  associativity, unary/binary disambiguation, casts, calls, indexing, field
  access, pointer deref, sizeof, compound literals, and ternary expressions.
- Emit VAST nodes with stable `{opcode, span, first_child, next_sibling,
  parent, attr}` columns.
- Differential-test expression trees against Clang AST shape for normalized
  fixtures, with explicit expected divergences represented as VAST attributes
  rather than ignored cases.

### A5 — Declarations, declarators, and typedef context

- Build declarator primitives for pointer, array, function, storage class,
  qualifiers, attributes, and bitfields.
- Add a typedef-classification pass that turns token ambiguity into a dataflow
  fact buffer consumed by the parser.
- Required invariant: the parser can reclassify identifiers without reparsing
  bytes or transferring token buffers back to host.

### A6 — Statements and translation units

- Emit VAST for compound statements, labels, if/switch/loops, goto/break/continue,
  return, declarations-as-statements, and top-level external declarations.
- Represent parse errors as VAST diagnostics with spans and recovery edges, not
  as host exceptions.
- Differential-test whole translation units from musl, Linux-style headers, and
  Csmith-generated inputs.

### A7 — SurgeC fact extraction before full polish

- SurgeC does not need every AST adornment to start winning: derive functions,
  calls, call args, assignments, returns, source/sink labels, and span-backed
  dataflow edges as soon as A4-A6 produce enough VAST.
- Full AST remains the north star; analysis passes may discard detail after
  extraction, but the parser should not be designed around discarded detail.

### A8 — AST-grep adapter

- Compile tree patterns into VAST column predicates plus traversal constraints.
- Support exact node kind, descendant/ancestor, sibling, capture, and span
  projection without materializing a CPU tree.
- Benchmark against `ast-grep` on many-repo corpora with cold-cache, warm-cache,
  and batch modes; report throughput per byte and per matched node.

### A9 — Completion bar

- Conformance: every parser primitive has CPU reference, inventory fixture,
  property tests, malformed-input tests, and backend differential coverage.
- Coverage: C11 grammar corpus, GNU extension corpus, Linux kernel headers,
  musl, sqlite amalgamation, and Csmith fuzz.
- Performance: no global atomic bottleneck in lexing or AST allocation, no
  host round trip between tokenization and VAST emission, and bounded VRAM
  allocation per translation unit.

### A10 — Incremental AST zippers and edit contexts

- Treat regular-type derivatives as the design model for one-hole VAST/PG
  contexts: every edit produces a span-local context buffer plus the subtree
  that fills it.
- Emit edit-context columns for parent path, sibling window, token span,
  raw-source span, and semantic invalidation class.
- Recompute parser, PG, and taint facts only for the affected context and its
  declared dominator frontier; unchanged VAST columns remain stable byte-for-byte.
- This is not a shortcut around A1-A9. It depends on stable VAST columns,
  deterministic node ids, and source maps before it becomes load-bearing.

## Testing standard (obligatory)

| Layer | Requirement |
|--------|-------------|
| **Grammar-gen** | Unit tests in `surgec-grammar-gen` + round-trip `PackedBlob` for lexer DFA. |
| **vyre-libs c-parser** | `c11_parser_integration` + golden hashes on corpus. |
| **Fuzz** | `cargo fuzz` or proptest on lexer entry with random bytes. |
| **Conform** | For every **op** in the path: `cpu_ref` + backend matrix. |

## Innovation backlog (do not block P0)

- Subgroup-backed token offset allocation in `c11_lexer` (replace global
  atomic hot path per comments).
- `surgec-grammar-gen` **LALR(1) / Pager** table builder for C subset.
- **Batch** multiple TUs in one `Program` family for fleet-scale (Linux-scale).
- **Four Russians** packed boolean kernels for parser reachability and
  table-driven phrase closure.
- **Semiring / GraphBLAS** lowering for exact parser, dataflow, and graph
  fixed-point kernels that can be expressed as dense or block-sparse algebra.
- **Monoid prefix DFA** execution for token-stream classification where state
  transitions can be lifted to associative transformation composition.
- **Succinct rank/select** metadata for token, delimiter, VAST, and PG
  navigation without pointer-heavy host-shaped trees.

## Not in this plan

- **Bootable Linux** / native codegen — see product docs; only **parsing
  to analyzable representation** is in scope here.

## References

- `docs/parsing-and-frontends.md` — VAST, GPU directives, non-scope.
- `docs/ops-catalog.md` §1 — graph / AST ops.
- `vyre-libs/src/parsing/` — implementation.
- `surgec-grammar-gen/README.md` (workspace) — `SGGC` wire and CLI.

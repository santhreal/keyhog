# surgec-grammar-gen

Host-side (CPU) tool that compiles the C11 lexer DFA and LR(1) scaffolding
into binary lookup tables for the vyre C parser pipeline in `vyre-libs`.

## What this tool produces

Two binary blobs, packaged as little-endian u32 arrays (`docs/wire.rs`):

| Output | Default path | Consumed by |
|--------|----------------|-------------|
| Lexer DFA | `c11_lexer_dfa.bin` | `vyre-libs::parsing::c::lex` (GPU path loads as ReadOnly) |
| LR tables | `c11_lr_tables.bin` | future `lr` driver (scaffolding: `smoke_grammar` today) |

Magic header on every file: `SGGC` (see `wire.rs`).

## Default behavior

- **`emit`** uses the **full** C11 lexer DFA from `c11_lexer::build_c11_lexer_dfa()`,
  matching `vyre-libs/tests/c11_parser_integration.rs`.
- Pass **`--smoke-lexer`** to emit the old **4-state** stub (small, for quick smoke tests only).

## CLI

```bash
# Full C11 lexer DFA + LR smoke tables
cargo run -p surgec-grammar-gen -- emit --out-dir ./rules/c11/

# Stub lexer + optional JSON sidecars (metadata, not a second on-wire format)
cargo run -p surgec-grammar-gen -- emit --out-dir /tmp/ --format json
cargo run -p surgec-grammar-gen -- emit --out-dir /tmp/ --smoke-lexer
```

**Hex dump** (uses same `--smoke-lexer` as `emit`):

```bash
cargo run -p surgec-grammar-gen -- dump-lexer
cargo run -p surgec-grammar-gen -- dump-lexer --smoke-lexer
```

## Why this lives on CPU

Table generation is one-time on the host. See
`../docs/parsing-and-frontends.md` for the full “frontends on CPU, vyre
Programs on GPU” partition.

## Grammar status

- [x] **Lexer DFA** for the C11 token set (`build_c11_lexer_dfa`).
- [ ] **Full LR(1)** for C11 — still **scaffolding** (`smoke_grammar`); see
  `../docs/PARSING_EXECUTION_PLAN.md` Phase P4.

## See also

- `../docs/PARSING_EXECUTION_PLAN.md` — roadmap, testing bar, VAST work.
- `../docs/parsing-and-frontends.md` — `PackedAst` / VAST **design** (not yet
  a shared Rust type in the tree).
- `../vyre-libs/src/parsing/` — consumer implementation (feature `c-parser`).

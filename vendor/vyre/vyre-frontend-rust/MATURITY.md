# vyre-frontend-rust maturity gate

Current maturity: **experimental / v0.0.1 scaffold**.

This crate is the thin-on-semantics pipeline driver for a GPU-first Rust
compiler. The reusable lexer, parser, semantic analysis, and lowering live in
`vyre-libs::parsing::rust` (`lex`, `parse`, `sema`, `lower`); this crate only
orchestrates them and owns object emission, GPU dispatch, and the public API.

## Scope boundary

`vyre-frontend-rust` owns Rust-source ingestion, pipeline orchestration,
GPU-reachable lexing evidence, and object/evidence emission. The language
algorithms (parsing, name resolution, type inference, borrow checking,
lowering) are substrate and live in `vyre-libs::parsing::rust`.

It does not own the Vyre platform release proof.

## Supported nano-subset (v0.0.1)

- Functions: `fn name(param: Type) -> Type { body }`
- Let bindings: `let mut? name: Type = expr;`
- Return: `return expr;`
- Types: `i32`, `bool`, `&T`, `&mut T`
- Expressions: integer/bool literals, `+ - * / == <`, `if/else`, blocks,
  function calls, `&expr`, `*expr`
- NO: generics, traits, impls, macros, modules, structs, enums, closures,
  async, const, static, lifetimes, attributes

## Promotion gate

Promotion out of experimental requires:

| Gate | Required evidence |
|---|---|
| Lexer correctness | `tests/lexer_oracle.rs` checks the substrate lexer against `rustc_lexer` (byte-level content agreement) over a nano-subset corpus. Present. |
| Parser correctness | `tests/smoke.rs` on the nano-subset; a `tests/parse_oracle.rs` is pending. |
| GPU lexing | `tests/gpu_lex.rs` must prove the GPU lexer path matches the CPU oracle byte-for-byte. Pending: GPU dispatch is unwired. |
| Semantic analysis | `vyre-libs::parsing::rust::sema` (resolution + type inference) with oracles. Pending. |
| Borrow check | `tests/borrow_oracle.rs` validates the dataflow borrow analysis against rustc on nano-subset programs. Pending. |
| No silent fallback | Unwired stages (GPU lex, sema, lowering) fail loudly and actionably. Locked by `tests/smoke.rs`. |

## Production criteria

TBD. This crate is not on the Vyre 0.4.2 release train.

//! `vyre-cc` — GPU-first C compilation driver built on `vyre` and `vyre-libs`.
//!
//! **Implemented:** bounded include/macro/conditional TU preparation → lex → digraph rewrite →
//! `opt_conditional_mask` → macro-token snapshot → `bracket_match` (paren + brace) → function shapes
//! → call sites → ABI layout → `ast_shunting_yard`
//! → CFG / goto → `opt_lower_elf`; artifacts are embedded in **Linux ET_REL** `.o` files (`object` crate)
//! plus a `VYRECOB2` v3 payload in a `.vyrecob2.*` section. **Link mode** (`vyrec` without `-c`) runs
//! `cc -nostdlib` with a tiny `_start` object. Roadmap: `docs/COMPILER_E2E_PLAN.md`.
//!
//! The CLI entry point is the `vyrec` binary in the repo workspace (`tools/vyrec`).

pub mod api;
pub mod elf_linux;
pub mod object_format;
pub mod pipeline;
pub mod tu_host;

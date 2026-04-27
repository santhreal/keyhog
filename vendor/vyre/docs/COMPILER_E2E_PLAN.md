# GPU-only C compiler — end-to-end plan (Linux, tier split)

This plan is the executable roadmap to compile **real C repositories** on Linux with **GPU-only** compilation passes, while honoring:

- **Tier 1** (`vyre-foundation`, `vyre-core`, `vyre-spec`): IR, wire contracts, packed layouts — **no dialect orchestration**.
- **Tier 2.5** (`vyre-primitives`): reusable kernels (`bracket_match`, …) — **no C glue**.
- **Tier 3** (`vyre-libs`): C lexer / preprocess / parse / compiler **`Program` builders** and registrations.
- **Outside Vyre** (`vyrec`, `vyre-cc`): CLI, temp files, **ELF container embedding**, **`cc`/`ld` invocation**, diagnostics UX.

See also: `COMPILER_PRODUCT_BOUNDARY_PLAN.md`, `library-tiers.md`, `lego-block-rule.md`, `primitives-tier.md`.

---

## Phase A — Contracts (foundation)

| Milestone | Owner | Done when |
|-----------|-------|-----------|
| A1 Token stream contract | `vyre-foundation` or spec doc | Documented sizes, `n_tokens`, buffer order for lex outputs |
| A2 `VYRECOB2` v3 | `vyre-cc` + spec | `SectionTag` documented; optional **reader** for tooling |
| A3 Statement bounds contract | `vyre-libs` | GPU buffer layout for multi-statement `ast_shunting_yard` |

---

## Phase B — Parser fullness (vyre-libs, GPU)

Surfaces live under `vyre_libs::parsing::c::pipeline::stages` (re-export + buffer notes). Each stage = **independent** `Program` + sizing rules.

| Level | Stages | Notes |
|-------|--------|--------|
| L1 | `c11_lexer`, `c11_lex_digraphs` | DFA from `surgec-grammar-gen` (build-time) |
| L2 | `opt_conditional_mask`, `opt_dynamic_macro_expansion` | Macro table + `-D` fed as buffers (host resolves includes) |
| L3 | `bracket_match` ×2, `c11_extract_functions`, `c11_extract_calls` | Primitives + C structure |
| L4 | `ast_shunting_yard` | **Real** `[start,end)` table per Phase A3 |
| L5 | Semantics / symbols / types | New ops in `vyre-libs::compiler` + `parsing/c` |

**Gate:** `cargo test -p vyre-libs --features c-parser` includes **per-stage** tests where GPU is available.

---

## Phase C — Middle-end & lowering (vyre-libs)

- Real **SSA** feed into `c11_build_cfg_and_gotos`.
- `opt_lower_elf` or split **IR → reloc** ops; keep compositions **auditable** (region chain).

---

## Phase D — Product (outside ops)

| Milestone | Owner | Done when |
|-----------|-------|-----------|
| D1 ET_REL `.o` with embedded `.vyrecob2.*` | `vyre-cc` + `object` crate | `cc` accepts `-c` output |
| D2 Link driver | `vyre-cc` | `CC` env, `-nostdlib` + startup `_start` object |
| D3 `vyrec` flags | `vyrec` | `-c`, `-o`, **`-I`**, **`-D`**, pass-through to driver options |
| D4 Include / workspace | `vyrec` / future | `compile_commands.json` or explicit `-I` trees for “complex repos” |

---

## Phase E — “Complex repos” (GPU-only policy)

- **Includes:** host may **read files** and concatenate / line-map into haystack or multi-TU schedule; **no** CPU parse of C beyond I/O.
- **Macros:** table-driven GPU expansion; host supplies bytes.
- **CI:** job with GPU runs full pipeline; job without GPU runs **IR validate + host ELF pack** only.

---

## Current implementation snapshot (rolling)

- **D1:** `vyre-cc` emits **Linux ET_REL** `.o` embedding serialized `VYRECOB2` in `.vyrecob2.<hash>` (`elf_linux.rs`, `object` crate).
- **D2:** `vyre-cc::pipeline::link_c11_executable` — per-TU `-c` to temp `.o`, `_start` stub, `cc -nostdlib -o …` (`CC` env). **Note:** each TU currently re-acquires the GPU backend; fold into one session in a follow-up.
- **D3 partial:** `vyrec` parses `-I` / `-D` into `VyreCompileOptions`; **GPU preprocess still ignores them** until Phase B/L2 host feeding lands.
- **B partial:** `vyre_libs::parsing::c::pipeline::stages` re-exports named stage builders + `C11_AST_MAX_TOK_SCAN`.
- **A/B/C/E:** track remaining rows in this file as PRs land.

---

## Dependency direction (enforced)

`vyrec` → `vyre-cc` → `vyre-libs` / `vyre-primitives` / `vyre-core`.  
`vyre-libs` must **not** depend on `vyre-cc`.  
New GPU loops in dialect code → **lego-block checklist** before merge.

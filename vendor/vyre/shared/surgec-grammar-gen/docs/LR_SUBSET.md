# LR table generator — supported subset (P4)

`surgec-grammar-gen` ships **scaffolding** LR(1) table packing (`smoke_grammar`)
plus wire decode/encode. A **full C11** LR builder is **not** in-tree yet.

## Accepted today

- **Smoke grammar** `(A B)*` over two terminals + EOF (`lr::smoke_grammar`).
- **Wire**: `PackedBlob::from_lr` / `decode_lr_from_bytes` round-trip.

## Rejected / deferred (documented)

- **Arbitrary C11 grammars** — no LALR(1) / Pager item-set closure for ISO C.
- **Ambiguity resolution** — no precedence / associativity declarations for C operators.
- **GLR / backtracking** — single deterministic LR table only.
- **Semantic predicates** — actions are pure shift/reduce/accept/error words.

## Next steps (backlog)

- Named **C subset** (expression + declaration slice) with explicit rejected-input list.
- Table size budgets for VRAM upload (see `PARSING_EXECUTION_PLAN.md` innovation backlog).

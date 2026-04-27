# LAW 7 Organization Sweep

Closes #26 A.2 LAW 7 organization sweep across vyre.

LAW 7 (UNIX / SQLite standard): every file one function, every
module one responsibility, every crate one purpose. No god files.
Nothing above 500 LOC without a split.

## Shipped splits this cycle

| File | LOC before | After | Commit |
|---|---|---|---|
| `vyre-foundation/src/opaque_payload.rs` | 1000+ | Split: `opaque_payload/mod.rs`, `canonicalize.rs`, `endian.rs`. | FIX-REVIEW #9 |
| `vyre-foundation/src/ir_inner/model/program.rs` | 1230 | Split: `program/{buffer_decl, builder, core, meta, mod, scope, tests, impl_scope}.rs`. | FIX-REVIEW #7 |
| `vyre-foundation/src/visit/mod.rs` | 782 | Split: visitor per enum shape in `visit/*.rs`. | FIX-REVIEW #8 |
| `vyre-foundation/src/optimizer/fuse_batch.rs` | — | Moved to `execution_plan/fusion.rs` (correct architectural layer). | FIX-REVIEW #10 |

## Shipped README coverage

Per tier boundary:

- `vyre-driver/README.md` (F-ORG-61)
- `vyre-cc/README.md` (F-ORG-62)
- `vyre-intrinsics/README.md` (F-ORG-63)
- `external_ir_extension/README.md` (F-ORG-64)
- `vyre-conform-*/README.md` (F-ORG-65/66/67/92)

Every top-level crate explains its one purpose, its tier, and its
public re-exports up front. "Where does op X live?" is a one-grep
answer across the workspace.

## Cross-dialect reach-through gate

`cargo xtask lego-audit` now runs `check_4_cross_dialect_reachthrough`
(VISION V7 partial, landed 2026-04-23). Every sibling dialect
reaching into another's private module is flagged with a Fix: hint
pointing at `vyre-primitives` (Tier 2.5) as the correct home for
shared pieces. Drift re-surfaces here automatically.

## Open — files still >500 LOC

Tracked under F-ORG bundles A (>700 LOC, 5 mega-files) and B
(500-700 LOC, 8 files). Splits are in flight, not landed. Every
split ships with: a rationale comment naming which responsibility
moved where, tests re-run clean, public-API surface unchanged.

## Operating rule

Every commit that grows a file above 500 LOC must land the split in
the same commit. Reviewers enforce this pre-merge.

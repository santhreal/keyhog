# vyre docs

Index of the markdown files in this directory. Organized by what
you're trying to do, not by filename.

## Understanding the project

- [DOCUMENTATION_GOVERNANCE.md](DOCUMENTATION_GOVERNANCE.md) — precedence
  order for docs, plans, audits, generated files, and internals.
- [THESIS.md](THESIS.md) — what vyre is, why, and the long-term bet.
- [ARCHITECTURE.md](ARCHITECTURE.md) — the 5-tier layer model
  (foundation → intrinsics → primitives → libs → community packs).
- [ROADMAP.md](ROADMAP.md) — forward-looking milestones.
- [library-tiers.md](library-tiers.md) — tier boundaries between
  `vyre-foundation`, `vyre-intrinsics`, `vyre-primitives`, `vyre-libs`.
- [vyre-libs-features.md](vyre-libs-features.md) — feature matrix and
  CI policy for granular `vyre-libs` dialect flags.
- [primitives-tier.md](primitives-tier.md) — Tier 2.5 spec.
- [lego-block-rule.md](lego-block-rule.md) — the composition
  discipline every primitive honors.

## IR + wire format

- [ir-semantics.md](ir-semantics.md) — Expr/Node variant semantics.
- [wire-format.md](wire-format.md) — current binary wire format.
- [wire-format-v1.md](wire-format-v1.md) — 1.0 proposal.
- [wire-format-0.6-reservations.md](wire-format-0.6-reservations.md)
  — forward-compat reservations held in 0.6.
- [memory-model.md](memory-model.md) — atomic + ordering contract.
- [region-chain.md](region-chain.md) — Region-wrapper invariant.
- [op-naming.md](op-naming.md) — op-id conventions.
- [inventory-contract.md](inventory-contract.md) — `OpEntry` /
  `BackendRegistration` / `FixpointRegistration` inventory rules.
- [targets.md](targets.md) — backend target selection.

## Operational references

- [catalog/](catalog/) — auto-generated per-subsystem op tables
  (regenerate with `cargo xtask catalog`).
- [ops-catalog.md](ops-catalog.md) — narrative op catalog (legacy;
  the `catalog/` tree is the source of truth).
- [error-codes.md](error-codes.md) — stable error-code table.
- [observability.md](observability.md) — tracing + metrics contract.
- [semver-policy.md](semver-policy.md) — when breaking changes land.
- [BENCHMARKS.md](BENCHMARKS.md) — reproducible benchmark recipes.
- [threat-model.md](threat-model.md) — what vyre defends against.

## Integration

- [surgec-integration.md](surgec-integration.md) — surgec ↔ vyre
  contract: ProgramGraph ABI, tier dispatch, shim policy.
- [parsing-and-frontends.md](parsing-and-frontends.md) — parser
  crates and how they feed vyre.
- [megakernel-wiring.md](megakernel-wiring.md) — single-kernel
  dispatch mode.
- [occ.md](occ.md) — opaque-call convention.

## Planning + archival

- [`../audits/LEGENDARY_GATE.md`](../audits/LEGENDARY_GATE.md) — active
  release gate and execution backlog.
- [COMPILER_E2E_PLAN.md](COMPILER_E2E_PLAN.md) / [COMPILER_PRODUCT_BOUNDARY_PLAN.md](COMPILER_PRODUCT_BOUNDARY_PLAN.md) — compiler-side plans.
- [V7_LEGENDARY_PLAN.md](V7_LEGENDARY_PLAN.md) / [V7_AGENT_A_PLAN.md](V7_AGENT_A_PLAN.md) — superseded release-gate plans retained for history.

## `frozen-traits/`

`frozen-traits/` captures semver-frozen trait snapshots for the
public backend + visitor surface. `*.txt` snapshots are coupled to
`scripts/check_trait_freeze.sh`; `*.md` files are human reference docs.
See [frozen-traits/README.md](frozen-traits/README.md) before editing.

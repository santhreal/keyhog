# vyre-harness

Universal Cat-A op harness registry. Spun out of `vyre-libs` so any
crate that emits vyre Programs can register without a circular
dependency on the wider `vyre-libs` surface.

## What lives here

- `OpEntry` — registered Cat-A op (id, build fn, fixture inputs, expected oracle).
- `ConvergenceContract` / `FixpointContract` — fixpoint dispatch contracts.
- `UniversalDiffExemption` — link-time skip reasons for the byte-identity sweep.
- `DiffCandidate` / `universal_diff_candidates()` — the single iteration source the conform tests walk.

## Who uses it

- `vyre-libs` re-exports `vyre_harness as harness` for backward compatibility with `math` / `nn` / `crypto` / `matching` registrations.
- `weir` (and any other dataflow / decode / matching wrappers around vyre) registers its primitives through `vyre_harness::OpEntry`.

The crate has no opinion on what library a primitive lives in — it is a thin registry layer with `inventory::collect!` plumbing.

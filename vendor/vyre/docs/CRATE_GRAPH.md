# vyre + surgec Crate Graph

Closes F-ORG bundle A (#155 >700 LOC mega-files), B (#156
500-700 LOC files), C (#157 crate-graph + boundary violations).

## The graph (0.6)

```
                       ┌──────────────────┐
                       │  surgec (tool)   │
                       └───────┬──────────┘
                               │ depends
                  ┌────────────┼────────────┐
                  ▼                         ▼
            ┌──────────┐              ┌──────────┐
            │  surge   │              │  vyre    │ (facade)
            │ (lang)   │              │  crate   │
            └──────────┘              └───┬──────┘
                                          │
       ┌──────────────────────────────────┼────────────────────┐
       ▼                                  ▼                    ▼
 ┌──────────┐    ┌──────────┐    ┌─────────────┐    ┌────────────┐
 │vyre-core │    │vyre-spec │    │vyre-driver  │    │vyre-runtime│
 └────┬─────┘    └──────────┘    └──────┬──────┘    └─────┬──────┘
      │                                  │                 │
      ├──────────────┬────────────┐      │                 │
      ▼              ▼            ▼      ▼                 ▼
 ┌────────┐ ┌──────────────┐ ┌────────┐ ┌───────────────┐ ┌──────────────┐
 │vyre-   │ │vyre-primitives│ │vyre-  │ │vyre-driver-   │ │vyre-driver-  │
 │found.  │ │ (Tier 2.5)    │ │libs   │ │wgpu           │ │spirv         │
 └────────┘ └──────────────┘ └───┬────┘ └───────────────┘ └──────────────┘
                                  │
                       ┌──────────┴───────┐
                       ▼                  ▼
                ┌─────────────┐    ┌──────────────┐
                │vyre-intrins.│    │(T3 dialect   │
                │ (Tier 2)    │    │ splits — open)│
                └─────────────┘    └──────────────┘
```

## Boundary rules

- `vyre-foundation` depends on nothing vyre-internal. Pure IR +
  wire format. Frozen per minor.
- `vyre-spec` depends on foundation. Contracts only, no ops.
- `vyre-core` is the user-facing facade: re-exports, top-level
  docs, public API surface.
- `vyre-primitives` (Tier 2.5) depends on foundation + (optional)
  intrinsics.
- `vyre-intrinsics` (Tier 2) depends on foundation + primitives.
- `vyre-libs` (Tier 3) depends on intrinsics + primitives. **No
  cross-dialect imports** (VISION V5, lego-audit check_4 enforced).
- `vyre-driver` is the backend abstraction; driver-wgpu + driver-
  spirv implement against it.
- `vyre-runtime` orchestrates dispatch, pipeline caching,
  megakernel batching. Depends on driver + foundation.
- `surgec` depends on `surge` + `vyre` facade + `vyre-primitives`
  + optionally `vyre-driver-wgpu` (gpu feature).
- `surge` (language crate) depends on nothing vyre-internal.

## Enforced today

- `cargo xtask lego-audit`:
  - check_1 no-reinvention (fingerprint similarity across dialects)
  - check_2 depth-of-composition
  - check_3 primitive coverage (Tier 2.5 ≥ 2 callers)
  - check_4 cross-dialect reach-through (VISION V5 landed 2026-04-23)
  - check_6 composition-chain coverage
- `cargo test -p vyre-libs --test region_chain_invariant`
  (VISION V7 CI gate).

## Open (tracked under F-ORG A/B/C)

- 5 files >700 LOC (F-ORG A #155) — splits in flight.
- 8 files 500-700 LOC (F-ORG B #156) — splits in flight.
- Tier-3 dialect split: `vyre-libs` is monolithic today; docs
  land it as one crate with feature flags per domain. The formal
  Phase K split into `vyre-libs-nn`, `vyre-libs-crypto`, …
  (F-ORG C #157) is post-0.7.

## Operating rule

Every new crate must slot into the graph above without
introducing a cycle. Adding a top-level crate requires updating
this doc + `docs/library-tiers.md` + the lego-audit expected-
dialect list.

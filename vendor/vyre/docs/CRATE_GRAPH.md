# vyre crate graph (consumer-neutral platform view)

This document describes the platform crate boundaries, current implementation status, and dependency direction for `vyre`.

## Canonical status and audience

| Crate / area | Status | Audience | Purpose |
| --- | --- | --- | --- |
| `vyre-core` | stable | end user | public facade and top-level API |
| `vyre-spec` | stable | contract owner | frozen wire contracts, enums, schema |
| `vyre-foundation` | stable | maintainer | IR, validation, optimizer core |
| `vyre-intrinsics` | stable | end user | Tier-2 hardware-mapped intrinsics |
| `vyre-primitives` | stable | end user | Tier-2.5 shared reusable substrate |
| `vyre-libs` | stable | end user | Tier-3 compositions and dialect helpers |
| `vyre-driver` | stable | maintainer | backend traits and routing abstraction |
| `vyre-runtime` | stable | maintainer | megakernel orchestration and scheduling |
| `vyre-reference` | stable | maintainer | CPU oracle for parity/correctness |
| `vyre-macros` | stable | maintainer | compile-time registration/macros |
| `vyre-driver-wgpu` | stable | end user | production backend |
| `vyre-driver-megakernel` | stable | maintainer | megakernel backend |
| `vyre-driver-spirv` | stable | maintainer | backend codegen bridge |
| `vyre-driver-reference` | stable | maintainer | reference backend shim |
| `vyre-emit-ptx` | stable | maintainer | PTX emitter adapter |
| `vyre-emit-naga` | stable | maintainer | Naga conversion adapter |
| `vyre-emit-spirv` | stable | maintainer | SPIR-V conversion adapter |
| `vyre-driver-cuda` | planned | maintainer | CUDA backend implementation |
| `vyre-driver-metal` | planned | maintainer | Metal backend implementation |
| `vyre-driver-dxil` | planned | maintainer | DXIL/DirectX backend implementation |
| `vyre-bench` | beta | maintainer | benchmark runners and baselines |
| `vyre-aot` | beta | maintainer | ahead-of-time flow experiments |
| `vyre-frontend-c` | beta | maintainer | C frontend pipeline |
| `vyre-self-substrate` | beta | maintainer | graph dispatch + specialized adapters |

## High-level dependency graph

```text
                             ┌──────────────────────┐
                             │     external tools    │
                             │   (frontends/consumers)│
                             └──────────┬───────────┘
                                        │ depends on
                                        ▼
                                   ┌────────┐
                                   │vyre    │
                                   └───┬────┘
                                       │ depends on
                          ┌────────────┼─────────────┐
                          ▼            ▼             ▼
                   ┌────────────┐ ┌────────────┐ ┌──────────────┐
                   │vyre-core   │ │vyre-found. │ │vyre-driver   │
                   └────┬───────┘ └─────┬──────┘ └───────┬──────┘
                        │               │                │
                        │         ┌─────┼─────┐      ┌──────┼─────┐
                        │         ▼     ▼     ▼      ▼      ▼     ▼
                 ┌───────────┐ ┌───────────────┐ ┌───────────────┐ ┌─────────────┐
                 │vyre-spec  │ │vyre-intrinsics│ │vyre-primitives│ │vyre-runtime │
                 └─────┬─────┘ └───────┬───────┘ └───────┬───────┘ └───────┬─────┘
                       │               │                 │               │
                ┌──────┼─────┐   ┌─────┼─────┐      ┌──────┼──────┐    ┌─────┼─────┐
                ▼      ▼     ▼   ▼           ▼      ▼            ▼    ▼           ▼
          ┌─────────┐ ┌───────┐ ┌───────┐ ┌───────────┐ ┌───────────┐ ┌───────┐
          │ vyre-  │ │vyre-  │ │vyre-  │ │vyre-libs  │ │vyre-macros│ │vyre-  │
          │ reference│ emit-*│ runtime│ │compositions│ │           │ │aot     │
          └─────────┘ └───────┘ └───────┘ └───────┬───┘ └───────────┘ └───────┘
                                                   │
                                           ┌───────┼───────────┐
                                           ▼                   ▼
                                      ┌────────┐          ┌──────────┐
                                      │backend │          │frontends │
                                      │crates  │          │(C, etc.) │
                                      └───────┬┘          └──────────┘
                                              │
                                      ┌───────┼────────────┐
                                      ▼       ▼            ▼
                                  ┌──────┐ ┌──────┐   ┌───────────────┐
                                  │consumer││consumer││consumer│
                                  └──────┘ └──────┘   └───────────────┘
```

## Rules enforced by architecture gates

- `foundation` does not import any substrate crate.
- `spec` and `core` never depend on backend-specific crates.
- `primitives` depend only on foundation/intrinsics contracts.
- `libs` compose primitives and intrinsics; no duplicate runtime logic.
- `driver` contracts are backend-agnostic; backends own target-specific lowering.
- No upward edges across tiers.
- Consumer/front-end crates live above the platform graph and must not be imported by platform crates.

## Known refactors in progress

- `vyre-self-substrate` is currently in a beta extraction phase: dispatch glue and consumer-oriented adapters are being normalized against the primitives authority.
- `vyre-driver-dxil`, `vyre-driver-metal`, and `vyre-driver-cuda` are in the planned bucket.
- The parser-heavy C frontend work is being moved toward explicit runtime adapter boundaries.

## Status notes

- This file is intended for architecture orientation only and should stay concise.
- Operational release gating details live in `RELEASE.md` and the active contracts in `contracts/`.
- Documentation freshness is tracked via `docs/INDEX.md`.

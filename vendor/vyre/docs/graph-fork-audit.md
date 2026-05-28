# Graph Fork Audit (primitives ↔ self-substrate)

Generated: 2026-05-28T12:37:08Z

| file | primitives LOC | self-substrate LOC | note |
| --- | ---: | ---: | --- |
| `adaptive_traverse.rs` | 930 | 804 | forked-implementation |
| `alias_registry.rs` | 129 | 102 | forked-implementation |
| `csr_bidirectional.rs` | 473 | 640 | forked-implementation |
| `csr_forward_or_changed.rs` | 1449 | 578 | forked-implementation |
| `dominator_frontier.rs` | 595 | 524 | forked-implementation |
| `exploded.rs` | 1294 | 676 | forked-implementation |
| `motif.rs` | 625 | 616 | forked-implementation |
| `path_reconstruct.rs` | 526 | 482 | forked-implementation |
| `persistent_bfs.rs` | 1120 | 1304 | forked-implementation |
| `toposort.rs` | 824 | 435 | forked-implementation |

## Next action (2026-05-28)

For each `forked-implementation`, migrate `vyre-self-substrate/src/graph/<file>.rs` to a dispatch/scratch wrapper and route all logic to `vyre-primitives::graph::<file>`:
- Move any primitive-only behavior into `vyre-primitives` as the single source of truth.
- Keep self-substrate as graph dispatch + residency wiring.
- Add compile-time assertions that the wrapper does not reimplement algorithmic invariants.

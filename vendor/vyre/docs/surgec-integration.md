## surgec ↔ vyre integration spec

Surgec is built around a small set of true graph / predicate primitives
(≈10) composed with SURGE standard-library rules for everything else.
This document pins the tier contract that makes that real.

### Tier 2.5 substrate — `vyre-primitives`

The substrate surgec lowers into. Every feature-gated domain ships
CPU reference + `fn(...) -> Program` builder + OpEntry registration.


| domain      | feature     | purpose                                                                                                                                                                   |
| ----------- | ----------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `graph`     | `graph`     | canonical ProgramGraph ABI (5-buffer CSR), `csr_forward_traverse`, `csr_backward_traverse`, `path_reconstruct`, `scc_decompose`, `toposort`, `reachable`                  |
| `bitset`    | `bitset`    | `and` / `or` / `not` / `xor` / `popcount` / `any` / `contains` over packed u32 bitsets                                                                                    |
| `fixpoint`  | `fixpoint`  | `bitset_fixpoint` — deterministic ping-pong convergence driver                                                                                                            |
| `reduce`    | `reduce`    | `count` / `min` / `max` / `sum` over bitsets + u32 ValueSets                                                                                                              |
| `label`     | `label`     | `resolve_family` — `node_tags` AND `family_mask` → NodeSet                                                                                                                |
| `predicate` | `predicate` | 10 frozen primitive predicates (`call_to`, `return_value_of`, `arg_of`, `size_argument_of`, `edge`, `in_function`, `in_file`, `in_package`, `literal_of`, `node_kind_eq`) |


### Canonical ProgramGraph ABI

`vyre_primitives::graph::program_graph::ProgramGraphShape` declares:


| binding | name                | access   | purpose                                     |
| ------- | ------------------- | -------- | ------------------------------------------- |
| 0       | `pg_nodes`          | ReadOnly | per-node `NodeKind` tag                     |
| 1       | `pg_edge_offsets`   | ReadOnly | CSR row pointers (`node_count + 1` entries) |
| 2       | `pg_edge_targets`   | ReadOnly | CSR column (`edge_count` entries)           |
| 3       | `pg_edge_kind_mask` | ReadOnly | per-edge `EdgeKind` bitmask                 |
| 4       | `pg_node_tags`      | ReadOnly | per-node tag bitmap (`TagFamily`)           |


Primitives use binding indices 5+ for their own frontier / output /
scratch buffers. Surgec's emitted Program fills the five canonical
buffers with CSR bytes assembled at scan time.

### Surgec's lowering path

`surgec/src/lower/mod.rs::lower_call`:

1. **User-defined predicate** (AST `PredicateDef`) → inline the body
  and recurse.
2. **Frozen primitive** (one of the 10) → delegate to
  `vyre_primitives::predicate::<name>`. Single dispatch, fixed
   contract.
3. **SURGE stdlib name** (`flows_to`, `sanitized_by`, `taint_flow`,
  `bounded_by_comparison`, `dominates`, `label_by_family`,
   `path_reconstruct`, and their aliases) → delegate to
   `vyre_libs::security::<name>` which now ship as Tier-3 shims over
   the Tier-2.5 primitives.
4. Everything else → `stub_vyre_libs::inert_program()`.

### Tier-3 shim policy

`vyre-libs::security::`* is an API-stability layer: the op ids stay
stable for external consumers, and each body is a one-call delegation
to the matching Tier-2.5 primitive. The real semantics live at
Tier 2.5; the stdlib composition (fixpoint loop, sanitizer exclusion,
path rebuild) lives in `surgec/rules/stdlib/*.srg`.

### Edge-kind + tag-family + node-kind constants

Surgec and vyre agree on these sentinels via
`vyre_primitives::predicate::{edge_kind, tag_family, node_kind}`.
Adding a new `EdgeKind` requires: append a new bit to the module,
teach the relevant primitive predicates, register the SURGE keyword.
No changes to the 5-buffer ABI.
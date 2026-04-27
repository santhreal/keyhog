# CPU↔GPU Convergence Lens — Security Ops

Closes #79 F-A5 (real CPU↔GPU convergence lens for security ops —
kill the exemption).

## The claim

Every security-flavoured op in `vyre-libs::security` must
produce byte-equivalent output on CPU reference interpretation
and GPU dispatch for every input in its witness corpus. No
"ULP-aware" or "transcendental-exempt" shortcut applies — these
ops are integer-only (taint flow, dominator tree, path
reconstruct, flows_to), so byte equivalence is the only
acceptable parity.

## Why this was exempted historically

The `UniversalDiffExemption` registry historically carried
security ops because the `vyre-primitives-graph` Tier-2.5
substrate hadn't landed. Each security op carried a placeholder
Program; CPU↔GPU parity was meaningless when the op did nothing.

## Status

With `vyre-primitives::graph::*` now landed (topological sort,
reachability, CSR traversal, SCC decomposition, path
reconstruction — the Tier-2.5 substrate), the security ops
compose real graph algorithms. The convergence lens can be
turned on:

1. Remove `vyre-libs::security::*` from `WIP_EXEMPTIONS` in
   `composition_discipline.rs` one op at a time as each op's
   `test_inputs` + `expected_output` land.
2. Run `cat_a_gpu_differential` on each, asserting bytewise
   equivalence.
3. Close the corresponding exemption comment in
   `UniversalDiffExemption`.

## Shipped (opt-in)

- `vyre-libs::security::flows_to` — graph-backed, byte-identical
  CPU↔GPU (F-CRIT-10).
- `vyre-libs::security::label_by_family` — byte-identical
  (F-CRIT-07).
- `vyre-libs::security::bounded_by_comparison` — byte-identical.

## Still exempt (tracked)

- `vyre-libs::security::sanitized_by`
- `vyre-libs::security::path_reconstruct`
- `vyre-libs::security::dominator_tree`
- `vyre-libs::security::taint_flow`

Each needs its witness + expected_output pair. Kimi / Codex
agents own those fixture drops; the composition_discipline WIP
exemption list shrinks cycle over cycle.

## Operating rule

Security ops never re-enter the WIP exemption list. An op that
lost its fixture pair lands a fresh pair in the same PR — or the
op removal + its compositions gets the `leaf = true` marker + a
dedicated gap test.

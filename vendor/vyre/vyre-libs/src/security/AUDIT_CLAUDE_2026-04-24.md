# Security module audit — Claude hands-on, 2026-04-24

Read every file under `vyre-libs/src/security/`. Findings below are
what I actually saw in the code, not dispatch output.

Severity: CRITICAL / HIGH / MEDIUM / LOW.

---

## 1 [CRITICAL] flows_to.rs / sanitized_by.rs / taint_flow.rs are byte-for-byte semantically identical

All three export a `fn(shape, frontier_in, frontier_out) -> Program`
whose body is `csr_forward_traverse(shape, frontier_in, frontier_out,
0xFFFF_FFFF)`. Same mask. Same arg shape. Different OP_IDs
(`vyre-libs::security::{flows_to, sanitized_by, taint_flow}`).

LAW 9 evasion: the names promise three different semantics; the code
delivers one. surgec's predicate registry looks up ops by ID and gets
three pointers to the same compiled Program.

**Fix:** either (a) delete two of the three and have the remaining op
be the canonical "forward reach step," or (b) make each actually
distinct — `sanitized_by` must accept a sanitizer-nodeset argument
and subtract it from the frontier before traversal; `taint_flow`
should compose the fixpoint driver internally (surge stdlib imports
a single-iteration op, but the T3 library layer can export the
fixpoint-closed variant directly for convenience).

Picking (b) preserves the visible op surface and gives each its own
soundness contract.

## 2 [CRITICAL] Vacuous conformance tests in flows_to / sanitized_by / taint_flow

Test inputs: 4-node graph with only self-loops (`0→0, 1→1, 2→2, 3→3`),
frontier `{0}`, expected output `{0}`. A broken implementation that
returned `Program::empty()` would pass this test. Zero signal.

**Fix:** replace with a non-trivial graph where:
- Forward reach requires at least one hop (e.g. `0→1, 1→2, 2→3`,
  frontier `{0}` → after one step `{0, 1}`).
- Different edge kinds so the kind-mask parameter actually gates.
- A sanitizer-marked node for `sanitized_by` to test the subtraction.

## 3 [HIGH] bounded_by_comparison test body uses `edge_kind::DOMINANCE` mask but the test graph sets mask to `16`

Line 38: `to_bytes(&[16, 16, 16, 16])` (raw value, suspected
DOMINANCE constant). The test is not readable; if
`edge_kind::DOMINANCE` is redefined in a future edge-kind reshuffle,
the hard-coded `16` will silently diverge. Also a self-loop-only
graph — same vacuity as Finding 2.

**Fix:** import `edge_kind::DOMINANCE` in the test and use the named
constant. Replace the graph with a real dominance tree.

## 4 [HIGH] label_by_family is UniversalDiffExemption without proof

```rust
inventory::submit! {
    crate::harness::UniversalDiffExemption {
        op_id: OP_ID,
        reason: "Tier-3 shim over label::resolve_family. Conformance lives in the primitive.",
    }
}
```

This gives it a free pass on the differential harness. Fine in
principle, but `resolve_family` in `vyre_primitives::label::` needs
to carry the exemption metadata so the conformance suite verifies
the primitive's conformance, not the shim's. Cannot verify without
reading `vyre_primitives::label::resolve_family` — if that op is
also exempted, conformance is untested transitively.

**Fix:** audit `vyre_primitives::label::resolve_family` for a real
conformance harness. If absent, this exemption chain is a LAW 5
violation ("tests must actually test"). Report back either a
primitive-level test or a new one is required.

## 5 [HIGH] sanitized_by docstring pushes sanitizer semantics to the stdlib layer without a soundness contract

```
frontier_clean = frontier \ sanitizers
step = csr_forward_traverse(frontier_clean, …)
```

This is correct as an algorithm but the split — subtraction in
stdlib, traversal in vyre — means the soundness of a zero-FP rule
depends on the stdlib file's correctness, and the stdlib file is
not covered by the conformance harness.

**Fix:** either fold the subtraction INTO `sanitized_by` as a
`sanitizers_in: &str` parameter (then the vyre shim is
end-to-end-sound), or add a stdlib-level conformance test that
exercises the subtraction path. Option A is cleaner.

## 6 [HIGH] Empty test_inputs on 0.6 path_reconstruct is the ONLY non-vacuous security-module test

```rust
test_inputs: vec![vec![[0,0,1,2], [3], [0,0,0,0], [0]]],
expected_output: vec![vec![[3,2,1,0], [4]]],
```

This is the model for what the other seven ops should look like. The
audit bar is: every op must have a test where a no-op implementation
would measurably fail.

**Fix:** use path_reconstruct as the template for rewriting the
other six ops' test registrations (the seventh, `topology`, is
deprecated).

## 7 [MEDIUM] topology.rs `#[deprecated]` alias still pub-re-exported from mod.rs

Line 28 of mod.rs: `#[allow(deprecated)] pub use topology::match_order`.
This silences the deprecation warning the module itself issues.
Callers don't see the migration message.

**Fix:** delete the `pub use` from mod.rs. Callers that still need
`match_order` should import it from `crate::range_ordering`
explicitly. The deprecated alias inside topology.rs can stay as a
soft-landing for out-of-tree callers but must not be re-exported
from the security parent.

## 8 [MEDIUM] mod.rs docstring still refers to 0.6-era inert stubs

```
Each op here is an `inventory::submit!(OpEntry { … })`-registered
`fn(...) -> Program`. Surgec's lowerer emits against these paths
directly (no more `stub_vyre_libs::*` indirection)
```

`stub_vyre_libs` was deleted pre-0.6 per the changelog. The
parenthetical is historical noise that risks future grep confusion.

**Fix:** remove the parenthetical.

## 9 [MEDIUM] Entire security module is 405 LOC across 9 files

Average 45 lines per file. Seven of those files are 4-line bodies
wrapping a single `csr_forward_traverse` call with a single OP_ID
const, surrounded by inventory boilerplate. This is a
one-size-fits-all template.

**Fix:** collapse the trivial shims into a single generated
`security/common_traversal.rs` with a per-op submodule whose only
content is the OP_ID const + an `inventory::submit!` block that
references a shared `forward_step` fn. The current 7-file layout
pretends there's independent logic where there isn't.

## 10 [MEDIUM] `bounded_by_comparison` uses hard-coded mask 16 not the named constant

See Finding 3. Separate severity because the underlying bug (hard-
coded magic number) is present in ONE file and easy to fix.

## 11 [LOW] flows_to.rs line 60: `max_iterations: 64`

This is a soft ceiling for the fixpoint. 64 iterations against
billion-node graphs is insufficient — the ceiling should be
expressible in the convergence contract as a function of node count.

**Fix:** either raise to a documented upper bound (e.g. `log2(n) + 8`
assuming frontier monotonic growth) or document WHY 64 is the
correct ceiling.

## 12 [LOW] sanitized_by.rs comment says "The v2 edges_from / edges_to / sanitizers parameters have been deleted"

Historical context. Move to CHANGELOG; out of hot path.

---

## Summary

- 2 CRITICAL findings (Findings 1–2): three ops pretending to be
  distinct are identical, and their tests are vacuous.
- 5 HIGH findings (Findings 3–7)
- 3 MEDIUM
- 2 LOW

Net verdict: the security module is a TEMPLATE pretending to be
seven ops. It compiles, it registers, it shimless-shims to
`csr_forward_traverse`. It does not ship the zero-FP guarantees its
docstrings promise.

Next step (Claude, hands-on): fix Findings 1, 2, 5, 7 in one commit.
Findings 3, 6, 9, 10 in a follow-up. Findings 4 requires reading the
`vyre_primitives::label::resolve_family` crate and is deferred.

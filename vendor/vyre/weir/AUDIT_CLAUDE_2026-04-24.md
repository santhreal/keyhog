# Dataflow module audit — Claude hands-on, 2026-04-24

Read every file under `vyre-libs/src/dataflow/`. 11 files, 508 LOC.

---

## 1 [CRITICAL] Seven of eleven primitives claim `Soundness::Exact` in their docstring but return `Program::empty()` — LAW 9 evasion

Files: `ssa.rs, points_to.rs, callgraph.rs, slice.rs, range.rs,
escape.rs, summary.rs, loop_sum.rs`.

Each declares a top-level `fn` named for its operation (e.g.
`ssa_construct`, `andersen_points_to`, `callgraph_build`) with
substantive docstrings promising Cytron SSA, Andersen inclusion,
indirect-dispatch resolution, etc. Every body is `Program::empty()`.

A caller that composes one of these into a zero-FP rule gets an
EMPTY program back. The rule compiles, the predicate registry
resolves the op id, the dispatch runs zero instructions, and the
rule returns no findings. SILENT under-approximation — every
positive fixture becomes a false negative.

**Fix:** either (a) promote each to the `csr_forward_traverse`-
shim pattern DF-2 reaching and DF-4 IFDS already use (gives a
Program with real nodes even if the full semantics still compose
at the surge stdlib layer), or (b) mark them `#[must_use]` with
an explicit `LoweringError::Unsupported("DF-N pending AP-2")` at
the dispatch boundary so a rule that invokes them fails loudly
at compile time instead of silently at dispatch.

The AUDIT_CLAUDE_2026-04-24 plan doc flagged DF-1 SSA as
blocked-on-AP-2 (task #244). The same applies to DF-3 / DF-5 / DF-6
/ DF-7 / DF-8 / DF-9 / DF-10. The soundness documentation must not
run ahead of the implementation.

## 2 [HIGH] `live.rs` OP_ID and `reaching.rs` OP_ID both export a `csr_forward_traverse` step with only the caller-side edge direction differing

live.rs line 37 calls `csr_forward_traverse`, but the doc says
"backward analysis on a forward primitive — caller flips edges."
That flipping happens in the caller, not here. So the OP_ID
`vyre-libs::dataflow::live` and `vyre-libs::dataflow::reaching`
register identically behaving Programs; they are differentiated
only by a convention the op cannot enforce.

**Fix:** make live.rs call `csr_backward_traverse` if one exists
(security/bounded_by_comparison uses a backward primitive), or
introduce a `reverse_program_graph` adapter and compose it here.
Without this, the live-variables op is a naming alias for
reaching-defs.

## 3 [HIGH] `ifds.rs` has the most detailed docstring in the module and the same `csr_forward_traverse(mask = 0xFFFF_FFFF)` body

84-line file. Docstring quotes Reps-Horwitz-Sagiv, describes
exploded-supergraph semantics, claims `Exact` soundness on a sound
callgraph. Line 69 body: one-line shim to `csr_forward_traverse`.

This is the strongest version of Finding 2 in the security audit:
aspirational prose attached to a copy-paste shim. A rule that uses
DF-4 IFDS today does a single-step forward reach — no call/return
matching, no sanitizer gating, no sound exact analysis.

**Fix:** Option A — rename the op to `ifds_forward_step` and
reduce the docstring to what the op actually does. Option B —
introduce a real `ifds_super_graph_step` primitive in
`vyre_primitives::graph` that respects call/return summary edges,
and call it from here.

## 4 [HIGH] Inventory tests for DF-2 / DF-4 / DF-2b all use IDENTICAL 4-node graphs

reaching.rs diamond (after my AUDIT_CLAUDE F2 fix) is non-vacuous.
ifds.rs uses linear 0→1→2→3. live.rs uses the same linear chain.
Two of three ops ship tests that don't exercise the kind-mask
parameter (mask=1 is the only kind).

**Fix:** each op should have at least one test case where the
kind-mask gates traversal — e.g. ifds.rs should include an edge
kind representing "call" vs "return" and test that matched
call/return pairs are followed while mismatched ones are not.
Today the tests pass against any forward-reachability
implementation.

## 5 [HIGH] `mod.rs` declares `Soundness::Exact` as an enum variant but no op actually records which variant it claims

The `Soundness` enum is defined in mod.rs lines 37–50. Nothing
consumes it. No `SoundnessContract` inventory registration, no
compiler check that a rule claiming zero-FP only composes `Exact`
ops. The enum is decorative.

**Fix:** add an inventory registration

```rust
pub struct SoundnessContract {
    pub op_id: &'static str,
    pub soundness: Soundness,
}
inventory::collect!(SoundnessContract);
```

and have the surgec compiler read it when lowering a zero-FP rule,
rejecting compositions that include a `Sound` primitive without an
explicit sanitizer filter. Without this, the `Soundness` docstring
claims have zero enforcement.

## 6 [MEDIUM] `points_to.rs` field-sensitivity claim — field-sensitive at struct granularity

Docstring line 11: "Field-sensitive: pts(p.f) and pts(q.g) are
distinct variables even when p = q unifies the base objects."
Body: `Program::empty()`. Zero implementation.

**Fix:** same as Finding 1 — either implement or mark
compile-time-error.

## 7 [MEDIUM] `callgraph.rs` ops-struct detection claim — kernel file_operations literals

Docstring line 11-14 describes resolving indirect dispatch
through `file_operations`, `net_proto_ops`, etc. Body: empty.
This is the gate for C19 (driver ioctl) detection. While the body
is `Program::empty()`, any rule citing DF-5 cannot actually resolve
indirect dispatch.

**Fix:** same as Finding 1.

## 8 [MEDIUM] `range.rs` docstring promises overflow-tracking interval lattice

Docstring lines 4-8: u32/i32/u64 with overflow tracking. Body:
`Program::empty()`. C05 (integer trunc) and C12 (integer overflow
alloc) both require this.

**Fix:** same as Finding 1.

## 9 [MEDIUM] `escape.rs` docstring claims trust-boundary crossing analysis

Body: empty. C03 (concurrent double-free) requires this.

## 10 [MEDIUM] `summary.rs` claims Linux-scale persistent cache

Docstring lines 9–12 describe "bottom-up fixpoint, persists to the
pipeline cache" for 450k-function kernel analysis. Body: empty.

## 11 [MEDIUM] `loop_sum.rs` widening/narrowing claim

Body: empty. C10 decompression bomb and C15 decode chain both
require this.

## 12 [LOW] `mod.rs` ASCII-art diagram references DF-1 → DF-10 as if they were wired

Lines 22-32 show data flow between primitives. With 7 of 10
primitives empty, the diagram is aspirational. A future reader
sees "DF-4 ifds consumes DF-3 points-to" and assumes the wire
exists.

**Fix:** add a "Status:" column to the diagram or rephrase as a
target architecture.

## 13 [LOW] Inconsistent suffix convention — some ops end in `_step`, most don't

`reaching_defs_step`, `live_step` vs `ssa_construct`,
`ifds_reach_step` (has suffix), `callgraph_build`, etc. The
`_step` suffix signals "one fixpoint iteration"; the absence
signals "end-to-end". The current naming does not consistently
match behavior.

**Fix:** post-bodies-implementation, standardise.

---

## Summary

- 1 CRITICAL (Finding 1, 7 files with `Program::empty()` bodies
  under aspirational `Exact` docstrings — LAW 9 evasion).
- 4 HIGH (Findings 2–5).
- 5 MEDIUM (Findings 6–10 are all instances of Finding 1 broken out
  per file for accountability).
- 2 LOW.

The module's soundness claims currently run two tiers ahead of its
implementation. The zero-FP precision contract in the legendary plan
depends on DF-3 / DF-5 / DF-7 / DF-8 actually working; seven of those
are empty today. Until AP-2 lands the AST buffer shape, the honest
move is to replace `Program::empty()` with a compile-time-visible
error at the dispatch site so a rule that leans on an un-implemented
primitive fails loudly.

Immediate fix (Claude, next commit): replace every
`Program::empty()` body with a panic that surfaces at the harness
`OpEntry::build` site, turning silent under-approximation into
loud "op not yet implemented" at test time.

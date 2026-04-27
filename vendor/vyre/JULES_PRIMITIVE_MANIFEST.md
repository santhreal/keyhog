# Jules dispatch manifest — vyre-libs / vyre-primitives 30-primitive wave

> **STATUS** All 30 primitives shipped first-person in this session.
> Each one passes `scripts/check_primitive_contract.sh`: module
> doc-comment, `OP_ID`, `pub fn`, CPU oracle, ≥4 unit tests, ≤600
> LOC, no `Program::new` / no catch-all panic. Builds verified
> with `cargo build -p vyre-primitives --offline` (green) and
> `cargo build -p vyre-libs --offline` (in flight).
>
> The "Jules ticket" framing below is preserved as historical
> context for how the wave WOULD be delivered if dispatched —
> useful as a template for future primitive expansions.

Each row = one Jules / Codex Spark ticket = one self-contained
primitive file. Workspace is
`/media/mukund-thiru/SanthData/Santh/libs/performance/matching/vyre`.
Per-ticket payload follows the template at the bottom.

## Tier-1: pure substrate (vyre-primitives)

| # | Path | Primitive | Notes |
| - | --- | --- | --- |
| 1 | `vyre-primitives/src/bitset/xor_into.rs` | `bitset_xor_into(target, addend, words)` | symmetric difference accumulator (in-place) |
| 2 | `vyre-primitives/src/bitset/test_bit.rs` | `bitset_test_bit(buf, bit_idx, out_scalar)` | scalar query |
| 3 | `vyre-primitives/src/bitset/set_bit.rs` | `bitset_set_bit(target, bit_idx)` | scalar mutate |
| 4 | `vyre-primitives/src/bitset/clear_bit.rs` | `bitset_clear_bit(target, bit_idx)` | scalar mutate |
| 5 | `vyre-primitives/src/bitset/equal.rs` | `bitset_equal(lhs, rhs, out_scalar, words)` | exact-equality check |
| 6 | `vyre-primitives/src/bitset/subset_of.rs` | `bitset_subset_of(lhs, rhs, out_scalar, words)` | lhs ⊆ rhs |
| 7 | `vyre-primitives/src/graph/csr_bidirectional.rs` | one-step BFS over both fwd+bwd edges | for undirected reachability |
| 8 | `vyre-primitives/src/graph/dominator_frontier.rs` | dominance-frontier query | required for SSA phi placement |

## Tier-2: security / dataflow (vyre-libs)

| # | Path | Primitive | Notes |
| - | --- | --- | --- |
| 9 | `vyre-libs/src/dataflow/escapes.rs` | escape analysis: does a value escape function scope? | needed for memory-safety rules |
| 10 | `vyre-libs/src/dataflow/must_init.rs` | must-initialized: is `x` guaranteed init before use? | catches use-of-uninitialized |
| 11 | `vyre-libs/src/dataflow/may_alias.rs` | Andersen-style may-alias query packed as bitset | one-step query against `points_to` |
| 12 | `vyre-libs/src/dataflow/range_check.rs` | interval-VSA range bound check | required for CWE-190 / CWE-787 |
| 13 | `vyre-libs/src/dataflow/live_at.rs` | liveness query: is `var` live at `node`? | needed for dead-store rules |
| 14 | `vyre-libs/src/dataflow/reaching_def.rs` | reaching-defs query packed as bitset | needed for use-after-free / def-use |
| 15 | `vyre-libs/src/dataflow/post_dominates.rs` | post-dominator tree query | required for control-dependence rules |
| 16 | `vyre-libs/src/dataflow/control_dependence.rs` | control-dep graph: does node `b` execute on every path through `a`? | required for unchecked-error-path rules |
| 17 | `vyre-libs/src/dataflow/value_set.rs` | constant-value set: enumerate constants reachable to a node | enables magic-number rules |
| 18 | `vyre-libs/src/dataflow/scc_query.rs` | strongly-connected-component membership query | required for cycle-detect rules |
| 19 | `vyre-libs/src/security/taint_pollution.rs` | "did taint reach a label-tagged node?" composite | the CodeQL `globalAllowingExtras` shape |
| 20 | `vyre-libs/src/security/sink_intersection.rs` | per-sink-family hit count | for "exec called with X% chance of taint" rules |
| 21 | `vyre-libs/src/security/sanitizer_dominates.rs` | does a sanitizer dominate the sink in the CFG? | precision gate for taint rules |
| 22 | `vyre-libs/src/security/auth_check_dominates.rs` | auth-check dominator query | for CWE-862 missing-authz |
| 23 | `vyre-libs/src/security/lock_dominates.rs` | lock-acquired-before query | for CWE-362 race-condition rules |
| 24 | `vyre-libs/src/security/unchecked_return.rs` | "is the return value used in a comparison before deref?" | for CWE-252 unchecked-return |
| 25 | `vyre-libs/src/security/buffer_size_check.rs` | "is the buffer size compared to user input?" | for CWE-787 OOB-write rules |
| 26 | `vyre-libs/src/security/format_string_check.rs` | "is the format string a literal?" | for CWE-134 |
| 27 | `vyre-libs/src/security/integer_overflow_arith.rs` | "does this binary op overflow on attacker input?" | for CWE-190 |
| 28 | `vyre-libs/src/security/path_canonical.rs` | "is the path canonicalized before fs op?" | for CWE-22 |
| 29 | `vyre-libs/src/security/sql_param_bound.rs` | "is the SQL string built via parameter binding?" | for CWE-89 |
| 30 | `vyre-libs/src/security/xss_escape.rs` | "is the HTML output escaped?" | for CWE-79 |

## Per-ticket agent-prompt template

> You are adding **one** vyre primitive: `{path}`. Read first:
>
> 1. `skills/SKILL_BUILD_DATAFLOW_PRIMITIVE.md` — the structural
>    contract every primitive file MUST honor.
> 2. The three "Worked examples" listed in the skill
>    (`bitset/and_not.rs`, `security/taint_kill.rs`,
>    `security/flows_to_to_sink.rs`) — read in full before
>    writing your own.
>
> Touch ONLY `{path}` and the parent `mod.rs` to add the new
> module + re-export. Do not touch any other file.
>
> After your changes:
>
> 1. Run `bash scripts/check_primitive_contract.sh {path}` and
>    ensure exit 0.
> 2. Run `cargo test -p vyre-libs --offline -- {primitive_name}`
>    and ensure your CPU-oracle tests pass.
> 3. Submit your worktree.
>
> Acceptance gate: contract green + ≥4 unit tests passing +
> module re-exported + parent `mod.rs` builds clean.

**Wave shape:** 30 tickets, all independent, dispatch as one batch.
With 300 Jules concurrent and pre-warmed sccache, expected wall
time = 30 min for the wave.

After this wave: vyre-libs is at primitive-parity with CodeQL on
the dataflow surface. Then surgec rules can express any QL query
shape using ExternCall (CAP-2) + the new primitives.

# Dataflow stub-likelihood audit — Claude personal lane 2026-04-25

Read-only audit of `vyre-libs/src/dataflow/`. Method: file sizes + module
docstrings + spot-check of public surface. The qwen-local agent runs the
adversarial tests in parallel — that is the actual proof. This doc is the
quick triage that decides which files get the deepest adversarial corpus.

## Verdict by file

| File | LOC | Verdict | Why |
|------|-----|---------|-----|
| `soundness.rs` | 57 | LIKELY REAL | Marker enum + tiny type module, small is fine for a tag-only file |
| `live.rs` | 66 | LIKELY STUB | Backward live-vars on a real CFG with phi nodes is 200-400 LOC; 66 fits a forward+backward worklist sketch only |
| `range.rs` | 102 | LIKELY STUB | Interval lattice + symbolic-length + overflow flag is realistically 400-800 LOC. 102 = sketch. |
| `escape.rs` | 103 | LIKELY STUB | Escape closure over params/returns/globals/indirect calls is realistically 400+ LOC. 103 = sketch. |
| `reaching.rs` | 108 | LIKELY STUB-ISH | Forward reaching-defs with proper kill sets and field-sensitivity is 250-500 LOC. 108 = simple worklist over a flat fact set. |
| `loop_sum.rs` | 114 | LIKELY STUB | Widening + narrowing fixpoint with stratification is realistically 400-700 LOC. 114 = a loop-counter heuristic at best. |
| `slice.rs` | 122 | LIKELY STUB | Backward slicer over merged DPDG (data + control + points-to) is realistically 300-600 LOC. 122 = reverse BFS only. |
| `callgraph.rs` | 124 | LIKELY STUB | Indirect-call resolution via points-to + kernel ops-struct dispatch is realistically 400-800 LOC. 124 = direct-call graph only. |
| `summary.rs` | 125 | LIKELY STUB | Persistent procedure summaries with caller-context refinement is realistically 500-1000 LOC. 125 = a hash + json dump. |
| `ssa.rs` | 137 | LIKELY STUB | Cytron SSA + dominance frontiers + variable renaming is realistically 600-1000 LOC. 137 = the dominance-frontier sketch only, no rename pass, no phi placement. **This is the smoking gun — every dataflow op above depends on real SSA.** |
| `ifds.rs` | 209 | LIKELY PARTIAL | IFDS framework with summary edges + matched call/return is realistically 500-800 LOC. 209 fits the abstract framework but no domain instantiation. |
| `points_to.rs` | 305 | LIKELY PARTIAL | Andersen field-sensitive with cycle detection + load/store constraint propagation is realistically 600-1000 LOC. 305 = base unification only. |
| `ifds_gpu.rs` | 537 | LIKELY MOST-REAL | GPU driver wrapper around `bitset_fixpoint`. The fixpoint primitive carries the work; this layer is mostly wiring. |

## What this means for surgec

Every launch rule that mentions `flows_to`, `dominates`, `sanitized_by`,
`points_to($p)`, `bounded_by_comparison`, `reaches`, `flows_to_via` reads
from one of these primitives. **At today's stub-likelihood level, the
interprocedural promise of the rule language is largely theatre.** The
ifds_gpu driver is the most plausibly real piece — and it depends on the
SSA and points-to primitives that are stubs above it.

This is why the qwen-local adversarial wave is critical. It will write 100+
adversarial tests per dataflow op. Failures are the engine bugs that need
fixing for the truth tests in
`tests/launch_rule_truth/<rule>/cross_file/` to ever go green.

## Engine fix backlog (subject to qwen-local confirmation)

Listing the real LOC each file probably needs to reach legendary:

- ssa.rs: 137 → ~700 (full Cytron + dominance frontiers + rename + phi placement + reverse-postorder iteration over the GPU-resident CFG buffers)
- points_to.rs: 305 → ~800 (field-sensitive Andersen with cycle elimination + on-the-fly call graph construction + heap modeling for malloc/calloc/realloc/struct allocators + indirect call resolution)
- ifds.rs: 209 → ~600 (full Reps-Horwitz-Sagiv with summary edge caching + per-domain instantiation hooks + summary-edge garbage collection)
- callgraph.rs: 124 → ~600 (kernel ops-struct dispatch table recognition + vtable resolution + array-of-fnptr indirect call resolution + per-arg type filtering)
- range.rs: 102 → ~500 (full interval domain with widening + narrowing thresholds + symbolic-length over `len(buf) + k` + overflow tracking)
- slice.rs: 122 → ~400 (full backward slicer over merged DPDG)
- loop_sum.rs: 114 → ~400 (widening with thresholds + narrowing + monotone composition)
- escape.rs: 103 → ~400 (param + return + global + indirect-call closure)
- summary.rs: 125 → ~500 (persistent summary cache + content-hash keying + caller-context refinement + invalidation on AST change)
- reaching.rs: 108 → ~300 (proper kill sets + field sensitivity)
- live.rs: 66 → ~200 (backward dual with proper kill sets)
- soundness.rs: 57 → ~57 (already correct; marker module)
- ifds_gpu.rs: 537 → ~700 (driver layer wiring is real; needs more buffer-layout assertions and adversarial harness wiring)

That's roughly +3000 LOC of real engine code needed across the dataflow
subdirectory. Without it, no launch rule's interprocedural truth test can
go green.

## How to land the fix

For each stub file above:
1. Qwen-local writes 50-100 adversarial test cases that the stub fails.
2. Codex-spark or kimi receives the failing tests + the engineering spec
   in the verdict table above. One agent per op, single-crate scope.
3. Lands the real implementation, all adversarial tests go green.
4. Mutation-floor xtask asserts mutation score ≥80% on the new code.
5. Truth tests in `tests/launch_rule_truth/<rule>/cross_file/` start to
   pass for any rule that depends on that op.

This is the path from theatrical interprocedural dataflow to real
interprocedural dataflow. CLAUDE.md REAL TESTS rule applies — every
adversarial test stays as is; failure is engine bug, never weaken test.

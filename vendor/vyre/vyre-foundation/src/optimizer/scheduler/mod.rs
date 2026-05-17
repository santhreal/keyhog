#![allow(clippy::expect_used)]
//! Topological scheduling from [`PassMetadata::requires`](crate::optimizer::PassMetadata),
//! then a fixpoint runner that clears capabilities listed in `invalidates` when a pass
//! rewrites the program.
//!
//! **Hand-curated pass-pair list:** There is no longer a static list of ~30 `(before, after)`
//! pairs in this module (location *N/A* — not present in this revision). Constraints that map
//! to named predecessor passes are encoded only via each pass’s `requires` entries and are
//! honored by [`schedule_passes`] and the runtime requirement check inside `PassScheduler`'s fixpoint step.
//!
//! **Adjustment-set / causal edges:** Ordering beyond that DAG needs a separate row-major
//! influence matrix `adj` (`adj[i·n+j] ≠ 0` ⇒ pass `i` may influence `j`). [`PassMetadata`](crate::optimizer::PassMetadata)
//! exposes `requires` and `invalidates` capability tags, not a full pass→pass influence graph
//! or `produces` facts, so **extra causal pairs are not derivable** from metadata alone.
//! When `adj` is supplied (substrate analysis, TOML rules, etc.), use
//! [`crate::pass_substrate::adjustment_set_pass_dependency::pass_descendants`] for transitive
//! downstream passes and [`crate::pass_substrate::adjustment_set_pass_dependency::ordering_is_safe`]
//! to validate a proposed “run treatment before outcome” ordering.
use crate::ir::{BufferDecl, Expr, Node};
use crate::ir_inner::model::program::Program;
use crate::optimizer::{registered_passes, OptimizerError, ProgramPassKind};
use rustc_hash::{FxHashMap, FxHashSet};
use std::sync::OnceLock;

pub(super) const DEFAULT_MAX_ITERATIONS: usize = 50;

/// Fixpoint scheduler for optimizer passes.
pub struct PassScheduler {
    passes: Vec<ProgramPassKind>,
    pass_index: FxHashMap<&'static str, usize>,
    execution_order: Vec<usize>,
    max_iterations: usize,
    invalidation_adjacency_cache: OnceLock<Vec<u32>>,
    invalidation_closure_cache: OnceLock<FxHashMap<&'static str, FxHashSet<&'static str>>>,
    /// When `true`, the scheduler enforces a cost-monotone-down post-condition
    /// on every `ProgramPass::transform` invocation: after the rewrite, the new
    /// `CostCertificate` must dominate-or-equal the old on every tracked
    /// dimension, OR the pass must have explicitly declined via
    /// `ProgramPass::try_transform` returning `Err(RefusalReason::CostIncrease { ... })`.
    /// Rewrites that increase a tracked dimension without an explicit refusal
    /// are reverted (the pre-rewrite Program is kept) and a structured warning
    /// is emitted via the per-pass `PassRunMetric`.
    ///
    /// Defaults to `false` so existing consumers and built-in pass behavior are
    /// preserved bit-for-bit. Audits, tests, and the catalog-landing pipeline
    /// (Phase 4) flip this to `true` to drive the cost contract end-to-end.
    enforce_cost_monotone: bool,
}

/// Optimized program plus per-pass runtime/size counters.
#[derive(Debug)]
pub struct OptimizerRunReport {
    /// Final program after convergence.
    pub program: Program,
    /// One metric row per pass considered by the scheduler.
    pub passes: Vec<PassRunMetric>,
}

/// Runtime and IR-size counters for one pass consideration.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PassRunMetric {
    /// Fixpoint iteration index.
    pub iteration: usize,
    /// Pass identifier.
    pub pass: &'static str,
    /// Whether transform actually ran.
    pub ran: bool,
    /// Whether transform changed the program.
    pub changed: bool,
    /// Transform wall-clock runtime in nanoseconds. Zero when skipped.
    pub runtime_ns: u128,
    /// Node count before the pass.
    pub nodes_before: usize,
    /// Node count after the pass.
    pub nodes_after: usize,
    /// Statically-known storage bytes before the pass.
    pub static_storage_bytes_before: u64,
    /// Statically-known storage bytes after the pass.
    pub static_storage_bytes_after: u64,
    /// Estimated instruction count before the pass.
    pub instruction_count_before: u64,
    /// Estimated instruction count after the pass.
    pub instruction_count_after: u64,
    /// Memory operation count before the pass.
    pub memory_op_count_before: u64,
    /// Memory operation count after the pass.
    pub memory_op_count_after: u64,
    /// Atomic operation count before the pass.
    pub atomic_op_count_before: u64,
    /// Atomic operation count after the pass.
    pub atomic_op_count_after: u64,
    /// Control-flow operation count before the pass.
    pub control_flow_count_before: u64,
    /// Control-flow operation count after the pass.
    pub control_flow_count_after: u64,
    /// Coarse register-pressure estimate before the pass.
    pub register_pressure_before: u32,
    /// Coarse register-pressure estimate after the pass.
    pub register_pressure_after: u32,
    /// Estimated count of heap-backed IR containers before the pass.
    pub ir_heap_allocations_before: usize,
    /// Estimated count of heap-backed IR containers after the pass.
    pub ir_heap_allocations_after: usize,
    /// Estimated bytes owned by heap-backed IR containers before the pass.
    pub ir_heap_bytes_before: usize,
    /// Estimated bytes owned by heap-backed IR containers after the pass.
    pub ir_heap_bytes_after: usize,
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct IrAllocationEstimate {
    allocations: usize,
    bytes: usize,
}

impl IrAllocationEstimate {
    fn add_container<T>(&mut self, len: usize) {
        self.allocations = self.allocations.saturating_add(1);
        self.bytes = self
            .bytes
            .saturating_add(len.saturating_mul(std::mem::size_of::<T>()));
    }

    fn add_box<T>(&mut self) {
        self.allocations = self.allocations.saturating_add(1);
        self.bytes = self.bytes.saturating_add(std::mem::size_of::<T>());
    }
}

fn estimate_ir_allocations(program: &Program) -> IrAllocationEstimate {
    let mut estimate = IrAllocationEstimate::default();
    // Program-owned shared containers: buffers, buffer index, entry body,
    // validation cache, plus any lazily-materialized stats/cache Arcs.
    estimate.add_container::<BufferDecl>(program.buffers().len());
    estimate.add_container::<Node>(program.entry().len());
    estimate.allocations = estimate.allocations.saturating_add(2);
    for node in program.entry() {
        estimate_node_allocations(node, &mut estimate);
    }
    estimate
}

fn estimate_node_allocations(node: &Node, estimate: &mut IrAllocationEstimate) {
    match node {
        Node::Let { value, .. } | Node::Assign { value, .. } => {
            estimate_expr_allocations(value, estimate);
        }
        Node::Store { index, value, .. } => {
            estimate_expr_allocations(index, estimate);
            estimate_expr_allocations(value, estimate);
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            estimate_expr_allocations(cond, estimate);
            estimate.add_container::<Node>(then.len());
            estimate.add_container::<Node>(otherwise.len());
            for node in then.iter().chain(otherwise.iter()) {
                estimate_node_allocations(node, estimate);
            }
        }
        Node::Loop { from, to, body, .. } => {
            estimate_expr_allocations(from, estimate);
            estimate_expr_allocations(to, estimate);
            estimate.add_container::<Node>(body.len());
            for node in body {
                estimate_node_allocations(node, estimate);
            }
        }
        Node::AsyncLoad { offset, size, .. } | Node::AsyncStore { offset, size, .. } => {
            estimate.add_box::<Expr>();
            estimate.add_box::<Expr>();
            estimate_expr_allocations(offset, estimate);
            estimate_expr_allocations(size, estimate);
        }
        Node::Trap { address, .. } => {
            estimate.add_box::<Expr>();
            estimate_expr_allocations(address, estimate);
        }
        Node::Block(body) => {
            estimate.add_container::<Node>(body.len());
            for node in body {
                estimate_node_allocations(node, estimate);
            }
        }
        Node::Region { body, .. } => {
            estimate.add_container::<Node>(body.len());
            for node in body.iter() {
                estimate_node_allocations(node, estimate);
            }
        }
        Node::Opaque(_) => {
            estimate.allocations = estimate.allocations.saturating_add(1);
        }
        Node::IndirectDispatch { .. }
        | Node::AsyncWait { .. }
        | Node::Resume { .. }
        | Node::Return
        | Node::Barrier { .. } => {}
    }
}

fn estimate_expr_allocations(expr: &Expr, estimate: &mut IrAllocationEstimate) {
    match expr {
        Expr::Load { index, .. } => {
            estimate.add_box::<Expr>();
            estimate_expr_allocations(index, estimate);
        }
        Expr::BinOp { left, right, .. } => {
            estimate.add_box::<Expr>();
            estimate.add_box::<Expr>();
            estimate_expr_allocations(left, estimate);
            estimate_expr_allocations(right, estimate);
        }
        Expr::UnOp { operand, .. }
        | Expr::Cast { value: operand, .. }
        | Expr::SubgroupBallot { cond: operand }
        | Expr::SubgroupAdd { value: operand } => {
            estimate.add_box::<Expr>();
            estimate_expr_allocations(operand, estimate);
        }
        Expr::Call { args, .. } => {
            estimate.add_container::<Expr>(args.len());
            for arg in args {
                estimate_expr_allocations(arg, estimate);
            }
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            estimate.add_box::<Expr>();
            estimate.add_box::<Expr>();
            estimate.add_box::<Expr>();
            estimate_expr_allocations(cond, estimate);
            estimate_expr_allocations(true_val, estimate);
            estimate_expr_allocations(false_val, estimate);
        }
        Expr::Fma { a, b, c } => {
            estimate.add_box::<Expr>();
            estimate.add_box::<Expr>();
            estimate.add_box::<Expr>();
            estimate_expr_allocations(a, estimate);
            estimate_expr_allocations(b, estimate);
            estimate_expr_allocations(c, estimate);
        }
        Expr::Atomic {
            index,
            expected,
            value,
            ..
        } => {
            estimate.add_box::<Expr>();
            estimate.add_box::<Expr>();
            estimate_expr_allocations(index, estimate);
            if let Some(expected) = expected {
                estimate.add_box::<Expr>();
                estimate_expr_allocations(expected, estimate);
            }
            estimate_expr_allocations(value, estimate);
        }
        Expr::SubgroupShuffle { value, lane } => {
            estimate.add_box::<Expr>();
            estimate.add_box::<Expr>();
            estimate_expr_allocations(value, estimate);
            estimate_expr_allocations(lane, estimate);
        }
        Expr::Opaque(_) => {
            estimate.allocations = estimate.allocations.saturating_add(1);
        }
        Expr::LitU32(_)
        | Expr::LitI32(_)
        | Expr::LitF32(_)
        | Expr::LitBool(_)
        | Expr::Var(_)
        | Expr::BufLen { .. }
        | Expr::InvocationId { .. }
        | Expr::WorkgroupId { .. }
        | Expr::LocalId { .. }
        | Expr::SubgroupLocalId
        | Expr::SubgroupSize => {}
    }
}

impl PassScheduler {
    /// Attempt to build a PassScheduler using the default registered passes.
    pub fn try_default() -> Result<Self, OptimizerError> {
        let passes = registered_passes()?;
        let pass_index = passes
            .iter()
            .enumerate()
            .map(|(i, pass)| (pass.metadata().name, i))
            .collect();
        let execution_order = (0..passes.len()).collect();
        Ok(Self {
            passes,
            pass_index,
            execution_order,
            max_iterations: DEFAULT_MAX_ITERATIONS,
            invalidation_adjacency_cache: OnceLock::new(),
            invalidation_closure_cache: OnceLock::new(),
            enforce_cost_monotone: false,
        })
    }

    /// Toggle the cost-monotone-down post-condition gate. See the field docs on
    /// `PassScheduler::enforce_cost_monotone`. Returns `self` so this composes
    /// with other builder-shaped configuration.
    #[must_use]
    pub fn with_cost_monotone_enforcement(mut self, enforce: bool) -> Self {
        self.enforce_cost_monotone = enforce;
        self
    }

    /// Whether the cost-monotone-down post-condition gate is active.
    #[must_use]
    pub fn cost_monotone_enforcement(&self) -> bool {
        self.enforce_cost_monotone
    }
}

impl Default for PassScheduler {
    fn default() -> Self {
        Self::try_default().unwrap_or_else(|error| {
            panic!(
                "Fix: built-in optimizer pass metadata is invalid; this is a vyre-foundation bug: {error}"
            )
        })
    }
}

// Audit cleanup A21 (2026-04-30): split scheduler.rs (1161 LOC) into
// per-concern submodules. Each carries its own `impl PassScheduler`
// block; Rust merges them at link time.

/// Topological scheduling: `schedule_passes` free fn, precomputed
/// execution-order indices, and the `PassSchedulingError` enum.
mod topo;

/// Fusion-query methods on PassScheduler (transitive_dependents, reaches,
/// invalidation_closure, fusion_pressure, fusable_subset, pair_commutes,
/// etc) + remaining constructor helpers (with_passes, with_max_iterations).
mod queries;

/// Run methods on PassScheduler: run, run_with_metrics, run_once,
/// run_once_with_metrics, mark_invalidated_passes.
mod run;

pub use topo::{schedule_passes, PassSchedulingError};

#[cfg(test)]
mod tests;

//! PassScheduler run methods + invalidation propagation.
//! Audit cleanup A21 (2026-04-30): split from monolithic scheduler.rs.

#![allow(unused_imports)]

use rustc_hash::{FxHashMap, FxHashSet};
use std::sync::OnceLock;

use super::{
    estimate_ir_allocations, IrAllocationEstimate, OptimizerRunReport, PassRunMetric, PassScheduler,
};
use crate::ir::{BufferDecl, Expr, Node};
use crate::ir_inner::model::program::Program;
use crate::optimizer::{
    registered_passes, requirements_satisfied, OptimizerError, PassMetadata, ProgramPassKind,
    ProgramPassRegistration,
};
use crate::runtime::perf::PerfScope;

impl PassScheduler {
    pub(crate) fn mark_invalidated_passes(
        &self,
        invalidated: &[&'static str],
        next_dirty: &mut FxHashSet<&'static str>,
    ) {
        for pass in &self.passes {
            let metadata = pass.metadata();
            if invalidated
                .iter()
                .any(|tag| metadata.name == *tag || metadata.requires.iter().any(|req| req == tag))
            {
                next_dirty.insert(metadata.name);
            }
        }
    }

    /// Execute the scheduled passes repeatedly until convergence or max iterations are reached.
    pub fn run(&self, program: Program) -> Result<Program, OptimizerError> {
        let mut program = program;
        let mut last_pass = "<none>";
        let mut dirty = self.initial_dirty_set();

        for _ in 0..self.max_iterations {
            let (next, changed, changed_by, next_dirty) = self.run_once(program, &dirty)?;
            program = next;
            if let Some(name) = changed_by {
                last_pass = name;
            }
            dirty = next_dirty;
            if !changed {
                return Ok(program.reconcile_runnable_top_level());
            }
        }
        Err(OptimizerError::MaxIterations {
            max_iterations: self.max_iterations,
            last_pass,
        })
    }

    /// Execute the scheduled passes and return per-pass runtime/IR counters.
    ///
    /// This mirrors [`Self::run`] but retains counters that identify expensive
    /// or clone-heavy passes without requiring a profiler.
    pub fn run_with_metrics(&self, program: Program) -> Result<OptimizerRunReport, OptimizerError> {
        let mut program = program;
        let mut last_pass = "<none>";
        let mut dirty = self.initial_dirty_set();
        let mut metrics = Vec::with_capacity(
            self.execution_order
                .len()
                .saturating_mul(self.max_iterations),
        );

        for iteration in 0..self.max_iterations {
            let (next, changed, changed_by, next_dirty) =
                self.run_once_with_metrics(program, &dirty, iteration, &mut metrics)?;
            program = next;
            if let Some(name) = changed_by {
                last_pass = name;
            }
            dirty = next_dirty;
            if !changed {
                return Ok(OptimizerRunReport {
                    program: program.reconcile_runnable_top_level(),
                    passes: metrics,
                });
            }
        }
        Err(OptimizerError::MaxIterations {
            max_iterations: self.max_iterations,
            last_pass,
        })
    }

    pub(crate) fn run_once(
        &self,
        mut program: Program,
        dirty: &FxHashSet<&'static str>,
    ) -> Result<(Program, bool, Option<&'static str>, FxHashSet<&'static str>), OptimizerError>
    {
        let mut available = FxHashSet::default();
        available.reserve(self.execution_order.len());
        let mut changed = false;
        let mut changed_by = None;
        let mut next_dirty = FxHashSet::default();
        next_dirty.reserve(self.passes.len());
        for &pass_index in &self.execution_order {
            let Some(pass) = self.passes.get(pass_index) else {
                continue;
            };
            let metadata = pass.metadata();
            if !requirements_satisfied(metadata, &available) {
                let missing = metadata
                    .requires
                    .iter()
                    .copied()
                    .find(|requirement| !available.contains(requirement))
                    .unwrap_or("<unknown>");
                return Err(OptimizerError::UnsatisfiedRequirement {
                    pass: metadata.name,
                    missing,
                });
            }

            if dirty.contains(metadata.name) && pass.analyze(&program).should_run {
                program = if self.enforce_cost_monotone {
                    let pre_cost = crate::optimizer::cost::CostCertificate::for_program(&program);
                    let pre_snapshot = program.clone();
                    let result = pass.transform(program);
                    let post_cost =
                        crate::optimizer::cost::CostCertificate::for_program(&result.program);
                    if result.changed && !post_cost.dominates_or_equal(&pre_cost) {
                        // Pass landed a rewrite that increased a tracked cost
                        // dimension without explicitly declining via
                        // `ProgramPass::try_transform`. Revert to the pre-snapshot;
                        // the change does NOT propagate into the next pass.
                        pre_snapshot
                    } else {
                        if result.changed {
                            changed = true;
                            changed_by = Some(pass.pass_id());
                            self.mark_invalidated_passes(metadata.invalidates, &mut next_dirty);
                        }
                        result.program
                    }
                } else {
                    let result = pass.transform(program);
                    if result.changed {
                        changed = true;
                        changed_by = Some(pass.pass_id());
                        self.mark_invalidated_passes(metadata.invalidates, &mut next_dirty);
                    }
                    result.program
                };
            }
            available.insert(metadata.name);
        }

        Ok((program, changed, changed_by, next_dirty))
    }

    pub(crate) fn run_once_with_metrics(
        &self,
        mut program: Program,
        dirty: &FxHashSet<&'static str>,
        iteration: usize,
        metrics: &mut Vec<PassRunMetric>,
    ) -> Result<(Program, bool, Option<&'static str>, FxHashSet<&'static str>), OptimizerError>
    {
        let mut available = FxHashSet::default();
        available.reserve(self.execution_order.len());
        let mut changed = false;
        let mut changed_by = None;
        let mut next_dirty = FxHashSet::default();
        next_dirty.reserve(self.passes.len());
        let mut cached_allocation_estimate: Option<IrAllocationEstimate> = None;

        for &pass_index in &self.execution_order {
            let Some(pass) = self.passes.get(pass_index) else {
                continue;
            };
            let metadata = pass.metadata();
            if !requirements_satisfied(metadata, &available) {
                let missing = metadata
                    .requires
                    .iter()
                    .copied()
                    .find(|requirement| !available.contains(requirement))
                    .unwrap_or("<unknown>");
                return Err(OptimizerError::UnsatisfiedRequirement {
                    pass: metadata.name,
                    missing,
                });
            }

            let before_stats = *program.stats();
            let before_allocations = *cached_allocation_estimate
                .get_or_insert_with(|| estimate_ir_allocations(&program));

            let mut metric = PassRunMetric {
                iteration,
                pass: metadata.name,
                ran: false,
                changed: false,
                runtime_ns: 0,
                nodes_before: before_stats.node_count,
                nodes_after: before_stats.node_count,
                static_storage_bytes_before: before_stats.static_storage_bytes,
                static_storage_bytes_after: before_stats.static_storage_bytes,
                instruction_count_before: before_stats.instruction_count,
                instruction_count_after: before_stats.instruction_count,
                memory_op_count_before: before_stats.memory_op_count,
                memory_op_count_after: before_stats.memory_op_count,
                atomic_op_count_before: before_stats.atomic_op_count,
                atomic_op_count_after: before_stats.atomic_op_count,
                control_flow_count_before: before_stats.control_flow_count,
                control_flow_count_after: before_stats.control_flow_count,
                register_pressure_before: before_stats.register_pressure_estimate,
                register_pressure_after: before_stats.register_pressure_estimate,
                ir_heap_allocations_before: before_allocations.allocations,
                ir_heap_allocations_after: before_allocations.allocations,
                ir_heap_bytes_before: before_allocations.bytes,
                ir_heap_bytes_after: before_allocations.bytes,
            };

            if dirty.contains(metadata.name) && pass.analyze(&program).should_run {
                metric.ran = true;
                let perf_scope = PerfScope::start("vyre-foundation", metadata.name);
                let pre_cost_for_gate = self
                    .enforce_cost_monotone
                    .then(|| crate::optimizer::cost::CostCertificate::for_program(&program));
                let pre_snapshot_for_gate = self.enforce_cost_monotone.then(|| program.clone());
                let result = pass.transform(program);
                metric.runtime_ns = u128::from(perf_scope.finish().elapsed_ns);
                let mut landed_changed = result.changed;
                program = match (pre_cost_for_gate, pre_snapshot_for_gate) {
                    (Some(pre_cost), Some(pre_snapshot)) if result.changed => {
                        let post_cost =
                            crate::optimizer::cost::CostCertificate::for_program(&result.program);
                        if post_cost.dominates_or_equal(&pre_cost) {
                            result.program
                        } else {
                            // Cost-monotone-down violation: a tracked dimension
                            // increased without an explicit refusal. Drop the
                            // rewrite, restore the pre-snapshot. The metrics
                            // captured below reflect the post-revert shape.
                            landed_changed = false;
                            pre_snapshot
                        }
                    }
                    _ => result.program,
                };
                let after_stats = *program.stats();
                let after_allocations = if landed_changed {
                    estimate_ir_allocations(&program)
                } else {
                    before_allocations
                };
                cached_allocation_estimate = Some(after_allocations);
                metric.nodes_after = after_stats.node_count;
                metric.static_storage_bytes_after = after_stats.static_storage_bytes;
                metric.instruction_count_after = after_stats.instruction_count;
                metric.memory_op_count_after = after_stats.memory_op_count;
                metric.atomic_op_count_after = after_stats.atomic_op_count;
                metric.control_flow_count_after = after_stats.control_flow_count;
                metric.register_pressure_after = after_stats.register_pressure_estimate;
                metric.ir_heap_allocations_after = after_allocations.allocations;
                metric.ir_heap_bytes_after = after_allocations.bytes;
                // Reflect post-gate state. Expression-only rewrites often keep
                // the same node count; they still invalidate downstream facts.
                metric.changed = landed_changed;
                if metric.changed {
                    changed = true;
                    changed_by = Some(pass.pass_id());
                    self.mark_invalidated_passes(metadata.invalidates, &mut next_dirty);
                }
            }
            metrics.push(metric);
            available.insert(metadata.name);
        }

        Ok((program, changed, changed_by, next_dirty))
    }

    fn initial_dirty_set(&self) -> FxHashSet<&'static str> {
        let mut dirty = FxHashSet::default();
        dirty.reserve(self.passes.len());
        dirty.extend(self.passes.iter().map(|pass| pass.metadata().name));
        dirty
    }
}

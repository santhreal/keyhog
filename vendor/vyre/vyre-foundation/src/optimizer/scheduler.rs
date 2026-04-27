#![allow(clippy::expect_used)]
use crate::ir_inner::model::program::Program;
use crate::optimizer::{
    registered_passes, requirements_satisfied, OptimizerError, PassKind, PassMetadata,
    PassRegistration,
};
use rustc_hash::{FxHashMap, FxHashSet};
use std::collections::VecDeque;

const DEFAULT_MAX_ITERATIONS: usize = 50;

/// Fixpoint scheduler for optimizer passes.
pub struct PassScheduler {
    passes: Vec<PassKind>,
    pass_index: FxHashMap<&'static str, usize>,
    max_iterations: usize,
}

impl PassScheduler {
    /// Construct from the globally registered pass set.
    ///
    /// # Errors
    ///
    /// Returns [`OptimizerError`] when the linked pass metadata contains
    /// an unresolvable scheduling conflict (unknown requirement or cycle).
    pub fn try_default() -> Result<Self, OptimizerError> {
        let passes = registered_passes()?;
        let pass_index = passes
            .iter()
            .enumerate()
            .map(|(i, pass)| (pass.metadata().name, i))
            .collect();
        Ok(Self {
            passes,
            pass_index,
            max_iterations: DEFAULT_MAX_ITERATIONS,
        })
    }
}

impl Default for PassScheduler {
    /// Construct from the globally registered pass set.
    ///
    /// # Panics
    ///
    /// Panics only when a linked pass declares contradictory metadata
    /// (unknown requirement or cycle). This should never happen with the
    /// built-in passes; use [`PassScheduler::try_default`] if you accept
    /// out-of-tree passes that may have broken metadata.
    fn default() -> Self {
        Self::try_default().expect(
            "Fix: built-in optimizer pass metadata is invalid; this is a vyre-foundation bug.",
        )
    }
}

/// Error returned when optimizer pass metadata cannot form a DAG.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[non_exhaustive]
pub enum PassSchedulingError {
    /// A pass depends on an id that is not registered.
    #[error(
        "optimizer pass `{pass}` requires unknown pass `{missing}`. Fix: register `{missing}` or remove it from `{pass}` requires."
    )]
    UnknownRequire {
        /// Pass declaring the missing requirement.
        pass: &'static str,
        /// Missing required pass id.
        missing: &'static str,
    },
    /// The pass dependency graph has a cycle.
    #[error("optimizer pass dependency cycle among {pass_ids:?}. Fix: {fix}")]
    Cycle {
        /// Pass ids participating in the cycle.
        pass_ids: Vec<&'static str>,
        /// Actionable repair guidance.
        fix: &'static str,
    },
    /// Duplicate pass ids make dependency edges ambiguous.
    #[error(
        "optimizer pass id `{id}` is registered more than once. Fix: give every pass a unique stable id."
    )]
    DuplicateId {
        /// Duplicate id.
        id: &'static str,
    },
}

/// Topologically order pass registrations by their `requires` edges.
///
/// `requires` means "run this required pass first". The returned vector is a
/// deterministic Kahn order: passes that become ready at the same time are
/// ordered by pass id so link-time inventory iteration cannot affect output.
///
/// # Errors
///
/// Returns [`PassSchedulingError::UnknownRequire`] for references to missing
/// pass ids, [`PassSchedulingError::DuplicateId`] for ambiguous ids, and
/// [`PassSchedulingError::Cycle`] when no linear order exists.
pub fn schedule_passes(
    passes: &[&'static PassRegistration],
) -> Result<Vec<&'static PassRegistration>, PassSchedulingError> {
    let mut by_id = FxHashMap::default();
    for pass in passes {
        let id = pass.metadata.name;
        if by_id.insert(id, *pass).is_some() {
            return Err(PassSchedulingError::DuplicateId { id });
        }
    }

    let mut indegree = FxHashMap::<&'static str, usize>::default();
    let mut dependents = FxHashMap::<&'static str, Vec<&'static str>>::default();
    for pass in passes {
        let id = pass.metadata.name;
        indegree.entry(id).or_insert(0);
        for required in pass.metadata.requires {
            if !by_id.contains_key(required) {
                return Err(PassSchedulingError::UnknownRequire {
                    pass: id,
                    missing: required,
                });
            }
            *indegree.entry(id).or_insert(0) += 1;
            dependents.entry(required).or_default().push(id);
        }
    }

    for ids in dependents.values_mut() {
        ids.sort_unstable();
    }

    let mut initial_ready = indegree
        .iter()
        .filter_map(|(id, degree)| (*degree == 0).then_some(*id))
        .collect::<Vec<_>>();
    initial_ready.sort_unstable();
    let mut ready = VecDeque::from(initial_ready);

    let mut ordered = Vec::with_capacity(passes.len());
    while let Some(id) = ready.pop_front() {
        ordered.push(
            by_id
                .get(id)
                .copied()
                .expect("Fix: scheduled pass id must exist in pass index."),
        );

        if let Some(children) = dependents.get(id) {
            for child in children {
                let degree = indegree
                    .get_mut(child)
                    .expect("Fix: dependent pass must have an indegree entry.");
                *degree -= 1;
                if *degree == 0 {
                    insert_ready_sorted(&mut ready, child);
                }
            }
        }
    }

    if ordered.len() != passes.len() {
        let mut pass_ids = indegree
            .into_iter()
            .filter_map(|(id, degree)| (degree > 0).then_some(id))
            .collect::<Vec<_>>();
        pass_ids.sort_unstable();
        return Err(PassSchedulingError::Cycle {
            pass_ids,
            fix: "Break the cycle by removing one of these `requires` entries.",
        });
    }

    Ok(ordered)
}

fn insert_ready_sorted(ready: &mut VecDeque<&'static str>, id: &'static str) {
    let pos = ready
        .iter()
        .position(|existing| id < *existing)
        .unwrap_or(ready.len());
    ready.insert(pos, id);
}

impl PassScheduler {
    /// Build a scheduler from explicit pass instances.
    #[must_use]
    pub fn with_passes(passes: Vec<PassKind>) -> Self {
        let pass_index = passes
            .iter()
            .enumerate()
            .map(|(i, pass)| (pass.metadata().name, i))
            .collect();
        Self {
            passes,
            pass_index,
            max_iterations: DEFAULT_MAX_ITERATIONS,
        }
    }

    /// Set the fixpoint safety cap.
    #[must_use]
    pub fn with_max_iterations(mut self, max_iterations: usize) -> Self {
        self.max_iterations = max_iterations;
        self
    }

    /// Run passes until no pass changes the program.
    ///
    /// # Errors
    ///
    /// Returns [`OptimizerError`] if the dependency metadata cannot be
    /// satisfied or if the pipeline exceeds its fixpoint iteration cap.
    pub fn run(&self, program: Program) -> Result<Program, OptimizerError> {
        let mut program = program;
        let mut last_pass = "<none>";
        let mut dirty: FxHashSet<&'static str> = self
            .passes
            .iter()
            .map(|pass| pass.metadata().name)
            .collect();

        for _ in 0..self.max_iterations {
            let (next, changed, changed_by, next_dirty) = self.run_once(program, &dirty)?;
            program = next;
            if let Some(name) = changed_by {
                last_pass = name;
            }
            dirty = next_dirty;
            if !changed {
                return Ok(program);
            }
        }
        Err(OptimizerError::MaxIterations {
            max_iterations: self.max_iterations,
            last_pass,
        })
    }

    fn run_once(
        &self,
        mut program: Program,
        dirty: &FxHashSet<&'static str>,
    ) -> Result<(Program, bool, Option<&'static str>, FxHashSet<&'static str>), OptimizerError>
    {
        let mut available = FxHashSet::default();
        let mut pending = self
            .passes
            .iter()
            .map(|pass| pass.metadata())
            .collect::<Vec<_>>();
        let mut changed = false;
        let mut changed_by = None;
        let mut next_dirty = FxHashSet::default();

        while !pending.is_empty() {
            let Some(index) = next_ready_pass(&pending, &available) else {
                let blocked = pending[0];
                let missing = blocked
                    .requires
                    .iter()
                    .copied()
                    .find(|requirement| !available.contains(requirement))
                    .unwrap_or("<unknown>");
                return Err(OptimizerError::UnsatisfiedRequirement {
                    pass: blocked.name,
                    missing,
                });
            };

            let metadata = pending.remove(index);
            let pass = self
                .passes
                .get(
                    *self
                        .pass_index
                        .get(metadata.name)
                        .expect("Fix: scheduler metadata must map to one pass instance."),
                )
                .expect("Fix: scheduler metadata must map to one pass instance.");

            if dirty.contains(metadata.name) && pass.analyze(&program).should_run {
                let result = pass.transform(program);
                program = result.program;
                if result.changed {
                    changed = true;
                    changed_by = Some(pass.pass_id());
                    for invalidated in metadata.invalidates {
                        // VYRE_OPTIMIZER HIGH-01: if the invalidated
                        // pass was SKIPped earlier this iteration,
                        // the previous `available.contains` guard
                        // would silently drop it from next_dirty —
                        // so a later iteration's analyze() never got
                        // a chance to flip it to RUN based on the
                        // rewritten program. Always mark it dirty.
                        next_dirty.insert(*invalidated);
                        available.remove(invalidated);
                    }
                }
            }
            available.insert(metadata.name);
        }

        Ok((program, changed, changed_by, next_dirty))
    }
}

fn next_ready_pass(pending: &[PassMetadata], available: &FxHashSet<&'static str>) -> Option<usize> {
    pending
        .iter()
        .position(|metadata| requirements_satisfied(*metadata, available))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BufferDecl, DataType, Expr, Node, Program};
    use crate::optimizer::{Pass, PassAnalysis, PassRegistration, PassResult};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    struct StablePass {
        analyze_calls: Arc<AtomicUsize>,
    }

    impl crate::optimizer::private::Sealed for StablePass {}

    impl Pass for StablePass {
        fn metadata(&self) -> PassMetadata {
            PassMetadata {
                name: "stable",
                requires: &[],
                invalidates: &[],
            }
        }

        fn analyze(&self, _program: &Program) -> PassAnalysis {
            self.analyze_calls.fetch_add(1, Ordering::SeqCst);
            PassAnalysis::SKIP
        }

        fn transform(&self, program: Program) -> PassResult {
            PassResult {
                program,
                changed: false,
            }
        }

        fn fingerprint(&self, _program: &Program) -> u64 {
            0
        }
    }

    struct ChangeOncePass {
        changed: Arc<std::sync::atomic::AtomicBool>,
    }

    impl crate::optimizer::private::Sealed for ChangeOncePass {}

    impl Pass for ChangeOncePass {
        fn metadata(&self) -> PassMetadata {
            PassMetadata {
                name: "change_once",
                requires: &[],
                invalidates: &[],
            }
        }

        fn analyze(&self, _program: &Program) -> PassAnalysis {
            PassAnalysis::RUN
        }

        fn transform(&self, program: Program) -> PassResult {
            let changed = self.changed.swap(false, Ordering::SeqCst);
            PassResult { program, changed }
        }

        fn fingerprint(&self, _program: &Program) -> u64 {
            0
        }
    }

    #[test]
    fn dirty_tracking_skips_clean_passes() {
        let program = Program::wrapped(
            vec![BufferDecl::read_write("out", 0, DataType::U32)],
            [1, 1, 1],
            vec![Node::store("out", Expr::u32(0), Expr::u32(1))],
        );

        let analyze_calls = Arc::new(AtomicUsize::new(0));
        let stable = StablePass {
            analyze_calls: analyze_calls.clone(),
        };
        let changed = Arc::new(std::sync::atomic::AtomicBool::new(true));
        let change_once = ChangeOncePass { changed };

        PassScheduler::with_passes(vec![
            PassKind::External(Box::new(change_once)),
            PassKind::External(Box::new(stable)),
        ])
        .with_max_iterations(5)
        .run(program)
        .expect("Fix: should converge");

        assert_eq!(
            analyze_calls.load(Ordering::SeqCst),
            1,
            "stable pass should be analyzed exactly once when no invalidation happens"
        );
    }

    #[derive(Debug)]
    struct NoopPass;

    impl crate::optimizer::private::Sealed for NoopPass {}

    impl Pass for NoopPass {
        fn metadata(&self) -> PassMetadata {
            PassMetadata {
                name: "noop",
                requires: &[],
                invalidates: &[],
            }
        }

        fn analyze(&self, _program: &Program) -> PassAnalysis {
            PassAnalysis::SKIP
        }

        fn transform(&self, program: Program) -> PassResult {
            PassResult {
                program,
                changed: false,
            }
        }

        fn fingerprint(&self, _program: &Program) -> u64 {
            0
        }
    }

    fn noop_factory() -> Box<dyn Pass> {
        Box::new(NoopPass)
    }

    static PASS_A: PassRegistration = pass("a", &[]);
    static PASS_B: PassRegistration = pass("b", &["a"]);
    static PASS_C: PassRegistration = pass("c", &["b"]);
    static PASS_D: PassRegistration = pass("d", &["a"]);
    static PASS_E: PassRegistration = pass("e", &["b", "d"]);
    static PASS_F: PassRegistration = pass("f", &["c"]);
    static PASS_G: PassRegistration = pass("g", &["e"]);
    static PASS_H: PassRegistration = pass("h", &["f", "g"]);
    static PASS_I: PassRegistration = pass("i", &["h"]);
    static PASS_J: PassRegistration = pass("j", &["h"]);
    static PASS_MISSING: PassRegistration = pass("missing_consumer", &["not_registered"]);

    const fn pass(id: &'static str, requires: &'static [&'static str]) -> PassRegistration {
        PassRegistration {
            metadata: PassMetadata {
                name: id,
                requires,
                invalidates: &[],
            },
            factory: noop_factory,
        }
    }

    #[test]
    fn missing_requires_id_fails_cleanly() {
        let err = schedule_passes(&[&PASS_MISSING]).expect_err("Fix: missing require must fail");
        assert_eq!(
            err,
            PassSchedulingError::UnknownRequire {
                pass: "missing_consumer",
                missing: "not_registered"
            }
        );
        assert!(
            err.to_string().contains("Fix: register `not_registered`"),
            "scheduler errors must include actionable repair text"
        );
    }

    #[test]
    fn three_pass_cycle_is_detected() {
        static CYCLE_A: PassRegistration = pass("cycle_a", &["cycle_c"]);
        static CYCLE_B: PassRegistration = pass("cycle_b", &["cycle_a"]);
        static CYCLE_C: PassRegistration = pass("cycle_c", &["cycle_b"]);

        let err = schedule_passes(&[&CYCLE_A, &CYCLE_B, &CYCLE_C])
            .expect_err("Fix: cycle must be rejected");
        assert_eq!(
            err,
            PassSchedulingError::Cycle {
                pass_ids: vec!["cycle_a", "cycle_b", "cycle_c"],
                fix: "Break the cycle by removing one of these `requires` entries."
            }
        );
    }

    #[test]
    fn ten_pass_dag_produces_topological_order() {
        let ordered = schedule_passes(&[
            &PASS_J, &PASS_I, &PASS_H, &PASS_G, &PASS_F, &PASS_E, &PASS_D, &PASS_C, &PASS_B,
            &PASS_A,
        ])
        .expect("Fix: valid DAG must schedule");
        let ids = ordered
            .into_iter()
            .map(|registration| registration.metadata.name)
            .collect::<Vec<_>>();
        assert_eq!(ids, vec!["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"]);
    }

    // CRITIQUE_FIX_REVIEW_2026-04-23 Finding #12 regression.

    #[derive(Debug)]
    struct OscillatingPass;

    impl crate::optimizer::private::Sealed for OscillatingPass {}

    impl Pass for OscillatingPass {
        fn metadata(&self) -> PassMetadata {
            PassMetadata {
                name: "oscillate",
                requires: &[],
                invalidates: &[],
            }
        }

        fn pass_id(&self) -> &'static str {
            "custom::oscillating_pass_id"
        }

        fn analyze(&self, _program: &Program) -> PassAnalysis {
            PassAnalysis::RUN
        }

        fn transform(&self, program: Program) -> PassResult {
            PassResult {
                program,
                changed: true,
            }
        }

        fn fingerprint(&self, _program: &Program) -> u64 {
            0
        }
    }

    #[test]
    fn max_iterations_error_includes_custom_pass_id() {
        let program = Program::wrapped(
            vec![BufferDecl::read_write("x", 0, DataType::U32).with_count(1)],
            [1, 1, 1],
            vec![Node::store("x", Expr::u32(0), Expr::u32(1))],
        );

        // max_iterations = 1 because the dirty-tracking logic skips the pass
        // on the second iteration; we only need one iteration to force the
        // cap and verify the error text carries the custom pass_id.
        let err = PassScheduler::with_passes(vec![PassKind::External(Box::new(OscillatingPass))])
            .with_max_iterations(1)
            .run(program)
            .expect_err("Fix: oscillating pass must hit max iterations");

        match err {
            OptimizerError::MaxIterations {
                max_iterations,
                last_pass,
            } => {
                assert_eq!(max_iterations, 1);
                assert_eq!(
                    last_pass, "custom::oscillating_pass_id",
                    "scheduler must report the custom pass_id, not metadata().name"
                );
            }
            other => panic!("Fix: expected MaxIterations error, got {other:?}"),
        }
    }
}

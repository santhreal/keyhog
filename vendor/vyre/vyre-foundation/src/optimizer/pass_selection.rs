//! Benchmark and hot-path driven optimizer pass selection.
//!
//! This is an execution input, not a docs surface: callers can build a
//! `PassScheduler` from [`registered_passes_for_profile_and_program`] so
//! expensive optimization families run only when program shape or runtime
//! telemetry justifies them. Correctness-critical normalizers remain selected.

use super::{
    registered_pass_registrations, CostModelFamily, OptimizerError, OptimizerProfile, PassMetadata,
    ProgramPassKind,
};
use crate::ir_inner::model::program::Program;
use crate::optimizer::hot_path_hints::HotPathHints;
use rustc_hash::FxHashSet;

const MIN_LOOP_NODES: usize = 12;
const MIN_MEMORY_BYTES: u64 = 16 * 1024;
const MIN_FUSION_REGIONS: usize = 2;
const MIN_DATAFLOW_NODES: usize = 64;
const MIN_MEGAKERNEL_NODES: usize = 512;

/// Why one pass was selected or skipped for a concrete Program.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PassSelectionReason {
    /// Pass is cheap or correctness-preserving enough to always keep.
    AlwaysOn,
    /// Program shape crosses the pass family's benchmark threshold.
    ProgramShape,
    /// Runtime hot-path telemetry says this region is expensive enough.
    HotPathTelemetry,
    /// Pass was included because another selected pass requires it.
    RequiredDependency,
    /// Pass does not belong to the requested profile.
    ProfileRejected,
    /// Program and telemetry do not justify this pass family.
    BelowThreshold,
}

/// Selection result for one pass metadata row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PassSelectionDecision {
    /// Pass metadata.
    pub metadata: PassMetadata,
    /// Whether the pass should be instantiated for this Program.
    pub selected: bool,
    /// Stable reason for the decision.
    pub reason: PassSelectionReason,
}

/// Instantiate registered passes accepted by `profile` and selected for
/// `program`.
///
/// # Errors
/// Returns [`OptimizerError`] if the live pass registry is invalid.
pub fn registered_passes_for_profile_and_program(
    profile: OptimizerProfile,
    program: &Program,
    hints: &HotPathHints,
) -> Result<Vec<ProgramPassKind>, OptimizerError> {
    let registrations = registered_pass_registrations()?;
    let metadata = registrations
        .iter()
        .map(|registration| registration.metadata)
        .collect::<Vec<_>>();
    let selected = selected_name_set(&metadata, profile, program, hints);
    let mut passes = Vec::with_capacity(selected.len());
    for registration in registrations.iter() {
        if selected.contains(registration.metadata.name) {
            passes.push(ProgramPassKind::from_boxed((registration.factory)()));
        }
    }
    Ok(passes)
}

/// Return pass-selection decisions for a metadata slice.
#[must_use]
pub fn select_pass_metadata_for_program(
    metadata: &[PassMetadata],
    profile: OptimizerProfile,
    program: &Program,
    hints: &HotPathHints,
) -> Vec<PassSelectionDecision> {
    let selected = selected_name_set(metadata, profile, program, hints);
    metadata
        .iter()
        .copied()
        .map(|metadata| {
            let profile_accepted = profile.accepts(metadata);
            let initially = initial_selection_reason(metadata, profile, program, hints);
            let selected_by_closure = selected.contains(metadata.name);
            let reason = if !profile_accepted {
                PassSelectionReason::ProfileRejected
            } else if matches!(initially, PassSelectionReason::BelowThreshold)
                && selected_by_closure
            {
                PassSelectionReason::RequiredDependency
            } else {
                initially
            };
            PassSelectionDecision {
                metadata,
                selected: selected_by_closure,
                reason,
            }
        })
        .collect()
}

fn selected_name_set(
    metadata: &[PassMetadata],
    profile: OptimizerProfile,
    program: &Program,
    hints: &HotPathHints,
) -> FxHashSet<&'static str> {
    let mut selected = FxHashSet::default();
    for pass in metadata {
        if matches!(
            initial_selection_reason(*pass, profile, program, hints),
            PassSelectionReason::AlwaysOn
                | PassSelectionReason::ProgramShape
                | PassSelectionReason::HotPathTelemetry
        ) {
            selected.insert(pass.name);
        }
    }
    close_over_requirements(metadata, &mut selected);
    selected
}

fn close_over_requirements(metadata: &[PassMetadata], selected: &mut FxHashSet<&'static str>) {
    loop {
        let before = selected.len();
        for pass in metadata {
            if selected.contains(pass.name) {
                for &requirement in pass.requires {
                    if metadata
                        .iter()
                        .any(|candidate| candidate.name == requirement)
                    {
                        selected.insert(requirement);
                    }
                }
            }
        }
        if selected.len() == before {
            break;
        }
    }
}

fn initial_selection_reason(
    metadata: PassMetadata,
    profile: OptimizerProfile,
    program: &Program,
    hints: &HotPathHints,
) -> PassSelectionReason {
    if !profile.accepts(metadata) {
        return PassSelectionReason::ProfileRejected;
    }
    if entry_region_is_hot(program, hints) {
        return PassSelectionReason::HotPathTelemetry;
    }
    let stats = program.stats();
    let reason_for = |above_threshold: bool| {
        if above_threshold {
            PassSelectionReason::ProgramShape
        } else {
            PassSelectionReason::BelowThreshold
        }
    };
    match metadata.cost_model_family {
        CostModelFamily::Loop => reason_for(stats.node_count >= MIN_LOOP_NODES),
        CostModelFamily::Memory => {
            reason_for(program.estimate_peak_vram_bytes() >= MIN_MEMORY_BYTES)
        }
        CostModelFamily::Fusion => {
            reason_for(stats.top_level_regions as usize >= MIN_FUSION_REGIONS)
        }
        CostModelFamily::Dataflow => reason_for(stats.node_count >= MIN_DATAFLOW_NODES),
        CostModelFamily::Megakernel => reason_for(stats.node_count >= MIN_MEGAKERNEL_NODES),
        CostModelFamily::Scalar | CostModelFamily::Sync | CostModelFamily::Unknown => {
            PassSelectionReason::AlwaysOn
        }
    }
}

fn entry_region_is_hot(program: &Program, hints: &HotPathHints) -> bool {
    program
        .entry_op_id()
        .is_some_and(|op_id| hints.is_hot(op_id))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{BufferDecl, DataType, Expr, Node, Program};
    use crate::optimizer::{PassBoundaryClass, PassPhase};

    fn meta(
        name: &'static str,
        family: CostModelFamily,
        phase: PassPhase,
        requires: &'static [&'static str],
    ) -> PassMetadata {
        PassMetadata {
            name,
            requires,
            invalidates: &[],
            phase,
            boundary_class: PassBoundaryClass::AbiPreserving,
            requires_caps: &[],
            preserves_abi: true,
            cost_model_family: family,
        }
    }

    fn tiny_program() -> Program {
        Program::wrapped(
            vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
            [1, 1, 1],
            vec![Node::store("out", Expr::u32(0), Expr::u32(1))],
        )
    }

    #[test]
    fn small_cold_program_skips_expensive_memory_pass() {
        let decisions = select_pass_metadata_for_program(
            &[meta(
                "decode_scan_fuse",
                CostModelFamily::Memory,
                PassPhase::Memory,
                &[],
            )],
            OptimizerProfile::Release,
            &tiny_program(),
            &HotPathHints::default(),
        );
        assert_eq!(decisions[0].selected, false);
        assert_eq!(decisions[0].reason, PassSelectionReason::BelowThreshold);
    }

    #[test]
    fn hot_region_selects_expensive_pass() {
        let hints = HotPathHints::with_capacity(4);
        hints.record("hot_entry", 1_000_000, 4);
        let program = Program::wrapped(
            vec![BufferDecl::output("out", 0, DataType::U32).with_count(1)],
            [1, 1, 1],
            vec![Node::store("out", Expr::u32(0), Expr::u32(1))],
        )
        .with_entry_op_id("hot_entry");
        let decisions = select_pass_metadata_for_program(
            &[meta(
                "decode_scan_fuse",
                CostModelFamily::Memory,
                PassPhase::Memory,
                &[],
            )],
            OptimizerProfile::Release,
            &program,
            &hints,
        );
        assert!(decisions[0].selected);
        assert_eq!(decisions[0].reason, PassSelectionReason::HotPathTelemetry);
    }

    #[test]
    fn selected_pass_closes_over_required_dependencies() {
        let metadata = [
            meta(
                "shape_facts",
                CostModelFamily::Memory,
                PassPhase::Memory,
                &[],
            ),
            meta(
                "memory_optimizer",
                CostModelFamily::Scalar,
                PassPhase::ScalarAlgebra,
                &["shape_facts"],
            ),
        ];
        let decisions = select_pass_metadata_for_program(
            &metadata,
            OptimizerProfile::Release,
            &tiny_program(),
            &HotPathHints::default(),
        );
        assert!(decisions.iter().all(|decision| decision.selected));
        assert_eq!(decisions[0].reason, PassSelectionReason::RequiredDependency);
    }

    #[test]
    fn selected_registered_passes_run_through_scheduler() {
        let program = tiny_program();
        let passes = registered_passes_for_profile_and_program(
            OptimizerProfile::Release,
            &program,
            &HotPathHints::default(),
        )
        .expect("Fix: live registry selection must succeed");
        let optimized = crate::optimizer::PassScheduler::with_passes(passes)
            .run(program)
            .expect("Fix: selected release pass scheduler must converge");
        assert!(optimized.stats().node_count > 0);
    }
}

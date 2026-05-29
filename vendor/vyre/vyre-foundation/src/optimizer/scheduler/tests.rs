//! Tests for `scheduler.rs`. Split out per audit item #85 to keep the
//! parent file focused on production code.

use super::*;
use crate::ir::{BufferDecl, DataType, Expr, Node, Program, ShapePredicate};
use crate::ir_inner::model::program::LinearType;
use crate::lower::effects::ProgramEffects;
use crate::optimizer::passes::const_fold::ConstFold;
use crate::optimizer::passes::fusion::Fusion;
use crate::optimizer::passes::normalize_atomics::NormalizeAtomicsPass;
use crate::optimizer::passes::strength_reduce::StrengthReduce;
use crate::optimizer::{
    PassAnalysis, PassMetadata, PassResult, ProgramPass, RefusalReason, RewriteBatch,
    RewriteBatchCandidates, RewriteCandidate,
};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

fn trivial_program() -> Program {
    Program::wrapped(
        vec![BufferDecl::read_write("out", 0, DataType::U32).with_count(1)],
        [1, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(42))],
    )
}

fn linear_program() -> Program {
    Program::wrapped(
        vec![BufferDecl::read_write("out", 0, DataType::U32)
            .with_count(1)
            .with_linear_type(LinearType::Linear)],
        [1, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(42))],
    )
}

fn shape_predicate_program() -> Program {
    Program::wrapped(
        vec![BufferDecl::read_write("out", 0, DataType::U32)
            .with_count(64)
            .with_shape_predicate(ShapePredicate::MultipleOf(64))],
        [1, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(42))],
    )
}

fn invalid_shape_predicate_program() -> Program {
    Program::wrapped(
        vec![BufferDecl::read_write("out", 0, DataType::U32)
            .with_count(63)
            .with_shape_predicate(ShapePredicate::MultipleOf(64))],
        [1, 1, 1],
        vec![Node::store("out", Expr::u32(0), Expr::u32(42))],
    )
}

#[derive(Debug)]
struct TestPass {
    metadata: PassMetadata,
    changes: bool,
}

impl crate::optimizer::private::Sealed for TestPass {}

impl ProgramPass for TestPass {
    fn metadata(&self) -> PassMetadata {
        self.metadata
    }

    fn analyze(&self, _program: &Program) -> PassAnalysis {
        PassAnalysis::RUN
    }

    fn transform(&self, program: Program) -> PassResult {
        if self.changes {
            let mut entry = Clone::clone(&program).into_entry_vec();
            entry.push(Node::barrier());
            PassResult {
                program: program.with_rewritten_entry(entry),
                changed: true,
            }
        } else {
            PassResult::unchanged(program)
        }
    }

    fn fingerprint(&self, _program: &Program) -> u64 {
        0
    }
}

#[derive(Debug)]
struct BarrierAddingPass {
    metadata: PassMetadata,
    allowed: ProgramEffects,
}

impl crate::optimizer::private::Sealed for BarrierAddingPass {}

impl ProgramPass for BarrierAddingPass {
    fn metadata(&self) -> PassMetadata {
        self.metadata
    }

    fn analyze(&self, _program: &Program) -> PassAnalysis {
        PassAnalysis::RUN
    }

    fn transform(&self, program: Program) -> PassResult {
        let mut entry = Clone::clone(&program).into_entry_vec();
        entry.push(Node::barrier());
        PassResult {
            program: program.with_rewritten_entry(entry),
            changed: true,
        }
    }

    fn allowed_effect_additions(&self) -> ProgramEffects {
        self.allowed
    }

    fn fingerprint(&self, _program: &Program) -> u64 {
        0
    }
}

#[derive(Debug)]
struct LinearBreakingPass {
    metadata: PassMetadata,
}

impl crate::optimizer::private::Sealed for LinearBreakingPass {}

impl ProgramPass for LinearBreakingPass {
    fn metadata(&self) -> PassMetadata {
        self.metadata
    }

    fn analyze(&self, _program: &Program) -> PassAnalysis {
        PassAnalysis::RUN
    }

    fn transform(&self, program: Program) -> PassResult {
        let mut entry = Clone::clone(&program).into_entry_vec();
        entry.push(Node::store("out", Expr::u32(0), Expr::u32(7)));
        PassResult {
            program: program.with_rewritten_entry(entry),
            changed: true,
        }
    }

    fn fingerprint(&self, _program: &Program) -> u64 {
        0
    }
}

#[derive(Debug)]
struct ShapeBreakingPass {
    metadata: PassMetadata,
}

impl crate::optimizer::private::Sealed for ShapeBreakingPass {}

impl ProgramPass for ShapeBreakingPass {
    fn metadata(&self) -> PassMetadata {
        self.metadata
    }

    fn analyze(&self, _program: &Program) -> PassAnalysis {
        PassAnalysis::RUN
    }

    fn transform(&self, program: Program) -> PassResult {
        let mut buffers = program.buffers().to_vec();
        if let Some(buffer) = buffers.first_mut() {
            *buffer = buffer.clone().with_count(63);
        }
        PassResult {
            program: program.with_rewritten_buffers(buffers),
            changed: true,
        }
    }

    fn fingerprint(&self, _program: &Program) -> u64 {
        0
    }
}

#[derive(Debug)]
struct ShapeRepairingPass {
    metadata: PassMetadata,
}

impl crate::optimizer::private::Sealed for ShapeRepairingPass {}

impl ProgramPass for ShapeRepairingPass {
    fn metadata(&self) -> PassMetadata {
        self.metadata
    }

    fn analyze(&self, _program: &Program) -> PassAnalysis {
        PassAnalysis::RUN
    }

    fn transform(&self, program: Program) -> PassResult {
        let mut buffers = program.buffers().to_vec();
        if let Some(buffer) = buffers.first_mut() {
            *buffer = buffer.clone().with_count(64);
        }
        PassResult {
            program: program.with_rewritten_buffers(buffers),
            changed: true,
        }
    }

    fn fingerprint(&self, _program: &Program) -> u64 {
        0
    }
}

#[derive(Debug)]
struct ExprOnlyPass {
    metadata: PassMetadata,
}

impl crate::optimizer::private::Sealed for ExprOnlyPass {}

impl ProgramPass for ExprOnlyPass {
    fn metadata(&self) -> PassMetadata {
        self.metadata
    }

    fn analyze(&self, _program: &Program) -> PassAnalysis {
        PassAnalysis::RUN
    }

    fn transform(&self, program: Program) -> PassResult {
        let mut entry = Clone::clone(&program).into_entry_vec();
        if rewrite_first_store_value(&mut entry) {
            return PassResult {
                program: program.with_rewritten_entry(entry),
                changed: true,
            };
        }
        PassResult::unchanged(program)
    }

    fn fingerprint(&self, _program: &Program) -> u64 {
        0
    }
}

#[derive(Debug)]
struct SkipPass;

impl crate::optimizer::private::Sealed for SkipPass {}

impl ProgramPass for SkipPass {
    fn metadata(&self) -> PassMetadata {
        PassMetadata::new("skip_pass", &[], &[])
    }

    fn analyze(&self, _program: &Program) -> PassAnalysis {
        PassAnalysis::SKIP
    }

    fn transform(&self, program: Program) -> PassResult {
        PassResult::unchanged(program)
    }

    fn fingerprint(&self, _program: &Program) -> u64 {
        0
    }
}

#[derive(Debug)]
struct RefusingPass {
    metadata: PassMetadata,
}

impl crate::optimizer::private::Sealed for RefusingPass {}

impl ProgramPass for RefusingPass {
    fn metadata(&self) -> PassMetadata {
        self.metadata
    }

    fn analyze(&self, _program: &Program) -> PassAnalysis {
        PassAnalysis::RUN
    }

    fn transform(&self, _program: Program) -> PassResult {
        panic!("cost-monotone scheduler must call try_transform before transform")
    }

    fn try_transform(&self, _program: Program) -> Result<PassResult, RefusalReason> {
        Err(RefusalReason::CostIncrease {
            delta: 1,
            detail: "test pass refuses cost-up rewrite",
        })
    }

    fn fingerprint(&self, _program: &Program) -> u64 {
        0
    }
}

#[derive(Debug)]
struct BatchingPass {
    batch_calls: Arc<AtomicUsize>,
    transform_calls: Arc<AtomicUsize>,
    threshold: usize,
}

impl crate::optimizer::private::Sealed for BatchingPass {}

impl ProgramPass for BatchingPass {
    fn metadata(&self) -> PassMetadata {
        PassMetadata::new("batching_pass", &[], &[])
    }

    fn analyze(&self, _program: &Program) -> PassAnalysis {
        PassAnalysis::RUN
    }

    fn transform(&self, program: Program) -> PassResult {
        self.transform_calls.fetch_add(1, Ordering::Relaxed);
        rewrite_matching_stores(program, None)
    }

    fn supports_planar_batching(&self) -> bool {
        true
    }

    fn rewrite_candidates(&self, program: &Program) -> RewriteBatchCandidates {
        let mut candidates = Vec::new();
        collect_store_candidates(program.entry(), &mut candidates);
        let width = candidates.len() as u32;
        RewriteBatchCandidates::new(candidates, 1, width, 2).with_threshold(self.threshold)
    }

    fn apply_rewrite_batch(&self, program: Program, batch: &RewriteBatch) -> PassResult {
        self.batch_calls.fetch_add(1, Ordering::Relaxed);
        rewrite_matching_stores(program, Some(batch))
    }

    fn fingerprint(&self, _program: &Program) -> u64 {
        0
    }
}

fn rewrite_first_store_value(nodes: &mut [Node]) -> bool {
    for node in nodes {
        match node {
            Node::Store { value, .. } => {
                *value = Expr::u32(43);
                return true;
            }
            Node::If {
                then, otherwise, ..
            } => {
                if rewrite_first_store_value(then) || rewrite_first_store_value(otherwise) {
                    return true;
                }
            }
            Node::Loop { body, .. } | Node::Block(body) => {
                if rewrite_first_store_value(body) {
                    return true;
                }
            }
            Node::Region { body, .. } => {
                let body_vec: &mut Vec<Node> = Arc::make_mut(body);
                if rewrite_first_store_value(body_vec.as_mut_slice()) {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn rewrite_matching_stores(program: Program, batch: Option<&RewriteBatch>) -> PassResult {
    let mut entry = Clone::clone(&program).into_entry_vec();
    let mut changed = false;
    match batch {
        Some(batch) => {
            let selected = batch
                .items()
                .iter()
                .map(|item| item.col as usize)
                .collect::<Vec<_>>();
            let mut ordinal = 0usize;
            changed |= rewrite_selected_store_ordinals(&mut entry, &selected, &mut ordinal);
        }
        None => {
            changed |= rewrite_all_matching_stores(&mut entry);
        }
    }
    if changed {
        PassResult {
            program: program.with_rewritten_entry(entry),
            changed: true,
        }
    } else {
        PassResult::unchanged(program)
    }
}

fn rewrite_store_value_if_matches(node: &mut Node, old: u32, new: u32) -> bool {
    match node {
        Node::Store { value, .. } if *value == Expr::u32(old) => {
            *value = Expr::u32(new);
            true
        }
        _ => false,
    }
}

fn store_value_is(node: &Node, expected: u32) -> bool {
    matches!(node, Node::Store { value, .. } if *value == Expr::u32(expected))
}

fn all_stores_have_value(nodes: &[Node], expected: u32) -> bool {
    nodes.iter().all(|node| match node {
        Node::Store { .. } => store_value_is(node, expected),
        Node::If {
            then, otherwise, ..
        } => all_stores_have_value(then, expected) && all_stores_have_value(otherwise, expected),
        Node::Loop { body, .. } | Node::Block(body) => all_stores_have_value(body, expected),
        Node::Region { body, .. } => all_stores_have_value(body, expected),
        _ => true,
    })
}

fn collect_store_candidates(nodes: &[Node], candidates: &mut Vec<RewriteCandidate>) {
    for node in nodes {
        match node {
            Node::Store { value, .. } if *value == Expr::u32(42) => {
                candidates.push(RewriteCandidate::new(0, candidates.len() as u32));
            }
            Node::If {
                then, otherwise, ..
            } => {
                collect_store_candidates(then, candidates);
                collect_store_candidates(otherwise, candidates);
            }
            Node::Loop { body, .. } | Node::Block(body) => {
                collect_store_candidates(body, candidates);
            }
            Node::Region { body, .. } => {
                collect_store_candidates(body, candidates);
            }
            _ => {}
        }
    }
}

fn rewrite_all_matching_stores(nodes: &mut [Node]) -> bool {
    let mut changed = false;
    for node in nodes {
        changed |= match node {
            Node::Store { .. } => rewrite_store_value_if_matches(node, 42, 43),
            Node::If {
                then, otherwise, ..
            } => rewrite_all_matching_stores(then) | rewrite_all_matching_stores(otherwise),
            Node::Loop { body, .. } | Node::Block(body) => rewrite_all_matching_stores(body),
            Node::Region { body, .. } => {
                let body_vec: &mut Vec<Node> = Arc::make_mut(body);
                rewrite_all_matching_stores(body_vec.as_mut_slice())
            }
            _ => false,
        };
    }
    changed
}

fn rewrite_selected_store_ordinals(
    nodes: &mut [Node],
    selected: &[usize],
    ordinal: &mut usize,
) -> bool {
    let mut changed = false;
    for node in nodes {
        changed |= match node {
            Node::Store { value, .. } => {
                let current = *ordinal;
                *ordinal += 1;
                if *value == Expr::u32(42) && selected.contains(&current) {
                    rewrite_store_value_if_matches(node, 42, 43)
                } else {
                    false
                }
            }
            Node::If {
                then, otherwise, ..
            } => {
                rewrite_selected_store_ordinals(then, selected, ordinal)
                    | rewrite_selected_store_ordinals(otherwise, selected, ordinal)
            }
            Node::Loop { body, .. } | Node::Block(body) => {
                rewrite_selected_store_ordinals(body, selected, ordinal)
            }
            Node::Region { body, .. } => {
                let body_vec: &mut Vec<Node> = Arc::make_mut(body);
                rewrite_selected_store_ordinals(body_vec.as_mut_slice(), selected, ordinal)
            }
            _ => false,
        };
    }
    changed
}

fn repeated_store_program(count: usize) -> Program {
    Program::wrapped(
        vec![BufferDecl::read_write("out", 0, DataType::U32).with_count(count as u32)],
        [1, 1, 1],
        (0..count)
            .map(|index| Node::store("out", Expr::u32(index as u32), Expr::u32(42)))
            .collect::<Vec<_>>(),
    )
}

struct SchedulerGateContract {
    build_breaking_pass: fn(PassMetadata) -> ProgramPassKind,
    build_preserving_pass: fn(PassMetadata) -> ProgramPassKind,
    program: fn() -> Program,
    enable: fn(PassScheduler) -> PassScheduler,
    is_enabled: fn(&PassScheduler) -> bool,
    check_violations: fn(&Program) -> usize,
    reverted_decision: PassRunDecision,
    violation_counts: fn(&PassRunMetric) -> (usize, usize),
}

fn assert_gate_disabled_by_default_keeps_breaking_rewrite(
    gate: &SchedulerGateContract,
    pass_id: &'static str,
    default_message: &str,
    run_message: &str,
    violation_message: &str,
) {
    let scheduler = PassScheduler::with_passes(vec![(gate.build_breaking_pass)(
        PassMetadata::new(pass_id, &[], &[]),
    )]);
    assert!(!(gate.is_enabled)(&scheduler), "{default_message}");

    let post = scheduler.run((gate.program)()).expect(run_message);
    assert!((gate.check_violations)(&post) > 0, "{violation_message}");
}

fn assert_gate_reverts_new_violations(
    gate: &SchedulerGateContract,
    pass_id: &'static str,
    run_message: &str,
    revert_message: &str,
) {
    let scheduler = (gate.enable)(PassScheduler::with_passes(vec![
        (gate.build_breaking_pass)(PassMetadata::new(pass_id, &[], &[])),
    ]));

    let post = scheduler.run((gate.program)()).expect(run_message);
    assert_eq!((gate.check_violations)(&post), 0, "{revert_message}");
}

fn assert_gate_revert_metrics_reflect_post_revert_state(
    gate: &SchedulerGateContract,
    pass_id: &'static str,
    run_message: &str,
    ran_message: &str,
    changed_message: &str,
) {
    let scheduler = (gate.enable)(PassScheduler::with_passes(vec![
        (gate.build_breaking_pass)(PassMetadata::new(pass_id, &[], &[])),
    ]));

    let report = scheduler
        .run_with_metrics((gate.program)())
        .expect(run_message);
    assert_eq!(report.passes.len(), 1);
    let metric = &report.passes[0];

    assert!(metric.ran, "{ran_message}");
    assert!(!metric.changed, "{changed_message}");
    assert_eq!(metric.decision, gate.reverted_decision);
    let (violations_before, violations_after) = (gate.violation_counts)(metric);
    assert_eq!(violations_before, 0);
    assert_eq!(violations_after, 0);
    assert_eq!(metric.refusal_kind, None);
}

fn assert_gate_allows_preserving_rewrites(
    gate: &SchedulerGateContract,
    pass_id: &'static str,
    run_message: &str,
    changed_message: &str,
) {
    let scheduler = (gate.enable)(PassScheduler::with_passes(vec![(gate
        .build_preserving_pass)(
        PassMetadata::new(pass_id, &[], &[]),
    )]));

    let report = scheduler
        .run_with_metrics((gate.program)())
        .expect(run_message);
    let metric = first_ran_metric(&report);

    assert!(metric.changed, "{changed_message}");
    assert_eq!(metric.decision, PassRunDecision::Changed);
    let (violations_before, violations_after) = (gate.violation_counts)(metric);
    assert_eq!(violations_before, 0);
    assert_eq!(violations_after, 0);
}

fn first_ran_metric(report: &OptimizerRunReport) -> &PassRunMetric {
    report
        .passes
        .iter()
        .find(|metric| metric.ran)
        .expect("Fix: preserving rewrite should produce one ran metric row")
}

mod basic_execution;
mod batching;
mod cost_monotone;
mod effect_handlers;
mod invalidation_metrics;
mod linear_types;
mod lookup_identity;
mod shape_predicates;

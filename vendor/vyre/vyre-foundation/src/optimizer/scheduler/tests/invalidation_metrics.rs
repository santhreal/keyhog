//! Integration test crate for the containing Vyre package.

use super::*;

#[test]
fn invalidation_marks_named_pass_and_requirement_dependents_dirty() {
    let scheduler = PassScheduler::with_passes(vec![
        ProgramPassKind::new(ConstFold),
        ProgramPassKind::new(StrengthReduce),
        ProgramPassKind::new(NormalizeAtomicsPass),
        ProgramPassKind::new(Fusion),
    ]);

    let mut dirty = FxHashSet::default();
    scheduler.mark_invalidated_passes(&["fusion"], &mut dirty);
    assert!(
        dirty.contains("fusion"),
        "pass-name invalidation must rerun that pass"
    );

    dirty.clear();
    scheduler.mark_invalidated_passes(&["const_fold"], &mut dirty);
    assert!(dirty.contains("const_fold"));
    assert!(
        dirty.contains("strength_reduce"),
        "passes requiring an invalidated pass/capability must rerun"
    );
}

#[test]
fn invalidating_prior_requirement_does_not_break_current_iteration() {
    let scheduler = PassScheduler::with_passes(vec![
        ProgramPassKind::new(TestPass {
            metadata: PassMetadata::new("prepare", &[], &[]),
            changes: false,
        }),
        ProgramPassKind::new(TestPass {
            metadata: PassMetadata::new("rewrite", &[], &["prepare"]),
            changes: true,
        }),
        ProgramPassKind::new(TestPass {
            metadata: PassMetadata::new("consume", &["prepare"], &[]),
            changes: false,
        }),
    ]);
    let report = scheduler
        .run_with_metrics(trivial_program())
        .expect("Fix: invalidating a prior requirement must queue a rerun, not make later passes unschedulable");

    assert!(
        report.passes.len() >= 6,
        "first iteration must queue prepare and consume for a second dirty-flag iteration"
    );
    assert!(
        report
            .passes
            .iter()
            .any(|metric| metric.iteration == 0 && metric.pass == "rewrite" && metric.changed),
        "the rewrite pass must land a change during the first metrics iteration"
    );
    assert_eq!(report.passes[3].pass, "prepare");
    assert!(
        report.passes[3].ran,
        "invalidating `prepare` must rerun the named pass on the next metrics iteration"
    );
    assert!(
        report
            .passes
            .iter()
            .any(|metric| metric.iteration == 1 && metric.pass == "consume" && metric.ran),
        "invalidating `prepare` must rerun dependents that require it"
    );
}

#[test]
fn run_with_metrics_tracks_expression_only_rewrites() {
    let scheduler = PassScheduler::with_passes(vec![ProgramPassKind::new(ExprOnlyPass {
        metadata: PassMetadata::new("expr_only", &[], &["value_numbering"]),
    })]);

    let report = scheduler
        .run_with_metrics(trivial_program())
        .expect("Fix: metrics run must converge for expression-only rewrites");
    assert_eq!(report.passes.len(), 2);
    let first = &report.passes[0];
    assert_eq!(first.pass, "expr_only");
    assert!(
        first.changed,
        "expression-only rewrites keep node_count stable but still changed the program and must invalidate downstream facts"
    );
    assert_eq!(
        first.nodes_before, first.nodes_after,
        "the regression target is a same-node-count expression rewrite"
    );
    assert!(
        !report.passes[1].changed,
        "the second iteration must observe convergence after the expression rewrite landed"
    );
}

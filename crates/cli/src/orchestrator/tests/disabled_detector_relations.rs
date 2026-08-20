//! Regression coverage for detector disabling across typed relation graphs.

use keyhog_core::{DetectorRelationKind, DetectorRelationSpec, DetectorSpec, EvidenceDirection};
use std::collections::HashSet;

use super::super::filter_disabled_detectors;

fn relation(detector_id: &str, kind: DetectorRelationKind) -> DetectorRelationSpec {
    DetectorRelationSpec {
        detector_id: detector_id.into(),
        kind,
        within_lines: 1,
        within_bytes: None,
        direction: EvidenceDirection::Either,
    }
}

fn detector(id: &str, detector_relations: Vec<DetectorRelationSpec>) -> DetectorSpec {
    DetectorSpec {
        id: id.into(),
        detector_relations,
        ..DetectorSpec::default()
    }
}

fn disabled(ids: &[&str]) -> HashSet<String> {
    ids.iter().map(|id| (*id).to_owned()).collect()
}

/// Disabling a required target must also remove the dependent detector, or
/// scanner compilation receives a dangling relation and refuses every scan.
#[test]
fn disabling_required_target_removes_its_dependent() {
    let mut detectors = vec![
        detector("target", vec![]),
        detector(
            "dependent",
            vec![relation("target", DetectorRelationKind::Requires)],
        ),
        detector("unrelated", vec![]),
    ];

    let dropped = filter_disabled_detectors(&mut detectors, &disabled(&["target"]));

    assert_eq!(dropped.len(), 2);
    assert_eq!(
        detectors
            .iter()
            .map(|detector| detector.id.as_str())
            .collect::<Vec<_>>(),
        vec!["unrelated"]
    );
}

/// Required relations form a dependency graph, so disabling a leaf must remove
/// every transitive dependent instead of leaving a second-order dangling edge.
#[test]
fn disabling_required_target_cascades_transitively() {
    let mut detectors = vec![
        detector("leaf", vec![]),
        detector(
            "middle",
            vec![relation("leaf", DetectorRelationKind::Requires)],
        ),
        detector(
            "root",
            vec![relation("middle", DetectorRelationKind::Requires)],
        ),
    ];

    let dropped = filter_disabled_detectors(&mut detectors, &disabled(&["leaf"]));

    assert_eq!(dropped.len(), 3);
    assert!(detectors.is_empty());
}

/// Conflict and subsumption owners remain useful without a disabled target;
/// their now-impossible relations must be removed before corpus validation.
#[test]
fn surviving_relations_to_disabled_targets_are_pruned() {
    let mut detectors = vec![
        detector("target", vec![]),
        detector(
            "conflict-owner",
            vec![relation("target", DetectorRelationKind::Conflicts)],
        ),
        detector(
            "subsuming-owner",
            vec![relation("target", DetectorRelationKind::Subsumes)],
        ),
    ];

    let dropped = filter_disabled_detectors(&mut detectors, &disabled(&["target"]));

    assert_eq!(dropped.len(), 1);
    assert_eq!(detectors.len(), 2);
    assert!(detectors
        .iter()
        .all(|detector| detector.detector_relations.is_empty()));
}

/// An unknown relation target is a malformed corpus, not an operator-disabled
/// detector. It must survive filtering so normal validation still fails closed.
#[test]
fn unknown_relation_targets_are_not_silently_pruned() {
    let mut detectors = vec![
        detector("disabled", vec![]),
        detector(
            "malformed-owner",
            vec![relation("missing", DetectorRelationKind::Requires)],
        ),
    ];

    let dropped = filter_disabled_detectors(&mut detectors, &disabled(&["disabled"]));

    assert_eq!(dropped.len(), 1);
    assert_eq!(detectors.len(), 1);
    assert_eq!(detectors[0].detector_relations[0].detector_id, "missing");
}

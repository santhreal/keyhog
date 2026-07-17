//! Empty literal in AC set disables GPU literal preparation.

use keyhog_scanner::testing::build_gpu_literals;

#[test]
fn compiler_gpu_literals_empty_disables_gpu() {
    let literals = vec!["ghp_".into(), String::new()];
    assert!(
        build_gpu_literals(&literals, &[], &[], &[], &[]).is_none(),
        "empty literal must disable GPU literal set"
    );
}

#[test]
fn compiler_gpu_literals_append_only_presence_segments_after_detector_literals() {
    let literals = vec!["GhP_".into()];
    let phase2_keywords = vec!["PhaseTwoKey".into()];
    let phase2_always_anchors = vec!["AlwaysAnchor".into()];
    let confirmed_anchors = vec!["ConfirmedAnchor".into()];
    let generic_keywords = vec!["GenericStem".into()];
    let built = build_gpu_literals(
        &literals,
        &phase2_keywords,
        &phase2_always_anchors,
        &confirmed_anchors,
        &generic_keywords,
    )
    .expect("gpu literals");

    assert_eq!(
        built.as_ref(),
        &vec![
            b"ghp_".to_vec(),
            b"phasetwokey".to_vec(),
            b"alwaysanchor".to_vec(),
            b"confirmedanchor".to_vec(),
            b"genericstem".to_vec(),
        ],
        "the fused GPU rows must preserve the canonical trigger, anchor, and generic-position segment order"
    );
}

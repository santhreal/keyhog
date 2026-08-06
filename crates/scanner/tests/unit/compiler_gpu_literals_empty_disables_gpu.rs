//! Empty literal in AC set disables GPU literal preparation.

use keyhog_scanner::testing::build_gpu_literals;

#[test]
fn compiler_gpu_literals_empty_disables_gpu() {
    let literals = vec!["ghp_".into(), String::new()];
    assert!(
        build_gpu_literals(
            literals.iter().map(String::as_bytes),
            std::iter::empty(),
            std::iter::empty(),
            std::iter::empty(),
            std::iter::empty(),
        )
        .is_none(),
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
        literals.iter().map(String::as_bytes),
        phase2_keywords.iter().map(String::as_bytes),
        phase2_always_anchors.iter().map(String::as_bytes),
        confirmed_anchors.iter().map(String::as_bytes),
        generic_keywords.iter().map(String::as_bytes),
    )
    .expect("gpu literals");

    assert_eq!(
        built.as_ref(),
        &vec![
            b"GhP_".to_vec(),
            b"PhaseTwoKey".to_vec(),
            b"AlwaysAnchor".to_vec(),
            b"ConfirmedAnchor".to_vec(),
            b"GenericStem".to_vec(),
        ],
        "the fused GPU rows must preserve canonical bytes and segment order"
    );
}

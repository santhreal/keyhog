use keyhog_core::{
    compose_detector_corpus, compute_detector_corpus_digest, DetectorCorpusError,
    DetectorCorpusMode, DetectorSpec,
};

fn detector(id: &str) -> DetectorSpec {
    DetectorSpec {
        id: id.to_string(),
        name: id.to_string(),
        service: "fixture".to_string(),
        ..DetectorSpec::default()
    }
}

/// Regression: replace mode must not retain any shipped detector implicitly.
#[test]
fn replace_uses_only_the_custom_corpus() {
    let effective = compose_detector_corpus(
        vec![detector("embedded-a"), detector("embedded-b")],
        vec![detector("custom-a")],
        DetectorCorpusMode::Replace,
    )
    .expect("replace corpus");

    assert_eq!(
        effective
            .iter()
            .map(|detector| detector.id.as_str())
            .collect::<Vec<_>>(),
        ["custom-a"]
    );
}

/// Regression: overlay mode must retain shipped detectors and append custom detectors.
#[test]
fn overlay_composes_disjoint_corpora() {
    let effective = compose_detector_corpus(
        vec![detector("embedded-a"), detector("embedded-b")],
        vec![detector("custom-a"), detector("custom-b")],
        DetectorCorpusMode::Overlay,
    )
    .expect("overlay corpus");

    assert_eq!(
        effective
            .iter()
            .map(|detector| detector.id.as_str())
            .collect::<Vec<_>>(),
        ["embedded-a", "embedded-b", "custom-a", "custom-b"]
    );
}

/// Regression: overlay mode must reject every custom ID that could shadow a shipped detector.
#[test]
fn overlay_rejects_sorted_detector_id_collisions() {
    let error = compose_detector_corpus(
        vec![detector("embedded-z"), detector("embedded-a")],
        vec![detector("embedded-z"), detector("custom"), detector("embedded-a")],
        DetectorCorpusMode::Overlay,
    )
    .expect_err("colliding overlay must fail closed");

    assert_eq!(
        error,
        DetectorCorpusError::IdCollision {
            ids: "embedded-a, embedded-z".to_string(),
        }
    );
}

/// Regression: effective corpus identity must not depend on source file or input vector order.
#[test]
fn effective_corpus_digest_is_deterministic() {
    let first = compose_detector_corpus(
        vec![detector("embedded-a"), detector("embedded-b")],
        vec![detector("custom-a"), detector("custom-b")],
        DetectorCorpusMode::Overlay,
    )
    .expect("first overlay");
    let second = compose_detector_corpus(
        vec![detector("embedded-b"), detector("embedded-a")],
        vec![detector("custom-b"), detector("custom-a")],
        DetectorCorpusMode::Overlay,
    )
    .expect("second overlay");

    assert_eq!(
        compute_detector_corpus_digest(&first).expect("first digest"),
        compute_detector_corpus_digest(&second).expect("second digest")
    );
}

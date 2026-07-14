//! PERF-locality_intern-1 regression gate.
//!
//! Detector id/name/service metadata must be interned once at scanner
//! construction and cloned by detector index on match emission. Dynamic fields
//! such as source path and commit still flow through `ScanState::intern_metadata`;
//! detector metadata must not.

use std::sync::Arc;

use keyhog_core::{Chunk, ChunkMetadata, DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::CompiledScanner;

fn detector(id: &str, name: &str, service: &str, regex: &str, keyword: &str) -> DetectorSpec {
    DetectorSpec {
        id: id.to_string(),
        name: name.to_string(),
        service: service.to_string(),
        severity: Severity::High,
        patterns: vec![PatternSpec {
            regex: regex.to_string(),
            ..Default::default()
        }],
        keywords: vec![keyword.to_string()],
        min_confidence: Some(0.1),
        ..Default::default()
    }
}

#[test]
fn metadata_intern_is_indexed_not_rehashed_per_match() {
    let scanner = CompiledScanner::compile(vec![
        detector(
            "alpha-token",
            "Alpha Token",
            "alpha",
            r"alpha_[A-Za-z0-9]{16}",
            "alpha_token",
        ),
        detector(
            "bravo-secret",
            "Bravo Secret",
            "bravo",
            r"bravo_[A-Za-z0-9]{16}",
            "bravo_secret",
        ),
    ])
    .expect("compile inline scanner");

    let first = scanner.interned_detector_metadata(0);
    let first_again = scanner.interned_detector_metadata(0);
    assert_eq!(first.0.as_ref(), "alpha-token");
    assert_eq!(first.1.as_ref(), "Alpha Token");
    assert_eq!(first.2.as_ref(), "alpha");
    assert!(
        Arc::ptr_eq(&first.0, &first_again.0)
            && Arc::ptr_eq(&first.1, &first_again.1)
            && Arc::ptr_eq(&first.2, &first_again.2),
        "detector metadata must come from one construction-time Arc per detector index"
    );

    let second = scanner.interned_detector_metadata(1);
    assert_eq!(second.0.as_ref(), "bravo-secret");
    assert_eq!(second.1.as_ref(), "Bravo Secret");
    assert_eq!(second.2.as_ref(), "bravo");

    let matches = scanner.scan(&Chunk {
        data: "alpha_Q7vL9nP2xR5kT8mW bravo_H4cN6yB9sD2qK7zP"
            .to_string()
            .into(),
        metadata: ChunkMetadata {
            source_type: "metadata-intern-test".into(),
            path: Some("fixture.env".into()),
            ..Default::default()
        },
    });
    let alpha = matches
        .iter()
        .find(|matched| matched.detector_id.as_ref() == "alpha-token")
        .expect("alpha detector emits through the production scan path");
    let bravo = matches
        .iter()
        .find(|matched| matched.detector_id.as_ref() == "bravo-secret")
        .expect("bravo detector emits through the production scan path");
    assert!(
        Arc::ptr_eq(&alpha.detector_id, &first.0)
            && Arc::ptr_eq(&alpha.detector_name, &first.1)
            && Arc::ptr_eq(&alpha.service, &first.2),
        "alpha emission must reuse its construction-time metadata allocations"
    );
    assert!(
        Arc::ptr_eq(&bravo.detector_id, &second.0)
            && Arc::ptr_eq(&bravo.detector_name, &second.1)
            && Arc::ptr_eq(&bravo.service, &second.2),
        "bravo emission must reuse its construction-time metadata allocations"
    );
}

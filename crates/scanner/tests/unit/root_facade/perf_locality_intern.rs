//! PERF-locality_intern-1 regression gate.
//!
//! Detector id/name/service metadata must be interned once at scanner
//! construction and cloned by detector index on match emission. Dynamic fields
//! such as source path and commit still flow through `ScanState::intern_metadata`;
//! detector metadata must not.

use std::sync::Arc;

use keyhog_core::{DetectorSpec, PatternSpec, Severity};
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

    let src = |rel: &str| {
        std::fs::read_to_string(std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join(rel))
            .unwrap_or_else(|e| panic!("{rel} not readable: {e}"))
    };
    let compile = src("src/engine/compile.rs");
    assert!(
        compile.contains("let metadata_by_index: Vec<(Arc<str>, Arc<str>, Arc<str>)>")
            && compile.contains("metadata_by_index,"),
        "compile.rs must build and store detector metadata by index"
    );

    let api = src("src/engine/compiled_api.rs");
    assert!(
        api.contains("fn interned_detector_metadata")
            && api.contains("self.metadata_by_index[detector_index]"),
        "compiled_api.rs must expose the index-clone owner"
    );

    let process = src("src/engine/process.rs");
    assert!(
        process
            .matches("self.interned_detector_metadata(entry.detector_index)")
            .count()
            >= 2,
        "regular confirmed/phase-2 match emission must clone detector metadata by index"
    );
    for forbidden in [
        "intern_metadata(&detector.id)",
        "intern_metadata(&detector.name)",
        "intern_metadata(&detector.service)",
    ] {
        assert!(
            !process.contains(forbidden),
            "process.rs must not re-hash detector metadata strings per match: {forbidden}"
        );
    }

    let hot = src("src/engine/hot_patterns.rs");
    assert!(
        hot.contains("self.process_match(")
            && hot.contains("self.hot_pattern_slots[pattern_idx]")
            && !hot.contains("self.hot_metadata_by_index[pattern_idx]")
            && !hot.contains("build_synthetic_raw_match")
            && !hot.contains("intern_metadata(HOT_PATTERN_DETECTOR_IDS"),
        "hot-pattern emission must route through canonical process_match metadata instead of synthetic hot metadata"
    );

    let entropy = src("src/engine/phase2_entropy.rs");
    assert!(
        entropy.contains("self.entropy_metadata_by_index[entropy_meta_idx]")
            && entropy.contains("Arc::clone(&metadata.0)"),
        "synthetic entropy metadata must be pre-indexed instead of rehashed"
    );
}

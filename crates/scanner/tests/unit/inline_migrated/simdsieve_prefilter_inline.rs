#![cfg(feature = "simdsieve")]

use keyhog_core::{DetectorSpec, PatternSpec, Severity};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn detector(id: &str, regex: &str, prefixes: &[&str]) -> DetectorSpec {
    DetectorSpec {
        id: id.into(),
        name: id.into(),
        service: "test".into(),
        severity: Severity::Critical,
        patterns: vec![PatternSpec {
            regex: regex.into(),
            ..Default::default()
        }],
        keywords: prefixes.iter().map(|s| (*s).to_string()).collect(),
        simdsieve_prefixes: prefixes.iter().map(|s| (*s).to_string()).collect(),
        min_confidence: Some(0.0),
        match_confidence: keyhog_core::detector_spec_by_id("datadog-api-key")
            .and_then(|detector| detector.match_confidence),
        ..keyhog_scanner::testing::named_detector_fixture_defaults()
    }
}

#[test]
fn embedded_hot_prefixes_are_detector_owned_and_compile_to_canonical_rows() {
    let detectors = keyhog_core::load_embedded_detectors_or_fail().expect("embedded corpus");
    let declared: usize = detectors.iter().map(|d| d.simdsieve_prefixes.len()).sum();
    assert!(
        declared >= 12,
        "embedded SIMD prefix coverage regressed to {declared}"
    );
    let scanner = CompiledScanner::compile(detectors).expect("embedded scanner");
    let rows = keyhog_scanner::testing::hot_pattern_rows(&scanner);
    assert_eq!(rows.len(), declared);
    for (prefix, id, name, service) in rows {
        let spec = keyhog_core::detector_spec_by_id(&id).expect("owning detector");
        assert!(spec
            .simdsieve_prefixes
            .iter()
            .any(|p| p.as_bytes() == prefix));
        assert_eq!(name, spec.name);
        assert_eq!(service, spec.service);
    }
}

#[test]
fn custom_detector_prefix_drives_the_real_hot_scan_without_a_rust_table_edit() {
    let scanner = CompiledScanner::compile(vec![detector(
        "custom-hot",
        r"CUSTOM_[A-Z0-9]{16}",
        &["CUSTOM_"],
    )])
    .expect("custom hot detector compiles");
    let rows = keyhog_scanner::testing::hot_pattern_rows(&scanner);
    assert_eq!(
        rows,
        vec![(
            b"CUSTOM_".to_vec(),
            "custom-hot".into(),
            "custom-hot".into(),
            "test".into()
        )]
    );
    let matches = scanner.scan_with_backend(
        &keyhog_core::Chunk::from("token=CUSTOM_1234567890ABCDEF"),
        ScanBackend::CpuFallback,
    );
    assert!(matches
        .iter()
        .any(|m| m.detector_id.as_ref() == "custom-hot"
            && m.credential.as_ref() == "CUSTOM_1234567890ABCDEF"));
}

#[test]
fn declared_prefix_must_be_backed_by_the_owning_detector_regex() {
    let error = match CompiledScanner::compile(vec![detector(
        "bad-hot",
        r"REAL_[A-Z0-9]{16}",
        &["WRONG_"],
    )]) {
        Ok(_) => panic!("unbacked accelerator declaration must fail closed"),
        Err(error) => error,
    };
    let message = error.to_string();
    assert!(
        message.contains("bad-hot") && message.contains("WRONG_"),
        "{message}"
    );
}

#[test]
fn hot_prefix_resolver_is_total_and_uses_the_compiled_slot_order() {
    let scanner = CompiledScanner::compile(vec![detector(
        "custom-hot",
        r"CUSTOM_[A-Z0-9]{16}",
        &["CUSTOM_"],
    )])
    .expect("scanner");
    assert_eq!(
        keyhog_scanner::testing::hot_pattern_index_at(&scanner, b"xxCUSTOM_tail", 2),
        Some(0)
    );
    assert_eq!(
        keyhog_scanner::testing::hot_pattern_index_at(&scanner, b"CUSTOM_tail", 99),
        None
    );
    assert_eq!(
        keyhog_scanner::testing::hot_pattern_index_at(&scanner, b"CUST0M_tail", 0),
        None
    );
}

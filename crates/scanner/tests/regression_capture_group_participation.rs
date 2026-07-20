use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScanBackend};

fn scanner() -> CompiledScanner {
    let dir = tempfile::tempdir().expect("tempdir");
    std::fs::write(
        dir.path().join("capture-participation.toml"),
        r#"
[detector]
id = "capture-participation-contract"
name = "Capture Participation Contract"
service = "capture-contract"
severity = "high"
ml = { match_mode = "disabled", entropy_mode = "disabled", weight = 0.0, context_radius_lines = 0 }
match_confidence = { literal_prefix_weight = 0.35, context_anchor_weight = 0.20, entropy_weight = 0.20, high_entropy_partial_weight = 0.12, moderate_entropy_threshold = 3.0, moderate_entropy_weight = 0.05, low_entropy_penalty_floor = 2.0, low_entropy_min_match_length = 10, low_entropy_penalty_multiplier = 0.60, keyword_nearby_weight = 0.10, sensitive_file_weight = 0.10, companion_weight = 0.05, very_high_entropy_margin = 1.3, named_anchor_floor = 0.55, assignment_context_multiplier = 1.0, string_literal_context_multiplier = 0.9, unknown_context_multiplier = 0.8, documentation_context_multiplier = 0.3, comment_context_multiplier = 0.4, test_context_multiplier = 0.3, encrypted_context_multiplier = 0.05, soft_context_suppression_threshold = 0.5, encrypted_context_suppression_threshold = 0.8, post_match = { placeholder_multiplier = 0.05, minimum_byte_diversity = 0.1, low_diversity_multiplier = 0.1, maximum_repeat_ratio = 0.8, degenerate_run_min_length = 10, degenerate_repeat_multiplier = 0.1, fixture_path_multiplier = 0.5, ml_context_reapply_below = 0.95 } }
keywords = ["capture_", "wrapper_"]
min_confidence = 0.0

[[detector.patterns]]
regex = '(?:capture_([A-Z0-9]{16})|wrapper_[A-Z0-9]{16})'
group = 1
"#,
    )
    .expect("write custom detector");

    CompiledScanner::compile(keyhog_core::load_detectors(dir.path()).expect("load custom detector"))
        .expect("compile custom detector")
}

fn credentials(scanner: &CompiledScanner, backend: ScanBackend, input: &str) -> Vec<String> {
    let chunk = Chunk {
        data: input.into(),
        metadata: ChunkMetadata {
            source_type: "capture-contract".into(),
            path: Some("capture-contract.txt".into()),
            ..Default::default()
        },
    };
    scanner
        .scan_with_backend(&chunk, backend)
        .into_iter()
        .filter(|finding| finding.detector_id.as_ref() == "capture-participation-contract")
        .map(|finding| finding.credential.as_str().to_owned())
        .collect()
}

#[test]
fn participating_selected_capture_emits_exact_credential() {
    let scanner = scanner();
    assert_eq!(
        credentials(
            &scanner,
            ScanBackend::CpuFallback,
            "capture_Q7VN2XK8CP4MR9TW",
        ),
        ["Q7VN2XK8CP4MR9TW"],
    );
}

#[test]
fn nonparticipating_selected_capture_fails_closed_across_available_backends() {
    let scanner = scanner();
    let input = "wrapper_Q7VN2XK8CP4MR9TW";
    assert!(
        credentials(&scanner, ScanBackend::CpuFallback, input).is_empty(),
        "a nonparticipating selected group must not substitute the full regex match",
    );

    #[cfg(feature = "simd")]
    if scanner.warm_backend(ScanBackend::SimdCpu) {
        assert!(credentials(&scanner, ScanBackend::SimdCpu, input).is_empty());
    }
    #[cfg(feature = "gpu")]
    for backend in [ScanBackend::GpuCuda, ScanBackend::GpuWgpu] {
        if scanner.warm_backend(backend) {
            assert!(credentials(&scanner, backend, input).is_empty());
        }
    }
}

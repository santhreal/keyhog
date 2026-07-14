//! Contract tests for two pure public classifiers (#177): the `--backend`
//! string parser and the entropy/generic detector-id predicates. Both are the
//! single source of truth for operator-visible behavior (CLI backend selection;
//! entropy-path routing), so a drift here is a coherence break.

use keyhog_scanner::hw_probe::{parse_backend_str, BACKEND_OVERRIDE_VALUES};
use keyhog_scanner::{is_entropy_detector, is_generic_or_entropy_detector, ScanBackend};

// ── parse_backend_str: advertised CLI values must all map (coherence) ────────

#[test]
fn every_advertised_backend_value_parses_except_the_auto_sentinel() {
    // `BACKEND_OVERRIDE_VALUES` is the clap `--backend` possible-value list.
    // Every one must be recognized by the canonical parser; `auto` is the one
    // deliberate `None` (it means "no forced backend, auto-route"). A silent
    // fall-through for any advertised forced backend would silently select auto.
    for value in BACKEND_OVERRIDE_VALUES {
        let parsed = parse_backend_str(value);
        if value == "auto" {
            assert_eq!(parsed, None, "`auto` must be the no-override sentinel");
        } else {
            assert!(
                parsed.is_some(),
                "advertised --backend value `{value}` must parse to a forced backend"
            );
        }
    }
}

#[test]
fn backend_strings_map_to_the_expected_backend() {
    assert_eq!(parse_backend_str("gpu"), None);
    assert_eq!(
        parse_backend_str("gpu-cuda-region-presence"),
        Some(ScanBackend::GpuCuda)
    );
    assert_eq!(
        parse_backend_str("gpu-wgpu-region-presence"),
        Some(ScanBackend::GpuWgpu)
    );
    assert_eq!(parse_backend_str("mega-scan"), None);
    assert_eq!(parse_backend_str("megascan"), None);
    assert_eq!(parse_backend_str("simd"), Some(ScanBackend::SimdCpu));
    assert_eq!(parse_backend_str("cpu"), Some(ScanBackend::CpuFallback));
    assert_eq!(
        parse_backend_str("cpu-fallback"),
        Some(ScanBackend::CpuFallback)
    );
}

#[test]
fn backend_parsing_trims_and_is_case_insensitive() {
    assert_eq!(
        parse_backend_str("  GPU-WGPU  "),
        Some(ScanBackend::GpuWgpu)
    );
    assert_eq!(parse_backend_str("Cpu"), Some(ScanBackend::CpuFallback));
    assert_eq!(parse_backend_str("SIMD"), Some(ScanBackend::SimdCpu));
}

#[test]
fn unknown_backend_strings_are_rejected() {
    assert_eq!(parse_backend_str("banana"), None);
    assert_eq!(parse_backend_str(""), None);
    assert_eq!(parse_backend_str("   "), None);
    assert_eq!(parse_backend_str("gpu!"), None);
}

// ── detector-id classification predicates ────────────────────────────────────

#[test]
fn entropy_detectors_are_recognized_by_the_entropy_prefix() {
    assert!(is_entropy_detector("entropy-api-key"));
    assert!(is_entropy_detector("entropy-token"));
    // Named service detectors are NOT entropy detectors.
    assert!(!is_entropy_detector("aws-access-key"));
    assert!(!is_entropy_detector("github-pat"));
    // A `generic-*` detector fires via entropy but is not `entropy-*` prefixed,
    // so the narrow predicate excludes it (the wider one below includes it).
    assert!(!is_entropy_detector("generic-secret"));
}

#[test]
fn generic_or_entropy_predicate_covers_both_families() {
    assert!(is_generic_or_entropy_detector("entropy-api-key"));
    assert!(is_generic_or_entropy_detector("generic-secret"));
    assert!(is_generic_or_entropy_detector("generic-api-key"));
    // A named vendor detector is neither generic nor entropy.
    assert!(!is_generic_or_entropy_detector("aws-access-key"));
    assert!(!is_generic_or_entropy_detector("stripe-secret-key"));
}

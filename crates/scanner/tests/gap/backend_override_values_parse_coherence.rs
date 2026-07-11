//! Gap test: the advertised --backend value list stays in sync with the parser.
//!
//! `BACKEND_OVERRIDE_VALUES` is the operator-facing `--backend` list (Clap
//! validation, docs, error messages); `parse_backend_str` is the canonical
//! string -> ScanBackend mapping. The module doc warns these must not drift.
//! Pin the coherence directly: every advertised value except the `auto`
//! sentinel parses to a concrete backend, stable evidence labels remain
//! readable, and retired aliases do not silently select another live engine.

use keyhog_scanner::hw_probe::{parse_backend_str, ScanBackend, BACKEND_OVERRIDE_VALUES};

#[test]
fn every_advertised_value_parses_except_the_auto_sentinel() {
    for &value in &BACKEND_OVERRIDE_VALUES {
        if value == "auto" {
            assert_eq!(
                parse_backend_str(value),
                None,
                "`auto` is the autoroute sentinel, not a forced backend"
            );
        } else {
            assert!(
                parse_backend_str(value).is_some(),
                "advertised --backend value `{value}` must map to a concrete backend"
            );
        }
    }
}

#[test]
fn canonical_backend_strings_map_exactly() {
    assert_eq!(parse_backend_str("gpu"), Some(ScanBackend::Gpu));
    assert_eq!(
        parse_backend_str("gpu-region-presence"),
        Some(ScanBackend::Gpu)
    );
    assert_eq!(parse_backend_str("simd"), Some(ScanBackend::SimdCpu));
    assert_eq!(parse_backend_str("simd-regex"), Some(ScanBackend::SimdCpu));
    assert_eq!(parse_backend_str("cpu"), Some(ScanBackend::CpuFallback));
    assert_eq!(
        parse_backend_str("cpu-fallback"),
        Some(ScanBackend::CpuFallback)
    );
}

#[test]
fn parser_trims_lowercases_and_rejects_unknown() {
    assert_eq!(parse_backend_str("  SIMD  "), Some(ScanBackend::SimdCpu));
    assert_eq!(parse_backend_str("Gpu"), Some(ScanBackend::Gpu));
    assert_eq!(parse_backend_str(""), None);
    assert_eq!(parse_backend_str("gibberish"), None);
}

#[test]
fn retired_aliases_are_rejected_instead_of_silently_remapped() {
    for retired in [
        "gpu-zero-copy",
        "literal-set",
        "mega-scan",
        "megascan",
        "gpu-mega-scan",
        "regex-nfa",
        "rule-pipeline",
        "hyperscan",
        "scalar",
    ] {
        assert_eq!(
            parse_backend_str(retired),
            None,
            "retired alias {retired:?}"
        );
    }
}

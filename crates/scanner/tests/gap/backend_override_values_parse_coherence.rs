//! Gap test: the advertised --backend value list stays in sync with the parser.
//!
//! `BACKEND_OVERRIDE_VALUES` is the operator-facing `--backend` list (Clap
//! validation, docs, error messages); `parse_backend_str` is the canonical
//! string -> ScanBackend mapping. The module doc warns these must not drift.
//! Existing parser tests assert hardcoded alias lists; none iterate the ACTUAL
//! const, so a value added to the advertised list but forgotten in the parser
//! would slip through. Pin the coherence directly: every advertised value
//! except the `auto` sentinel parses to a concrete backend, with the exact
//! canonical mappings (incl. the no-hyphen `megascan` that once silently fell
//! through to auto-routing).

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
    assert_eq!(parse_backend_str("mega-scan"), Some(ScanBackend::MegaScan));
    // The no-hyphen spelling is an advertised value that previously dropped to
    // None (silently auto-routing instead of forcing the GPU mega-scan path).
    assert_eq!(parse_backend_str("megascan"), Some(ScanBackend::MegaScan));
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

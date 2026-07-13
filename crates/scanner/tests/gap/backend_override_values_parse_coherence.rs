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

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin the advertised-list coherence and canonical mappings;
// these SWEEP the parser's normalization. `parse_backend_str` trims + lowercases,
// so every advertised value maps to the SAME backend under arbitrary case and
// surrounding whitespace, a self-differential over the whole advertised list
// (covers `auto`→None too). And a string that cannot be any advertised alias is
// rejected (None). Traced against `parse_backend_str`. No proptest before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(3_000))]

    /// Every advertised value parses to the same backend regardless of ASCII case
    /// or surrounding whitespace (the parser trims + lowercases first).
    #[test]
    fn advertised_values_parse_case_and_whitespace_insensitively(
        vi in 0usize..BACKEND_OVERRIDE_VALUES.len(),
        lead in "[ \t]{0,3}",
        trail in "[ \t]{0,3}",
        upper in any::<bool>(),
    ) {
        let base = BACKEND_OVERRIDE_VALUES[vi];
        let cased = if upper { base.to_uppercase() } else { base.to_string() };
        let padded = format!("{lead}{cased}{trail}");
        prop_assert_eq!(parse_backend_str(&padded), parse_backend_str(base));
    }

    /// A string that cannot be any advertised alias is rejected (None).
    #[test]
    fn clearly_unknown_string_rejects(s in "[a-z0-9]{0,10}") {
        let value = format!("notabackend-{s}");
        prop_assert_eq!(parse_backend_str(&value), None);
    }
}

//! Property/fuzz invariants for the discovery + routing public API (#177).
//!
//! `find_*_strings` run over attacker-controlled file bytes and `gpu_routing_
//! profile` / `parse_backend_str` over user/driver strings, so the load-bearing
//! guarantees are: (1) NEVER panic on any input, and (2) honour their documented
//! filter/well-formedness contracts for ALL inputs — not just the fixed vectors
//! in the known-answer suites.

use keyhog_scanner::decode::{find_base64_strings, find_hex_strings, is_base64_candidate_byte};
use keyhog_scanner::hw_probe::{gpu_routing_profile, parse_backend_str, BACKEND_OVERRIDE_VALUES};
use keyhog_scanner::{is_entropy_detector, is_generic_or_entropy_detector};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(10_000))]

    /// Every base64 run surfaced by discovery must (a) meet the min-length floor
    /// and (b) contain only base64-alphabet bytes — the two filter predicates in
    /// `visit_classified_base64_string_spans`. A violation would feed a
    /// non-candidate run into the decode-and-rescan pipeline.
    #[test]
    fn find_base64_strings_honours_its_filter_contract(
        text in "[A-Za-z0-9+/=_\\-. \t\n:;,\"']{0,300}",
        min_len in 0usize..64,
    ) {
        for e in find_base64_strings(&text, min_len) {
            prop_assert!(e.value.len() >= min_len, "surfaced {:?} shorter than floor {min_len}", e.value);
            prop_assert!(
                e.value.bytes().all(is_base64_candidate_byte),
                "surfaced {:?} contains a non-base64 byte",
                e.value
            );
        }
    }

    /// Hex discovery honours the min-length floor and never panics.
    #[test]
    fn find_hex_strings_honours_its_min_len_floor(
        text in "[0-9a-fA-F_xX ,;:\n\"']{0,300}",
        min_len in 0usize..64,
    ) {
        for e in find_hex_strings(&text, min_len) {
            prop_assert!(e.value.len() >= min_len, "surfaced {:?} shorter than floor {min_len}", e.value);
        }
    }

    /// For ANY adapter name string, the routing profile is well-formed: positive
    /// thresholds, a non-empty tier, and solo_bytes >= min_bytes (you cannot run
    /// the GPU solo before it is allowed to engage). No name may panic routing.
    #[test]
    fn gpu_routing_profile_is_well_formed_for_any_name(name in ".{0,80}") {
        let p = gpu_routing_profile(Some(&name));
        prop_assert!(!p.tier.is_empty());
        prop_assert!(p.min_bytes > 0);
        prop_assert!(p.solo_bytes > 0);
        prop_assert!(p.pattern_breakeven > 0);
        prop_assert!(p.solo_bytes >= p.min_bytes);
    }

    /// `parse_backend_str` is total: it never panics for arbitrary input (the
    /// Some/None result is discarded — only crash-freedom is asserted here).
    #[test]
    fn parse_backend_str_never_panics(raw in ".{0,40}") {
        let _ = parse_backend_str(&raw);
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4096))]

    /// The entropy family is a SUBSET of the generic-or-entropy family: any id
    /// the narrow predicate accepts, the wide one must accept too. A predicate
    /// edit that broke this containment would mis-route entropy detectors.
    #[test]
    fn entropy_detectors_are_a_subset_of_generic_or_entropy(id in "[a-z0-9-]{0,40}") {
        if is_entropy_detector(&id) {
            prop_assert!(
                is_generic_or_entropy_detector(&id),
                "`{id}` is an entropy detector but not generic-or-entropy"
            );
        }
    }

    /// Any `entropy-<suffix>` id is classified as an entropy detector (and hence
    /// generic-or-entropy) regardless of the suffix.
    #[test]
    fn entropy_prefixed_ids_classify_as_entropy(suffix in "[a-z0-9-]{1,30}") {
        let id = format!("entropy-{suffix}");
        prop_assert!(is_entropy_detector(&id));
        prop_assert!(is_generic_or_entropy_detector(&id));
    }
}

/// Every advertised backend value survives surrounding whitespace + a full
/// case flip (raw-independent, so a single deterministic check, not a property).
#[test]
fn advertised_backend_values_parse_under_whitespace_and_case() {
    for v in BACKEND_OVERRIDE_VALUES {
        let noisy = format!("  {}  ", v.to_uppercase());
        assert_eq!(
            parse_backend_str(&noisy),
            parse_backend_str(v),
            "`{noisy:?}` must parse like `{v}`"
        );
    }
}

//! Property invariants for the `default_excludes` rule-list validators
//! (`src/filesystem/filter.rs`). These gate every entry of the built-in exclude
//! lists, so the structural contract for each kind must hold across the whole
//! input space, not just the hand-picked examples in
//! `contract/default_excludes_rule_validation.rs`. ~4000 cases per tier.

use keyhog_sources::testing::{normalize_rule_list_for_test, validate_rule_value_for_test};
use proptest::prelude::*;

const KINDS: &[&str] = &["extension", "path_segment", "suffix", "filename", "infix"];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(4_000))]

    /// The validator must NEVER panic and must return a bool-ish Result for any
    /// (value, kind) pair (arbitrary config bytes cannot crash the loader).
    #[test]
    fn validate_never_panics_on_arbitrary_value(
        value in ".{0,32}",
        which in 0usize..5,
    ) {
        let _ = validate_rule_value_for_test("field", &value, KINDS[which]);
    }

    /// An accepted entry is ALWAYS lowercase, non-empty, and control-char-free
    /// these three guards apply before any kind-specific shape check, so no
    /// accepted value may violate them regardless of kind.
    #[test]
    fn accepted_value_is_lowercase_nonempty_and_clean(
        value in ".{0,24}",
        which in 0usize..5,
    ) {
        if validate_rule_value_for_test("field", &value, KINDS[which]).is_ok() {
            let trimmed = value.trim();
            prop_assert!(!trimmed.is_empty());
            prop_assert_eq!(trimmed, trimmed.to_ascii_lowercase());
            prop_assert!(!trimmed.chars().any(char::is_control));
        }
    }

    /// No accepted entry of ANY kind may contain a path separator, that is a
    /// universal refusal shared by every branch.
    #[test]
    fn accepted_value_never_contains_a_separator(
        value in "[a-z0-9._/\\\\]{0,24}",
        which in 0usize..5,
    ) {
        if validate_rule_value_for_test("field", &value, KINDS[which]).is_ok() {
            prop_assert!(!value.contains('/'));
            prop_assert!(!value.contains('\\'));
        }
    }

    /// An accepted `extension` never starts with a dot; an accepted `suffix`
    /// always does; an accepted `infix` starts AND ends with one. These are the
    /// kind discriminators and must hold exactly.
    #[test]
    fn dot_shape_matches_the_kind(value in "[a-z0-9.]{1,16}") {
        if validate_rule_value_for_test("field", &value, "extension").is_ok() {
            prop_assert!(!value.starts_with('.'));
        }
        if validate_rule_value_for_test("field", &value, "suffix").is_ok() {
            prop_assert!(value.starts_with('.'));
        }
        if validate_rule_value_for_test("field", &value, "infix").is_ok() {
            prop_assert!(value.starts_with('.') && value.ends_with('.'));
        }
    }

    /// `normalize_rule_list` is duplicate-free by construction: any two distinct
    /// accepted lists of unique tokens round-trip to themselves (order-preserved),
    /// and a list containing a repeat is always rejected.
    #[test]
    fn normalize_rejects_any_repeat(
        tokens in prop::collection::vec("[a-z]{1,6}", 1..8),
    ) {
        let values: Vec<String> = tokens.iter().cloned().collect();
        let has_dup = {
            let mut seen = std::collections::BTreeSet::new();
            values.iter().any(|v| !seen.insert(v.clone()))
        };
        let result = normalize_rule_list_for_test("extensions", values.clone(), "extension");
        match result {
            Ok(out) => {
                prop_assert!(!has_dup);
                prop_assert_eq!(out, values);
            }
            Err(e) => {
                // Rejection is only allowed for a duplicate here (tokens are all
                // valid bare lowercase extensions).
                prop_assert!(has_dup, "unexpected rejection of a unique list: {}", e);
            }
        }
    }
}

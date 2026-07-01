//! Shared detector-catalog validation helpers for scanner Tier-B rule files.

use std::collections::HashSet;
use std::sync::OnceLock;

pub(crate) fn bundled_detector_ids() -> Result<&'static HashSet<String>, String> {
    static DETECTOR_IDS: OnceLock<Result<HashSet<String>, String>> = OnceLock::new();
    DETECTOR_IDS
        .get_or_init(|| {
            keyhog_core::load_embedded_detectors_or_fail()
                .map(|detectors| {
                    detectors
                        .into_iter()
                        .map(|detector| detector.id)
                        .collect::<HashSet<_>>()
                })
                .map_err(|error| format!("failed to validate detector rule ids: {error}"))
        })
        .as_ref()
        .map_err(Clone::clone)
}

/// Fail closed if a Tier-B rule file names a detector that is not in the bundled
/// catalog (a typo or a dead rule that would otherwise load silently and never
/// match anything).
///
/// Every unknown id is collected and reported together — in first-appearance
/// (file) order, deduplicated — so an operator fixing a rule file sees the full
/// set of bad ids at once instead of one re-run per typo. The single-unknown
/// message is kept in the exact `references unknown detector '<id>'` form its
/// callers document; two or more switch to the plural `unknown detectors` list.
pub(crate) fn validate_rule_detector_ids<'a>(
    rule_name: &str,
    detector_ids: impl IntoIterator<Item = &'a str>,
    valid_detector_ids: &HashSet<String>,
) -> Result<(), String> {
    let mut unknown: Vec<&str> = Vec::new();
    for detector_id in detector_ids {
        if !valid_detector_ids.contains(detector_id) && !unknown.contains(&detector_id) {
            unknown.push(detector_id);
        }
    }
    match unknown.as_slice() {
        [] => Ok(()),
        [only] => Err(format!("{rule_name} references unknown detector '{only}'")),
        many => {
            let list = many
                .iter()
                .map(|id| format!("'{id}'"))
                .collect::<Vec<_>>()
                .join(", ");
            Err(format!("{rule_name} references unknown detectors {list}"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_set(ids: &[&str]) -> HashSet<String> {
        ids.iter().map(|id| id.to_string()).collect()
    }

    // ── all-valid / empty inputs pass ────────────────────────────────────
    #[test]
    fn empty_rule_passes() {
        let set = valid_set(&["a", "b"]);
        assert!(validate_rule_detector_ids("rule", Vec::<&str>::new(), &set).is_ok());
    }

    #[test]
    fn all_ids_valid_passes() {
        let set = valid_set(&["a", "b", "c"]);
        assert!(validate_rule_detector_ids("rule", ["a", "c"], &set).is_ok());
    }

    #[test]
    fn repeated_valid_ids_pass() {
        let set = valid_set(&["a"]);
        assert!(validate_rule_detector_ids("rule", ["a", "a", "a"], &set).is_ok());
    }

    #[test]
    fn empty_valid_set_with_no_ids_passes() {
        let set = valid_set(&[]);
        assert!(validate_rule_detector_ids("rule", Vec::<&str>::new(), &set).is_ok());
    }

    // ── single unknown: exact backward-compatible singular message ────────
    #[test]
    fn single_unknown_errors() {
        let set = valid_set(&["a"]);
        assert!(validate_rule_detector_ids("rule", ["x"], &set).is_err());
    }

    #[test]
    fn single_unknown_uses_the_exact_singular_message() {
        let set = valid_set(&["a"]);
        let err = validate_rule_detector_ids("myrule", ["x"], &set).unwrap_err();
        assert_eq!(err, "myrule references unknown detector 'x'");
    }

    #[test]
    fn single_unknown_among_valid_ids_reports_only_the_unknown() {
        let set = valid_set(&["a", "b"]);
        let err = validate_rule_detector_ids("rule", ["a", "x", "b"], &set).unwrap_err();
        assert_eq!(err, "rule references unknown detector 'x'");
    }

    // ── multiple unknowns: all reported, plural noun, file order ──────────
    #[test]
    fn two_unknowns_are_both_reported() {
        let set = valid_set(&["a"]);
        let err = validate_rule_detector_ids("rule", ["x", "y"], &set).unwrap_err();
        assert!(err.contains("'x'"));
        assert!(err.contains("'y'"));
    }

    #[test]
    fn multiple_unknowns_use_the_plural_noun_not_the_singular() {
        let set = valid_set(&["a"]);
        let err = validate_rule_detector_ids("rule", ["x", "y"], &set).unwrap_err();
        assert!(err.contains("unknown detectors"));
        assert!(!err.contains("unknown detector '"));
    }

    #[test]
    fn three_unknowns_are_all_reported_in_first_appearance_order() {
        let set = valid_set(&["ok"]);
        let err = validate_rule_detector_ids("rule", ["c", "ok", "a", "b"], &set).unwrap_err();
        assert_eq!(err, "rule references unknown detectors 'c', 'a', 'b'");
    }

    #[test]
    fn plural_list_is_comma_space_separated_and_single_quoted() {
        let set = valid_set(&[]);
        let err = validate_rule_detector_ids("rule", ["a", "b"], &set).unwrap_err();
        assert!(err.ends_with("'a', 'b'"));
    }

    // ── dedup: a repeated unknown is listed once, order preserved ─────────
    #[test]
    fn a_repeated_unknown_is_reported_once_as_singular() {
        let set = valid_set(&["a"]);
        let err = validate_rule_detector_ids("rule", ["x", "x", "x"], &set).unwrap_err();
        assert_eq!(err, "rule references unknown detector 'x'");
    }

    #[test]
    fn distinct_unknowns_with_a_repeat_are_deduped_but_kept() {
        let set = valid_set(&[]);
        let err = validate_rule_detector_ids("rule", ["x", "y", "x"], &set).unwrap_err();
        assert_eq!(err, "rule references unknown detectors 'x', 'y'");
    }

    // ── rule_name is echoed verbatim ─────────────────────────────────────
    #[test]
    fn rule_name_appears_in_singular_error() {
        let set = valid_set(&[]);
        let err = validate_rule_detector_ids("credential shape rule", ["x"], &set).unwrap_err();
        assert!(err.starts_with("credential shape rule "));
    }

    #[test]
    fn rule_name_appears_in_plural_error() {
        let set = valid_set(&[]);
        let err = validate_rule_detector_ids("shape rule", ["x", "y"], &set).unwrap_err();
        assert!(err.starts_with("shape rule "));
    }

    // ── membership semantics ─────────────────────────────────────────────
    #[test]
    fn membership_is_case_sensitive() {
        let set = valid_set(&["aws-key"]);
        let err = validate_rule_detector_ids("rule", ["AWS-KEY"], &set).unwrap_err();
        assert_eq!(err, "rule references unknown detector 'AWS-KEY'");
    }

    #[test]
    fn empty_string_id_is_unknown_and_quoted_empty() {
        let set = valid_set(&["a"]);
        let err = validate_rule_detector_ids("rule", [""], &set).unwrap_err();
        assert_eq!(err, "rule references unknown detector ''");
    }

    #[test]
    fn whitespace_id_is_unknown_and_not_trimmed() {
        let set = valid_set(&["a"]);
        let err = validate_rule_detector_ids("rule", [" a "], &set).unwrap_err();
        assert_eq!(err, "rule references unknown detector ' a '");
    }

    // ── integration against the real bundled catalog ─────────────────────
    #[test]
    fn bundled_detector_ids_is_nonempty() {
        let ids = bundled_detector_ids().unwrap();
        assert!(!ids.is_empty());
    }

    #[test]
    fn bundled_detector_ids_is_memoized_to_the_same_instance() {
        let first = bundled_detector_ids().unwrap();
        let second = bundled_detector_ids().unwrap();
        assert!(std::ptr::eq(first, second));
    }

    #[test]
    fn a_fabricated_id_fails_against_the_real_bundled_catalog() {
        let ids = bundled_detector_ids().unwrap();
        let err = validate_rule_detector_ids("rule", ["definitely-not-a-real-detector-xyz"], ids)
            .unwrap_err();
        assert!(err.contains("definitely-not-a-real-detector-xyz"));
    }

    #[test]
    fn a_real_bundled_id_validates_against_its_own_catalog() {
        let ids = bundled_detector_ids().unwrap();
        let sample = ids.iter().next().expect("bundled catalog is non-empty");
        assert!(validate_rule_detector_ids("rule", [sample.as_str()], ids).is_ok());
    }
}

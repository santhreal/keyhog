//! Detector classification overrides loaded from Tier-B data.
//!
//! This now loads ONLY the Stripe hot-path prefix list, a genuine PREFIX list,
//! not a per-detector property. The `weak_anchor` and `private_key_block`
//! classifications that used to live here as centralized detector-id lists are
//! now per-detector `DetectorSpec` fields declared in each detector's own
//! `detectors/<id>.toml` (the DET-0 architecture law: "a detector's TOML is the
//! whole story"). Their family membership is pinned by the
//! `weak_anchor_family_is_toml_declared` / `private_key_block_family_is_toml_declared`
//! drift-guard tests in `detector_ids.rs`. Because the flag now lives on the
//! detector's own spec, the previous "unknown detector id" validation class is
//! impossible by construction (you cannot flag a detector that does not exist),
//! so all the id-list validation machinery this file once carried is gone.

use serde::Deserialize;
use std::collections::HashSet;
use std::sync::OnceLock;

const DETECTOR_CLASSIFICATION_TOML: &str =
    include_str!("../../../rules/detector-classification.toml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetectorClassificationFile {
    #[serde(default)]
    stripe_hot_confirmed_prefix: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct DetectorClassification {
    stripe_hot_confirmed_prefix: Vec<String>,
}

pub(crate) fn stripe_hot_confirmed_prefixes() -> Result<&'static [String], String> {
    classification_rules().map(|rules| rules.stripe_hot_confirmed_prefix.as_slice())
}

pub(crate) fn validate() -> Result<(), String> {
    classification_rules().map(|_| ())
}

fn classification_rules() -> Result<&'static DetectorClassification, String> {
    static CLASSIFICATION_RULES: OnceLock<Result<DetectorClassification, String>> = OnceLock::new();
    CLASSIFICATION_RULES
        .get_or_init(|| parse_classification_rules(DETECTOR_CLASSIFICATION_TOML))
        .as_ref()
        .map_err(Clone::clone)
}

fn parse_classification_rules(raw: &str) -> Result<DetectorClassification, String> {
    let rules: DetectorClassificationFile = toml::from_str(raw)
        .map_err(|error| format!("invalid detector classification rules: {error}"))?;
    validate_prefixes(
        "stripe_hot_confirmed_prefix",
        &rules.stripe_hot_confirmed_prefix,
    )?;
    Ok(DetectorClassification {
        stripe_hot_confirmed_prefix: rules.stripe_hot_confirmed_prefix,
    })
}

fn validate_prefixes(rule_name: &str, prefixes: &[String]) -> Result<(), String> {
    let mut seen = HashSet::new();
    for prefix in prefixes {
        if prefix.is_empty() {
            return Err(format!(
                "detector classification {rule_name} has an empty prefix"
            ));
        }
        if prefix.trim() != prefix {
            return Err(format!(
                "detector classification {rule_name} prefix {prefix:?} has surrounding whitespace"
            ));
        }
        if !prefix.is_ascii() {
            return Err(format!(
                "detector classification {rule_name} prefix {prefix:?} is not ASCII"
            ));
        }
        if !seen.insert(prefix.as_str()) {
            return Err(format!(
                "detector classification {rule_name} lists prefix {prefix:?} more than once"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn live_classification_rules_parse() {
        let rules = parse_classification_rules(DETECTOR_CLASSIFICATION_TOML).unwrap();
        assert!(rules
            .stripe_hot_confirmed_prefix
            .iter()
            .any(|prefix| prefix == "sk_live_"));
    }

    #[test]
    fn parse_rejects_duplicate_prefixes() {
        let err = parse_classification_rules(
            r#"
stripe_hot_confirmed_prefix = ["sk_live_", "sk_live_"]
"#,
        )
        .unwrap_err();

        assert!(err.contains("stripe_hot_confirmed_prefix"));
        assert!(err.contains("more than once"));
    }

    /// The `weak_anchor` / `private_key_block` id lists were MIGRATED OUT to
    /// per-detector `DetectorSpec` fields. `deny_unknown_fields` must now REJECT
    /// them if they reappear here, so the migration cannot silently regress into
    /// a second home for the same data (ONE PLACE law).
    #[test]
    fn parse_rejects_migrated_out_id_lists() {
        let weak_err = parse_classification_rules(r#"weak_anchor = ["flickr-api-key"]"#)
            .expect_err("weak_anchor must no longer be a valid classification field");
        assert!(
            weak_err.contains("weak_anchor") || weak_err.contains("unknown field"),
            "expected an unknown-field rejection for weak_anchor, got: {weak_err}"
        );

        let pkb_err = parse_classification_rules(r#"private_key_block = ["private-key"]"#)
            .expect_err("private_key_block must no longer be a valid classification field");
        assert!(
            pkb_err.contains("private_key_block") || pkb_err.contains("unknown field"),
            "expected an unknown-field rejection for private_key_block, got: {pkb_err}"
        );
    }
}

//! Stripe hot-path prefixes loaded from Tier-B data.
//!
//! Detector properties such as `weak_anchor` and `private_key_block` live in
//! each detector TOML. This module owns only the reusable Stripe prefix list.

use serde::Deserialize;
use std::collections::HashSet;
use std::sync::OnceLock;

const DETECTOR_CLASSIFICATION_TOML: &str =
    include_str!("../../../rules/stripe-hot-confirmed-prefixes.toml");

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

    #[test]
    fn parse_rejects_migrated_detector_property_lists() {
        assert!(parse_classification_rules(r#"weak_anchor = ["flickr-api-key"]"#).is_err());
        assert!(
            parse_classification_rules(r#"private_key_block = ["private-key"]"#).is_err()
        );
    }
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

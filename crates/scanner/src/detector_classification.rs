//! Detector classification overrides loaded from Tier-B data.

use serde::Deserialize;
use std::collections::HashSet;
use std::sync::OnceLock;

const DETECTOR_CLASSIFICATION_TOML: &str =
    include_str!("../../../rules/detector-classification.toml");

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetectorClassificationFile {
    #[serde(default)]
    weak_anchor: Vec<String>,
    #[serde(default)]
    private_key_block: Vec<String>,
    #[serde(default)]
    stripe_hot_confirmed_prefix: Vec<String>,
}

#[derive(Debug)]
pub(crate) struct DetectorClassification {
    weak_anchor: HashSet<String>,
    private_key_block: HashSet<String>,
    stripe_hot_confirmed_prefix: Vec<String>,
}

pub(crate) fn is_residual_weak_anchor(detector_id: &str) -> Result<bool, String> {
    classification_rules().map(|rules| rules.weak_anchor.contains(detector_id))
}

pub(crate) fn is_private_key_block_detector(detector_id: &str) -> Result<bool, String> {
    classification_rules().map(|rules| rules.private_key_block.contains(detector_id))
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
    let valid_detector_ids = crate::detector_catalog::bundled_detector_ids()?;
    validate_classification_ids("weak_anchor", &rules.weak_anchor, valid_detector_ids)?;
    validate_classification_ids(
        "private_key_block",
        &rules.private_key_block,
        valid_detector_ids,
    )?;
    validate_prefixes(
        "stripe_hot_confirmed_prefix",
        &rules.stripe_hot_confirmed_prefix,
    )?;
    Ok(DetectorClassification {
        weak_anchor: rules.weak_anchor.into_iter().collect(),
        private_key_block: rules.private_key_block.into_iter().collect(),
        stripe_hot_confirmed_prefix: rules.stripe_hot_confirmed_prefix,
    })
}

fn validate_classification_ids(
    rule_name: &str,
    detector_ids: &[String],
    valid_detector_ids: &HashSet<String>,
) -> Result<(), String> {
    let mut seen = HashSet::new();
    for detector_id in detector_ids {
        if detector_id.trim().is_empty() {
            return Err(format!(
                "detector classification {rule_name} has an empty detector id"
            ));
        }
        if !seen.insert(detector_id.as_str()) {
            return Err(format!(
                "detector classification {rule_name} lists detector '{detector_id}' more than once"
            ));
        }
    }
    crate::detector_catalog::validate_rule_detector_ids(
        &format!("detector classification {rule_name}"),
        detector_ids.iter().map(String::as_str),
        valid_detector_ids,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flickr_id() -> String {
        ["flickr", "api", "key"].join("-")
    }

    #[test]
    fn live_classification_rules_parse() {
        let rules = parse_classification_rules(DETECTOR_CLASSIFICATION_TOML).unwrap();

        assert!(rules.weak_anchor.contains(&flickr_id()));
        assert!(rules.private_key_block.contains("private-key"));
        assert!(rules
            .stripe_hot_confirmed_prefix
            .iter()
            .any(|prefix| prefix == "sk_live_"));
    }

    #[test]
    fn parse_rejects_duplicate_detector_ids() {
        let id = flickr_id();
        let err = parse_classification_rules(&format!(
            "weak_anchor = [{id:?}, {id:?}]\nprivate_key_block = []"
        ))
        .unwrap_err();

        assert!(err.contains("more than once"));
    }

    #[test]
    fn parse_rejects_unknown_detector_ids() {
        let err = parse_classification_rules(
            r#"
weak_anchor = ["missing-detector"]
"#,
        )
        .unwrap_err();

        assert!(err.contains("unknown detector 'missing-detector'"));
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

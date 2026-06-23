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
}

pub(crate) fn is_residual_weak_anchor(detector_id: &str) -> Result<bool, String> {
    residual_weak_anchor_ids().map(|detector_ids| detector_ids.contains(detector_id))
}

fn residual_weak_anchor_ids() -> Result<&'static HashSet<String>, String> {
    static WEAK_ANCHOR_IDS: OnceLock<Result<HashSet<String>, String>> = OnceLock::new();
    WEAK_ANCHOR_IDS
        .get_or_init(|| parse_classification_rules(DETECTOR_CLASSIFICATION_TOML))
        .as_ref()
        .map_err(Clone::clone)
}

fn parse_classification_rules(raw: &str) -> Result<HashSet<String>, String> {
    let rules: DetectorClassificationFile = toml::from_str(raw)
        .map_err(|error| format!("invalid detector classification rules: {error}"))?;
    validate_classification_ids(&rules.weak_anchor)?;
    Ok(rules.weak_anchor.into_iter().collect())
}

fn validate_classification_ids(detector_ids: &[String]) -> Result<(), String> {
    let mut seen = HashSet::new();
    for detector_id in detector_ids {
        if detector_id.trim().is_empty() {
            return Err("detector classification rule has an empty detector id".to_string());
        }
        if !seen.insert(detector_id.as_str()) {
            return Err(format!(
                "detector classification weak_anchor lists detector '{}' more than once",
                detector_id
            ));
        }
    }
    crate::detector_catalog::validate_rule_detector_ids(
        "detector classification weak_anchor",
        detector_ids.iter().map(String::as_str),
        crate::detector_catalog::bundled_detector_ids()?,
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
        let weak_anchors = parse_classification_rules(DETECTOR_CLASSIFICATION_TOML).unwrap();

        assert!(weak_anchors.contains(&flickr_id()));
    }

    #[test]
    fn parse_rejects_duplicate_detector_ids() {
        let id = flickr_id();
        let err =
            parse_classification_rules(&format!("weak_anchor = [{id:?}, {id:?}]")).unwrap_err();

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
}

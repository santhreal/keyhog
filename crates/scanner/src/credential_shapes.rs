//! Detector-owned credential shape rules loaded from Tier-B data.

use keyhog_core::DetectorSpec;
use serde::Deserialize;
use std::collections::HashSet;
use std::sync::OnceLock;

const CREDENTIAL_SHAPES_TOML: &str = include_str!("../../../rules/detector-credential-shapes.toml");

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct CredentialShapeRule {
    exact_length: Option<usize>,
    prefix: Option<String>,
    body_min_length: Option<usize>,
    body_max_length: Option<usize>,
}

impl CredentialShapeRule {
    pub(crate) fn allows(&self, credential: &str) -> bool {
        if self
            .exact_length
            .is_some_and(|expected| credential.len() != expected)
        {
            return false;
        }

        if let Some(prefix) = self.prefix.as_deref() {
            let Some(body) = credential.strip_prefix(prefix) else {
                return true;
            };
            if self
                .body_min_length
                .is_some_and(|minimum| body.len() < minimum)
            {
                return false;
            }
            if self
                .body_max_length
                .is_some_and(|maximum| body.len() > maximum)
            {
                return false;
            }
        }

        true
    }

    #[cfg(test)]
    pub(crate) fn exact_length_for_test(exact_length: usize) -> Self {
        Self {
            exact_length: Some(exact_length),
            prefix: None,
            body_min_length: None,
            body_max_length: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn prefix_body_range_for_test(
        prefix: &str,
        body_min_length: usize,
        body_max_length: usize,
    ) -> Self {
        Self {
            exact_length: None,
            prefix: Some(prefix.to_string()),
            body_min_length: Some(body_min_length),
            body_max_length: Some(body_max_length),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialShapeFile {
    #[serde(default)]
    shape: Vec<CredentialShapeEntry>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CredentialShapeEntry {
    detector: String,
    exact_length: Option<usize>,
    prefix: Option<String>,
    body_min_length: Option<usize>,
    body_max_length: Option<usize>,
}

pub(crate) fn build_detector_shape_rules(
    detectors: &[DetectorSpec],
) -> Result<Vec<Option<CredentialShapeRule>>, String> {
    let entries = parsed_shape_rules()?;
    crate::detector_catalog::validate_rule_detector_ids(
        "credential shape rule",
        entries.iter().map(|entry| entry.detector.as_str()),
        crate::detector_catalog::bundled_detector_ids()?,
    )?;
    Ok(detectors
        .iter()
        .map(|detector| {
            entries
                .iter()
                .find(|entry| entry.detector == detector.id)
                .map(CredentialShapeEntry::rule)
        })
        .collect())
}

fn parsed_shape_rules() -> Result<&'static [CredentialShapeEntry], String> {
    static SHAPE_RULES: OnceLock<Result<Vec<CredentialShapeEntry>, String>> = OnceLock::new();
    SHAPE_RULES
        .get_or_init(|| parse_shape_rules(CREDENTIAL_SHAPES_TOML))
        .as_ref()
        .map(Vec::as_slice)
        .map_err(Clone::clone)
}

fn parse_shape_rules(raw: &str) -> Result<Vec<CredentialShapeEntry>, String> {
    let file: CredentialShapeFile =
        toml::from_str(raw).map_err(|error| format!("invalid credential shape rules: {error}"))?;
    validate_shape_entries(&file.shape)?;
    Ok(file.shape)
}

fn validate_shape_entries(entries: &[CredentialShapeEntry]) -> Result<(), String> {
    let mut seen = HashSet::new();
    for entry in entries {
        if entry.detector.trim().is_empty() {
            return Err("credential shape rule has an empty detector id".to_string());
        }
        if !seen.insert(entry.detector.as_str()) {
            return Err(format!(
                "credential shape rules define detector '{}' more than once",
                entry.detector
            ));
        }
        if entry.exact_length.is_none()
            && entry.prefix.is_none()
            && entry.body_min_length.is_none()
            && entry.body_max_length.is_none()
        {
            return Err(format!(
                "credential shape rule for '{}' has no shape constraints",
                entry.detector
            ));
        }
        if entry.prefix.is_some()
            && entry.exact_length.is_none()
            && entry.body_min_length.is_none()
            && entry.body_max_length.is_none()
        {
            return Err(format!(
                "credential shape rule for '{}' has a prefix but no length constraint",
                entry.detector
            ));
        }
        if entry.exact_length == Some(0) {
            return Err(format!(
                "credential shape rule for '{}' has exact_length=0",
                entry.detector
            ));
        }
        if entry.prefix.as_deref() == Some("") {
            return Err(format!(
                "credential shape rule for '{}' has an empty prefix",
                entry.detector
            ));
        }
        if let (Some(minimum), Some(maximum)) = (entry.body_min_length, entry.body_max_length) {
            if minimum > maximum {
                return Err(format!(
                    "credential shape rule for '{}' has body_min_length greater than body_max_length",
                    entry.detector
                ));
            }
        }
        if (entry.body_min_length.is_some() || entry.body_max_length.is_some())
            && entry.prefix.is_none()
        {
            return Err(format!(
                "credential shape rule for '{}' sets body length without a prefix",
                entry.detector
            ));
        }
        if let (Some(exact_length), Some(prefix)) = (entry.exact_length, entry.prefix.as_deref()) {
            if let Some(minimum) = entry.body_min_length {
                let minimum_total = prefix.len().checked_add(minimum).ok_or_else(|| {
                    format!(
                        "credential shape rule for '{}' overflows prefix plus body_min_length",
                        entry.detector
                    )
                })?;
                if exact_length < minimum_total {
                    return Err(format!(
                        "credential shape rule for '{}' has exact_length below prefix plus body_min_length",
                        entry.detector
                    ));
                }
            }
            if let Some(maximum) = entry.body_max_length {
                let maximum_total = prefix.len().checked_add(maximum).ok_or_else(|| {
                    format!(
                        "credential shape rule for '{}' overflows prefix plus body_max_length",
                        entry.detector
                    )
                })?;
                if exact_length > maximum_total {
                    return Err(format!(
                        "credential shape rule for '{}' has exact_length above prefix plus body_max_length",
                        entry.detector
                    ));
                }
            }
        }
    }
    Ok(())
}

impl CredentialShapeEntry {
    fn rule(&self) -> CredentialShapeRule {
        CredentialShapeRule {
            exact_length: self.exact_length,
            prefix: self.prefix.clone(),
            body_min_length: self.body_min_length,
            body_max_length: self.body_max_length,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn aws_access_key_id() -> String {
        ["aws", "access", "key"].join("-")
    }

    fn anthropic_api_key_id() -> String {
        ["anthropic", "api", "key"].join("-")
    }

    #[test]
    fn exact_length_rule_rejects_wrong_length() {
        let rule = CredentialShapeRule::exact_length_for_test(20);

        assert!(rule.allows("AKIAIOSFODNN7EXAMPLE"));
        assert!(!rule.allows("AKIAIOSFODNN7EXAMPL"));
    }

    #[test]
    fn prefix_body_range_only_applies_to_matching_prefix() {
        let rule = CredentialShapeRule::prefix_body_range_for_test("sk-ant-api03-", 80, 120);
        let valid_legacy = format!("sk-ant-api03-{}", "a".repeat(80));

        assert!(rule.allows(&valid_legacy));
        assert!(!rule.allows("sk-ant-api03-short"));
        assert!(rule.allows("sk-ant-modern-key-shape-not-owned-by-this-rule"));
    }

    #[test]
    fn parse_rejects_duplicate_detector_rules() {
        let err = parse_shape_rules(
            r#"
[[shape]]
detector = "same"
exact_length = 20

[[shape]]
detector = "same"
exact_length = 21
"#,
        )
        .unwrap_err();

        assert!(err.contains("more than once"));
    }

    #[test]
    fn parse_rejects_body_range_without_prefix() {
        let err = parse_shape_rules(
            r#"
[[shape]]
detector = "bad"
body_min_length = 80
"#,
        )
        .unwrap_err();

        assert!(err.contains("body length without a prefix"));
    }

    #[test]
    fn parse_rejects_inverted_body_range() {
        let err = parse_shape_rules(
            r#"
[[shape]]
detector = "bad"
prefix = "sk-"
body_min_length = 120
body_max_length = 80
"#,
        )
        .unwrap_err();

        assert!(err.contains("body_min_length greater than body_max_length"));
    }

    #[test]
    fn live_credential_shape_rules_parse() {
        let rules = parse_shape_rules(CREDENTIAL_SHAPES_TOML).unwrap();

        assert!(rules
            .iter()
            .any(|entry| entry.detector == aws_access_key_id()));
        assert!(rules
            .iter()
            .any(|entry| entry.detector == anthropic_api_key_id()));
    }

    #[test]
    fn build_rejects_shape_rule_for_unknown_detector() {
        let entries = parse_shape_rules(
            r#"
[[shape]]
detector = "missing"
exact_length = 20
"#,
        )
        .unwrap();
        let detector_ids = ["present".to_string()].into_iter().collect();
        let err = crate::detector_catalog::validate_rule_detector_ids(
            "credential shape rule",
            entries.iter().map(|entry| entry.detector.as_str()),
            &detector_ids,
        )
        .unwrap_err();

        assert!(err.contains("unknown detector 'missing'"));
    }

    #[test]
    fn build_maps_live_shape_rules_to_loaded_detector_ids() {
        let aws = DetectorSpec {
            id: aws_access_key_id(),
            ..DetectorSpec::default()
        };
        let anthropic = DetectorSpec {
            id: anthropic_api_key_id(),
            ..DetectorSpec::default()
        };

        let rules = build_detector_shape_rules(&[aws, anthropic]).unwrap();

        assert_eq!(rules.len(), 2);
        assert!(rules[0].as_ref().is_some_and(|rule| {
            rule.allows("AKIAIOSFODNN7EXAMPLE") && !rule.allows("AKIAIOSFODNN7EXAMPL")
        }));
        assert!(rules[1]
            .as_ref()
            .is_some_and(|rule| !rule.allows("sk-ant-api03-short")));
    }

    #[test]
    fn parse_rejects_prefix_without_length_constraint() {
        let err = parse_shape_rules(
            r#"
[[shape]]
detector = "bad"
prefix = "sk-"
"#,
        )
        .unwrap_err();

        assert!(err.contains("prefix but no length constraint"));
    }

    #[test]
    fn parse_rejects_exact_length_below_prefix_minimum() {
        let err = parse_shape_rules(
            r#"
[[shape]]
detector = "bad"
exact_length = 20
prefix = "sk-ant-api03-"
body_min_length = 80
"#,
        )
        .unwrap_err();

        assert!(err.contains("exact_length below prefix plus body_min_length"));
    }

    #[test]
    fn parse_rejects_exact_length_above_prefix_maximum() {
        let err = parse_shape_rules(
            r#"
[[shape]]
detector = "bad"
exact_length = 200
prefix = "sk-ant-api03-"
body_max_length = 80
"#,
        )
        .unwrap_err();

        assert!(err.contains("exact_length above prefix plus body_max_length"));
    }
}

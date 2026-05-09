//! Declarative rule-based finding suppression.
//!
//! Loads a `.keyhogignore.toml` file alongside the legacy line-based
//! `.keyhogignore`. Each `[[suppress]]` table compiles into a vyre
//! `RuleFormula` evaluated per-finding via vyre's CPU evaluator
//! (`vyre_libs::rule::evaluate_formula`). Findings whose rules
//! evaluate to `true` are dropped from the report — same semantics
//! as the line-based allowlist, just composable.
//!
//! Schema (one or more `[[suppress]]` tables):
//!
//! ```toml
//! # Drop every aws-access-key finding inside test directories.
//! [[suppress]]
//! detector = "aws-access-key"
//! path_contains = "/tests/"
//!
//! # Drop low-severity stripe findings on a specific file.
//! [[suppress]]
//! service = "stripe"
//! severity_lte = "low"
//! path_eq = "fixtures/stripe.yml"
//!
//! # Drop a single credential by hash, regardless of where it
//! # appears (mirrors the legacy `hash:` entry in .keyhogignore).
//! [[suppress]]
//! credential_hash = "5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8"
//! ```
//!
//! Within one `[[suppress]]` the named fields combine with AND.
//! Across multiple `[[suppress]]` tables they combine with OR (any
//! suppress matching the finding drops it). All conditions are
//! optional; a `[[suppress]]` table with no condition matches every
//! finding (use `LiteralTrue` if you want that explicit).
//!
//! Why this lives in `keyhog-core`: the rule engine is general
//! infra (it consumes vyre's CPU evaluator) but the schema is
//! keyhog-specific (FindingContext shape). The vyre side stays
//! consumer-agnostic.

use std::path::Path;
use std::sync::Arc;

use serde::Deserialize;
use vyre_libs::rule::{evaluate_formula, RuleCondition, RuleEvaluationContext, RuleFormula};

use crate::{Severity, VerifiedFinding};

/// Parsed `.keyhogignore.toml` — a list of `[[suppress]]` rules,
/// each compiled into a `RuleFormula`.
#[derive(Debug, Default)]
pub struct RuleSuppressor {
    rules: Vec<RuleFormula>,
}

/// One `[[suppress]]` table from the TOML.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SuppressEntry {
    /// Detector ID exact match (e.g. `"aws-access-key"`).
    detector: Option<String>,
    /// Service exact match (e.g. `"stripe"`).
    service: Option<String>,
    /// Severity equals — case-insensitive (info / low / medium / high / critical).
    severity: Option<String>,
    /// Severity ≤ — finding's severity must be at most this rank.
    severity_lte: Option<String>,
    /// File path exact match.
    path_eq: Option<String>,
    /// File path contains substring.
    path_contains: Option<String>,
    /// File path starts with prefix.
    path_starts_with: Option<String>,
    /// File path ends with suffix.
    path_ends_with: Option<String>,
    /// File path matches regex.
    path_regex: Option<String>,
    /// Credential SHA-256 hash exact match (mirrors legacy
    /// `.keyhogignore` `hash:<sha>` entries).
    credential_hash: Option<String>,
}

/// File around which a `RuleFormula` is evaluated. One per finding.
struct FindingContext<'a> {
    detector_id: &'a str,
    service: &'a str,
    severity: Severity,
    path: &'a str,
    credential_hash: &'a str,
}

impl<'a> RuleEvaluationContext for FindingContext<'a> {
    fn field_value(&self, name: &str) -> Option<&str> {
        match name {
            "detector_id" => Some(self.detector_id),
            "service" => Some(self.service),
            "path" => Some(self.path),
            "credential_hash" => Some(self.credential_hash),
            "severity" => Some(self.severity_str()),
            _ => None,
        }
    }
}

impl<'a> FindingContext<'a> {
    fn severity_str(&self) -> &'static str {
        match self.severity {
            Severity::Info => "info",
            Severity::Low => "low",
            Severity::Medium => "medium",
            Severity::High => "high",
            Severity::Critical => "critical",
        }
    }
}

impl RuleSuppressor {
    /// Build an empty suppressor — matches no findings.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Load from a TOML path. Returns `Ok(empty())` when the file
    /// is missing (matches the legacy `.keyhogignore` behaviour) so
    /// callers don't need to gate on existence.
    pub fn load(path: &Path) -> Result<Self, RuleSuppressorError> {
        if !path.exists() {
            return Ok(Self::empty());
        }
        let raw = std::fs::read_to_string(path).map_err(RuleSuppressorError::Io)?;
        Self::parse(&raw)
    }

    /// Parse a TOML string. Useful for tests.
    pub fn parse(toml_text: &str) -> Result<Self, RuleSuppressorError> {
        #[derive(Deserialize)]
        struct Doc {
            #[serde(default)]
            suppress: Vec<SuppressEntry>,
        }
        let doc: Doc = toml::from_str(toml_text).map_err(RuleSuppressorError::Toml)?;
        let mut rules = Vec::with_capacity(doc.suppress.len());
        for (idx, entry) in doc.suppress.into_iter().enumerate() {
            rules.push(entry_to_formula(&entry).map_err(|e| {
                RuleSuppressorError::Schema {
                    rule_index: idx,
                    message: e,
                }
            })?);
        }
        Ok(Self { rules })
    }

    /// `true` when at least one rule matches and the finding should
    /// be dropped. Empty suppressor → always `false` (no
    /// suppressions, which matches `Self::empty()`'s contract).
    #[must_use]
    pub fn matches(&self, finding: &VerifiedFinding) -> bool {
        if self.rules.is_empty() {
            return false;
        }
        let path = finding
            .location
            .file_path
            .as_deref()
            .map(|s| s.as_ref())
            .unwrap_or("");
        let ctx = FindingContext {
            detector_id: finding.detector_id.as_ref(),
            service: finding.service.as_ref(),
            severity: finding.severity,
            path,
            credential_hash: finding.credential_hash.as_str(),
        };
        self.rules
            .iter()
            .any(|rule| evaluate_formula(rule, &ctx))
    }

    /// Number of compiled rules.
    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }
}

fn entry_to_formula(entry: &SuppressEntry) -> Result<RuleFormula, String> {
    let mut conditions: Vec<RuleCondition> = Vec::new();

    if let Some(d) = entry.detector.as_deref() {
        conditions.push(eq_field("detector_id", d));
    }
    if let Some(s) = entry.service.as_deref() {
        conditions.push(eq_field("service", s));
    }
    if let Some(s) = entry.severity.as_deref() {
        conditions.push(eq_field("severity", &normalise_severity(s)?));
    }
    if let Some(s) = entry.severity_lte.as_deref() {
        // severity_lte over the curated rank set.
        let max = severity_rank(&normalise_severity(s)?)?;
        let allowed: smallvec::SmallVec<[Arc<str>; 4]> = (0..=max)
            .map(|r| Arc::from(severity_label(r)))
            .collect();
        conditions.push(RuleCondition::FieldInSet {
            field: "severity".into(),
            set: allowed,
        });
    }
    if let Some(p) = entry.path_eq.as_deref() {
        conditions.push(RuleCondition::FieldInSet {
            field: "path".into(),
            set: smallvec::smallvec![Arc::from(p)],
        });
    }
    if let Some(p) = entry.path_contains.as_deref() {
        conditions.push(RuleCondition::SubstringMatch {
            haystack: "path".into(),
            needle: Arc::from(p),
        });
    }
    if let Some(p) = entry.path_starts_with.as_deref() {
        conditions.push(RuleCondition::PrefixMatch {
            value: "path".into(),
            prefix: Arc::from(p),
        });
    }
    if let Some(p) = entry.path_ends_with.as_deref() {
        conditions.push(RuleCondition::SuffixMatch {
            value: "path".into(),
            suffix: Arc::from(p),
        });
    }
    if let Some(p) = entry.path_regex.as_deref() {
        conditions.push(RuleCondition::RegexMatch {
            field: "path".into(),
            pattern: Arc::from(p),
        });
    }
    if let Some(h) = entry.credential_hash.as_deref() {
        conditions.push(eq_field("credential_hash", h));
    }

    if conditions.is_empty() {
        // Empty `[[suppress]]` table is almost always a typo. Refuse
        // rather than silently matching every finding.
        return Err(
            "no conditions specified in [[suppress]] entry; \
             use `[[suppress]]\\nliteral_true = true` if you really want \
             to drop every finding"
                .into(),
        );
    }

    // AND of all conditions inside one [[suppress]] table.
    let mut iter = conditions.into_iter();
    let first = iter.next().unwrap();
    let mut formula = RuleFormula::condition(first);
    for cond in iter {
        formula = RuleFormula::and(formula, RuleFormula::condition(cond));
    }
    Ok(formula)
}

fn eq_field(field: &'static str, value: &str) -> RuleCondition {
    RuleCondition::FieldInSet {
        field: field.into(),
        set: smallvec::smallvec![Arc::from(value)],
    }
}

fn normalise_severity(s: &str) -> Result<String, String> {
    let lower = s.trim().to_ascii_lowercase();
    match lower.as_str() {
        "info" | "low" | "medium" | "high" | "critical" => Ok(lower),
        other => Err(format!(
            "unknown severity {other:?}; expected info|low|medium|high|critical"
        )),
    }
}

fn severity_rank(s: &str) -> Result<usize, String> {
    match s {
        "info" => Ok(0),
        "low" => Ok(1),
        "medium" => Ok(2),
        "high" => Ok(3),
        "critical" => Ok(4),
        other => Err(format!("unknown severity rank {other:?}")),
    }
}

fn severity_label(rank: usize) -> &'static str {
    match rank {
        0 => "info",
        1 => "low",
        2 => "medium",
        3 => "high",
        _ => "critical",
    }
}

/// Errors from loading or parsing `.keyhogignore.toml`.
#[derive(Debug)]
pub enum RuleSuppressorError {
    /// Filesystem read failed.
    Io(std::io::Error),
    /// TOML deserialisation failed.
    Toml(toml::de::Error),
    /// One `[[suppress]]` entry failed schema validation.
    Schema {
        /// Zero-based index of the offending `[[suppress]]` entry.
        rule_index: usize,
        /// Human-readable message.
        message: String,
    },
}

impl std::fmt::Display for RuleSuppressorError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(e) => write!(f, "reading .keyhogignore.toml: {e}"),
            Self::Toml(e) => write!(f, "parsing .keyhogignore.toml: {e}"),
            Self::Schema { rule_index, message } => write!(
                f,
                "schema error in [[suppress]] entry {rule_index}: {message}"
            ),
        }
    }
}

impl std::error::Error for RuleSuppressorError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{MatchLocation, VerificationResult};
    use std::collections::HashMap;

    fn finding(detector: &str, service: &str, sev: Severity, path: &str, hash: &str) -> VerifiedFinding {
        VerifiedFinding {
            detector_id: Arc::from(detector),
            detector_name: Arc::from(detector),
            service: Arc::from(service),
            severity: sev,
            credential_redacted: std::borrow::Cow::Borrowed("REDACTED"),
            credential_hash: hash.to_string(),
            location: MatchLocation {
                source: Arc::from("filesystem"),
                file_path: Some(Arc::from(path)),
                line: Some(1),
                offset: 0,
                commit: None,
                author: None,
                date: None,
            },
            verification: VerificationResult::Skipped,
            metadata: HashMap::new(),
            additional_locations: Vec::new(),
            confidence: Some(0.9),
        }
    }

    #[test]
    fn empty_suppressor_matches_nothing() {
        let s = RuleSuppressor::empty();
        let f = finding("aws-access-key", "aws", Severity::Critical, "src/a.rs", "h1");
        assert!(!s.matches(&f));
    }

    #[test]
    fn detector_match_only() {
        let toml = r#"
[[suppress]]
detector = "aws-access-key"
"#;
        let s = RuleSuppressor::parse(toml).expect("parse");
        let aws = finding("aws-access-key", "aws", Severity::Critical, "x.rs", "h1");
        let github = finding("github-pat", "github", Severity::Critical, "x.rs", "h2");
        assert!(s.matches(&aws));
        assert!(!s.matches(&github));
    }

    #[test]
    fn detector_and_path_combine_with_and() {
        let toml = r#"
[[suppress]]
detector = "aws-access-key"
path_contains = "/tests/"
"#;
        let s = RuleSuppressor::parse(toml).expect("parse");
        let aws_in_test = finding(
            "aws-access-key",
            "aws",
            Severity::Critical,
            "src/tests/fixtures.rs",
            "h",
        );
        let aws_in_src = finding(
            "aws-access-key",
            "aws",
            Severity::Critical,
            "src/main.rs",
            "h",
        );
        let stripe_in_test = finding(
            "stripe",
            "stripe",
            Severity::Critical,
            "src/tests/fixtures.rs",
            "h",
        );
        assert!(s.matches(&aws_in_test));
        assert!(!s.matches(&aws_in_src));
        assert!(!s.matches(&stripe_in_test));
    }

    #[test]
    fn multiple_suppress_combine_with_or() {
        let toml = r#"
[[suppress]]
detector = "aws-access-key"

[[suppress]]
detector = "github-pat"
"#;
        let s = RuleSuppressor::parse(toml).expect("parse");
        assert_eq!(s.len(), 2);
        assert!(s.matches(&finding("aws-access-key", "aws", Severity::Critical, "x", "h1")));
        assert!(s.matches(&finding("github-pat", "github", Severity::Critical, "x", "h2")));
        assert!(!s.matches(&finding("stripe", "stripe", Severity::Critical, "x", "h3")));
    }

    #[test]
    fn severity_lte_matches_at_or_below_threshold() {
        let toml = r#"
[[suppress]]
detector = "aws-access-key"
severity_lte = "medium"
"#;
        let s = RuleSuppressor::parse(toml).expect("parse");
        for (sev, expect) in [
            (Severity::Info, true),
            (Severity::Low, true),
            (Severity::Medium, true),
            (Severity::High, false),
            (Severity::Critical, false),
        ] {
            let f = finding("aws-access-key", "aws", sev, "x", "h");
            assert_eq!(s.matches(&f), expect, "severity={sev:?}");
        }
    }

    #[test]
    fn path_predicates_combine() {
        let toml = r#"
[[suppress]]
path_starts_with = "vendor/"

[[suppress]]
path_ends_with = ".min.js"

[[suppress]]
path_regex = "^docs/[a-z]+\\.md$"
"#;
        let s = RuleSuppressor::parse(toml).expect("parse");
        let v = |p: &str| finding("any", "any", Severity::High, p, "h");
        assert!(s.matches(&v("vendor/lib/foo.rs")));
        assert!(s.matches(&v("dist/app.min.js")));
        assert!(s.matches(&v("docs/readme.md")));
        assert!(!s.matches(&v("src/main.rs")));
    }

    #[test]
    fn credential_hash_eq_matches() {
        let toml = r#"
[[suppress]]
credential_hash = "deadbeefdeadbeefdeadbeefdeadbeef"
"#;
        let s = RuleSuppressor::parse(toml).expect("parse");
        assert!(s.matches(&finding(
            "x", "x", Severity::High, "p", "deadbeefdeadbeefdeadbeefdeadbeef"
        )));
        assert!(!s.matches(&finding("x", "x", Severity::High, "p", "feedfacefeedfacefeedfacefeedface")));
    }

    #[test]
    fn missing_file_returns_empty() {
        let path = std::path::PathBuf::from("/nonexistent/.keyhogignore.toml");
        let s = RuleSuppressor::load(&path).expect("load");
        assert!(s.is_empty());
    }

    #[test]
    fn empty_suppress_entry_is_rejected() {
        let toml = r#"
[[suppress]]
"#;
        let err = RuleSuppressor::parse(toml).expect_err("must reject");
        let msg = format!("{err}");
        assert!(msg.contains("no conditions"), "got: {msg}");
    }

    #[test]
    fn unknown_field_is_rejected() {
        let toml = r#"
[[suppress]]
not_a_field = "x"
"#;
        let err = RuleSuppressor::parse(toml).expect_err("must reject");
        let msg = format!("{err}");
        // serde's deny_unknown_fields produces a message naming the
        // bad field; just verify it errors.
        assert!(msg.contains("not_a_field") || msg.contains("unknown"), "got: {msg}");
    }

    #[test]
    fn unknown_severity_is_rejected() {
        let toml = r#"
[[suppress]]
detector = "x"
severity = "panic"
"#;
        let err = RuleSuppressor::parse(toml).expect_err("must reject");
        let msg = format!("{err}");
        assert!(msg.contains("severity"), "got: {msg}");
    }
}

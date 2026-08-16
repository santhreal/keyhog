//! Declarative rule-based finding suppression.
//!
//! Loads a `.keyhogignore.toml` file alongside the legacy line-based
//! `.keyhogignore`. Each `[[suppress]]` table compiles into a vyre
//! `RuleFormula` evaluated per-finding via VYRE CPU evaluator
//! (`vyre_libs::rule::evaluate_formula`). Findings whose rules
//! evaluate to `true` are dropped from the report.
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
//! optional; a `[[suppress]]` table with no condition is rejected.
//! Use `literal_true = true` to request an explicit match-everything rule.

use std::path::Path;
use std::sync::Arc;

use serde::Deserialize;
use vyre_libs::rule::{evaluate_formula, RuleCondition, RuleEvaluationContext, RuleFormula};

use crate::{RawMatch, Severity, VerifiedFinding};

/// Parsed `.keyhogignore.toml` containing a list of `[[suppress]]` rules,
/// each compiled into a `RuleFormula`.
#[derive(Debug, Default)]
pub struct RuleSuppressor {
    rules: Vec<RuleFormula>,
}

/// One `[[suppress]]` table from the TOML.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct SuppressEntry {
    /// Explicit match-everything predicate. Kept noisy on purpose: an empty
    /// table is rejected so a missing or typoed condition cannot suppress every
    /// finding accidentally.
    #[serde(default)]
    literal_true: bool,
    /// Detector ID exact match (e.g. `"aws-access-key"`).
    detector: Option<String>,
    /// Service exact match (e.g. `"stripe"`).
    service: Option<String>,
    /// Severity equals (case-insensitive: info, client-safe, low, medium, high, critical).
    severity: Option<String>,
    /// Severity <= (finding severity must be at most this rank).
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
    /// Credential SHA-256 hash exact match.
    credential_hash: Option<String>,
}

/// File context around which a `RuleFormula` is evaluated. One per finding.
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
            "severity" => Some(self.severity.as_str()),
            _ => None,
        }
    }
}

/// Trim leading and trailing ASCII whitespace from a byte slice.
#[inline]
pub fn trim_ascii_whitespace(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    while start < bytes.len() && bytes[start].is_ascii_whitespace() {
        start += 1;
    }
    let mut end = bytes.len();
    while end > start && bytes[end - 1].is_ascii_whitespace() {
        end -= 1;
    }
    &bytes[start..end]
}

/// Trim leading and trailing ASCII whitespace from a string slice without allocation.
#[inline]
pub fn trim_ascii_str(s: &str) -> &str {
    let bytes = s.as_bytes();
    let trimmed = trim_ascii_whitespace(bytes);
    let start = trimmed.as_ptr() as usize - bytes.as_ptr() as usize;
    &s[start..start + trimmed.len()]
}

/// Split a byte slice by delimiter, trimming ASCII whitespace from each non-empty slice.
#[inline]
pub fn split_byte_tokens(bytes: &[u8], delimiter: u8) -> impl Iterator<Item = &[u8]> {
    bytes
        .split(move |&b| b == delimiter)
        .map(trim_ascii_whitespace)
        .filter(|slice| !slice.is_empty())
}

/// Return severity rank using canonical Severity table.
pub(crate) fn severity_rank_from_str(s: &str) -> Result<usize, String> {
    Severity::from_filter_label(s)
        .map(|sev| sev.rank())
        .ok_or_else(|| {
            format!(
                "unknown severity {:?}; expected {}",
                s.trim().to_ascii_lowercase(),
                Severity::FILTER_EXPECTED_LABELS
            )
        })
}

/// Check if character is a regular expression metacharacter.
#[inline]
fn is_regex_meta(c: char) -> bool {
    matches!(
        c,
        '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$'
    )
}

impl RuleSuppressor {
    /// Build an empty suppressor that matches no findings.
    pub fn empty() -> Self {
        Self::default()
    }

    /// Load from a TOML path. Returns `Ok(empty())` when the file
    /// is missing so callers do not need to gate on existence.
    pub(crate) fn load(path: &Path) -> Result<Self, RuleSuppressorError> {
        if !path.exists() {
            return Ok(Self::empty());
        }
        let bytes = crate::state_file::read_capped(
            path,
            crate::state_file::RULE_CONFIG_FILE_BYTES,
            "suppression rules",
        )
        .map_err(RuleSuppressorError::Io)?;
        let raw = String::from_utf8(bytes).map_err(|e| {
            RuleSuppressorError::Io(std::io::Error::new(std::io::ErrorKind::InvalidData, e))
        })?;
        Self::parse(&raw)
    }

    /// Parse a TOML string.
    pub(crate) fn parse(toml_text: &str) -> Result<Self, RuleSuppressorError> {
        #[derive(Deserialize)]
        struct Doc {
            #[serde(default)]
            suppress: Vec<SuppressEntry>,
        }
        let doc: Doc = toml::from_str(toml_text).map_err(RuleSuppressorError::Toml)?;
        let mut rules = Vec::with_capacity(doc.suppress.len());
        for (idx, entry) in doc.suppress.into_iter().enumerate() {
            rules.push(
                entry_to_formula(&entry).map_err(|e| RuleSuppressorError::Schema {
                    rule_index: idx,
                    message: e,
                })?,
            );
        }
        Ok(Self { rules })
    }

    /// True when at least one rule matches and the finding should be dropped.
    #[must_use]
    pub fn matches(&self, finding: &VerifiedFinding) -> bool {
        self.matches_identity(
            finding.detector_id.as_ref(),
            finding.service.as_ref(),
            finding.severity,
            finding.location.file_path.as_deref(),
            &finding.credential_hash,
        )
    }

    /// Same predicate as [`Self::matches`] for a pre-verify [`RawMatch`].
    #[must_use]
    pub fn matches_raw_match(&self, matched: &RawMatch) -> bool {
        self.matches_identity(
            matched.detector_id.as_ref(),
            matched.service.as_ref(),
            matched.severity,
            matched.location.file_path.as_deref(),
            &matched.credential_hash,
        )
    }

    /// Shared rule evaluation over identity fields.
    #[must_use]
    pub fn matches_identity(
        &self,
        detector_id: &str,
        service: &str,
        severity: crate::Severity,
        file_path: Option<&str>,
        credential_hash: &crate::CredentialHash,
    ) -> bool {
        if self.rules.is_empty() {
            return false;
        }
        let path = file_path.unwrap_or("");
        let credential_hash_hex = crate::finding::hex_encode(credential_hash);
        let ctx = FindingContext {
            detector_id,
            service,
            severity,
            path,
            credential_hash: &credential_hash_hex,
        };
        self.rules.iter().any(|rule| evaluate_formula(rule, &ctx))
    }
}

impl std::str::FromStr for RuleSuppressor {
    type Err = RuleSuppressorError;

    fn from_str(toml_text: &str) -> Result<Self, Self::Err> {
        Self::parse(toml_text)
    }
}

/// Single owner for the empty table rejection message.
const NO_CONDITIONS_ERR: &str = "no conditions specified in [[suppress]] entry; \
     use `[[suppress]]\\nliteral_true = true` if you really want \
     to drop every finding";

fn entry_to_formula(entry: &SuppressEntry) -> Result<RuleFormula, String> {
    let mut conditions: Vec<RuleCondition> = Vec::new();

    if entry.literal_true {
        conditions.push(RuleCondition::LiteralTrue);
    }

    if let Some(d) = entry.detector.as_deref() {
        let trimmed = trim_ascii_str(d);
        conditions.push(eq_field("detector_id", trimmed));
    }
    if let Some(s) = entry.service.as_deref() {
        let trimmed = trim_ascii_str(s);
        conditions.push(eq_field("service", trimmed));
    }
    if let Some(s) = entry.severity.as_deref() {
        let normalized = Severity::from_filter_label(s)
            .map(|sev| sev.as_str())
            .ok_or_else(|| {
                format!(
                    "unknown severity {:?}; expected {}",
                    s.trim().to_ascii_lowercase(),
                    Severity::FILTER_EXPECTED_LABELS
                )
            })?;
        conditions.push(eq_field("severity", normalized));
    }
    if let Some(s) = entry.severity_lte.as_deref() {
        let max = severity_rank_from_str(s)?;
        let allowed: smallvec::SmallVec<[Arc<str>; 4]> = (0..=max)
            .map(|r| Arc::from(Severity::label_for_rank(r)))
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
        // Optimize exact literal path rules to avoid regex allocation and evaluation.
        if p.starts_with('^') && p.ends_with('$') && p.len() >= 2 {
            let inner = &p[1..p.len() - 1];
            if !inner.is_empty() && !inner.chars().any(is_regex_meta) {
                conditions.push(RuleCondition::FieldInSet {
                    field: "path".into(),
                    set: smallvec::smallvec![Arc::from(inner)],
                });
            } else {
                conditions.push(RuleCondition::RegexMatch {
                    field: "path".into(),
                    pattern: Arc::from(p),
                });
            }
        } else if p.starts_with('^') && p.ends_with(".*") && p.len() >= 3 {
            let inner = &p[1..p.len() - 2];
            if !inner.is_empty() && !inner.chars().any(is_regex_meta) {
                conditions.push(RuleCondition::PrefixMatch {
                    value: "path".into(),
                    prefix: Arc::from(inner),
                });
            } else {
                conditions.push(RuleCondition::RegexMatch {
                    field: "path".into(),
                    pattern: Arc::from(p),
                });
            }
        } else if p.starts_with('^') && p.len() > 1 {
            let inner = &p[1..];
            if !inner.is_empty() && !inner.chars().any(is_regex_meta) {
                conditions.push(RuleCondition::PrefixMatch {
                    value: "path".into(),
                    prefix: Arc::from(inner),
                });
            } else {
                conditions.push(RuleCondition::RegexMatch {
                    field: "path".into(),
                    pattern: Arc::from(p),
                });
            }
        } else if p.ends_with('$') && p.len() > 1 {
            let inner = &p[..p.len() - 1];
            if !inner.is_empty() && !inner.chars().any(is_regex_meta) {
                conditions.push(RuleCondition::SuffixMatch {
                    value: "path".into(),
                    suffix: Arc::from(inner),
                });
            } else {
                conditions.push(RuleCondition::RegexMatch {
                    field: "path".into(),
                    pattern: Arc::from(p),
                });
            }
        } else if p.starts_with(".*") && p.ends_with(".*") && p.len() >= 4 {
            let inner = &p[2..p.len() - 2];
            if !inner.is_empty() && !inner.chars().any(is_regex_meta) {
                conditions.push(RuleCondition::SubstringMatch {
                    haystack: "path".into(),
                    needle: Arc::from(inner),
                });
            } else {
                conditions.push(RuleCondition::RegexMatch {
                    field: "path".into(),
                    pattern: Arc::from(p),
                });
            }
        } else if !p.is_empty() && !p.chars().any(is_regex_meta) {
            conditions.push(RuleCondition::SubstringMatch {
                haystack: "path".into(),
                needle: Arc::from(p),
            });
        } else {
            conditions.push(RuleCondition::RegexMatch {
                field: "path".into(),
                pattern: Arc::from(p),
            });
        }
    }
    if let Some(h) = entry.credential_hash.as_deref() {
        let trimmed = trim_ascii_str(h);
        conditions.push(eq_field("credential_hash", trimmed));
    }

    if conditions.is_empty() {
        return Err(NO_CONDITIONS_ERR.into());
    }

    let mut iter = conditions.into_iter();
    let Some(first) = iter.next() else {
        return Err(NO_CONDITIONS_ERR.into());
    };
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

/// Errors from loading or parsing `.keyhogignore.toml`.
#[derive(Debug)]
pub enum RuleSuppressorError {
    /// Filesystem read failed.
    Io(std::io::Error),
    /// TOML deserialization failed.
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
            Self::Schema {
                rule_index,
                message,
            } => write!(
                f,
                "schema error in [[suppress]] entry {rule_index}: {message}"
            ),
        }
    }
}

impl std::error::Error for RuleSuppressorError {}

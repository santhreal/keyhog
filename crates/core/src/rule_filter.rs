//! Declarative rule-based finding suppression.
//!
//! Loads a `.keyhogignore.toml` file alongside the legacy line-based
//! `.keyhogignore`. Each `[[suppress]]` table compiles into a vyre
//! `RuleFormula` evaluated per-finding via vyre's CPU evaluator
//! (`vyre_libs::rule::evaluate_formula`). Findings whose rules
//! evaluate to `true` are dropped from the report - same semantics
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

/// Parsed `.keyhogignore.toml` - a list of `[[suppress]]` rules,
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
    /// Severity equals - case-insensitive (info / low / medium / high / critical).
    severity: Option<String>,
    /// Severity ≤ - finding's severity must be at most this rank.
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
            // `Severity::as_str` is the single source of truth for the
            // kebab-case wire form; rehand-rolling the match here drifted
            // from it once already (the `client-safe` tier).
            "severity" => Some(self.severity.as_str()),
            _ => None,
        }
    }
}

impl RuleSuppressor {
    /// Build an empty suppressor - matches no findings.
    fn empty() -> Self {
        Self::default()
    }

    /// Load from a TOML path. Returns `Ok(empty())` when the file
    /// is missing (matches the legacy `.keyhogignore` behaviour) so
    /// callers don't need to gate on existence.
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

    /// Parse a TOML string. Useful for tests.
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

    /// `true` when at least one rule matches and the finding should
    /// be dropped. Empty suppressor → always `false` (no
    /// suppressions, which matches `Self::empty()`'s contract).
    #[must_use]
    pub fn matches(&self, finding: &VerifiedFinding) -> bool {
        if self.rules.is_empty() {
            return false;
        }
        // Law 10: recall-safe (fail-OPEN for suppression), a finding with no
        // file_path yields `""`, which a path-scoped suppression rule will not
        // match, so the finding is LESS likely to be suppressed and MORE likely
        // to be reported. A missing path can never silently drop a real finding.
        let path = finding.location.file_path.as_deref().unwrap_or(""); // LAW10: missing/non-string field => empty/placeholder; recall-safe
                                                                        // `Finding.credential_hash` is the raw 32 bytes; rule predicates match
                                                                        // against the hex form (see the module-doc example). Hex-encode into a
                                                                        // local that outlives `ctx`'s borrow below.
        let credential_hash_hex = crate::finding::hex_encode(&finding.credential_hash);
        let ctx = FindingContext {
            detector_id: finding.detector_id.as_ref(),
            service: finding.service.as_ref(),
            severity: finding.severity,
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

/// Single owner for the "empty `[[suppress]]` table" rejection message. Emitted
/// both at the primary empty-conditions guard and at the defensive fall-through
/// below, so the two sites cannot drift into differently-worded errors.
const NO_CONDITIONS_ERR: &str = "no conditions specified in [[suppress]] entry; \
     use `[[suppress]]\\nliteral_true = true` if you really want \
     to drop every finding";

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
            .map(|r| Arc::from(severity_label_for_rank(r)))
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
        return Err(NO_CONDITIONS_ERR.into());
    }

    // AND of all conditions inside one [[suppress]] table.
    let mut iter = conditions.into_iter();
    // The `if conditions.is_empty() { return Err(...) }` guard ~9
    // lines above proves non-empty here, but a future refactor that
    // tightens the guard (or drops it) shouldn't panic the rule
    // compiler - fall through to the same error path so the user
    // gets the parsable "no conditions" message instead of a
    // backtrace.
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

fn normalise_severity(s: &str) -> Result<String, String> {
    Severity::from_filter_label(s)
        .map(|severity| severity.as_str().to_string())
        .ok_or_else(|| {
            format!(
                "unknown severity {:?}; expected {}",
                s.trim().to_ascii_lowercase(),
                Severity::FILTER_EXPECTED_LABELS
            )
        })
}

/// Rank ordering MUST match the `Severity` enum's derived `Ord`
/// (Info < ClientSafe < Low < Medium < High < Critical). `severity_lte`
/// expands to the set of every label at or below the threshold rank, so a
/// drift between this table and the enum would suppress the wrong tiers - in
/// particular, omitting `client-safe` made `severity_lte = "low"` silently
/// skip client-safe findings that rank *below* low.
fn severity_rank(s: &str) -> Result<usize, String> {
    Severity::from_filter_label(s)
        .map(Severity::rank)
        .ok_or_else(|| format!("unknown severity rank {s:?}"))
}

fn severity_label_for_rank(rank: usize) -> &'static str {
    Severity::label_for_rank(rank)
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

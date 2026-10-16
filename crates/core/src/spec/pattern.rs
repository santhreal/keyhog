//! Detector pattern, credential shape, self-test, companion, and relation specifications.

use serde::{Deserialize, Serialize};

use super::DetectorHardNegativeClass;

/// Per-detector credential SHAPE constraint (`[detector.credential_shape]`),
/// OWNED HERE per the architecture law (was a centralized
/// `rules/detector-credential-shapes.toml` `[[shape]]` list keyed by detector
/// id, a per-detector property in a second file). A candidate whose byte length
/// / prefix / post-prefix body length does not fit the declared shape is
/// suppressed by the scanner's shape gate (`CredentialShapeRule::allows`). Only a
/// couple of fixed-format vendor detectors declare it: `aws-access-key` is
/// exactly 20 bytes; `anthropic-api-key` is `sk-ant-api03-` + an 80..=120 body.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct CredentialShape {
    /// Exact total credential byte length, for a fixed-length format.
    #[serde(default)]
    pub exact_length: Option<usize>,
    /// Literal prefix. The body-length bounds below apply ONLY to a candidate
    /// that starts with this prefix (a differently-shaped credential is not
    /// owned by this rule and passes untouched).
    #[serde(default)]
    pub prefix: Option<String>,
    /// Minimum body byte length AFTER `prefix` (requires `prefix`).
    #[serde(default)]
    pub body_min_length: Option<usize>,
    /// Maximum body byte length AFTER `prefix` (requires `prefix`).
    #[serde(default)]
    pub body_max_length: Option<usize>,
}

impl CredentialShape {
    /// Validate the internal consistency of a declared shape (the single owner of
    /// these rules, was `credential_shapes::validate_shape_entries`). `detector_id`
    /// is only used to build a precise error message. Fails closed so a malformed
    /// per-detector shape is caught at load/build, never silently ignored.
    pub fn validate(&self, detector_id: &str) -> Result<(), String> {
        let has_constraint = self.exact_length.is_some()
            || self.prefix.is_some()
            || self.body_min_length.is_some()
            || self.body_max_length.is_some();
        if !has_constraint {
            return Err(format!(
                "credential shape for '{detector_id}' has no shape constraints"
            ));
        }
        if self.prefix.is_some()
            && self.exact_length.is_none()
            && self.body_min_length.is_none()
            && self.body_max_length.is_none()
        {
            return Err(format!(
                "credential shape for '{detector_id}' has a prefix but no length constraint"
            ));
        }
        if self.exact_length == Some(0) {
            return Err(format!(
                "credential shape for '{detector_id}' has exact_length=0"
            ));
        }
        if self.prefix.as_deref() == Some("") {
            return Err(format!(
                "credential shape for '{detector_id}' has an empty prefix"
            ));
        }
        if let (Some(minimum), Some(maximum)) = (self.body_min_length, self.body_max_length) {
            if minimum > maximum {
                return Err(format!(
                    "credential shape for '{detector_id}' has body_min_length greater than body_max_length"
                ));
            }
        }
        if (self.body_min_length.is_some() || self.body_max_length.is_some())
            && self.prefix.is_none()
        {
            return Err(format!(
                "credential shape for '{detector_id}' sets body length without a prefix"
            ));
        }
        if let (Some(exact_length), Some(prefix)) = (self.exact_length, self.prefix.as_deref()) {
            if let Some(minimum) = self.body_min_length {
                let minimum_total = prefix.len().checked_add(minimum).ok_or_else(|| {
                    format!("credential shape for '{detector_id}' overflows prefix plus body_min_length")
                })?;
                if exact_length < minimum_total {
                    return Err(format!(
                        "credential shape for '{detector_id}' has exact_length below prefix plus body_min_length"
                    ));
                }
            }
            if let Some(maximum) = self.body_max_length {
                let maximum_total = prefix.len().checked_add(maximum).ok_or_else(|| {
                    format!("credential shape for '{detector_id}' overflows prefix plus body_max_length")
                })?;
                if exact_length > maximum_total {
                    return Err(format!(
                        "credential shape for '{detector_id}' has exact_length above prefix plus body_max_length"
                    ));
                }
            }
        }
        Ok(())
    }
}

/// One inline detector self-test fixture (`[[detector.tests]]`).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct DetectorTestSpec {
    /// Text this detector MUST fire on.
    #[serde(default)]
    pub test_positive: Option<String>,
    /// Text this detector MUST NOT fire on.
    #[serde(default)]
    pub test_negative: Option<String>,
    /// Canonical zero-based pattern ordinal this evidence directly covers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern_index: Option<u32>,
    /// Named false-positive class for `test_negative`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub negative_class: Option<DetectorHardNegativeClass>,
    /// Optional source path used when executing this fixture through the scanner.
    #[serde(default)]
    pub test_path: Option<String>,
}

/// A regex pattern with optional capture group and description.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct PatternSpec {
    /// Regular expression string (Rust flavor). The owning detector TOML
    /// defines its exact separator and quantifier semantics; loading never
    /// rewrites the expression.
    pub regex: String,
    /// Optional context description.
    pub description: Option<String>,
    /// Optional capture group index containing the secret.
    pub group: Option<usize>,
    /// ASCII literals used only for candidate routing. Every full regex match
    /// must contain at least one declared literal; detector validation proves
    /// that OR-condition from the regex AST before the corpus can load.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_literals: Vec<String>,
    /// When true, a match against THIS pattern downgrades the
    /// finding to `Severity::ClientSafe` (regardless of the detector's
    /// nominal severity). Used by services that intentionally ship
    /// public-facing keys in client bundles:
    ///
    ///   - Sentry DSN (the `https://<key>@` URL is meant for the browser)
    ///   - Stripe `pk_live_` / `pk_test_` (publishable, sk_ is secret)
    ///   - Mapbox `pk.` (public, `sk.` is secret)
    ///   - Firebase Web API key, Google Maps browser key
    ///   - PostHog / Mixpanel / Algolia search / Datadog browser RUM
    ///
    /// Per-pattern (not per-detector) so detectors that fire on both
    /// the public *and* the secret prefix can tag only the public one.
    ///
    /// Case sensitivity: keyhog compiles every regex `case_insensitive(true)`,
    /// so to make a single pattern case-SENSITIVE (AWS `AKIA` is uppercase,
    /// GCP/Snowflake ids are lowercase) prefix its regex with the inline flag
    /// `(?-i)` in the TOML - no schema field needed.
    #[serde(default)]
    pub client_safe: bool,
    /// Keep generic shape and entropy gates active for matches from this
    /// pattern. Declare this beside the regex so policy cannot drift when a
    /// detector's patterns are reordered. Detector-level `weak_anchor = true`
    /// applies the same policy to every pattern.
    #[serde(default)]
    pub weak_anchor: bool,
    /// Treat matches from this exact regex as syntactically proven password
    /// slots. Unlike the detector-level flag, this does not exempt generic
    /// keyword-bridge candidates or sibling patterns from Tier-B shape gates.
    #[serde(default)]
    pub structural_password_slot: bool,
}

impl PatternSpec {
    /// Validate that the declared routing literals are a necessary OR-condition
    /// of every regex match. The proof is conservative: declarations that span
    /// optional or structurally ambiguous AST nodes are rejected.
    pub fn validate_required_literals(&self) -> Result<(), String> {
        use regex_syntax::ast::{parse::Parser, Ast, RepetitionKind, RepetitionRange};

        if self.required_literals.is_empty() {
            return Ok(());
        }
        if self
            .required_literals
            .iter()
            .any(|literal| literal.is_empty() || !literal.is_ascii())
        {
            return Err("must contain only non-empty ASCII strings".into());
        }
        let mut literals = self
            .required_literals
            .iter()
            .map(|literal| literal.to_ascii_lowercase())
            .collect::<Vec<_>>();
        literals.sort_unstable();
        if literals.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err("contains a duplicate ASCII-insensitive literal".into());
        }

        fn repetition_min(kind: &RepetitionKind) -> u32 {
            match kind {
                RepetitionKind::ZeroOrOne | RepetitionKind::ZeroOrMore => 0,
                RepetitionKind::OneOrMore => 1,
                RepetitionKind::Range(RepetitionRange::Exactly(min))
                | RepetitionKind::Range(RepetitionRange::AtLeast(min))
                | RepetitionKind::Range(RepetitionRange::Bounded(min, _)) => *min,
            }
        }

        fn guarantees(ast: &Ast, literals: &[String]) -> bool {
            fn run_contains(run: &str, literals: &[String]) -> bool {
                let folded = run.to_ascii_lowercase();
                literals.iter().any(|literal| folded.contains(literal))
            }

            match ast {
                Ast::Literal(literal) => run_contains(&literal.c.to_string(), literals),
                Ast::Group(group) => guarantees(&group.ast, literals),
                Ast::Alternation(alternation) => {
                    !alternation.asts.is_empty()
                        && alternation
                            .asts
                            .iter()
                            .all(|branch| guarantees(branch, literals))
                }
                Ast::Repetition(repetition) => {
                    repetition_min(&repetition.op.kind) > 0 && guarantees(&repetition.ast, literals)
                }
                Ast::Concat(concat) => {
                    let mut run = String::new();
                    for node in &concat.asts {
                        if let Ast::Literal(literal) = node {
                            run.push(literal.c);
                            continue;
                        }
                        if run_contains(&run, literals) || guarantees(node, literals) {
                            return true;
                        }
                        run.clear();
                    }
                    run_contains(&run, literals)
                }
                Ast::Empty(_)
                | Ast::Dot(_)
                | Ast::Assertion(_)
                | Ast::ClassUnicode(_)
                | Ast::ClassPerl(_)
                | Ast::ClassBracketed(_)
                | Ast::Flags(_) => false,
            }
        }

        let ast = Parser::new()
            .parse(&self.regex)
            .map_err(|error| format!("cannot prove literals against invalid regex: {error}"))?;
        if guarantees(&ast, &literals) {
            Ok(())
        } else {
            Err("is not a proven necessary OR-condition of every regex match".into())
        }
    }
}

/// How a contextual evidence match must be positioned relative to the primary credential.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceDirection {
    /// Accept evidence on either side of the primary credential.
    #[default]
    Either,
    /// Accept only evidence ending before the primary credential begins.
    Before,
    /// Accept only evidence beginning after the primary credential ends.
    After,
}

/// The structural boundary in which contextual evidence may satisfy a relation.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceScope {
    /// Search the configured line and byte window.
    #[default]
    Window,
    /// Search only the primary credential's physical line.
    SameLine,
    /// Search only the blank-line-delimited record containing the credential.
    SameRecord,
    /// Search only the smallest balanced JSON-like object or array containing the credential.
    SameObject,
}

/// Whether contextual evidence admits, strengthens, or rejects a detector match.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceRequirement {
    /// Preserve the match without the evidence, but include a found value in scoring and verification.
    #[default]
    Reinforcing,
    /// Suppress the primary match when the evidence is absent.
    Required,
    /// Suppress the primary match when the evidence is present.
    Forbidden,
}

/// The value relationship between a selected evidence capture and the primary credential.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceValueRelation {
    /// Presence inside the declared structural and distance bounds is sufficient.
    #[default]
    Present,
    /// The selected evidence bytes must exactly equal the primary credential.
    EqualsPrimary,
    /// The selected evidence bytes must differ from the primary credential.
    DiffersFromPrimary,
}

impl EvidenceDirection {
    /// Stable detector-schema spelling used by diagnostics and corpus identities.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Either => "either",
            Self::Before => "before",
            Self::After => "after",
        }
    }
}

impl EvidenceScope {
    /// Stable detector-schema spelling used by diagnostics and corpus identities.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Window => "window",
            Self::SameLine => "same-line",
            Self::SameRecord => "same-record",
            Self::SameObject => "same-object",
        }
    }
}

impl EvidenceRequirement {
    /// Stable detector-schema spelling used by diagnostics and corpus identities.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Reinforcing => "reinforcing",
            Self::Required => "required",
            Self::Forbidden => "forbidden",
        }
    }
}

impl EvidenceValueRelation {
    /// Stable detector-schema spelling used by diagnostics and corpus identities.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Present => "present",
            Self::EqualsPrimary => "equals-primary",
            Self::DiffersFromPrimary => "differs-from-primary",
        }
    }
}

/// Cross-detector evidence operation applied during deterministic match resolution.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DetectorRelationKind {
    /// Keep this detector's finding only when the target detector also matches nearby.
    Requires,
    /// Suppress this detector's finding when the target detector matches nearby.
    Conflicts,
    /// Suppress nearby target-detector findings when this detector matches.
    Subsumes,
}

impl DetectorRelationKind {
    /// Stable detector-schema spelling used by diagnostics and corpus identities.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Requires => "requires",
            Self::Conflicts => "conflicts",
            Self::Subsumes => "subsumes",
        }
    }
}

/// A bounded relationship between findings from two detector owners.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorRelationSpec {
    /// Stable target detector ID.
    pub detector_id: String,
    /// Resolution operation performed when target evidence is present or absent.
    pub kind: DetectorRelationKind,
    /// Maximum absolute line distance between source and target findings.
    pub within_lines: usize,
    /// Optional maximum byte gap between source and target finding spans.
    #[serde(default)]
    pub within_bytes: Option<usize>,
    /// Direction of the target finding relative to this detector's finding.
    #[serde(default)]
    pub direction: EvidenceDirection,
}

/// Positive source selectors for detector families valid only in known locations.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceAdmissionSpec {
    /// File-path regexes. At least one must match when this list is non-empty.
    #[serde(default)]
    pub path_patterns: Vec<String>,
    /// Exact `ChunkMetadata::source_type` values admitted by this detector.
    #[serde(default)]
    pub source_types: Vec<String>,
    /// Case-insensitive filename extensions without a leading dot.
    #[serde(default)]
    pub file_extensions: Vec<String>,
}

/// Secondary pattern used to confirm a primary match or provide extra context.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompanionSpec {
    /// Field name used in verification templates (e.g. \`{{companion.secret_key}}\`).
    pub name: String,
    /// Regex to find the companion value nearby. The owning detector TOML
    /// defines its exact semantics; loading never rewrites the expression.
    pub regex: String,
    /// Maximum line distance from the primary match.
    pub within_lines: usize,
    /// Optional maximum byte gap between the evidence and primary spans.
    #[serde(default)]
    pub within_bytes: Option<usize>,
    /// Direction in which the evidence must occur.
    #[serde(default)]
    pub direction: EvidenceDirection,
    /// Structural boundary that both evidence and primary spans must share.
    #[serde(default)]
    pub scope: EvidenceScope,
    /// Admission effect of a present or absent evidence match.
    #[serde(default)]
    pub requirement: EvidenceRequirement,
    /// Explicit regex capture group whose bytes become the evidence value.
    ///
    /// `None` preserves the existing rule: select group 1 when the regex has a
    /// capture, otherwise select the whole match. Group 0 explicitly selects
    /// the whole match even when captures exist.
    #[serde(default)]
    pub capture_group: Option<usize>,
    /// Exact relationship required between the selected evidence and primary values.
    #[serde(default)]
    pub value_relation: EvidenceValueRelation,
    /// Schema-v2 compatibility input. New detector corpora use
    /// `requirement = "required"` instead.
    #[serde(default)]
    pub required: bool,
}

impl CompanionSpec {
    /// Resolve the schema-v2 boolean into the typed admission requirement.
    pub fn effective_requirement(&self) -> EvidenceRequirement {
        if self.required {
            EvidenceRequirement::Required
        } else {
            self.requirement
        }
    }
}


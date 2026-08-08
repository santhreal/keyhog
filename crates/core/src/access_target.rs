//! Access targets: the door a credential opens.
//!
//! A finding says "there is a Postgres password on line 2 of `config.yaml`". It
//! does not say which database that password reaches, and that is the first
//! thing a responder needs in order to decide whether this is a staging toy or
//! the production customer store. The address is almost always sitting right
//! next to the credential (in the same connection string, in the same `.env`,
//! in the same Terraform variable block) and no detector can see it: a
//! `[[detector.companions]]` regex is bounded to a few lines of one chunk and
//! is written to capture the OTHER HALF OF THE CREDENTIAL, not the resource.
//!
//! This module runs after the scan, over the findings the report is about to
//! publish, and attaches typed access targets to them:
//!
//! * [`AccessTargetKind::Account`] - a billing or ownership boundary.
//! * [`AccessTargetKind::Tenant`] - an identity/org boundary inside a provider.
//! * [`AccessTargetKind::Endpoint`] - a network address it authenticates to.
//! * [`AccessTargetKind::Database`] - a named logical database inside one.
//! * [`AccessTargetKind::Resource`] - a concrete addressable object.
//!
//! Every provider this pass understands lives in the Tier-B
//! `data/access-targets.toml` policy, never in a match arm here, so extending
//! coverage is a reviewable data edit.
//!
//! Three guarantees hold by construction.
//!
//! **Additive.** The pass reads findings and returns a separate report. It never
//! adds, drops, reorders, or edits a finding, so a report produced without it is
//! byte-identical to one produced before this module existed.
//!
//! **Redaction-safe.** A rule may only capture an address, never an
//! authenticator: connection-string rules skip userinfo with a non-capturing
//! group, so a password cannot reach a capture. On top of that every candidate
//! whose SHA-256 equals a credential digest in the same report is dropped
//! unconditionally, and the per-rule [`Redaction`] policy is applied before the
//! value reaches an artifact. Evidence carries the rule id, line, column, span
//! length, and line distance; it never carries document text, so an artifact
//! contains no plaintext secret and no unrelated document body.
//!
//! **Bounded.** File context comes from an index built at most once per distinct
//! file, over at most `max_file_bytes` of it, under a whole-pass
//! `max_total_bytes` ceiling. Cost is linear in indexed bytes plus a sort per
//! finding, never quadratic in findings.
//!
//! When context cannot be honored the pass says so. A finding read from git
//! history, a container layer, stdin, or an unreadable path is counted in
//! [`AccessTargetCoverage::gaps`] with the reason, and
//! [`AccessTargetCoverage::complete`] goes false. An empty target list under an
//! incomplete coverage report means "not looked at", which is a different fact
//! from "looked at, found no door", and the two are never conflated.

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::io::Read;
use std::sync::LazyLock;

use regex::Regex;

use crate::{hex_encode, sha256_hash, CredentialHash, VerifiedFinding};

/// What kind of thing a credential opens.
///
/// Ordered broadest blast radius first, so the derived `Ord` sorts an account
/// above a single resource when two targets tie on distance and confidence.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum AccessTargetKind {
    /// A billing or ownership boundary, such as an AWS account id.
    Account,
    /// An identity or organization boundary inside a provider.
    Tenant,
    /// A network address the credential authenticates to.
    Endpoint,
    /// A named logical database or schema inside an endpoint.
    Database,
    /// A concrete addressable object, such as a bucket, ARN, or repository.
    Resource,
}

impl AccessTargetKind {
    /// Stable machine-readable discriminator, shared by the JSON projection and
    /// any renderer so the two can never disagree about a target's kind.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Account => "account",
            Self::Tenant => "tenant",
            Self::Endpoint => "endpoint",
            Self::Database => "database",
            Self::Resource => "resource",
        }
    }
}

/// How a target was tied to a credential.
///
/// Ordered strongest first: a value decoded out of the credential itself cannot
/// be a coincidence of proximity, while a same-file hit is the weakest claim the
/// pass makes.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum TargetRelation {
    /// Recovered from the credential itself, offline, with no file context.
    Decoded,
    /// Found on the same line as the finding.
    SameLine,
    /// Found elsewhere in the same file, inside the indexed prefix.
    SameFile,
}

impl TargetRelation {
    /// Stable machine-readable discriminator.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Decoded => "decoded",
            Self::SameLine => "same_line",
            Self::SameFile => "same_file",
        }
    }
}

/// What was done to a target value before it was allowed into an artifact.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum Redaction {
    /// Emitted verbatim. Only for values that are addresses by construction.
    None,
    /// Emitted as an ellipsis plus a short suffix.
    Tail,
    /// Emitted as `sha256:` plus the first 16 hex characters of the digest.
    Hash,
}

/// Why the pass could not build file context for some findings.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum CoverageGapReason {
    /// The finding carried no file path at all.
    NoFilePath,
    /// The source backend does not expose a re-readable local file.
    SourceNotReadable,
    /// The finding describes historical content at a commit, not the file on
    /// disk today, so indexing the working-tree file would attribute a door
    /// that may never have coexisted with the credential.
    HistoricalContent,
    /// The file could not be read for a reason that may not hold a moment
    /// later: it was removed or replaced after the scan, briefly locked, or the
    /// read was interrupted. This is a candidate for retry by whatever owns the
    /// scan's retry policy, and it is NOT the same fact as a permanent hole.
    TransientReadFailed,
    /// The file could not be read for a reason retrying cannot change:
    /// permission denied, the path is a directory, or the device rejected it.
    PermanentReadFailed,
    /// The indexed prefix is not valid UTF-8, so byte offsets could not be
    /// mapped to lines without corrupting them.
    NotUtf8,
    /// The credential was recovered from a DERIVED view of the file rather than
    /// from the file's own byte stream. Two kinds produce this, both labelled
    /// `filesystem/<view>`: a decode view (`filesystem/base64`,
    /// `filesystem/hex`, `filesystem/reverse`, `filesystem/quoted-printable`)
    /// and a windowed read of a large file (`filesystem/windowed`), whose line
    /// numbers are relative to the window, not the file.
    ///
    /// The file on disk is readable and its doors are real, so it is still
    /// indexed and its targets are still reported. What is missing is a line
    /// ANCHOR: the finding's line does not index the file, so no honest
    /// distance exists and every target is charged the maximum decay rather
    /// than claiming a proximity the number cannot support.
    DerivedViewAnchorless,
    /// The file is longer than `max_file_bytes`; only its prefix was indexed.
    FileTruncated,
    /// The whole-pass `max_total_bytes` ceiling was reached before this file.
    ByteBudgetExhausted,
}

impl CoverageGapReason {
    /// Stable machine-readable discriminator.
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoFilePath => "no_file_path",
            Self::SourceNotReadable => "source_not_readable",
            Self::HistoricalContent => "historical_content",
            Self::TransientReadFailed => "transient_read_failed",
            Self::PermanentReadFailed => "permanent_read_failed",
            Self::NotUtf8 => "not_utf8",
            Self::DerivedViewAnchorless => "derived_view_anchorless",
            Self::FileTruncated => "file_truncated",
            Self::ByteBudgetExhausted => "byte_budget_exhausted",
        }
    }

    /// One calm sentence an operator can act on.
    #[must_use]
    pub fn explain(self) -> &'static str {
        match self {
            Self::NoFilePath => "the finding carries no file path, so there is nothing to index",
            Self::SourceNotReadable => {
                "this source backend does not expose a re-readable local file; \
                 rescan the extracted content from disk to get access targets"
            }
            Self::HistoricalContent => {
                "the finding is historical content at a commit; the working-tree \
                 file was not indexed because its neighbours may postdate the credential"
            }
            Self::TransientReadFailed => {
                "the file could not be read, for a reason that may not hold a moment \
                 later; it was removed, replaced, or locked between the scan and this \
                 pass, so rerunning may cover it"
            }
            Self::PermanentReadFailed => {
                "the file could not be read and rerunning will not change that; check \
                 permissions and whether the path is a regular file"
            }
            Self::NotUtf8 => "the indexed prefix is not valid UTF-8",
            Self::DerivedViewAnchorless => {
                "the credential came from a derived view of this file (a decode view, \
                 or a windowed read of a large file), so its line number does not \
                 index the file; the file was still indexed and its targets are still \
                 reported, but at maximum distance decay rather than by proximity"
            }
            Self::FileTruncated => {
                "the file is larger than the configured max_file_bytes, so only \
                 its prefix was indexed"
            }
            Self::ByteBudgetExhausted => {
                "the pass reached max_total_bytes before reaching this file"
            }
        }
    }
}

/// Why one target is attributed to one credential.
///
/// Deliberately structural. There is no excerpt field, and adding one would
/// break the module's redaction guarantee: a line holding a credential also
/// holds the credential.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct TargetEvidence {
    /// How the target was tied to the credential.
    pub relation: TargetRelation,
    /// Tier-B rule id, or `metadata:<key>` for a decoded target.
    pub rule_id: String,
    /// File the evidence was observed in. Absent for a decoded target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    /// One-based line of the evidence span. Absent for a decoded target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    /// One-based byte column of the evidence span start.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub column: Option<usize>,
    /// Length of the evidence span in bytes. The span itself is not emitted.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub span_bytes: Option<usize>,
    /// Absolute line distance between the finding and the evidence.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line_distance: Option<usize>,
    /// Where the confidence number came from, so a reader can audit the score
    /// without reverse-engineering it.
    pub provenance: ConfidenceProvenance,
}

/// Exactly how a target's confidence was produced.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct ConfidenceProvenance {
    /// `tier_b_rule` or `credential_metadata`.
    pub source: String,
    /// Confidence the rule declared before relation weighting.
    pub base: f64,
    /// Number of `same_file_decay` applications, from the line distance.
    pub decay_steps: u32,
    /// Multiplier applied per decay step.
    pub decay_factor: f64,
}

/// One resource a credential is believed to open.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AccessTarget {
    /// What kind of thing this is.
    pub kind: AccessTargetKind,
    /// The address, after the rule's redaction policy.
    pub value: String,
    /// What was done to `value` before emitting it.
    pub redaction: Redaction,
    /// Short operator-facing name of the target class, from Tier-B data.
    pub label: String,
    /// Provider namespace the rule belongs to, when it names one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,
    /// Score after relation weighting and distance decay, rounded to 3 places.
    pub confidence: f64,
    /// Why this target is attributed to this credential.
    pub evidence: TargetEvidence,
}

/// Where a credential with access targets was found.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct TargetedLocation {
    /// Logical source backend of the finding.
    pub source: String,
    /// File path, object key, or logical path when the finding had one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_path: Option<String>,
    /// One-based line when the source knew one.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
}

/// One finding and the doors it opens.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct CredentialAccessTargets {
    /// Hex SHA-256 digest of the credential, the stable link back to the
    /// finding this row describes.
    pub credential_hash: String,
    /// Detector that produced the finding.
    pub detector_id: String,
    /// Service namespace of the finding.
    pub service: String,
    /// Where the finding was.
    pub location: TargetedLocation,
    /// Targets, strongest attribution first.
    pub targets: Vec<AccessTarget>,
}

/// One reason some findings had no file context, and how many were affected.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct CoverageGap {
    /// Why context was unavailable.
    pub reason: CoverageGapReason,
    /// One calm sentence an operator can act on.
    pub explanation: String,
    /// Number of findings affected.
    pub findings: usize,
    /// Up to a handful of affected paths or source labels, for triage.
    pub examples: Vec<String>,
}

/// What the pass actually managed to look at.
///
/// This exists so that an empty `targets` list can never be mistaken for "this
/// credential opens nothing". If `complete` is false, some findings were never
/// inspected and the reason is in `gaps`.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AccessTargetCoverage {
    /// Findings the pass was given.
    pub findings_total: usize,
    /// Findings whose file was successfully indexed.
    pub findings_with_file_context: usize,
    /// Distinct files indexed.
    pub files_indexed: usize,
    /// Bytes read while indexing.
    pub bytes_indexed: u64,
    /// True only when every finding got file context.
    pub complete: bool,
    /// Why the rest did not, sorted by reason.
    pub gaps: Vec<CoverageGap>,
}

/// The complete result of one association pass.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct AccessTargetReport {
    /// Findings that got at least one target, sorted by path then line.
    pub targets: Vec<CredentialAccessTargets>,
    /// What the pass looked at and what it could not.
    pub coverage: AccessTargetCoverage,
}

impl AccessTargetReport {
    /// True when the pass produced nothing at all and hit no coverage gap, the
    /// only case in which a caller may omit the section entirely.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.targets.is_empty() && self.coverage.gaps.is_empty()
    }
}

// ---------------------------------------------------------------------------
// Tier-B policy
// ---------------------------------------------------------------------------

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct Settings {
    max_file_bytes: u64,
    max_total_bytes: u64,
    max_targets_per_finding: usize,
    max_matches_per_rule: usize,
    min_confidence: f64,
    same_file_decay: f64,
    decay_line_step: usize,
    decay_max_steps: u32,
    decoded_confidence: f64,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct MetadataRule {
    key: String,
    kind: AccessTargetKind,
    #[serde(default)]
    service: Option<String>,
    label: String,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleSpec {
    id: String,
    kind: AccessTargetKind,
    label: String,
    #[serde(default)]
    service: Option<String>,
    pattern: String,
    group: usize,
    confidence: f64,
    redact: Redaction,
    #[serde(default)]
    redact_keep: Option<usize>,
}

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    settings: Settings,
    #[serde(default)]
    metadata: Vec<MetadataRule>,
    #[serde(default)]
    rule: Vec<RuleSpec>,
}

/// A rule with its pattern compiled.
struct CompiledRule {
    spec: RuleSpec,
    regex: Regex,
}

struct Policy {
    settings: Settings,
    metadata: Vec<MetadataRule>,
    rules: Vec<CompiledRule>,
}

/// The compiled-in policy. `include_str!` makes an invalid document a BUILD bug,
/// never a runtime condition the operator can act on, so the initializer panics
/// rather than degrading to an empty policy: an empty policy would report zero
/// access targets on a repository full of them while still claiming complete
/// coverage, which is exactly the fail-silent shape Law 10 forbids.
///
/// Nothing forces this `LazyLock` unless the caller asks for access targets, so
/// a default scan pays neither the parse nor the regex compilation.
#[allow(clippy::panic)]
static POLICY: LazyLock<Policy> = LazyLock::new(|| {
    match compile_policy(
        include_str!("../data/access-targets.toml"),
        "<embedded data/access-targets.toml>",
    ) {
        Ok(policy) => policy,
        Err(error) => panic!(
            "keyhog: access-target policy '<embedded data/access-targets.toml>' \
             is invalid: {error}. Fix: correct crates/core/data/access-targets.toml and rebuild"
        ),
    }
});

/// Parse, validate, and compile one access-target policy document.
///
/// Returned as `Err` rather than panicking so the same validation runs over
/// candidate documents in tests without taking the process down.
fn compile_policy(raw: &str, origin: &str) -> Result<Policy, String> {
    let file = toml::from_str::<PolicyFile>(raw)
        .map_err(|error| format!("failed to parse {origin}: {error}"))?;
    validate_settings(&file.settings, origin)?;

    let mut seen = BTreeSet::new();
    let mut rules = Vec::with_capacity(file.rule.len());
    for spec in file.rule {
        let id = spec.id.trim().to_string();
        if id.is_empty() {
            return Err(format!("{origin} [[rule]] has an empty id"));
        }
        if !seen.insert(id.clone()) {
            return Err(format!("{origin} [[rule]] duplicate id {id:?}"));
        }
        if spec.label.trim().is_empty() {
            return Err(format!("{origin} [[rule]] {id:?} has an empty label"));
        }
        if !(spec.confidence > 0.0 && spec.confidence <= 1.0) {
            return Err(format!(
                "{origin} [[rule]] {id:?} confidence must be in (0.0, 1.0], got {}",
                spec.confidence
            ));
        }
        if spec.group == 0 {
            return Err(format!(
                "{origin} [[rule]] {id:?} group must be at least 1; group 0 is the \
                 whole match, which would emit surrounding text"
            ));
        }
        if matches!(spec.redact, Redaction::Tail) && spec.redact_keep.unwrap_or(0) == 0 {
            // LAW10: absent tail length is treated as invalid here, so validation fails closed before any credential is emitted.
            return Err(format!(
                "{origin} [[rule]] {id:?} uses redact = \"tail\" and must set a \
                 positive redact_keep"
            ));
        }
        let regex = Regex::new(&spec.pattern)
            .map_err(|error| format!("{origin} [[rule]] {id:?} pattern is invalid: {error}"))?;
        let groups = regex.captures_len();
        if spec.group >= groups {
            return Err(format!(
                "{origin} [[rule]] {id:?} wants capture group {} but the pattern has {}",
                spec.group,
                groups.saturating_sub(1)
            ));
        }
        rules.push(CompiledRule { spec, regex });
    }

    let mut seen_keys = BTreeSet::new();
    for entry in &file.metadata {
        if entry.key.trim().is_empty() {
            return Err(format!("{origin} [[metadata]] has an empty key"));
        }
        if !seen_keys.insert(entry.key.clone()) {
            return Err(format!(
                "{origin} [[metadata]] duplicate key {:?}",
                entry.key
            ));
        }
        if entry.label.trim().is_empty() {
            return Err(format!(
                "{origin} [[metadata]] {:?} has an empty label",
                entry.key
            ));
        }
    }

    Ok(Policy {
        settings: file.settings,
        metadata: file.metadata,
        rules,
    })
}

/// Fail closed on settings that would make the pass claim more than it did: a
/// zero byte budget indexes nothing while reporting itself complete, a decay
/// outside `(0, 1]` either amplifies distant matches or erases them, and a zero
/// target cap silently discards every target the rules found.
fn validate_settings(settings: &Settings, origin: &str) -> Result<(), String> {
    if settings.max_file_bytes == 0 {
        return Err(format!(
            "{origin} [settings] max_file_bytes must be positive"
        ));
    }
    if settings.max_total_bytes < settings.max_file_bytes {
        return Err(format!(
            "{origin} [settings] max_total_bytes ({}) must be at least max_file_bytes ({})",
            settings.max_total_bytes, settings.max_file_bytes
        ));
    }
    if settings.max_targets_per_finding == 0 {
        return Err(format!(
            "{origin} [settings] max_targets_per_finding must be positive"
        ));
    }
    if settings.max_matches_per_rule == 0 {
        return Err(format!(
            "{origin} [settings] max_matches_per_rule must be positive"
        ));
    }
    if !(settings.min_confidence >= 0.0 && settings.min_confidence < 1.0) {
        return Err(format!(
            "{origin} [settings] min_confidence must be in [0.0, 1.0), got {}",
            settings.min_confidence
        ));
    }
    if !(settings.same_file_decay > 0.0 && settings.same_file_decay <= 1.0) {
        return Err(format!(
            "{origin} [settings] same_file_decay must be in (0.0, 1.0], got {}",
            settings.same_file_decay
        ));
    }
    if settings.decay_line_step == 0 {
        return Err(format!(
            "{origin} [settings] decay_line_step must be positive"
        ));
    }
    if settings.decay_max_steps == 0 {
        return Err(format!(
            "{origin} [settings] decay_max_steps must be at least 1; zero would make \
             a match on the far end of a file score exactly as a match on the \
             credential's own line"
        ));
    }
    if !(settings.decoded_confidence > 0.0 && settings.decoded_confidence <= 1.0) {
        return Err(format!(
            "{origin} [settings] decoded_confidence must be in (0.0, 1.0], got {}",
            settings.decoded_confidence
        ));
    }
    Ok(())
}

/// Validate a candidate access-target policy document without installing it.
///
/// Exposed so a regression test can prove the shipped file and any contributed
/// edit are both accepted by the same code path the binary uses.
pub fn validate_access_target_policy(raw: &str, origin: &str) -> Result<(), String> {
    compile_policy(raw, origin).map(|_| ())
}

/// Rule ids the shipped policy defines, in file order.
///
/// Lets a test assert that a rule was not silently dropped by an edit.
#[must_use]
pub fn access_target_rule_ids() -> Vec<&'static str> {
    POLICY
        .rules
        .iter()
        .map(|rule| rule.spec.id.as_str())
        .collect()
}

// ---------------------------------------------------------------------------
// File content
// ---------------------------------------------------------------------------

/// Why a file could not be turned into an index.
///
/// Transient and permanent are separate variants on purpose. This pass re-opens
/// a file AFTER the scan finished, so between the two a file can be deleted,
/// replaced, or briefly locked by another process. That is a different fact
/// from "this file is a directory" or "you may not read it", and collapsing the
/// two would report a momentary blip as a permanent hole in coverage.
///
/// The failure the pass can design out, it does: [`FilesystemContent`] opens
/// once and works from the handle rather than stat-ing a path and then opening
/// it, so there is no check-then-use race of its own making. What is left is
/// genuinely external, which is why it is classified rather than looped over.
/// Retry policy is not decided here; a caller that owns one wraps
/// [`FileContentSource`] and retries only [`ContentError::TransientRead`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ContentError {
    /// The read failed for a reason that may not hold a moment later: the file
    /// was removed or replaced after the scan, a lock was held, a syscall was
    /// interrupted, or a resource was momentarily busy.
    TransientRead,
    /// The read failed for a reason retrying cannot change: permission denied,
    /// the path is a directory, or the device rejected it.
    PermanentRead,
    /// The prefix is not valid UTF-8.
    NotUtf8,
}

impl ContentError {
    /// Classify an I/O failure. Anything not known to be permanent is treated
    /// as transient, because calling a momentary condition permanent is the
    /// error that costs coverage; the reverse only costs one retry.
    #[must_use]
    pub fn classify(error: &std::io::Error) -> Self {
        use std::io::ErrorKind;
        match error.kind() {
            ErrorKind::PermissionDenied
            | ErrorKind::InvalidInput
            | ErrorKind::InvalidData
            | ErrorKind::Unsupported => Self::PermanentRead,
            _ => Self::TransientRead,
        }
    }
}

/// One file's content prefix, plus whether it was cut short.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileContent {
    /// The prefix that was read, valid UTF-8.
    pub text: String,
    /// True when the file was longer than the requested cap.
    pub truncated: bool,
}

/// Where the association pass gets file bytes.
///
/// A trait so the association logic is pure and testable without a filesystem,
/// so a future source backend that can re-materialize its own content (an
/// archive member, a container layer) can supply it without this module
/// learning about that backend, and so a caller that owns a retry policy can
/// wrap the implementation instead of this module growing a loop.
pub trait FileContentSource {
    /// Read at most `max_bytes` from `path`, or say why not.
    ///
    /// # Errors
    /// Returns [`ContentError`] when the file cannot be opened, cannot be read,
    /// or its prefix is not valid UTF-8.
    fn read_prefix(&self, path: &str, max_bytes: u64) -> Result<FileContent, ContentError>;
}

/// Reads from the local filesystem.
#[derive(Debug, Clone, Copy, Default)]
pub struct FilesystemContent;

impl FileContentSource for FilesystemContent {
    fn read_prefix(&self, path: &str, max_bytes: u64) -> Result<FileContent, ContentError> {
        // Open once and read from the handle. Nothing stats the path first, so
        // a replacement between two syscalls cannot produce a wrong answer or a
        // failure this pass created for itself.
        let file = std::fs::File::open(path).map_err(|error| ContentError::classify(&error))?;
        // Read one byte past the cap so a file sitting exactly at the cap is not
        // reported as truncated, and a longer one always is. The capacity is
        // bounded by the cap, never by a size the file claims to have, so a file
        // growing under the read cannot cost unbounded memory.
        let mut buffer = Vec::new();
        file.take(max_bytes.saturating_add(1))
            .read_to_end(&mut buffer)
            .map_err(|error| ContentError::classify(&error))?;
        let truncated = buffer.len() as u64 > max_bytes;
        if truncated {
            buffer.truncate(usize::try_from(max_bytes).unwrap_or(usize::MAX)); // LAW10: a u64 limit wider than usize cannot truncate an in-memory buffer further; usize::MAX is the exact effective cap.
        }
        let text = String::from_utf8(buffer).map_err(|_| ContentError::NotUtf8)?;
        Ok(FileContent { text, truncated })
    }
}

/// Source backends whose `file_path` names a re-readable local file.
///
/// Deliberately an allowlist. A backend not named here is reported as a
/// coverage gap rather than guessed at, because guessing means opening whatever
/// happens to sit at that path in the working tree and attributing its contents
/// to a credential that came from somewhere else entirely.
const READABLE_SOURCES: &[&str] = &["filesystem", "fs"];

// ---------------------------------------------------------------------------
// Association
// ---------------------------------------------------------------------------

/// One target candidate found in a file, before it is tied to a finding.
struct IndexedTarget {
    rule: usize,
    line: usize,
    column: usize,
    span_bytes: usize,
    value: String,
}

/// A file's target candidates, sorted by line.
struct FileIndex {
    targets: Vec<IndexedTarget>,
    truncated: bool,
}

/// Build the bounded index for one file's text.
///
/// Runs each rule once over the whole prefix. Per-rule output is capped at
/// `max_matches_per_rule`, so one pathological file cannot let one rule consume
/// the whole per-finding target budget.
fn index_content(text: &str, deny: &HashSet<CredentialHash>, truncated: bool) -> FileIndex {
    let policy = &*POLICY;
    let line_starts = line_start_offsets(text);
    let mut targets = Vec::new();
    for (index, rule) in policy.rules.iter().enumerate() {
        let mut emitted = 0usize;
        for captures in rule.regex.captures_iter(text) {
            if emitted >= policy.settings.max_matches_per_rule {
                break;
            }
            let Some(group) = captures.get(rule.spec.group) else {
                continue;
            };
            let raw = group.as_str();
            if raw.is_empty() {
                continue;
            }
            // Hard redaction guard: a candidate that hashes to a credential in
            // this report is the credential, whatever the rule intended.
            if deny.contains(&sha256_hash(raw)) {
                continue;
            }
            let (line, column) = position_of(&line_starts, group.start());
            targets.push(IndexedTarget {
                rule: index,
                line,
                column,
                span_bytes: raw.len(),
                value: apply_redaction(raw, &rule.spec),
            });
            emitted += 1;
        }
    }
    targets.sort_by(|a, b| {
        a.line
            .cmp(&b.line)
            .then_with(|| a.column.cmp(&b.column))
            .then_with(|| a.rule.cmp(&b.rule))
    });
    FileIndex { targets, truncated }
}

fn apply_redaction(raw: &str, spec: &RuleSpec) -> String {
    match spec.redact {
        Redaction::None => raw.to_string(),
        Redaction::Tail => {
            let keep = spec.redact_keep.unwrap_or(4); // LAW10: absent optional tail length uses the documented redaction default and never exposes more than four characters.
            let start = raw
                .char_indices()
                .rev()
                .take(keep)
                .last()
                .map_or(raw.len(), |(offset, _)| offset);
            let mut out = String::with_capacity(3 + raw.len() - start);
            out.push_str("...");
            out.push_str(&raw[start..]);
            out
        }
        Redaction::Hash => {
            let digest = hex_encode(sha256_hash(raw));
            let mut out = String::with_capacity(23);
            out.push_str("sha256:");
            out.push_str(&digest[..16]);
            out
        }
    }
}

/// Byte offset of the start of every line in `text`.
fn line_start_offsets(text: &str) -> Vec<usize> {
    let mut starts = Vec::with_capacity(text.len() / 40 + 1);
    starts.push(0);
    for (offset, byte) in text.bytes().enumerate() {
        if byte == b'\n' {
            starts.push(offset + 1);
        }
    }
    starts
}

/// One-based line and one-based byte column of `offset`.
fn position_of(line_starts: &[usize], offset: usize) -> (usize, usize) {
    let line_index = match line_starts.binary_search(&offset) {
        Ok(index) => index,
        Err(index) => index.saturating_sub(1),
    };
    let start = line_starts.get(line_index).copied().unwrap_or(0); // LAW10: absent line metadata conservatively measures the column from byte zero; it does not drop the target.
    (line_index + 1, offset - start + 1)
}

/// Round to three decimals so the emitted score is stable across platforms and
/// diffable between runs.
fn round3(value: f64) -> f64 {
    (value * 1000.0).round() / 1000.0
}

/// Accumulates coverage gaps without letting one bad directory flood the report.
#[derive(Default)]
struct GapTally {
    counts: BTreeMap<CoverageGapReason, (usize, Vec<String>)>,
}

const MAX_GAP_EXAMPLES: usize = 5;

impl GapTally {
    fn record(&mut self, reason: CoverageGapReason, example: &str) {
        let entry = self.counts.entry(reason).or_insert((0, Vec::new()));
        entry.0 += 1;
        if entry.1.len() < MAX_GAP_EXAMPLES && !entry.1.iter().any(|seen| seen == example) {
            entry.1.push(example.to_string());
        }
    }

    fn finish(self) -> Vec<CoverageGap> {
        self.counts
            .into_iter()
            .map(|(reason, (findings, examples))| CoverageGap {
                reason,
                explanation: reason.explain().to_string(),
                findings,
                examples,
            })
            .collect()
    }
}

/// Attach access targets to a finding set, reading file context from disk.
///
/// This is the entry point the CLI uses behind `--access-targets`. It is never
/// called on the default path, so a default scan pays nothing for it.
///
/// The read goes through [`RetryingContentSource`](crate::retry::RetryingContentSource),
/// the product's one retry policy, so a file removed or locked between the scan
/// and this pass gets a bounded second look before it becomes a coverage gap.
/// Only [`ContentError::TransientRead`] is retried; a permission denial returns
/// on the first attempt.
#[must_use]
pub fn associate_access_targets(findings: &[VerifiedFinding]) -> AccessTargetReport {
    let content = crate::retry::RetryingContentSource::new(&FilesystemContent);
    associate_access_targets_with(findings, &content)
}

/// Attach access targets using a caller-supplied content source.
#[must_use]
pub fn associate_access_targets_with(
    findings: &[VerifiedFinding],
    content: &dyn FileContentSource,
) -> AccessTargetReport {
    let policy = &*POLICY;
    let settings = &policy.settings;

    // Every credential digest in this report. A candidate value that hashes into
    // this set is a secret, not an address, and is dropped before redaction.
    let deny: HashSet<CredentialHash> = findings
        .iter()
        .map(|finding| finding.credential_hash)
        .collect();

    // One entry per distinct path: the index, or the reason there is none. The
    // reason is cached with the path so the second finding in an unreadable file
    // is tallied as a gap too, instead of quietly counting as "no doors found".
    let mut indexes: BTreeMap<String, Result<FileIndex, CoverageGapReason>> = BTreeMap::new();
    let mut bytes_indexed: u64 = 0;
    let mut budget_exhausted = false;
    let mut gaps = GapTally::default();
    let mut with_context = 0usize;
    let mut rows: Vec<CredentialAccessTargets> = Vec::new();

    for finding in findings {
        let mut targets = decoded_targets(finding, policy);

        let index = match indexable(finding) {
            Ok(target) => {
                let path = target.path();
                if !indexes.contains_key(path) {
                    let entry = if budget_exhausted || bytes_indexed >= settings.max_total_bytes {
                        budget_exhausted = true;
                        Err(CoverageGapReason::ByteBudgetExhausted)
                    } else {
                        let remaining = settings.max_total_bytes - bytes_indexed;
                        let cap = settings.max_file_bytes.min(remaining);
                        match content.read_prefix(path, cap) {
                            Ok(file) => {
                                bytes_indexed =
                                    bytes_indexed.saturating_add(file.text.len() as u64);
                                let truncated = file.truncated || cap < settings.max_file_bytes;
                                Ok(index_content(&file.text, &deny, truncated))
                            }
                            Err(ContentError::TransientRead) => {
                                Err(CoverageGapReason::TransientReadFailed)
                            }
                            Err(ContentError::PermanentRead) => {
                                Err(CoverageGapReason::PermanentReadFailed)
                            }
                            Err(ContentError::NotUtf8) => Err(CoverageGapReason::NotUtf8),
                        }
                    };
                    indexes.insert(path.to_string(), entry);
                }
                match indexes.get(path) {
                    Some(Ok(index)) => {
                        with_context += 1;
                        if index.truncated {
                            gaps.record(CoverageGapReason::FileTruncated, path);
                        }
                        if target.anchor().is_none() {
                            gaps.record(CoverageGapReason::DerivedViewAnchorless, path);
                        }
                        Some((path, index, target.anchor()))
                    }
                    Some(Err(reason)) => {
                        gaps.record(*reason, path);
                        None
                    }
                    None => None,
                }
            }
            Err(reason) => {
                let example = finding
                    .location
                    .file_path
                    .as_deref()
                    .unwrap_or(finding.location.source.as_ref()); // LAW10: absent optional file path uses the finding source only as a coverage-gap example; the gap remains recorded.
                gaps.record(reason, example);
                None
            }
        };

        if let Some((path, index, anchor)) = index {
            for candidate in &index.targets {
                if let Some(target) = score(candidate, anchor, path, policy) {
                    targets.push(target);
                }
            }
        }

        if targets.is_empty() {
            continue;
        }

        targets.sort_by(|a, b| {
            let a_distance = a.evidence.line_distance.unwrap_or(0); // LAW10: absent optional distance affects deterministic ranking only; every access target remains present.
            let b_distance = b.evidence.line_distance.unwrap_or(0); // LAW10: absent optional distance affects deterministic ranking only; every access target remains present.
            a.evidence
                .relation
                .cmp(&b.evidence.relation)
                .then_with(|| a_distance.cmp(&b_distance))
                .then_with(|| {
                    b.confidence
                        .partial_cmp(&a.confidence)
                        .unwrap_or(std::cmp::Ordering::Equal) // LAW10: incomparable confidence values tie only in ordering; subsequent keys retain every target deterministically.
                })
                .then_with(|| a.kind.cmp(&b.kind))
                .then_with(|| a.value.cmp(&b.value))
        });
        targets.dedup_by(|a, b| a.kind == b.kind && a.value == b.value);
        targets.truncate(settings.max_targets_per_finding);

        rows.push(CredentialAccessTargets {
            credential_hash: hex_encode(finding.credential_hash),
            detector_id: finding.detector_id.to_string(),
            service: finding.service.to_string(),
            location: TargetedLocation {
                source: finding.location.source.to_string(),
                file_path: finding.location.file_path.as_deref().map(str::to_string),
                line: finding.location.line,
            },
            targets,
        });
    }

    rows.sort_by(|a, b| {
        a.location
            .file_path
            .cmp(&b.location.file_path)
            .then_with(|| a.location.line.cmp(&b.location.line))
            .then_with(|| a.detector_id.cmp(&b.detector_id))
            .then_with(|| a.credential_hash.cmp(&b.credential_hash))
    });

    let gaps = gaps.finish();
    AccessTargetReport {
        targets: rows,
        coverage: AccessTargetCoverage {
            findings_total: findings.len(),
            findings_with_file_context: with_context,
            files_indexed: indexes.values().filter(|entry| entry.is_ok()).count(),
            bytes_indexed,
            complete: gaps.is_empty(),
            gaps,
        },
    }
}

/// Targets recovered from the credential itself, with no file read.
fn decoded_targets(finding: &VerifiedFinding, policy: &Policy) -> Vec<AccessTarget> {
    let mut out = Vec::new();
    for entry in &policy.metadata {
        let Some(value) = finding.metadata.get(&entry.key) else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        out.push(AccessTarget {
            kind: entry.kind,
            value: value.clone(),
            redaction: Redaction::None,
            label: entry.label.clone(),
            service: entry.service.clone(),
            confidence: round3(policy.settings.decoded_confidence),
            evidence: TargetEvidence {
                relation: TargetRelation::Decoded,
                rule_id: format!("metadata:{}", entry.key),
                file_path: None,
                line: None,
                column: None,
                span_bytes: None,
                line_distance: None,
                provenance: ConfidenceProvenance {
                    source: "credential_metadata".to_string(),
                    base: round3(policy.settings.decoded_confidence),
                    decay_steps: 0,
                    decay_factor: 1.0,
                },
            },
        });
    }
    out
}

/// Score one indexed candidate against one finding, or reject it.
///
/// `anchor` is `None` when the finding's line number indexes a derived view of
/// the file rather than the file itself. There is no honest distance to
/// measure in that case, so every candidate is charged the maximum decay: the
/// door is still reported, but never with a proximity claim it cannot support.
fn score(
    candidate: &IndexedTarget,
    anchor: Option<usize>,
    path: &str,
    policy: &Policy,
) -> Option<AccessTarget> {
    let settings = &policy.settings;
    let rule = policy.rules.get(candidate.rule)?;
    let (relation, steps, distance) = match anchor {
        Some(anchor) => {
            let distance = candidate.line.abs_diff(anchor);
            if distance == 0 {
                (TargetRelation::SameLine, 0u32, Some(0usize))
            } else {
                let steps = u32::try_from(distance / settings.decay_line_step)
                    .unwrap_or(settings.decay_max_steps) // LAW10: distance-to-step overflow conservatively applies maximum confidence decay; it cannot create a stronger target.
                    .clamp(1, settings.decay_max_steps);
                (TargetRelation::SameFile, steps, Some(distance))
            }
        }
        None => (TargetRelation::SameFile, settings.decay_max_steps, None),
    };
    let confidence = rule.spec.confidence * settings.same_file_decay.powi(steps as i32);
    if confidence < settings.min_confidence {
        return None;
    }
    Some(AccessTarget {
        kind: rule.spec.kind,
        value: candidate.value.clone(),
        redaction: rule.spec.redact,
        label: rule.spec.label.clone(),
        service: rule.spec.service.clone(),
        confidence: round3(confidence),
        evidence: TargetEvidence {
            relation,
            rule_id: rule.spec.id.clone(),
            file_path: Some(path.to_string()),
            line: Some(candidate.line),
            column: Some(candidate.column),
            span_bytes: Some(candidate.span_bytes),
            line_distance: distance,
            provenance: ConfidenceProvenance {
                source: "tier_b_rule".to_string(),
                base: round3(rule.spec.confidence),
                decay_steps: steps,
                decay_factor: settings.same_file_decay,
            },
        },
    })
}

/// How a finding's file context may be used.
enum Indexable<'a> {
    /// Read the file and anchor targets at this line.
    Anchored(&'a str, usize),
    /// Read the file, but the finding's line indexes a derived view of it (a
    /// decode view or a window), so there is no anchor and the caller must also
    /// record the caveat.
    Anchorless(&'a str),
}

impl<'a> Indexable<'a> {
    fn path(&self) -> &'a str {
        match *self {
            Self::Anchored(path, _) | Self::Anchorless(path) => path,
        }
    }

    fn anchor(&self) -> Option<usize> {
        match *self {
            Self::Anchored(_, line) => Some(line),
            Self::Anchorless(_) => None,
        }
    }
}

/// The local path this finding's context may be read from, and how, or why not.
///
/// A DERIVED view is labelled `filesystem/<view>`. Two kinds occur: decode
/// views (`filesystem/hex`, `filesystem/base64`, `filesystem/reverse`,
/// `filesystem/quoted-printable`) and the windowed reader used for large files
/// (`filesystem/windowed`), whose line numbers are relative to the window. In
/// both the underlying file is real and its doors are real, so refusing to
/// index it would throw away true coverage; but the finding's line number does
/// not index the file, so claiming a same-line pairing would be a lie. Those
/// get the file, not the anchor.
///
/// The `/` test is what keeps this honest as new views appear: any future
/// `filesystem/<something>` is treated as derived and anchorless by default,
/// which under-claims rather than inventing a proximity.
fn indexable(finding: &VerifiedFinding) -> Result<Indexable<'_>, CoverageGapReason> {
    if finding.location.commit.is_some() {
        return Err(CoverageGapReason::HistoricalContent);
    }
    let source = finding.location.source.as_ref();
    let anchored = READABLE_SOURCES.contains(&source);
    let derived = !anchored
        && READABLE_SOURCES.iter().any(|readable| {
            source.starts_with(readable) && source.as_bytes().get(readable.len()) == Some(&b'/')
        });
    if !anchored && !derived {
        return Err(CoverageGapReason::SourceNotReadable);
    }
    let path = match finding.location.file_path.as_deref() {
        Some(path) if !path.is_empty() => path,
        _ => return Err(CoverageGapReason::NoFilePath),
    };
    if anchored {
        let line = finding.location.line.unwrap_or(1); // LAW10: absent line uses the canonical default; finding remains indexable.
        Ok(Indexable::Anchored(path, line))
    } else {
        Ok(Indexable::Anchorless(path))
    }
}

// Tests live in `crates/core/tests/` (KH-GAP-004: no inline test modules in
// `src/`). See `regression_access_target_policy.rs` for the Tier-B policy
// contract and `regression_access_target_association.rs` for association,
// redaction, bounding, and coverage behavior.

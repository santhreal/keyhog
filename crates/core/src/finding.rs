//! Scanner findings: the output type for detected secrets with location,
//! confidence, detector metadata, and optional verification status.

use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use crate::Severity;

/// A raw pattern match before verification or deduplication.
///
/// `entropy` and `confidence` are stored as `f64` but are guaranteed never to
/// be `NaN` (sanitized at construction time). This keeps the manual `Eq` impl
/// reflexive, which downstream code relies on for `HashMap`/`BTreeMap` keys.
///
/// Manual `Debug` impl redacts the `credential` field — the previous
/// derive-`Debug` was a CRITICAL leak vector (any `{:?}` print, panic
/// handler, or `tracing::error!(?match)` would expose plaintext). See
/// audit kimi-wave1 finding 1.1.
#[derive(Clone, Serialize, Deserialize)]
pub struct RawMatch {
    /// Stable detector identifier.
    #[serde(with = "serde_arc_str")]
    pub detector_id: Arc<str>,
    /// Human-readable detector name.
    #[serde(with = "serde_arc_str")]
    pub detector_name: Arc<str>,
    /// Service namespace associated with the detector.
    #[serde(with = "serde_arc_str")]
    pub service: Arc<str>,
    /// Detector severity level.
    pub severity: Severity,
    /// Matched credential bytes before redaction.
    #[serde(with = "serde_arc_str")]
    pub credential: Arc<str>,
    /// SHA-256 hash of the credential for allowlisting and deduplication.
    pub credential_hash: String,
    /// Companion credential or context value extracted nearby.
    pub companions: std::collections::HashMap<String, String>,
    /// Source location for the match.
    pub location: MatchLocation,
    /// Shannon entropy of the matched credential (0.0 - 8.0). NaN-sanitized.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
    /// Confidence score (0.0 - 1.0). NaN-sanitized at construction.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

impl RawMatch {
    /// Replace NaN floats with `None` so the manual `Eq` impl stays reflexive
    /// and `HashMap`/`BTreeMap` lookups don't trap. Call this on any externally
    /// constructed `RawMatch` (deserialized findings, scanner outputs).
    pub fn sanitize_floats(mut self) -> Self {
        if self.entropy.is_some_and(f64::is_nan) {
            self.entropy = None;
        }
        if self.confidence.is_some_and(f64::is_nan) {
            self.confidence = None;
        }
        self
    }
}

impl PartialEq for RawMatch {
    fn eq(&self, other: &Self) -> bool {
        // Compare every field; for the f64 options use `total_cmp` semantics so
        // NaN-vs-NaN compares equal. We additionally normalize NaN→None on
        // construction (`sanitize_floats`), but the total-ordering comparison
        // here keeps the impl sound even if a NaN slips through.
        self.detector_id == other.detector_id
            && self.detector_name == other.detector_name
            && self.service == other.service
            && self.severity == other.severity
            && self.credential == other.credential
            && self.credential_hash == other.credential_hash
            && self.companions == other.companions
            && self.location == other.location
            && opt_f64_total_eq(self.entropy, other.entropy)
            && opt_f64_total_eq(self.confidence, other.confidence)
    }
}

impl Eq for RawMatch {}

impl std::fmt::Debug for RawMatch {
    /// Redacted Debug. Replaces `derive(Debug)` which would print the raw
    /// `credential: Arc<str>` plaintext. See kimi-wave1 audit finding 1.1.
    /// `credential_hash` is preserved because it's already a one-way SHA-256.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RawMatch")
            .field("detector_id", &self.detector_id)
            .field("detector_name", &self.detector_name)
            .field("service", &self.service)
            .field("severity", &self.severity)
            .field(
                "credential",
                &format_args!("<redacted {} bytes>", self.credential.len()),
            )
            .field("credential_hash", &self.credential_hash)
            .field(
                "companions",
                &format_args!("<{} redacted companions>", self.companions.len()),
            )
            .field("location", &self.location)
            .field("entropy", &self.entropy)
            .field("confidence", &self.confidence)
            .finish()
    }
}

#[inline]
fn opt_f64_total_eq(a: Option<f64>, b: Option<f64>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(x), Some(y)) => x.total_cmp(&y) == std::cmp::Ordering::Equal,
        _ => false,
    }
}

impl PartialOrd for RawMatch {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for RawMatch {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        // Higher confidence first
        let self_conf = self.confidence.unwrap_or(0.0);
        let other_conf = other.confidence.unwrap_or(0.0);

        match other_conf.total_cmp(&self_conf) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }

        // Then higher severity first (Critical > High > Medium > Low > Info)
        match other.severity.cmp(&self.severity) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }

        // Finally, deterministic sort by detector and credential
        match self.detector_id.cmp(&other.detector_id) {
            std::cmp::Ordering::Equal => self.credential.cmp(&other.credential),
            ord => ord,
        }
    }
}

/// Where a credential was found: file path, line number, commit, and author.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MatchLocation {
    /// Logical source backend, such as `filesystem` or `git`.
    #[serde(with = "serde_arc_str")]
    pub source: Arc<str>,
    /// File path, object key, or logical path when available.
    ///
    /// Paths stored here must be valid UTF-8. Source implementations that see
    /// non-UTF-8 paths should encode them into a reversible escaped string
    /// before constructing a [`MatchLocation`].
    #[serde(with = "serde_arc_str_opt")]
    pub file_path: Option<Arc<str>>,
    /// One-based line number when known.
    pub line: Option<usize>,
    /// Byte offset from the start of the source chunk.
    pub offset: usize,
    /// Commit identifier for history-derived matches.
    #[serde(with = "serde_arc_str_opt")]
    pub commit: Option<Arc<str>>,
    /// Commit author when available.
    #[serde(with = "serde_arc_str_opt")]
    pub author: Option<Arc<str>>,
    /// Commit timestamp when available.
    #[serde(with = "serde_arc_str_opt")]
    pub date: Option<Arc<str>>,
}

/// A finding after verification — the final output.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerifiedFinding {
    /// Stable detector identifier.
    #[serde(with = "serde_arc_str")]
    pub detector_id: Arc<str>,
    /// Human-readable detector name.
    #[serde(with = "serde_arc_str")]
    pub detector_name: Arc<str>,
    /// Service namespace associated with the detector.
    #[serde(with = "serde_arc_str")]
    pub service: Arc<str>,
    /// Detector severity level.
    pub severity: Severity,
    /// Redacted version of the credential for reporting.
    pub credential_redacted: Cow<'static, str>,
    /// SHA-256 hash of the original credential for internal correlation.
    pub credential_hash: String,
    /// Source location for the match.
    pub location: MatchLocation,
    /// Verification result.
    pub verification: VerificationResult,
    /// Additional provider-specific metadata (e.g. account ID, scope).
    pub metadata: HashMap<String, String>,
    /// Additional duplicate locations found for this credential.
    pub additional_locations: Vec<MatchLocation>,
    /// Confidence score (0.0 - 1.0) combining entropy, keyword proximity, file type, etc.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

/// Result of live verification: whether the credential is active, revoked, or untested.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum VerificationResult {
    /// Credential is active and verified by the provider.
    Live,
    /// Credential is valid but has been explicitly revoked or disabled.
    Revoked,
    /// Credential was rejected by the provider (invalid password/token).
    Dead,
    /// Provider returned a rate-limit error (e.g. 429).
    RateLimited,
    /// Verification failed due to network error or timeout.
    Error(String),
    /// Detector does not support live verification.
    Unverifiable,
    /// Verification was not attempted (e.g. disabled via flag).
    Skipped,
}

impl RawMatch {
    /// Get unique key for deduplication.
    pub fn deduplication_key(&self) -> (&str, &str) {
        (&self.detector_id, &self.credential)
    }

    /// Convert into a serialization-safe DTO that never carries the plaintext
    /// credential. Use this anywhere a `RawMatch` would otherwise be written
    /// to disk, sent over the network, or rendered into a user-visible
    /// report. See kimi-wave1 audit finding 2.1 (`scan_system.rs` JSON exfil).
    pub fn to_redacted(&self) -> RedactedFinding {
        RedactedFinding {
            detector_id: self.detector_id.clone(),
            detector_name: self.detector_name.clone(),
            service: self.service.clone(),
            severity: self.severity,
            credential_redacted: crate::redact(&self.credential),
            credential_hash: self.credential_hash.clone(),
            companions_redacted: self
                .companions
                .iter()
                .map(|(k, v)| (k.clone(), crate::redact(v).into_owned()))
                .collect(),
            location: self.location.clone(),
            entropy: self.entropy,
            confidence: self.confidence,
        }
    }
}

/// Redacted, disk-safe view of a `RawMatch`. Carries only the SHA-256 hash
/// and a "first4...last4" preview, never the plaintext credential. This is
/// the only finding shape that should ever leave keyhog's process boundary.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactedFinding {
    #[serde(with = "serde_arc_str")]
    pub detector_id: Arc<str>,
    #[serde(with = "serde_arc_str")]
    pub detector_name: Arc<str>,
    #[serde(with = "serde_arc_str")]
    pub service: Arc<str>,
    pub severity: Severity,
    pub credential_redacted: Cow<'static, str>,
    pub credential_hash: String,
    pub companions_redacted: HashMap<String, String>,
    pub location: MatchLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

pub mod serde_arc_str {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::sync::Arc;

    pub fn serialize<S>(val: &Arc<str>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        val.as_ref().serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Arc<str>, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Arc::from)
    }
}

pub mod serde_arc_str_opt {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::sync::Arc;

    pub fn serialize<S>(val: &Option<Arc<str>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        val.as_ref().map(|s| s.as_ref()).serialize(serializer)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<Arc<str>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer).map(|opt| opt.map(Arc::from))
    }
}

#[cfg(test)]
mod hostile_metadata_tests {
    //! "Production-level robustness" coverage: a finding with NUL
    //! bytes, control characters, or other unusual metadata content
    //! must not panic on JSON serialization, Display formatting, or
    //! any standard operation. The fields come from filesystem
    //! walks (PathBuf::display) and external source backends, so
    //! "hostile content" is realistic — operators scanning
    //! adversarial repositories or untrusted HTTP responses see
    //! these every day.

    use super::*;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn finding_with_hostile_path(path: &str) -> VerifiedFinding {
        VerifiedFinding {
            detector_id: Arc::from("test-detector"),
            detector_name: Arc::from("Test Detector"),
            service: Arc::from("test"),
            severity: Severity::Medium,
            credential_redacted: Cow::Borrowed("****"),
            credential_hash: "deadbeef".into(),
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
            confidence: Some(0.5),
        }
    }

    #[test]
    fn nul_bytes_in_path_serialize_to_valid_json() {
        // A path containing a NUL byte (e.g. crafted by a Source
        // emitting through the registry) must round-trip via JSON
        // without panic and without producing malformed output.
        // serde_json escapes NUL as ` `.
        let finding = finding_with_hostile_path("evil\0name.env");
        let json = serde_json::to_string(&finding).expect("serialize ok");
        assert!(json.contains("\\u0000"), "NUL must be escaped in JSON");
        // And it must parse back cleanly.
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse ok");
        assert!(v.is_object());
    }

    #[test]
    fn control_chars_in_path_serialize_safely() {
        // Embedded \r, \n, \t, ESC, etc. — common in attacker-
        // controlled filenames. JSON must escape rather than emit
        // raw control bytes (which would corrupt log scrapers /
        // SARIF readers).
        let finding =
            finding_with_hostile_path("path\r\nwith\x1b[31mANSI\x1bcontrol\tchars");
        let json = serde_json::to_string(&finding).expect("serialize ok");
        assert!(json.contains("\\r"));
        assert!(json.contains("\\n"));
        assert!(json.contains("\\t"));
        // ESC (0x1b) escapes to  in JSON.
        assert!(json.contains("\\u001b"));
        let _: serde_json::Value = serde_json::from_str(&json).expect("parse ok");
    }

    #[test]
    fn replacement_char_in_path_round_trips() {
        // Lossy UTF-8 paths from `Path::display()` contain U+FFFD
        // for invalid byte sequences. Must serialize/deserialize
        // cleanly — Rust strings are valid UTF-8 by construction so
        // U+FFFD is a normal char.
        let finding = finding_with_hostile_path("name_\u{FFFD}_after");
        let json = serde_json::to_string(&finding).expect("serialize ok");
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse ok");
        let recovered = v["location"]["file_path"].as_str().unwrap();
        assert!(recovered.contains('\u{FFFD}'));
    }

    #[test]
    fn extremely_long_path_does_not_panic() {
        // A 1 MiB path string. No panic, no truncation, no allocation
        // failure on a typical machine. Tests that no Display
        // formatter has a hidden length limit that would error.
        let long = "a".repeat(1024 * 1024);
        let finding = finding_with_hostile_path(&long);
        let json = serde_json::to_string(&finding).expect("serialize ok");
        assert!(json.len() > 1024 * 1024);
        let v: serde_json::Value = serde_json::from_str(&json).expect("parse ok");
        assert_eq!(
            v["location"]["file_path"].as_str().unwrap().len(),
            long.len()
        );
    }
}

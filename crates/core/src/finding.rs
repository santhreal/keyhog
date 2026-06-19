//! Scanner findings: the output type for detected secrets with location,
//! confidence, detector metadata, and optional verification status.

// Debt bucket: 16 public items predating the crate floor raising `missing_docs`
// to `warn`. Public output schema; remove once each carries a doc line.
#![allow(missing_docs)]

use serde::ser::SerializeStruct;
use serde::{Deserialize, Serialize, Serializer};
use std::borrow::Cow;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use crate::{SensitiveString, Severity};

/// A raw pattern match before verification or deduplication.
///
/// `entropy` and `confidence` are stored as `f64` but are guaranteed never to
/// be `NaN` (sanitized at construction time). This keeps the manual `Eq` impl
/// reflexive, which downstream code relies on for `HashMap`/`BTreeMap` keys.
///
/// Manual `Debug` impl redacts the `credential` field - the previous
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
    pub credential: SensitiveString,
    /// SHA-256 digest of the credential for allowlisting and deduplication.
    ///
    /// Stored as the raw 32 inline bytes (matching the verifier `CacheKey`),
    /// never the 64-char hex `String`: zero heap, half the per-finding
    /// footprint, no per-match allocation on the pre-dedup hot path. Hex
    /// encoding happens lazily at the serde/reporter boundary only.
    #[serde(with = "serde_hash_hex")]
    pub credential_hash: [u8; 32],
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
    pub(crate) fn sanitize_floats(mut self) -> Self {
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
    /// credential plaintext. See kimi-wave1 audit finding 1.1.
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
            .field(
                "credential_hash",
                &format_args!("{}", hex_encode(&self.credential_hash)),
            )
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
        // LAW10 (both): recall-safe — a `None` confidence sorts as 0.0 (lowest)
        // for stable display ordering ONLY. Both findings remain in the result
        // set; sort position never drops a finding.
        let self_conf = self.confidence.unwrap_or(0.0); // LAW10: absent confidence => 0.0 for sort/partition ordering only; recall-safe
        let other_conf = other.confidence.unwrap_or(0.0); // LAW10: absent confidence => 0.0 for sort/partition ordering only; recall-safe

        match other_conf.total_cmp(&self_conf) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }

        // Then higher severity first (Critical > High > Medium > Low > Info)
        match other.severity.cmp(&self.severity) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }

        // Then by detector and credential.
        match self.detector_id.cmp(&other.detector_id) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }
        match self.credential.cmp(&other.credential) {
            std::cmp::Ordering::Equal => {}
            ord => return ord,
        }

        // Finally by location (offset, then line) so the order is TOTAL with
        // respect to the dedup identity (detector, credential, offset). Without
        // this last key, two matches of the same secret at different offsets
        // compare Equal, so when the capped per-chunk match heap
        // (`ScanState::push_match`) evicts among them at `max_matches_per_chunk`,
        // the survivor is chosen by insertion order — which is HashMap-iteration
        // and rayon-thread nondeterministic. A dense, repetitive chunk (e.g. the
        // concat-source throughput corpus) overflows the cap with many such
        // ties, so the finding set flickered run-to-run. Including the location
        // makes eviction content-determined: the kept set is reproducible
        // regardless of marking volume or thread interleaving.
        match self.location.offset.cmp(&other.location.offset) {
            std::cmp::Ordering::Equal => self.location.line.cmp(&other.location.line),
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

/// A finding after verification - the final output.
#[derive(Debug, Clone, Deserialize)]
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
    /// SHA-256 digest of the original credential for internal correlation.
    /// Raw 32 inline bytes; hex-encoded lazily at the serde/reporter boundary.
    #[serde(with = "serde_hash_hex")]
    pub credential_hash: [u8; 32],
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

impl Serialize for VerifiedFinding {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let remediation =
            crate::auto_fix::remediation_for(&self.detector_id, &self.service, self.severity);
        let mut field_count = 11;
        if self.confidence.is_some() {
            field_count += 1;
        }
        let mut state = serializer.serialize_struct("VerifiedFinding", field_count)?;
        state.serialize_field("detector_id", self.detector_id.as_ref())?;
        state.serialize_field("detector_name", self.detector_name.as_ref())?;
        state.serialize_field("service", self.service.as_ref())?;
        state.serialize_field("severity", &self.severity)?;
        state.serialize_field("credential_redacted", self.credential_redacted.as_ref())?;
        state.serialize_field("credential_hash", &hex_encode(&self.credential_hash))?;
        state.serialize_field("location", &self.location)?;
        state.serialize_field("verification", &self.verification)?;
        let sorted_metadata: BTreeMap<&str, &str> = self
            .metadata
            .iter()
            .map(|(key, value)| (key.as_str(), value.as_str()))
            .collect();
        state.serialize_field("metadata", &sorted_metadata)?;
        state.serialize_field("additional_locations", &self.additional_locations)?;
        if let Some(confidence) = self.confidence {
            state.serialize_field("confidence", &confidence)?;
        }
        state.serialize_field("remediation", &remediation)?;
        state.end()
    }
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
    pub(crate) fn deduplication_key(&self) -> (&str, &str) {
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
            credential_hash: self.credential_hash,
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
    /// SHA-256 digest as raw 32 inline bytes; hex-encoded at the serde boundary.
    #[serde(with = "serde_hash_hex")]
    pub credential_hash: [u8; 32],
    pub companions_redacted: HashMap<String, String>,
    pub location: MatchLocation,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entropy: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f64>,
}

/// Lower-case hex of a 32-byte SHA-256 digest. The only place the hex string
/// is materialized for a `[u8; 32]` `credential_hash` (reporters, Debug).
#[inline]
pub fn hex_encode(bytes: &[u8; 32]) -> String {
    hex::encode(bytes)
}

/// SHA-256 of a string as the raw 32 inline bytes, matching the
/// `credential_hash: [u8; 32]` field. This is the single source for credential
/// hashing across the workspace (scanner, dedup, telemetry); hex encoding is a
/// separate step at the serde/reporter boundary via [`hex_encode`], keeping the
/// pre-dedup hot path zero-heap. Every `credential_hash` assignment forwards
/// this value straight into the `[u8; 32]` field, so callers want the byte form
/// here, not the hex string.
#[inline]
pub fn sha256_hash(s: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hasher.finalize().into()
}

/// Serde adapter keeping the on-wire shape of `credential_hash` a 64-char
/// lower-case hex string while the in-memory field is raw `[u8; 32]`. This
/// preserves the documented JSON/JSONL/baseline/SARIF format (`.credential_hash`
/// consumers, `keyhogignore` `hash:` entries) with zero heap on the hot path.
pub(crate) mod serde_hash_hex {
    use serde::{Deserialize, Deserializer, Serializer};

    pub(crate) fn serialize<S>(val: &[u8; 32], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&hex::encode(val))
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 32], D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let bytes = hex::decode(&s).map_err(serde::de::Error::custom)?;
        bytes
            .try_into()
            .map_err(|_| serde::de::Error::invalid_length(s.len() / 2, &"32-byte SHA-256 digest"))
    }
}

pub(crate) mod serde_arc_str {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::sync::Arc;

    pub(crate) fn serialize<S>(val: &Arc<str>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        val.as_ref().serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Arc<str>, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer).map(Arc::from)
    }
}

pub(crate) mod serde_arc_str_opt {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use std::sync::Arc;

    pub(crate) fn serialize<S>(val: &Option<Arc<str>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        val.as_ref().map(|s| s.as_ref()).serialize(serializer)
    }

    pub(crate) fn deserialize<'de, D>(deserializer: D) -> Result<Option<Arc<str>>, D::Error>
    where
        D: Deserializer<'de>,
    {
        Option::<String>::deserialize(deserializer).map(|opt| opt.map(Arc::from))
    }
}

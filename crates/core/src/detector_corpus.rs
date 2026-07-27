//! Explicit detector-corpus composition policy.

use crate::DetectorSpec;
use std::collections::BTreeSet;

/// How a custom detector corpus participates in the effective corpus.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DetectorCorpusMode {
    /// The custom corpus is the complete effective corpus.
    Replace,
    /// The custom corpus is appended to the embedded corpus after collision checks.
    Overlay,
}

/// Failure to compose an effective detector corpus.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DetectorCorpusError {
    /// An overlay tried to reuse an embedded detector identifier.
    #[error(
        "detector overlay collides with embedded detector id(s): {ids}. \
         Overlay mode never shadows shipped detectors; rename the custom detector id(s), \
         or select replace mode for a fully custom corpus"
    )]
    IdCollision {
        /// Sorted, comma-separated detector identifiers present in both corpora.
        ids: String,
    },
}

/// Compose an effective detector corpus without implicit merging.
///
/// Replace mode returns the custom vector directly and does not clone either
/// corpus. Overlay mode preserves each input's order, rejects every identifier
/// shared by the embedded and custom sets, and then moves the custom specs onto
/// the end of the embedded vector.
pub fn compose_detector_corpus(
    mut embedded: Vec<DetectorSpec>,
    custom: Vec<DetectorSpec>,
    mode: DetectorCorpusMode,
) -> Result<Vec<DetectorSpec>, DetectorCorpusError> {
    if mode == DetectorCorpusMode::Replace {
        return Ok(custom);
    }

    let embedded_ids: BTreeSet<&str> = embedded
        .iter()
        .map(|detector| detector.id.as_str())
        .collect();
    let collisions: BTreeSet<&str> = custom
        .iter()
        .map(|detector| detector.id.as_str())
        .filter(|id| embedded_ids.contains(id))
        .collect();
    if !collisions.is_empty() {
        return Err(DetectorCorpusError::IdCollision {
            ids: collisions.into_iter().collect::<Vec<_>>().join(", "),
        });
    }

    embedded.reserve(custom.len());
    embedded.extend(custom);
    Ok(embedded)
}
/// Compute a deterministic digest of current-schema detector specs.
///
/// Embedded callers that cannot select another schema use this convenience
/// entry point. Directory loaders should retain [`crate::LoadedDetectorCorpus`]
/// and call its schema-aware `compute_digest` method instead.
pub fn compute_detector_corpus_digest(
    detectors: &[DetectorSpec],
) -> Result<[u8; 32], serde_json::Error> {
    compute_detector_corpus_digest_for_schema(detectors, crate::DETECTOR_CORPUS_SCHEMA_VERSION)
}

/// Compute a deterministic, schema-bound digest of a complete effective
/// detector corpus.
///
/// Unlike [`crate::compute_spec_hash`], whose contract intentionally includes
/// only fields that can change scan finding sets, this identity serializes every
/// declared detector field. It also binds the canonical corpus-manifest path and
/// the schema version that normalized the specs, so a legacy schema-1 corpus
/// cannot share cache, handshake, or autoroute evidence with an otherwise equal
/// current-schema corpus.
pub fn compute_detector_corpus_digest_for_schema(
    detectors: &[DetectorSpec],
    schema_version: u32,
) -> Result<[u8; 32], serde_json::Error> {
    let mut canonical: Vec<&DetectorSpec> = detectors.iter().collect();
    canonical.sort_by(|left, right| left.id.cmp(&right.id));
    let encoded = serde_json::to_vec(&canonical)?;
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"keyhog-effective-detector-corpus-v2\0");
    hasher.update(crate::DETECTOR_CORPUS_MANIFEST_FILE.as_bytes());
    hasher.update(&[0]);
    hasher.update(&schema_version.to_le_bytes());
    hasher.update(&encoded);
    Ok(*hasher.finalize().as_bytes())
}

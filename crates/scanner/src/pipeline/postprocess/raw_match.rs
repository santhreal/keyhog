use crate::types::*;
use keyhog_core::{Chunk, MatchLocation, RawMatch};
use std::collections::HashMap;
use std::sync::Arc;

#[allow(clippy::too_many_arguments)]
pub fn build_raw_match(
    detector: &keyhog_core::DetectorSpec,
    // Pre-interned (detector_id, detector_name, service) for this detector,
    // cloned by index from `CompiledScanner::metadata_by_index` instead of
    // re-hashed per match (PERF-locality_intern-1). Byte-identical to the
    // `intern_metadata` result it replaces.
    metadata: (Arc<str>, Arc<str>, Arc<str>),
    chunk: &Chunk,
    credential: &str,
    companions: HashMap<String, String>,
    offset: usize,
    line: usize,
    ent: f64,
    confidence: f64,
    scan_state: &mut ScanState,
) -> RawMatch {
    let (detector_id, detector_name, service) = metadata;
    // Diff-aware severity: a credential whose only sighting is in non-HEAD
    // git history (the developer already removed it from `main`) is still
    // a leak - but it's strictly less urgent than a credential live in HEAD
    // that an attacker can grep right now. Drop one tier when the source
    // backend tagged this chunk as `git/history`. Everything else (live
    // filesystem, `git/head`, S3/Docker/Web/etc) keeps the detector's
    // declared severity.
    let severity = if chunk.metadata.source_type == "git/history" {
        detector.severity.downgrade_one()
    } else {
        detector.severity
    };
    RawMatch {
        detector_id,
        detector_name,
        service,
        severity,
        credential_hash: crate::sha256_hash(credential),
        credential: scan_state.intern_credential(credential),
        companions,
        location: MatchLocation {
            source: scan_state.intern_metadata(&chunk.metadata.source_type),
            file_path: chunk
                .metadata
                .path
                .as_ref()
                .map(|p| scan_state.intern_metadata(p)),
            line: Some(line),
            offset: offset + chunk.metadata.base_offset,
            commit: chunk
                .metadata
                .commit
                .as_ref()
                .map(|c| scan_state.intern_metadata(c)),
            author: chunk
                .metadata
                .author
                .as_ref()
                .map(|a| scan_state.intern_metadata(a)),
            date: chunk
                .metadata
                .date
                .as_ref()
                .map(|d| scan_state.intern_metadata(d)),
        },
        entropy: Some(ent),
        confidence: Some(confidence),
    }
}

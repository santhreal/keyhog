//! Post-match processing: raw match construction and placeholder suppression.

#[cfg(feature = "entropy")]
pub(crate) use crate::suppression::{contains_uuid_v4_substring, looks_like_email_address};
pub(crate) use crate::suppression::{
    looks_like_public_version_identifier, looks_like_punctuation_decorated_identifier,
    looks_like_pure_identifier, looks_like_regex_literal_tail, looks_like_scheme_prefixed_uri,
    looks_like_shell_template_value, looks_like_train_case_prose_identifier,
    looks_like_url_or_path_segment, looks_like_vendored_minified_path,
    looks_like_word_separated_identifier,
};
// See pipeline/mod.rs: only the `simdsieve` hot-pattern fast path imports
// this symbol through the pipeline module path; gate to silence the lean
// build without an #[allow] evasion.
#[cfg(feature = "simdsieve")]
pub(crate) use crate::suppression::looks_like_secret_scanner_source;
#[cfg(any(feature = "entropy", feature = "simdsieve", test))]
pub(crate) use crate::suppression::should_suppress_known_example_credential_with_source;
pub(crate) use crate::suppression::{
    detector_weak_anchor, should_suppress_named_detector_finding_weak,
};
#[cfg(test)]
pub(crate) use crate::suppression::{
    should_suppress_known_example_credential, should_suppress_named_detector_finding,
};

use crate::types::*;
use keyhog_core::{Chunk, MatchLocation, RawMatch};
use std::collections::HashMap;
use std::sync::Arc;

#[allow(clippy::too_many_arguments)]
pub(crate) fn build_raw_match(
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
    pattern_client_safe: bool,
) -> RawMatch {
    let (detector_id, detector_name, service) = metadata;
    // Diff-aware severity: a credential whose only sighting is in non-HEAD
    // git history (the developer already removed it from `main`) is still
    // a leak - but it's strictly less urgent than a credential live in HEAD
    // that an attacker can grep right now. Drop one tier when the source
    // backend tagged this chunk as `git/history`. Everything else (live
    // filesystem, `git/head`, S3/Docker/Web/etc) keeps the detector's
    // declared severity.
    //
    // Client-safe tier: a match against a pattern marked `client_safe = true`
    // (Sentry DSN, Stripe pk_*, Firebase web key, etc.) is collapsed to
    // `Severity::ClientSafe` regardless of the detector's nominal severity
    // and regardless of the git-diff state. The credential is real but it
    // was *intended* to ship in client bundles - bug-bounty hunters running
    // `--hide-client-safe` drop these entirely; defaults still surface them
    // below `Low` so a misconfigured "publishable" key on a server-only
    // detector still gets flagged.
    let severity = if pattern_client_safe {
        keyhog_core::Severity::ClientSafe
    } else if chunk.metadata.source_type == "git/history" {
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
            // `line` is the match's line WITHIN the chunk text (1-based);
            // `base_line` is the count of lines before the chunk's start in
            // the original file (non-zero only for windowed >window_size
            // files). Summing them gives the absolute file line, exactly as
            // `offset + base_offset` gives the absolute byte offset. Without
            // this a secret on line 584307 of a 70 MiB file reported the
            // per-window line (~2). base_line is 0 for whole-file chunks, so
            // this is a no-op on the common path.
            line: Some(line + chunk.metadata.base_line),
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

use super::ExtractedPair;

mod env;
mod hcl;
mod json;
mod line;
mod yaml;

pub(crate) use env::parse_env;
pub(crate) use hcl::parse_hcl;
pub(crate) use json::{parse_jupyter, parse_tfstate};
pub(crate) use yaml::{parse_docker_compose, parse_k8s_secret};

/// Decide whether a structured-format parse/shape gap is a REAL lost decode
/// surface, recording it against the structured-parse-failure telemetry when so.
///
/// At decode depth 0 (`decode_derived == false`) the parsed text IS the original
/// file, so a gap genuinely drops the decode-through surface (the encoded values
/// never become scannable lines): it is counted (Law 10) and the caller SHOULD
/// emit its loud `warn!`.
///
/// At depth > 0 (`decode_derived == true`) the text is a buffer the
/// decode-through pipeline synthesised by splicing an already-decoded payload
/// back into the parent scaffold (`ChunkMetadata::decoded_span.is_some()`). Such
/// a buffer is not guaranteed to be valid YAML/JSON, and a value inside it has
/// already been decoded once - so re-failing to parse or re-decode it loses
/// nothing. The gap is NOT counted and the caller should stay quiet (a `debug!`
/// at most); announcing a lost surface here would be a false Law-10 alarm and
/// would inflate the coverage-gap telemetry. Returns `true` iff the gap is real.
#[must_use]
pub(super) fn structured_gap_is_real(decode_derived: bool) -> bool {
    if decode_derived {
        return false;
    }
    crate::telemetry::record_structured_parse_failure();
    true
}

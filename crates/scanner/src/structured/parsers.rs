use super::ExtractedPair;

/// Cap recursion depth on adversarial structured input. A large document of
/// deeply nested arrays/maps can exceed the default thread stack; 256 is beyond
/// any real Terraform state, docker-compose schema, or Kubernetes List wrapper.
/// Single owner for the JSON (tfstate/jupyter) and YAML (k8s/compose) depth
/// guards so the two caps cannot silently drift apart.
pub(crate) const MAX_STRUCTURED_TRAVERSAL_DEPTH: usize = 256;

mod env;
mod hcl;
mod json;
mod line;
mod yaml;

pub(crate) use env::parse_env;
pub(crate) use hcl::parse_hcl;
pub(crate) use json::{parse_jupyter, parse_tfstate};
pub(crate) use line::resolve_line_number_options;
pub(crate) use yaml::{parse_docker_compose, parse_k8s_secret};

/// Pure query: is a structured-format parse/shape gap a REAL lost decode surface?
///
/// At decode depth 0 (`decode_derived == false`) the parsed text IS the original
/// file, so a gap genuinely drops the decode-through surface (the encoded values
/// never become scannable lines): it is real and the caller SHOULD record it and
/// emit its loud `warn!`.
///
/// At depth > 0 (`decode_derived == true`) the text is a buffer the
/// decode-through pipeline synthesised by splicing an already-decoded payload
/// back into the parent scaffold (`ChunkMetadata::decoded_span.is_some()`). Such
/// a buffer is not guaranteed to be valid YAML/JSON, and a value inside it has
/// already been decoded once - so re-failing to parse or re-decode it loses
/// nothing. The gap is NOT real and the caller should stay quiet (a `debug!` at
/// most); announcing a lost surface here would be a false Law-10 alarm.
///
/// This is a PURE predicate with no side effect: recording the telemetry counter
/// is the caller's separate decision via [`record_structured_gap`], so a per-
/// fragment `if gap_is_real(..)` check cannot double-count a file (the counter
/// counts FILES, not fragments).
#[must_use]
pub(super) fn gap_is_real(decode_derived: bool) -> bool {
    !decode_derived
}

/// Effect: record ONE structured decode-through coverage gap against the
/// file-level telemetry counter (Law 10). Call at most once per file, only when
/// [`gap_is_real`] holds, the counter counts FILES that lost decode-through, so
/// a file with N malformed fragments/documents/values must still record once.
pub(super) fn record_structured_gap() {
    crate::telemetry::record_structured_parse_failure();
}

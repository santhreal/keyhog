//! Focused shape helpers for fallback entropy filtering.

#[cfg(feature = "entropy")]
use crate::detector_ids::{
    ENTROPY_API_KEY, ENTROPY_GENERIC, ENTROPY_PASSWORD, ENTROPY_TOKEN, GENERIC_API_KEY,
    GENERIC_KEYWORD_SECRET, GENERIC_PASSWORD, GENERIC_SECRET,
};

/// Generic detector owners for the four entropy-fallback classes, index-parallel
/// with [`classify_entropy_detector_index`]. The loaded detector TOMLs provide
/// the emitted identity through `entropy_fallback`; these ids only select the
/// owner policy at compile time.
#[cfg(feature = "entropy")]
pub(crate) const ENTROPY_FALLBACK_OWNER_IDS: [&str; 4] = [
    GENERIC_SECRET,
    GENERIC_PASSWORD,
    GENERIC_KEYWORD_SECRET,
    GENERIC_API_KEY,
];

/// Compatibility metadata for custom/legacy specs that omit the optional
/// detector-owned identity block. Embedded generic TOMLs all declare their
/// metadata, so shipped output is TOML-defined.
#[cfg(feature = "entropy")]
pub(crate) const ENTROPY_DETECTOR_METADATA_COMPAT: [(&str, &str, &str); 4] = [
    (ENTROPY_GENERIC, "Generic High-Entropy Secret", "generic"),
    (ENTROPY_PASSWORD, "Password (Entropy Detected)", "generic"),
    (ENTROPY_TOKEN, "API Token (Entropy Detected)", "generic"),
    (ENTROPY_API_KEY, "API Key (Entropy Detected)", "generic"),
];

/// Classify an entropy candidate's keyword into the index of its metadata
/// triple in the compiled metadata table. The branch order matches the
/// historical keyword→detector mapping, so the resolved detector
/// id/name/service are unchanged; the scanner clones the pre-interned triple
/// at this index at the emit site (PERF-locality_intern-1).
#[cfg(feature = "entropy")]
#[inline]
pub(crate) fn classify_entropy_detector_index(keyword: &str) -> usize {
    // The keyword is the captured assignment key and preserves its source case
    // (`PASSWORD=`, `Api_Key=`, `SEGMENT_WRITE_KEY=`), the sibling
    // `keyword_is_credential_anchor` lowercases it for exactly this reason. Match
    // case-insensitively so an all-caps `PASSWORD`/`TOKEN` anchor is labelled
    // Password/Token, not defaulted to the API-Key bucket. `ci_find` jumps to
    // first-byte candidates with memchr2 and allocates nothing (Law 7).
    use crate::ascii_ci::ci_find;
    let bytes = keyword.as_bytes();
    if keyword == crate::entropy::KEYWORD_FREE_LABEL {
        0
    } else if crate::entropy::keywords::keyword_is_password_family(keyword) {
        1
    } else if ci_find(bytes, b"token") {
        2
    } else {
        3
    }
}

/// True when the entropy candidate's keyword indicates a strong credential
/// anchor was directly responsible for the candidate's extraction. The
/// caller uses this to admit the candidate past the file-extension gate
/// in `scan_entropy_fallback`: if the line carries `api_key=`, `token=`,
/// `password=`, etc., the file extension (source code vs. config) is no
/// longer the deciding signal - the keyword anchor IS positive evidence
/// the value is a credential.
///
/// `keyword == KEYWORD_FREE_LABEL` is the no-keyword path (very-high
/// entropy threshold was used); it is NOT a credential anchor.
#[cfg(feature = "entropy")]
pub(crate) fn keyword_is_credential_anchor(keyword: &str) -> bool {
    if keyword == crate::entropy::KEYWORD_FREE_LABEL {
        return false;
    }
    // The normalized-keyword path is checked first and reads `keyword`
    // directly, so defer the `to_ascii_lowercase()` allocation until after it:
    // a credential keyword (`api_key`, `token`, …) returns here without ever
    // allocating the lowercase copy (Law 7).
    if crate::engine::phase2_generic::keywords::normalize_assignment_keyword(keyword)
        .as_deref()
        .is_some_and(crate::entropy::keywords::normalized_assignment_keyword_is_credential)
    {
        return true;
    }
    let lower = keyword.to_ascii_lowercase();
    crate::assignment_keywords::assignment_keywords()
        .iter()
        .any(|anchor| lower.contains(anchor.as_str()))
        || lower.contains("bearer")
}

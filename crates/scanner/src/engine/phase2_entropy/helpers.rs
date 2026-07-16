//! Focused shape helpers for fallback entropy filtering.

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

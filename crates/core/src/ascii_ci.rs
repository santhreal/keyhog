//! Shared ASCII case-insensitive primitives: `starts_with` /
//! `ends_with_ignore_ascii_case` and the `ci_find` byte-substring search.
//! Single owner (ONE PLACE) for allocation-free case-folded comparisons on the
//! scanner and verifier hot paths, callers use these instead of allocating a
//! lowercased copy of each candidate.

/// Returns true when `value` starts with `prefix`, ignoring ASCII case.
#[inline]
pub fn starts_with_ignore_ascii_case(value: &str, prefix: &str) -> bool {
    value
        .as_bytes()
        .get(..prefix.len())
        .is_some_and(|head| head.eq_ignore_ascii_case(prefix.as_bytes()))
}

/// Returns true when `value` contains `needle`, ignoring ASCII case.
#[inline]
pub fn contains_ignore_ascii_case(value: &str, needle: &str) -> bool {
    contains_bytes_ignore_ascii_case(value, needle.as_bytes())
}

/// Returns true when `value` contains `needle`, ignoring ASCII case.
#[inline]
pub fn contains_bytes_ignore_ascii_case(value: &str, needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    value
        .as_bytes()
        .windows(needle.len())
        .any(|window| window.eq_ignore_ascii_case(needle))
}

/// Returns true when the last `suffix.len()` bytes of `bytes` equal `suffix`,
/// ignoring ASCII case. Byte-based so it is the ONE owner for both the scanner
/// (which works in `&[u8]`) and the sources crate (string callers pass
/// `value.as_bytes()` / a `b"..."` literal). An empty suffix always matches; a
/// suffix longer than `bytes` never matches.
#[inline]
pub fn ends_with_ignore_ascii_case(bytes: &[u8], suffix: &[u8]) -> bool {
    bytes
        .get(bytes.len().saturating_sub(suffix.len())..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix))
}

/// Returns true when `value` contains only ASCII letters and decimal digits.
/// The empty string follows the standard `Iterator::all` identity and returns
/// true. Non-ASCII Unicode letters and digits are rejected deliberately so
/// format validators share the same byte-level contract.
#[inline]
pub fn is_ascii_alphanumeric_str(value: &str) -> bool {
    is_ascii_alphanumeric_bytes(value.as_bytes())
}

/// Returns true when every byte in `bytes` is an ASCII letter or decimal digit.
/// The empty slice returns true, matching `slice.iter().all(...)`.
#[inline]
pub fn is_ascii_alphanumeric_bytes(bytes: &[u8]) -> bool {
    bytes.iter().all(|byte| byte.is_ascii_alphanumeric())
}

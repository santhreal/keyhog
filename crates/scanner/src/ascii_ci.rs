//! ASCII case-insensitive byte-search primitives shared by every hot path
//! that wants to skim text for a known set of fixed needles without first
//! lowering the haystack.
//!
//! Why this exists: `text.to_ascii_lowercase().contains(needle)` is the
//! natural Rust idiom but allocates a `String` the size of the haystack
//! every call. In the scanner hot path (per-match suppression checks,
//! per-line context inference) that pattern was responsible for tens of
//! thousands of transient allocations per chunk. The functions here walk
//! the haystack as raw bytes against pre-lowercased static needles,
//! using `memchr::memchr2_iter` to skim past chunks where the first byte
//! of the needle is absent.

/// Case-insensitive `ends_with`. Returns true when the last `suffix.len()`
/// bytes of `bytes` compare equal to `suffix` ignoring ASCII case.
#[inline]
pub fn ends_with_ignore_ascii_case(bytes: &[u8], suffix: &[u8]) -> bool {
    if suffix.len() > bytes.len() {
        return false;
    }
    let tail = &bytes[bytes.len() - suffix.len()..];
    tail.eq_ignore_ascii_case(suffix)
}

/// Case-insensitive `starts_with`.
#[inline]
pub fn starts_with_ignore_ascii_case(bytes: &[u8], prefix: &[u8]) -> bool {
    bytes
        .get(..prefix.len())
        .is_some_and(|p| p.eq_ignore_ascii_case(prefix))
}

/// Case-insensitive ASCII byte substring search.
///
/// `needle_lower` MUST already be ASCII-lowercase (its bytes are compared
/// case-insensitively against `haystack` so this saves the caller from
/// lowering the haystack).
///
/// Skim cost is one `memchr2` SIMD pass; full compare runs only at each
/// candidate first-byte position.
#[inline]
pub fn ci_find(haystack: &[u8], needle_lower: &[u8]) -> bool {
    if needle_lower.is_empty() {
        return true;
    }
    let n = needle_lower.len();
    if haystack.len() < n {
        return false;
    }
    let first_lower = needle_lower[0];
    let first_upper = first_lower.to_ascii_uppercase();
    for start in memchr::memchr2_iter(first_lower, first_upper, haystack) {
        if start + n > haystack.len() {
            break;
        }
        if haystack[start..start + n].eq_ignore_ascii_case(needle_lower) {
            return true;
        }
    }
    false
}

/// True when `path` (POSIX or Windows shape) contains the path segment
/// `segment` (e.g. matches `/<segment>/` OR `\<segment>\`). Walks `path`
/// once via `memchr2_iter` over `/` and `\\` separator bytes - no
/// allocations regardless of whether the path is case-mismatched or
/// extremely long.
///
/// Used by the vendored-tree suppression check; called up to a dozen
/// times per match before this fix would otherwise allocate two `String`
/// needles per call (`/seg/` and `\seg\`) at ~50 bytes each.
#[inline]
pub fn contains_path_segment(path: &str, segment: &str) -> bool {
    let bytes = path.as_bytes();
    let seg = segment.as_bytes();
    let n = seg.len();
    if n == 0 || bytes.len() < n + 2 {
        return false;
    }
    for sep_idx in memchr::memchr2_iter(b'/', b'\\', bytes) {
        let body_start = sep_idx + 1;
        let body_end = body_start + n;
        if body_end >= bytes.len() {
            break;
        }
        if !bytes[body_start..body_end].eq_ignore_ascii_case(seg) {
            continue;
        }
        if matches!(bytes[body_end], b'/' | b'\\') {
            return true;
        }
    }
    false
}

/// Two-segment variant: matches `/a/b/` (POSIX) or `\a\b\` (Windows).
#[inline]
pub fn contains_path_segment_two(path: &str, a: &str, b: &str) -> bool {
    let bytes = path.as_bytes();
    let a_b = a.as_bytes();
    let b_b = b.as_bytes();
    if a_b.is_empty() || b_b.is_empty() {
        return false;
    }
    let total = a_b.len() + b_b.len();
    if bytes.len() < total + 3 {
        return false;
    }
    for sep_idx in memchr::memchr2_iter(b'/', b'\\', bytes) {
        let a_start = sep_idx + 1;
        let a_end = a_start + a_b.len();
        if a_end + 1 + b_b.len() >= bytes.len() {
            break;
        }
        if !bytes[a_start..a_end].eq_ignore_ascii_case(a_b) {
            continue;
        }
        if !matches!(bytes[a_end], b'/' | b'\\') {
            continue;
        }
        let b_start = a_end + 1;
        let b_end = b_start + b_b.len();
        if b_end >= bytes.len() {
            continue;
        }
        if !bytes[b_start..b_end].eq_ignore_ascii_case(b_b) {
            continue;
        }
        if matches!(bytes[b_end], b'/' | b'\\') {
            return true;
        }
    }
    false
}

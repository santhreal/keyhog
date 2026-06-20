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

#[cfg(any(feature = "gpu", test))]
use std::mem::MaybeUninit;

/// Append `src` to `dst` while ASCII-lowercasing bytes in one pass.
///
/// This is for hot paths that must materialize a lowercase byte buffer for an
/// external engine. It preserves non-ASCII bytes exactly, matching
/// [`[u8]::make_ascii_lowercase`] semantics without first copying the original
/// bytes and then walking them again to fold case.
#[inline]
#[cfg(any(feature = "gpu", test))]
pub(crate) fn extend_ascii_lowercase_from(dst: &mut Vec<u8>, src: &[u8]) {
    let old_len = dst.len();
    dst.reserve(src.len());
    let spare = &mut dst.spare_capacity_mut()[..src.len()];
    write_ascii_lowercase_into(spare, src);
    // SAFETY: every element in the spare slice above was initialized exactly
    // once by write_ascii_lowercase_into, and reserve() guaranteed enough
    // capacity for src.len() bytes.
    unsafe {
        dst.set_len(old_len + src.len());
    }
}

#[inline]
#[cfg(any(feature = "gpu", test))]
fn write_ascii_lowercase_into(dst: &mut [MaybeUninit<u8>], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());
    let simd_len = write_ascii_lowercase_simd_prefix(dst, src);
    for (slot, &byte) in dst[simd_len..].iter_mut().zip(&src[simd_len..]) {
        slot.write(ascii_lower_branchless(byte));
    }
}

#[inline]
#[cfg(all(any(feature = "gpu", test), target_arch = "x86_64"))]
fn write_ascii_lowercase_simd_prefix(dst: &mut [MaybeUninit<u8>], src: &[u8]) -> usize {
    if src.len() >= 128 && std::is_x86_feature_detected!("avx2") {
        // SAFETY: runtime detection proved AVX2 support. `dst` and `src` have
        // equal length; the AVX2 writer only stores complete 32-byte chunks
        // inside that range and leaves the scalar tail uninitialized.
        return unsafe { write_ascii_lowercase_avx2(dst.as_mut_ptr().cast::<u8>(), src) };
    }
    0
}

#[inline]
#[cfg(all(any(feature = "gpu", test), not(target_arch = "x86_64")))]
fn write_ascii_lowercase_simd_prefix(_dst: &mut [MaybeUninit<u8>], _src: &[u8]) -> usize {
    0
}

#[cfg(all(any(feature = "gpu", test), target_arch = "x86_64"))]
#[target_feature(enable = "avx2")]
unsafe fn write_ascii_lowercase_avx2(dst: *mut u8, src: &[u8]) -> usize {
    use std::arch::x86_64::{
        __m256i, _mm256_and_si256, _mm256_cmpgt_epi8, _mm256_loadu_si256, _mm256_or_si256,
        _mm256_set1_epi8, _mm256_storeu_si256,
    };

    let upper_start_minus_one = _mm256_set1_epi8((b'A' - 1) as i8);
    let upper_end_plus_one = _mm256_set1_epi8((b'Z' + 1) as i8);
    let lowercase_bit = _mm256_set1_epi8(0x20);
    let mut offset = 0usize;
    while offset + 32 <= src.len() {
        // SAFETY: the loop guard keeps the 32-byte unaligned load/store inside
        // `src` and the caller-provided destination range.
        let chunk = unsafe { _mm256_loadu_si256(src.as_ptr().add(offset).cast::<__m256i>()) };
        let above_upper_start = _mm256_cmpgt_epi8(chunk, upper_start_minus_one);
        let below_upper_end = _mm256_cmpgt_epi8(upper_end_plus_one, chunk);
        let uppercase_mask = _mm256_and_si256(above_upper_start, below_upper_end);
        let folded = _mm256_or_si256(chunk, _mm256_and_si256(uppercase_mask, lowercase_bit));
        unsafe {
            _mm256_storeu_si256(dst.add(offset).cast::<__m256i>(), folded);
        }
        offset += 32;
    }
    offset
}

#[inline]
#[cfg(any(feature = "gpu", test))]
fn ascii_lower_branchless(byte: u8) -> u8 {
    let uppercase = byte.wrapping_sub(b'A') <= (b'Z' - b'A');
    byte | ((uppercase as u8) << 5)
}

/// Case-insensitive `ends_with`. Returns true when the last `suffix.len()`
/// bytes of `bytes` compare equal to `suffix` ignoring ASCII case.
#[inline]
pub(crate) fn ends_with_ignore_ascii_case(bytes: &[u8], suffix: &[u8]) -> bool {
    if suffix.len() > bytes.len() {
        return false;
    }
    let tail = &bytes[bytes.len() - suffix.len()..];
    tail.eq_ignore_ascii_case(suffix)
}

/// Case-insensitive `starts_with`.
#[inline]
#[cfg(any(feature = "entropy", feature = "simdsieve"))]
pub(crate) fn starts_with_ignore_ascii_case(bytes: &[u8], prefix: &[u8]) -> bool {
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
pub(crate) fn ci_find(haystack: &[u8], needle_lower: &[u8]) -> bool {
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
pub(crate) fn contains_path_segment(path: &str, segment: &str) -> bool {
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
pub(crate) fn contains_path_segment_two(path: &str, a: &str, b: &str) -> bool {
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

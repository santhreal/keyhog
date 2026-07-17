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

/// Case-insensitive `ends_with`, re-exported from the canonical owner
/// [`keyhog_core::ascii_ci::ends_with_ignore_ascii_case`]. Scanner call sites
/// keep the `crate::ascii_ci::` path while the logic lives in ONE place (shared
/// with the sources crate).
pub(crate) use keyhog_core::ascii_ci::ends_with_ignore_ascii_case;

/// Case-insensitive `starts_with`.
#[inline]
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
    ci_find_nonempty(haystack, needle_lower)
}

/// Case-insensitive ASCII byte substring search for caller-supplied needles.
///
/// Unlike [`ci_find`], the needle may contain any ASCII case and an empty
/// needle is treated as "not found". That makes this the right primitive for
/// user/configured keyword lists where `""` must not match every byte offset.
#[inline]
pub(crate) fn ci_find_nonempty(haystack: &[u8], needle: &[u8]) -> bool {
    ci_find_at(haystack, needle).is_some()
}

/// Case-insensitive ASCII byte substring search returning the byte offset of
/// the first match, or `None` when the needle does not occur.
///
/// The needle may contain any ASCII case; an empty needle is treated as "not
/// found" (returns `None`), matching [`ci_find_nonempty`]. Because the match is
/// ASCII-case-insensitive against a needle whose bytes are ASCII, the returned
/// offset is byte-exact and lands on a UTF-8 char boundary, so a caller holding
/// the original `&str` can slice `&s[offset + needle.len()..]` without risking a
/// mid-codepoint panic.
///
/// This is the position-returning sibling of [`ci_find_nonempty`], which
/// delegates here so the two never drift: one `memchr2` SIMD skim over the
/// needle's first-byte case pair, with the full `eq_ignore_ascii_case` compare
/// running only at each candidate offset.
#[inline]
pub(crate) fn ci_find_at(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    let n = needle.len();
    if n == 0 || haystack.len() < n {
        return None;
    }
    // Take the first (lowest-offset) match from the shared rare-byte-anchored
    // scan. Anchoring the SIMD skim on the needle's RAREST byte (not `needle[0]`)
    // is the O(n·m) first-byte-DoS defense: a 1 MiB run of `a` against needle
    // `api_key` would otherwise make EVERY offset a candidate (~170ms observed
    // in the multiline keyword gate). One loop owner in [`ci_find_iter`].
    ci_find_iter(haystack, needle).next()
}

/// Index of the needle's statistically rarest byte, used to anchor the
/// case-insensitive `memchr2` skim on a byte uncommon in real text so a
/// repetitive/adversarial haystack yields few candidate windows (the O(n·m)
/// first-byte-anchor DoS defense, see [`ci_find_at`]). Case is folded (`x`/`X`
/// share a rank) because the skim matches both. Ties resolve to the earliest
/// index for determinism. Non-empty needle is a precondition (callers check).
#[inline]
fn rarest_byte_index(needle: &[u8]) -> usize {
    let mut best = 0usize;
    let mut best_rank = u16::MAX;
    let mut i = 0usize;
    while i < needle.len() {
        let rank = ascii_ci_frequency_rank(needle[i]);
        if rank < best_rank {
            best_rank = rank;
            best = i;
        }
        i += 1;
    }
    best
}

/// Coarse text+source byte-frequency rank: HIGHER = more common, so the
/// rarest-byte anchor in [`rarest_byte_index`] picks the LOWEST-ranked needle
/// byte. Case-folded. Only the ORDER matters (separators/digits/rare letters
/// must rank below common letters), not the exact values, so an anchor lands
/// on a byte a repetitive buffer is unlikely to carry. ONE owner for the
/// ordering so the two callers cannot drift.
#[inline]
const fn ascii_ci_frequency_rank(b: u8) -> u16 {
    match b.to_ascii_lowercase() {
        b' ' => 255,
        b'e' => 200,
        b't' => 190,
        b'a' => 180,
        b'o' => 175,
        b'i' => 170,
        b'n' => 165,
        b's' => 160,
        b'r' => 155,
        b'h' => 150,
        b'l' => 145,
        b'd' => 140,
        b'c' => 135,
        b'u' => 130,
        b'm' => 125,
        b'f' => 120,
        b'p' => 115,
        b'g' => 110,
        b'w' => 105,
        b'y' => 100,
        b'b' => 95,
        b'v' => 90,
        b'k' => 60,
        b'x' => 45,
        b'j' => 40,
        b'q' => 35,
        b'z' => 30,
        b'0'..=b'9' => 50,
        // Underscore, dash, dot, braces, and every other separator/punctuation
        // byte: the rarest class, so a keyword like `api_key` anchors on `_`.
        _ => 10,
    }
}

/// Iterator over EVERY start offset where `needle` occurs case-insensitively in
/// `haystack`, in ascending order, sharing [`ci_find_at`]'s rarest-byte
/// `memchr2` anchor so a repetitive/adversarial haystack cannot force the
/// O(n·m) first-byte-anchor blowup. Windows may overlap; an empty needle (or a
/// needle longer than the haystack) yields nothing. This is the ONE owner of
/// the case-insensitive scan loop: [`ci_find_at`] takes its first element.
#[inline]
pub(crate) fn ci_find_iter<'h, 'n>(haystack: &'h [u8], needle: &'n [u8]) -> CiMatches<'h, 'n> {
    let anchor = if needle.is_empty() {
        0
    } else {
        rarest_byte_index(needle)
    };
    let (a_lower, a_upper) = needle
        .get(anchor)
        .map(|&b| (b.to_ascii_lowercase(), b.to_ascii_uppercase()))
        .map_or((0, 0), |pair| pair);
    CiMatches {
        haystack,
        needle,
        anchor,
        a_lower,
        a_upper,
        pos: 0,
    }
}

/// Rare-byte-anchored case-insensitive match iterator; see [`ci_find_iter`].
pub(crate) struct CiMatches<'h, 'n> {
    haystack: &'h [u8],
    needle: &'n [u8],
    anchor: usize,
    a_lower: u8,
    a_upper: u8,
    pos: usize,
}

impl Iterator for CiMatches<'_, '_> {
    type Item = usize;

    #[inline]
    fn next(&mut self) -> Option<usize> {
        let n = self.needle.len();
        if n == 0 || self.haystack.len() < n {
            return None;
        }
        while self.pos <= self.haystack.len() {
            let rel = memchr::memchr2(self.a_lower, self.a_upper, &self.haystack[self.pos..])?;
            let hit = self.pos + rel;
            // Advance past this anchor byte so the next call resumes after it
            // consecutive/overlapping matches each surface their own anchor hit.
            self.pos = hit + 1;
            let Some(start) = hit.checked_sub(self.anchor) else {
                // Anchor hit too near the buffer start to form a full window.
                continue;
            };
            if start + n > self.haystack.len() {
                // Window runs past the end; anchor hits only grow, so we are done.
                return None;
            }
            if self.haystack[start..start + n].eq_ignore_ascii_case(self.needle) {
                return Some(start);
            }
        }
        None
    }
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
    if n == 0 || bytes.len() < n + 1 {
        return false;
    }
    // Leading segment at offset 0 of a RELATIVE path (`node_modules/foo`): there
    // is no preceding separator, so the separator-anchored loop below, which
    // only inspects bytes AFTER a `/` or `\\` - would never test it, silently
    // skipping vendored-tree suppression on relative roots (`keyhog scan
    // node_modules`). Require an immediately-following separator so a prefix like
    // `node_modules2/` does NOT match (preserves the substring-safety contract).
    if bytes[..n].eq_ignore_ascii_case(seg) && matches!(bytes[n], b'/' | b'\\') {
        return true;
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
    if bytes.len() < total + 2 {
        return false;
    }
    // Leading `a/b/` at offset 0 of a relative path (`public/plugins/foo`): no
    // preceding separator, so the loop below would miss it (same start-of-path
    // gap as `contains_path_segment`). Both inner separators are still required
    // so `publicX/plugins/` cannot false-match.
    {
        let a_end = a_b.len();
        let b_start = a_end + 1;
        let b_end = b_start + b_b.len();
        if b_end < bytes.len()
            && bytes[..a_end].eq_ignore_ascii_case(a_b)
            && matches!(bytes[a_end], b'/' | b'\\')
            && bytes[b_start..b_end].eq_ignore_ascii_case(b_b)
            && matches!(bytes[b_end], b'/' | b'\\')
        {
            return true;
        }
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

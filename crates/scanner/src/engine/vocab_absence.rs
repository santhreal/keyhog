//! Markerless-shape predicates and vocabulary-stage absence memos shared by
//! decode admission, backend_triggered skips, and windowed/postprocess paths.
//! Extracted from `scan.rs` to keep that file under the STANDARD 500 LOC cap.

/// Single-line text with no classical encode markers. Used to skip decode-through
/// and always-active phase-2 work on minified / dense JSON blobs where that work
/// cannot distinguish opaque identifiers from nopad encodings.
#[inline]
pub(crate) fn text_is_markerless_single_line(text: &str) -> bool {
    let bytes = text.as_bytes();
    if bytes.is_empty() || bytes.contains(&b'\n') {
        return false;
    }
    !bytes
        .iter()
        .any(|&byte| matches!(byte, b'+' | b'/' | b'=' | b'%' | b'\\'))
}

/// Minimum size before markerless single-line no-hit / always-active skips engage.
/// Short unterminated lines (bare high-entropy tokens) still reach the keyword-free
/// entropy lane; dense minified JSON (one_long_line) stays skipped.
pub(crate) const MARKERLESS_NO_HIT_MIN_BYTES: usize = 64 * 1024;

/// Dense markerless single-line: same shape as [`text_is_markerless_single_line`]
/// but only for large windows where the entropy-only no-hit storm dominates.
#[inline]
pub(crate) fn text_is_dense_markerless_single_line(text: &str) -> bool {
    text.len() >= MARKERLESS_NO_HIT_MIN_BYTES && text_is_markerless_single_line(text)
}

/// Cap on unique lines participating in a decode-vocab fingerprint. Above this,
/// the window is too diverse for cross-window empty-decode memoization to help,
/// and hashing every distinct line would dominate the skip check.
const DECODE_VOCAB_FINGERPRINT_MAX_UNIQUE_LINES: usize = 512;
const DECODE_VOCAB_EMPTY_CACHE_CAP: usize = 1024;

#[derive(Clone, Copy, Default)]
pub(crate) struct VocabStageAbsence {
    pub(crate) decode_empty: bool,
    pub(crate) confirmed: bool,
    pub(crate) entropy: bool,
    /// Whole prepared-scan produced no matches for this vocabulary.
    pub(crate) clean: bool,
}

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) struct VocabAbsenceKey {
    pub(crate) detector_digest: u64,
    pub(crate) entropy_config_digest: [u8; 32],
    pub(crate) path_class: u64,
    pub(crate) vocab_fp: [u8; 16],
}

/// Order-independent fingerprint of the unique-line vocabulary in `text`.
///
/// Every unique line participates, including first/last lines, so a one-off
/// secret on an edge line cannot alias onto a previously proven-clean filler
/// vocabulary. Returns `None` when the text is empty or too diverse to memoize.
///
/// Clean short-circuits that consume this fingerprint are limited to
/// `filesystem/windowed` parent windows and are path-scoped, so a reordering on
/// another path cannot inherit a clean proof. Autoroute classification does not
/// short-circuit on these proofs. Overlapping windows of repetitive corpora share
/// the same unique-line set; an ordered/multiplicity-sensitive fingerprint would
/// miss those hits and erase the one_large residual win.
#[inline]
pub(crate) fn decode_vocab_fingerprint(text: &str) -> Option<[u8; 16]> {
    if text.is_empty() {
        return None;
    }
    let mut unique: ahash::AHashSet<&str> = ahash::AHashSet::with_capacity(16);
    for line in text.lines() {
        if unique.len() >= DECODE_VOCAB_FINGERPRINT_MAX_UNIQUE_LINES && !unique.contains(line) {
            return None;
        }
        unique.insert(line);
    }
    if unique.is_empty() {
        return None;
    }
    let mut lines: Vec<&str> = unique.into_iter().collect();
    lines.sort_unstable();
    let mut hasher = blake3::Hasher::new();
    for line in &lines {
        hasher.update(line.as_bytes());
        hasher.update(&[0]);
    }
    let full = hasher.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&full.as_bytes()[..16]);
    Some(out)
}
#[inline]
pub(crate) fn vocab_path_class(source_type: &str, path: Option<&str>) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = ahash::AHasher::default();
    source_type.hash(&mut hasher);
    // Full path participates so a clean/entropy absence proof recorded for
    // `/tmp/notes.log` cannot short-circuit `/etc/secrets/prod.log` with the
    // same line vocabulary (entropy thresholds follow is_sensitive_path).
    path.unwrap_or("").hash(&mut hasher);
    path.is_some_and(crate::confidence::is_sensitive_path)
        .hash(&mut hasher);
    hasher.finish()
}

#[inline]
fn vocab_absence_key(
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    path_class: u64,
    text: &str,
) -> Option<VocabAbsenceKey> {
    let vocab_fp = decode_vocab_fingerprint(text)?;
    Some(VocabAbsenceKey {
        detector_digest,
        entropy_config_digest,
        path_class,
        vocab_fp,
    })
}

type VocabAbsenceMap = dashmap::DashMap<VocabAbsenceKey, VocabStageAbsence, ahash::RandomState>;

#[inline]
pub(crate) fn vocab_stage_absence(
    cache: &VocabAbsenceMap,
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    path_class: u64,
    text: &str,
) -> Option<VocabStageAbsence> {
    // Empty cache: skip fingerprint hashing; every lookup would miss.
    if cache.is_empty() {
        return None;
    }
    let key = vocab_absence_key(detector_digest, entropy_config_digest, path_class, text)?;
    cache.get(&key).map(|entry| *entry)
}

#[inline]
fn mark_vocab_stage_absence(
    cache: &VocabAbsenceMap,
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    path_class: u64,
    text: &str,
    update: impl FnOnce(&mut VocabStageAbsence),
) {
    let Some(key) = vocab_absence_key(detector_digest, entropy_config_digest, path_class, text)
    else {
        return;
    };
    // Bound growth without wiping unrelated clean/confirmed/entropy proofs.
    // Dropping a new key at capacity keeps existing stage proofs intact.
    if cache.len() >= DECODE_VOCAB_EMPTY_CACHE_CAP && !cache.contains_key(&key) {
        return;
    }
    let mut entry = cache.entry(key).or_default();
    update(entry.value_mut());
}

#[inline]
pub(crate) fn decode_vocab_previously_empty(
    cache: &VocabAbsenceMap,
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    path_class: u64,
    text: &str,
) -> bool {
    vocab_stage_absence(
        cache,
        detector_digest,
        entropy_config_digest,
        path_class,
        text,
    )
    .is_some_and(|absence| absence.decode_empty)
}

#[inline]
pub(crate) fn mark_decode_vocab_empty(
    cache: &VocabAbsenceMap,
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    path_class: u64,
    text: &str,
) {
    mark_vocab_stage_absence(
        cache,
        detector_digest,
        entropy_config_digest,
        path_class,
        text,
        |absence| absence.decode_empty = true,
    );
}

#[inline]
pub(crate) fn mark_vocab_confirmed_absent(
    cache: &VocabAbsenceMap,
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    path_class: u64,
    text: &str,
) {
    mark_vocab_stage_absence(
        cache,
        detector_digest,
        entropy_config_digest,
        path_class,
        text,
        |absence| absence.confirmed = true,
    );
}

#[inline]
pub(crate) fn mark_vocab_entropy_absent(
    cache: &VocabAbsenceMap,
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    path_class: u64,
    text: &str,
) {
    mark_vocab_stage_absence(
        cache,
        detector_digest,
        entropy_config_digest,
        path_class,
        text,
        |absence| absence.entropy = true,
    );
}

#[inline]
pub(crate) fn vocab_previously_clean(
    cache: &VocabAbsenceMap,
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    path_class: u64,
    text: &str,
) -> bool {
    vocab_stage_absence(
        cache,
        detector_digest,
        entropy_config_digest,
        path_class,
        text,
    )
    .is_some_and(|absence| absence.clean)
}

#[inline]
pub(crate) fn mark_vocab_clean(
    cache: &VocabAbsenceMap,
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    path_class: u64,
    text: &str,
) {
    mark_vocab_stage_absence(
        cache,
        detector_digest,
        entropy_config_digest,
        path_class,
        text,
        |absence| {
            absence.clean = true;
            absence.confirmed = true;
            absence.entropy = true;
        },
    );
}

#[doc(hidden)]
pub(crate) fn clear_vocab_stage_absence_cache_for_diagnostics(cache: &VocabAbsenceMap) {
    cache.clear();
}

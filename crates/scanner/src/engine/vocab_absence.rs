//! Content-scoped stage-absence memos shared by decode admission,
//! backend-triggered skips, and windowed postprocessing.

const DECODE_VOCAB_EMPTY_CACHE_CAP: usize = 1024;

#[derive(Clone, Copy, Default)]
pub(crate) struct VocabStageAbsence {
    pub(crate) decode_empty: bool,
    pub(crate) confirmed: bool,
    pub(crate) entropy: bool,
    /// Whole prepared scan produced no matches for this exact content.
    pub(crate) clean: bool,
}

#[derive(Clone, Copy, Eq, PartialEq, Hash)]
pub(crate) struct VocabAbsenceKey {
    pub(crate) detector_digest: u64,
    pub(crate) entropy_config_digest: [u8; 32],
    pub(crate) path_class: u64,
    pub(crate) content_digest: [u8; 32],
}

/// Exact-content fingerprint for a proven-empty parent window.
///
/// Order and multiplicity are load-bearing. The same unique lines in another
/// order can create different multiline, decode, or companion matches.
#[inline]
fn window_content_digest(text: &str) -> Option<[u8; 32]> {
    (!text.is_empty()).then(|| *blake3::hash(text.as_bytes()).as_bytes())
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
    let content_digest = window_content_digest(text)?;
    Some(VocabAbsenceKey {
        detector_digest,
        entropy_config_digest,
        path_class,
        content_digest,
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

use super::*;

impl CompiledScanner {
    /// Capture the effective decode policy consumed by this scanner.
    pub fn decode_workload_plan(&self) -> crate::decode::DecodeWorkloadPlan {
        crate::decode::DecodeWorkloadPlan::from_compiled_limits(
            self.config.max_decode_depth,
            self.config.max_decode_bytes,
            self.detector_plans.decode_transforms_arc(),
            self.detector_plans.decoder_plan_arc(),
        )
    }

    #[cfg(feature = "decode")]
    #[inline]
    pub(crate) fn decoder_admission_context_key(&self, chunk: &keyhog_core::Chunk) -> Option<u8> {
        self.detector_plans
            .decoder_plan()
            .admission_context_key(chunk)
    }

    #[cfg(not(feature = "decode"))]
    #[inline]
    pub(crate) fn decoder_admission_context_key(&self, _chunk: &keyhog_core::Chunk) -> Option<u8> {
        None
    }

    #[cfg(feature = "decode")]
    #[inline]
    pub(crate) fn chunk_needs_decode_postprocess(&self, chunk: &keyhog_core::Chunk) -> bool {
        self.chunk_needs_decode_postprocess_with_absence(chunk, false)
    }

    #[cfg(feature = "decode")]
    #[inline]
    pub(crate) fn chunk_needs_decode_postprocess_with_absence(
        &self,
        chunk: &keyhog_core::Chunk,
        decoder_absence: bool,
    ) -> bool {
        self.config.max_decode_depth > 0
            && (chunk.data.len() <= self.config.max_decode_bytes
                || self.chunk_uses_bounded_decode_windows(chunk))
            && !decoder_absence
            // Single-line blobs without classical encode markers (`+`, `/`, `=`,
            // `%`, `\`) are dominated by opaque alphanumeric JSON/minified
            // tokens. Trial-decoding every repeated value is pure waste: the
            // root plaintext scan already covers bare credentials, and nopad
            // base64 without those markers is not distinguishable from ordinary
            // identifiers at admission time. Skip decode-through on that shape
            // so one_long_line residual stays bounded; windows that do carry a
            // marker still decode normally.
            && !chunk_is_markerless_single_line(chunk)
            // Repetitive multi-line corpora (one_large) share a tiny line
            // vocabulary across overlapping windows. Once a vocab has been
            // decode-through'd to an empty child set, later windows with the
            // same unique-line fingerprint skip decode-through entirely.
            && !decode_vocab_previously_empty(self.detector_digest, self.entropy_evidence_config_digest(), &chunk.data)
            && {
                #[cfg(debug_assertions)]
                self.decoder_admission_scanned_bytes.fetch_add(
                    // LAW10: debug accounting saturates on impossible usize-to-u64 overflow; scan behavior is unchanged.
                    u64::try_from(chunk.data.len()).unwrap_or(u64::MAX),
                    std::sync::atomic::Ordering::Relaxed,
                );
                crate::decode::decoder_admission(
                    chunk,
                    self.detector_plans.decode_transforms(),
                    self.detector_plans.decoder_plan(),
                ) != crate::decode::DecodeAdmission::Impossible
            }
    }

    #[cfg(feature = "decode")]
    #[inline]
    pub(crate) fn chunk_uses_bounded_decode_windows(&self, chunk: &keyhog_core::Chunk) -> bool {
        chunk.data.len() > self.config.max_decode_bytes
            && self.config.max_decode_bytes >= 4
            && chunk.metadata.source_type.as_ref() == "filesystem/windowed"
    }

    #[cfg(not(feature = "decode"))]
    #[inline]
    pub(crate) fn chunk_needs_decode_postprocess(&self, _chunk: &keyhog_core::Chunk) -> bool {
        false
    }

    #[cfg(not(feature = "decode"))]
    #[inline]
    pub(crate) fn chunk_needs_decode_postprocess_with_absence(
        &self,
        _chunk: &keyhog_core::Chunk,
        _decoder_absence: bool,
    ) -> bool {
        false
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn reset_decoder_admission_scanned_bytes_for_diagnostics(&self) {
        self.decoder_admission_scanned_bytes
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn decoder_admission_scanned_bytes_for_diagnostics(&self) -> u64 {
        self.decoder_admission_scanned_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }
    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn reset_direct_scan_absence_skipped_bytes_for_diagnostics(&self) {
        self.direct_scan_absence_skipped_bytes
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn direct_scan_absence_skipped_bytes_for_diagnostics(&self) -> u64 {
        self.direct_scan_absence_skipped_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn reset_direct_scan_absence_batches_for_diagnostics(&self) {
        self.direct_scan_absence_batches
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn direct_scan_absence_batches_for_diagnostics(&self) -> u64 {
        self.direct_scan_absence_batches
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn reset_simd_phase2_tail_absence_skipped_bytes_for_diagnostics(&self) {
        self.simd_phase2_tail_absence_skipped_bytes
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn simd_phase2_tail_absence_skipped_bytes_for_diagnostics(&self) -> u64 {
        self.simd_phase2_tail_absence_skipped_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[doc(hidden)]
    #[cfg(all(debug_assertions, feature = "simd"))]
    pub fn reset_reusable_simd_trigger_hits_for_diagnostics(&self) {
        self.reusable_simd_triggers.lock().reset_hits();
    }

    #[doc(hidden)]
    #[cfg(all(debug_assertions, feature = "simd"))]
    #[must_use]
    pub fn reusable_simd_trigger_hits_for_diagnostics(&self) -> u64 {
        self.reusable_simd_triggers.lock().hits()
    }

    /// Surface a decode-through pass declined because its source cannot use
    /// bounded decode windows and exceeds `max_decode_bytes`.
    ///
    /// Filesystem chunks are subdivided with overlap and retain this value as a
    /// working-set ceiling. Other source types preserve the explicit whole-chunk
    /// limit: their raw bytes are scanned, but encoded content is not recovered.
    ///
    /// Deliberately keyed on size and source type, not on `decoder_admission`.
    /// Admission is an O(chunk) alphabet probe; repeating it here would add a
    /// full pass over each rejected chunk. The operator-selected limit is enough
    /// to establish the decline.
    ///
    /// INVARIANT: this is called at exactly the sites that call
    /// `record_file_scanned`, and the two must stay paired. An earlier version of
    /// this comment claimed `scan_inner` was "the one guaranteed once-per-chunk
    /// site"; that was wrong, and `engine/scan_coalesced.rs` says so three
    /// modules over: the coalesced SIMD route bypasses `scan_inner` entirely and
    /// records the scanner telemetry itself. The consequence was a
    /// BACKEND-DEPENDENT coverage gap, caught by a peer's calibration guard and
    /// then reproduced directly: on `crates/`, `--backend cpu` reported one
    /// declined chunk and `--backend simd` reported none, for byte-identical
    /// findings (25, same identity digest). Recall never differed; only the
    /// operator's warning did, which is worse in the sense that it was invisible.
    /// Pairing with `record_file_scanned` is what makes the count route-agnostic,
    /// because that event already has one call per chunk per route by contract.
    #[cfg(feature = "decode")]
    #[inline]
    pub(crate) fn record_decode_size_decline(&self, chunk: &Chunk) {
        if self.config.max_decode_depth > 0
            && chunk.data.len() > self.config.max_decode_bytes
            && !self.chunk_uses_bounded_decode_windows(chunk)
        {
            crate::telemetry::record_decode_oversize_skip();
            tracing::warn!(
                chunk_bytes = chunk.data.len(),
                ceiling = self.config.max_decode_bytes,
                "chunk exceeds max_decode_bytes; decode-through did NOT run, encoded secrets inside it were not recovered"
            );
        }
    }

    #[cfg(not(feature = "decode"))]
    #[inline]
    pub(crate) fn record_decode_size_decline(&self, _chunk: &Chunk) {}

    pub(crate) fn scan_inner(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
        deadline: Option<std::time::Instant>,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<Vec<RawMatch>> {
        self.scan_inner_with_admission_hints(
            chunk, backend, deadline, false, false, None, false, false, None, None, None, None,
            route,
        )
    }

    pub(crate) fn scan_inner_with_admission_hints(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
        deadline: Option<std::time::Instant>,
        normalization_passthrough: bool,
        multiline_absence: bool,
        line_context_index: Option<&std::sync::Arc<crate::context::LineContextIndex>>,
        confirmed_patterns_absence: bool,
        entropy_absence: bool,
        cpu_trigger_hints: Option<&[u64]>,
        phase2_keyword_hints: Option<&[u32]>,
        phase2_always_active_evidence: Option<super::phase2::Phase2AlwaysActiveGpuEvidence<'_>>,
        generic_keyword_positions: Option<&[u32]>,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<Vec<RawMatch>> {
        if crate::deadline::expired(deadline) {
            return Ok(Vec::new());
        }
        // KH-116: Record scan metrics atomically
        crate::telemetry::record_file_scanned(chunk.data.len());
        self.record_decode_size_decline(chunk);
        if backend.is_gpu() {
            crate::telemetry::record_gpu_dispatch();
        }
        // prepare_chunk and phase-1 timing are owned by the unified profiler's
        // Preprocess / Phase1Triggers leaf spans (opened inside those calls).
        if chunk.metadata.decoded_span.is_none()
            && vocab_previously_clean(self.detector_digest, self.entropy_evidence_config_digest(), &chunk.data)
        {
            return Ok(Vec::new());
        }
        let prepared = self.prepare_chunk_with_normalization_passthrough(
            chunk,
            normalization_passthrough,
            multiline_absence,
            line_context_index,
        );
        if crate::deadline::expired(deadline) {
            return Ok(Vec::new());
        }
        let triggered = match cpu_trigger_hints {
            Some(hints) => std::borrow::Cow::Borrowed(hints),
            None => std::borrow::Cow::Owned(
                self.collect_triggered_patterns_for_backend(&chunk.data, backend)?,
            ),
        };
        if crate::deadline::expired(deadline) {
            return Ok(Vec::new());
        }
        self.scan_prepared_with_triggered(
            prepared,
            &triggered,
            deadline,
            confirmed_patterns_absence,
            entropy_absence,
            phase2_keyword_hints,
            phase2_always_active_evidence,
            None,
            generic_keyword_positions,
            route,
        )
    }
}


#[cfg(feature = "decode")]
#[inline]
pub(crate) fn chunk_is_markerless_single_line(chunk: &keyhog_core::Chunk) -> bool {
    text_is_markerless_single_line(&chunk.data)
}

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
struct VocabAbsenceKey {
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    vocab_fp: [u8; 16],
}

static VOCAB_STAGE_ABSENCE_CACHE: std::sync::LazyLock<
    dashmap::DashMap<VocabAbsenceKey, VocabStageAbsence, ahash::RandomState>,
> = std::sync::LazyLock::new(|| dashmap::DashMap::with_hasher(ahash::RandomState::new()));

/// Order-independent fingerprint of the unique-line vocabulary in `text`.
///
/// Every unique line participates, including first/last lines, so a one-off
/// secret on an edge line cannot alias onto a previously proven-clean filler
/// vocabulary. Returns `None` when the text is empty or too diverse to memoize.
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
fn vocab_absence_key(
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    text: &str,
) -> Option<VocabAbsenceKey> {
    let vocab_fp = decode_vocab_fingerprint(text)?;
    Some(VocabAbsenceKey {
        detector_digest,
        entropy_config_digest,
        vocab_fp,
    })
}

#[inline]
pub(crate) fn vocab_stage_absence(
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    text: &str,
) -> Option<VocabStageAbsence> {
    let key = vocab_absence_key(detector_digest, entropy_config_digest, text)?;
    VOCAB_STAGE_ABSENCE_CACHE.get(&key).map(|entry| *entry)
}

#[inline]
fn mark_vocab_stage_absence(
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    text: &str,
    update: impl FnOnce(&mut VocabStageAbsence),
) {
    let Some(key) = vocab_absence_key(detector_digest, entropy_config_digest, text) else {
        return;
    };
    if VOCAB_STAGE_ABSENCE_CACHE.len() >= DECODE_VOCAB_EMPTY_CACHE_CAP
        && !VOCAB_STAGE_ABSENCE_CACHE.contains_key(&key)
    {
        VOCAB_STAGE_ABSENCE_CACHE.clear();
    }
    let mut entry = VOCAB_STAGE_ABSENCE_CACHE.entry(key).or_default();
    update(entry.value_mut());
}

#[inline]
pub(crate) fn decode_vocab_previously_empty(
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    text: &str,
) -> bool {
    vocab_stage_absence(detector_digest, entropy_config_digest, text)
        .is_some_and(|absence| absence.decode_empty)
}

#[inline]
pub(crate) fn mark_decode_vocab_empty(
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    text: &str,
) {
    mark_vocab_stage_absence(
        detector_digest,
        entropy_config_digest,
        text,
        |absence| absence.decode_empty = true,
    );
}

#[inline]
pub(crate) fn mark_vocab_confirmed_absent(
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    text: &str,
) {
    mark_vocab_stage_absence(
        detector_digest,
        entropy_config_digest,
        text,
        |absence| absence.confirmed = true,
    );
}

#[inline]
pub(crate) fn mark_vocab_entropy_absent(
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    text: &str,
) {
    mark_vocab_stage_absence(
        detector_digest,
        entropy_config_digest,
        text,
        |absence| absence.entropy = true,
    );
}

#[inline]
pub(crate) fn vocab_previously_clean(
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    text: &str,
) -> bool {
    vocab_stage_absence(detector_digest, entropy_config_digest, text)
        .is_some_and(|absence| absence.clean)
}

#[inline]
pub(crate) fn mark_vocab_clean(
    detector_digest: u64,
    entropy_config_digest: [u8; 32],
    text: &str,
) {
    // Plaintext matcher absence only. Decode-through keeps its own empty memo
    // after the decode pipeline actually produces zero children — otherwise an
    // encoded-only secret in a "clean" vocabulary would be skipped.
    mark_vocab_stage_absence(
        detector_digest,
        entropy_config_digest,
        text,
        |absence| {
            absence.clean = true;
            absence.confirmed = true;
            absence.entropy = true;
        },
    );
}

#[doc(hidden)]
pub(crate) fn clear_vocab_stage_absence_cache_for_diagnostics() {
    VOCAB_STAGE_ABSENCE_CACHE.clear();
}




// `scan_filters` is consumed by `should_scan_no_hit_chunk` (the no-phase-1-hit
// admission gate) on the shared phase-2 tail. That tail is reached by the
// coalesced producer (`simd`) and GPU region presence, and `gpu` implies
// `simd` at the feature level.
#[cfg(feature = "simd")]
use super::scan_filters::*;
use super::*;

#[cfg(feature = "simd")]
use std::cell::RefCell;

// The trigger-buffer pool is only used in the Hyperscan-prefilter scratch path
// of `scan_coalesced`. The pool's win is reuse of buffers that stay inside the
// pool; extending it to per-chunk trigger builders regressed long-lines benches.
#[cfg(feature = "simd")]
thread_local! {
    /// Per-thread pool of trigger-bitmask vectors. Phase-1 of `scan_coalesced`
    /// allocates one `Vec<u64>` of size `ac_len.div_ceil(64)` per chunk.
    static TRIGGER_POOL: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

#[cfg(feature = "simd")]
#[inline]
fn with_trigger_buffer<R>(words_needed: usize, f: impl FnOnce(&mut [u64]) -> R) -> R {
    TRIGGER_POOL.with(|cell| {
        let mut buf = cell.borrow_mut();
        if buf.len() < words_needed {
            buf.resize(words_needed, 0);
        }
        let slice = &mut buf[..words_needed];
        slice.fill(0);
        f(slice)
    })
}

#[cfg(feature = "simd")]
#[inline]
fn mark_hs_trigger(
    scratch: &mut [u64],
    scanner: &crate::simd::backend::HsScanner,
    hs_index_map: &super::CsrU32,
    ac_len: usize,
    hs_id: usize,
) {
    let Some((_det, dedup_id, _grp)) = scanner.pattern_info(hs_id) else {
        return;
    };
    if let Some(orig) = hs_index_map.get(dedup_id) {
        for &idx in orig {
            let idx = idx as usize;
            if idx < ac_len {
                scratch[idx / 64] |= 1u64 << (idx % 64);
            }
        }
    }
}

impl CompiledScanner {
    #[cfg(feature = "simd")]
    #[inline]
    fn post_process_coalesced_matches(
        &self,
        chunk: &keyhog_core::Chunk,
        matches: &mut Vec<keyhog_core::RawMatch>,
    ) {
        if self.chunk_needs_decode_postprocess(chunk) {
            self.post_process_matches(chunk, matches, None);
        } else {
            self.scan_cross_chunk_fragments(chunk, matches, None);
        }
    }

    #[cfg(feature = "simd")]
    #[inline]
    fn decode_only_coalesced_matches(
        &self,
        chunk: &keyhog_core::Chunk,
    ) -> Option<Vec<keyhog_core::RawMatch>> {
        if !self.chunk_needs_decode_postprocess(chunk) {
            return None;
        }
        let mut matches = Vec::new();
        self.post_process_matches(chunk, &mut matches, None);
        Some(matches)
    }

    /// High-throughput coalesced scan: all files scanned in parallel, zero
    /// overhead for non-hit files.
    #[allow(clippy::needless_return)] // return needed under non-simd cfg branch
    pub fn scan_coalesced(&self, chunks: &[keyhog_core::Chunk]) -> Vec<Vec<keyhog_core::RawMatch>> {
        use rayon::prelude::*;

        #[cfg(not(feature = "simd"))]
        {
            let mut results: Vec<Vec<keyhog_core::RawMatch>> = chunks
                .par_iter()
                .map(|c| self.scan_with_backend(c, crate::hw_probe::ScanBackend::SimdCpu))
                .collect();
            super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
            return results;
        }

        #[cfg(feature = "simd")]
        {
            let Some(scanner) = &self.simd_prefilter else {
                let mut results: Vec<Vec<keyhog_core::RawMatch>> = chunks
                    .par_iter()
                    .map(|c| self.scan_with_backend(c, crate::hw_probe::ScanBackend::SimdCpu))
                    .collect();
                super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
                return results;
            };

            let triggers = self.compute_coalesced_triggers(chunks, scanner);
            return self.scan_coalesced_phase2(chunks, triggers);
        }
    }

    /// Phase 1 of the coalesced scan: the Hyperscan literal prefilter over raw
    /// chunk bytes, producing one trigger bitmap per chunk. GPU region presence
    /// is the alternative producer feeding the same phase 2.
    #[cfg(feature = "simd")]
    pub(crate) fn compute_coalesced_triggers(
        &self,
        chunks: &[keyhog_core::Chunk],
        scanner: &crate::simd::backend::HsScanner,
    ) -> Vec<Option<Vec<u64>>> {
        use rayon::prelude::*;
        let ac_len = self.ac_map.len();
        let words_needed = ac_len.div_ceil(64);
        let triggers: Vec<Option<Vec<u64>>> = chunks
            .par_iter()
            .map(|chunk| {
                let data = chunk.data.as_bytes();
                let alphabet_rejected = self
                    .alphabet_screen
                    .as_ref()
                    .is_some_and(|screen| !screen.screen(data));
                if alphabet_rejected
                    || (data.len() >= 64 && !self.bigram_bloom.maybe_overlaps(data))
                {
                    return None;
                }
                with_trigger_buffer(words_needed, |scratch| {
                    let scan_result = scanner.scan_each_result(data, |hs_id| {
                        mark_hs_trigger(scratch, scanner, &self.hs_index_map, ac_len, hs_id);
                    });
                    if let Err(error) = scan_result {
                        tracing::warn!(
                            %error,
                            "hyperscan coalesced phase-1 scan failed; over-marking SIMD-covered patterns for this chunk"
                        );
                        scratch.fill(0);
                        for hs_id in 0..scanner.pattern_count() {
                            mark_hs_trigger(scratch, scanner, &self.hs_index_map, ac_len, hs_id);
                        }
                    }
                    if scratch.iter().any(|&w| w != 0) {
                        Some(scratch.to_vec())
                    } else {
                        None
                    }
                })
            })
            .collect();

        if tracing::enabled!(tracing::Level::INFO) {
            let hit_count = triggers.iter().filter(|t| t.is_some()).count();
            let total_hs_matches: usize = triggers
                .iter()
                .filter_map(|t| t.as_ref())
                .map(|t| t.iter().map(|w| w.count_ones() as usize).sum::<usize>())
                .sum();
            tracing::info!(
                files = chunks.len(),
                hits = hit_count,
                hs_matches = total_hs_matches,
                "coalesced scan phase 1 complete"
            );
        }
        triggers
    }

    /// No-hit chunk admission: should a chunk that produced no phase-1 trigger
    /// still be driven through the phase-2 / generic / entropy tail?
    #[cfg(feature = "simd")]
    pub(crate) fn should_scan_no_hit_chunk(&self, chunk: &keyhog_core::Chunk) -> bool {
        if self.has_active_phase2_patterns_for_chunk(&chunk.data) {
            return true;
        }
        let data = chunk.data.as_bytes();
        #[cfg(feature = "multiline")]
        if crate::multiline::has_concatenation_indicators(&chunk.data)
            && has_secret_keyword_fast(data)
        {
            return true;
        }
        let entropy_admits = self.config.entropy_enabled
            && crate::entropy::is_entropy_appropriate(
                chunk.metadata.path.as_deref(),
                self.config.entropy_in_source_files,
            )
            && has_high_entropy_run_fast(data);
        chunk.data.len() <= 32 * 1024
            && (has_generic_assignment_keyword(data)
                || has_secret_keyword_fast(data)
                || entropy_admits)
    }

    /// Shared phase-2 tail for the SIMD coalesced producer and GPU
    /// region-presence producer. Both backends feed identical per-chunk trigger
    /// bitmaps into this owner so findings remain backend-invariant.
    #[cfg(feature = "simd")]
    pub(crate) fn scan_coalesced_phase2(
        &self,
        chunks: &[keyhog_core::Chunk],
        triggers: Vec<Option<Vec<u64>>>,
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        self.scan_coalesced_phase2_with_admission(chunks, triggers, None, None, None)
    }

    #[cfg(feature = "simd")]
    fn normalize_coalesced_phase2_triggers(
        &self,
        chunks: &[keyhog_core::Chunk],
        mut triggers: Vec<Option<Vec<u64>>>,
    ) -> Vec<Option<Vec<u64>>> {
        let chunk_count = chunks.len();
        let trigger_count = triggers.len();
        if trigger_count == chunk_count {
            return triggers;
        }

        tracing::warn!(
            chunks = chunk_count,
            trigger_rows = trigger_count,
            "coalesced phase-2 trigger row count mismatch; normalizing rows before shared phase-2"
        );
        if trigger_count > chunk_count {
            triggers.truncate(chunk_count);
            return triggers;
        }

        triggers.reserve(chunk_count - trigger_count);
        for chunk in chunks.iter().skip(trigger_count) {
            let triggered = self.collect_triggered_patterns_for_backend(
                &chunk.data,
                crate::hw_probe::ScanBackend::SimdCpu,
            );
            if triggered.iter().any(|&word| word != 0) {
                triggers.push(Some(triggered));
            } else {
                triggers.push(None);
            }
        }
        triggers
    }

    /// [`scan_coalesced_phase2`](Self::scan_coalesced_phase2) with an optional
    /// producer-side phase-2 admission bitmap. A `true` bit only admits a
    /// no-trigger chunk to the shared tail; a `false` bit is never trusted as a
    /// skip proof because GPU regex-DFA coverage may be partial or capped.
    #[cfg(feature = "simd")]
    pub(crate) fn scan_coalesced_phase2_with_admission(
        &self,
        chunks: &[keyhog_core::Chunk],
        triggers: Vec<Option<Vec<u64>>>,
        phase2_admission: Option<&[bool]>,
        phase2_keyword_hints: Option<&[Vec<u32>]>,
        phase2_always_anchor_presence: Option<&[bool]>,
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        use crate::hw_probe::ScanBackend;
        use rayon::prelude::*;

        let triggers = self.normalize_coalesced_phase2_triggers(chunks, triggers);
        let phase2_start = std::time::Instant::now();
        let mut results: Vec<Vec<keyhog_core::RawMatch>> = chunks
            .par_iter()
            .zip(triggers.into_par_iter())
            .enumerate()
            .map(|(chunk_index, (chunk, triggered_opt))| {
                let keyword_hints = phase2_keyword_hints
                    .and_then(|rows| rows.get(chunk_index))
                    .map(Vec::as_slice);
                let always_anchor_present =
                    phase2_always_anchor_presence.and_then(|rows| rows.get(chunk_index).copied());
                if let Some(triggered) = triggered_opt {
                    let mut matches = if chunk.data.len() > MAX_SCAN_CHUNK_BYTES {
                        self.scan_windowed_with_triggered(
                            chunk,
                            &triggered,
                            None,
                            keyword_hints,
                            always_anchor_present,
                        )
                    } else {
                        let prepared = self.prepare_chunk(chunk);
                        self.scan_prepared_with_triggered(
                            prepared,
                            ScanBackend::SimdCpu,
                            triggered,
                            None,
                            keyword_hints,
                            always_anchor_present,
                        )
                    };
                    self.post_process_coalesced_matches(chunk, &mut matches);
                    return matches;
                }
                let admitted_by_phase2_gpu =
                    match phase2_admission.and_then(|admission| admission.get(chunk_index)) {
                        Some(&admitted) => admitted,
                        None => false, // LAW10: recall_preserving; absent GPU admission never skips CPU admission.
                    };
                let admitted_by_phase2_keyword_hint =
                    keyword_hints.is_some_and(|hints| !hints.is_empty());
                let admitted_by_phase2_always_anchor = always_anchor_present.unwrap_or(false); // LAW10: absent GPU row does not skip; CPU no-hit admission remains authoritative.
                if !admitted_by_phase2_gpu
                    && !admitted_by_phase2_keyword_hint
                    && !admitted_by_phase2_always_anchor
                    && !self.should_scan_no_hit_chunk(chunk)
                {
                    if let Some(matches) = self.decode_only_coalesced_matches(chunk) {
                        return matches;
                    }
                    return Vec::new();
                }

                let prepared = self.prepare_chunk(chunk);
                let triggered = if prepared.preprocessed.text.as_bytes() == chunk.data.as_bytes() {
                    Vec::new()
                } else {
                    self.collect_triggered_patterns_for_backend(
                        &prepared.preprocessed.text,
                        ScanBackend::SimdCpu,
                    )
                };
                let mut matches = self.scan_prepared_with_triggered(
                    prepared,
                    ScanBackend::SimdCpu,
                    triggered,
                    None,
                    keyword_hints,
                    always_anchor_present,
                );
                self.record_and_reassemble_for_no_hit_chunk(chunk, &mut matches);
                self.post_process_coalesced_matches(chunk, &mut matches);
                matches
            })
            .collect();

        let phase2_elapsed = phase2_start.elapsed();
        let boundary_start = std::time::Instant::now();
        super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
        if super::profile::perf_trace_enabled() {
            eprintln!(
                "perf-trace scan_coalesced_phase2: chunks={} p2={:.3}s boundary={:.3}s",
                chunks.len(),
                phase2_elapsed.as_secs_f64(),
                boundary_start.elapsed().as_secs_f64()
            );
        }
        results
    }
}

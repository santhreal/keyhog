// `scan_filters` is consumed by `should_scan_no_hit_chunk` (the no-phase-1-hit
// admission gate) on the shared phase-2 tail. SIMD and GPU use it after their
// trigger pass. Portable builds use it before their phase-2 tail so no-hit
// chunks are not dropped before anchorless detection.
#[cfg(feature = "simd")]
use super::phase2::Phase2AlwaysActiveGpuEvidence;
use super::scan_filters::*;
use super::*;

#[cfg(feature = "simd")]
use std::cell::RefCell;

/// Upper size bound for admitting a no-phase-1-hit chunk to the keyword-free
/// entropy fallback. A no-hit chunk larger than this that carries a bare
/// high-entropy secret with no keyword/assignment anchor is NOT admitted to the
/// entropy path, the bound caps the cost of the entropy scan on chunks that
/// produced no literal trigger. Raising it trades scan time for recall on large
/// anchorless blobs. Recall-affecting; kept beside the other engine thresholds
/// (`MAX_INNER_LOOP_ITERS`, `BIGRAM_BLOOM_MIN_CHUNK_BYTES`).
#[cfg(any(feature = "entropy", test))]
pub(crate) const NO_HIT_ENTROPY_ADMISSION_MAX_BYTES: usize = 32 * 1024;

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
    prefilter: &super::SimdPhase1Prefilter,
    ac_len: usize,
    hs_id: usize,
) {
    if let Some(orig) = prefilter.original_indices(hs_id) {
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
        route: crate::ScanExecutionRoute,
    ) {
        if self.chunk_needs_decode_postprocess(chunk) {
            self.post_process_matches(chunk, matches, None, route);
        } else {
            self.scan_cross_chunk_fragments(chunk, matches, None, route);
        }
    }

    #[cfg(feature = "simd")]
    #[inline]
    fn decode_only_coalesced_matches(
        &self,
        chunk: &keyhog_core::Chunk,
        route: crate::ScanExecutionRoute,
    ) -> Option<Vec<keyhog_core::RawMatch>> {
        if !self.chunk_needs_decode_postprocess(chunk) {
            return None;
        }
        let mut matches = Vec::new();
        self.post_process_matches(chunk, &mut matches, None, route);
        Some(matches)
    }

    /// High-throughput coalesced scan: all files scanned in parallel, zero
    /// overhead for non-hit files.
    ///
    /// Direct library backend selection is a hard process contract. CLI
    /// orchestrators that own stable input replay use the fallible companion
    /// method below and record any automatic-route recovery explicitly.
    pub fn scan_coalesced_with_backend(
        &self,
        chunks: &[keyhog_core::Chunk],
        backend: crate::hw_probe::ScanBackend,
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        self.scan_coalesced_with_backend_and_admission(chunks, backend, None)
    }

    /// Coalesced scan using admission evidence computed by the autoroute key
    /// builder. A mismatched plan is ignored and the scanner recomputes its
    /// own exact admissions, preserving recall over the optimization.
    pub fn scan_coalesced_with_backend_and_admission(
        &self,
        chunks: &[keyhog_core::Chunk],
        backend: crate::hw_probe::ScanBackend,
        plan: Option<&super::Phase1AdmissionPlan>,
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        self.scan_coalesced_with_backend_admission_and_route(
            chunks,
            backend,
            plan,
            self.default_execution_route(),
        )
    }

    /// Coalesced scan with an explicit recall-equivalent execution route.
    pub fn scan_coalesced_with_backend_admission_and_route(
        &self,
        chunks: &[keyhog_core::Chunk],
        backend: crate::hw_probe::ScanBackend,
        plan: Option<&super::Phase1AdmissionPlan>,
        route: crate::ScanExecutionRoute,
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        match self.try_scan_coalesced_with_backend_admission_and_route(chunks, backend, plan, route)
        {
            Ok(matches) => matches,
            Err(crate::error::ScanError::Gpu(reason)) => {
                super::gpu_forced::fail_selected_gpu_dispatch(self, &reason)
            }
            Err(error) => crate::process_exit::backend_unavailable(format!(
                "selected scanner backend failed: {error}"
            )),
        }
    }

    /// Fallible production dispatch boundary used by orchestrators that can
    /// recover the same stable input bytes after a transient accelerator fault.
    /// This method never substitutes a backend itself: the caller must either
    /// surface the error or explicitly replay the input and record recovery.
    pub fn try_scan_coalesced_with_backend_and_admission(
        &self,
        chunks: &[keyhog_core::Chunk],
        backend: crate::hw_probe::ScanBackend,
        plan: Option<&super::Phase1AdmissionPlan>,
    ) -> crate::error::Result<Vec<Vec<keyhog_core::RawMatch>>> {
        self.try_scan_coalesced_with_backend_admission_and_route(
            chunks,
            backend,
            plan,
            self.default_execution_route(),
        )
    }

    /// Fallible production dispatch with an immutable per-request execution route.
    pub fn try_scan_coalesced_with_backend_admission_and_route(
        &self,
        chunks: &[keyhog_core::Chunk],
        backend: crate::hw_probe::ScanBackend,
        plan: Option<&super::Phase1AdmissionPlan>,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<Vec<Vec<keyhog_core::RawMatch>>> {
        let result = if backend == crate::hw_probe::ScanBackend::SimdCpu {
            self.require_selected_backend_stack(backend);
            Ok(self.scan_coalesced_simd(
                chunks,
                plan.filter(|plan| plan.matches_chunks(chunks)),
                route,
            ))
        } else if backend.is_gpu() {
            #[cfg(feature = "gpu")]
            {
                self.try_scan_coalesced_gpu_region_presence(chunks, backend, route)
                    .map_err(|error| {
                        self.record_gpu_runtime_fault(error.reason());
                        crate::error::ScanError::Gpu(error.to_string())
                    })
            }
            #[cfg(not(feature = "gpu"))]
            {
                Err(crate::error::ScanError::Gpu(format!(
                    "{} selected but this scanner build has no GPU support",
                    backend.label()
                )))
            }
        } else {
            Ok(self.scan_chunks_with_backend_internal_admission_and_route(
                chunks,
                backend,
                plan.filter(|plan| plan.matches_chunks(chunks)),
                route,
            ))
        };
        // Count logical input only after a complete route succeeds. A failed GPU
        // attempt followed by visible CPU replay therefore records the input
        // once, while every successful coalesced backend reports the same bytes.
        if result.is_ok() {
            profile::add_bytes(chunks.iter().map(|chunk| chunk.data.len() as u64).sum());
            profile::add_files(chunks.len() as u64);
        }
        result
    }

    /// Deterministic portable reference scan over several chunks.
    ///
    /// Accelerated callers use [`Self::scan_coalesced_with_backend`] with an
    /// explicit measured backend. Keeping the no-backend API on `CpuFallback`
    /// makes library results independent of host hardware and calibration state.
    pub fn scan_coalesced(&self, chunks: &[keyhog_core::Chunk]) -> Vec<Vec<keyhog_core::RawMatch>> {
        self.scan_chunks_with_backend(chunks, crate::hw_probe::ScanBackend::CpuFallback)
    }

    /// Explicit Hyperscan coalesced path: all files scanned in parallel, zero
    /// overhead for non-hit files. Only reached for `ScanBackend::SimdCpu`.
    #[allow(clippy::needless_return)] // return needed under non-simd cfg branch
    fn scan_coalesced_simd(
        &self,
        chunks: &[keyhog_core::Chunk],
        admission_plan: Option<&super::Phase1AdmissionPlan>,
        route: crate::ScanExecutionRoute,
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        use rayon::prelude::*;

        #[cfg(not(feature = "simd"))]
        let _admission_plan = admission_plan;

        #[cfg(not(feature = "simd"))]
        {
            let telemetry = crate::telemetry::capture_scan_telemetry();
            let mut results: Vec<Vec<keyhog_core::RawMatch>> = chunks
                .par_iter()
                .map(|c| {
                    crate::telemetry::with_captured_scan_telemetry(telemetry.as_ref(), || {
                        self.scan_with_deadline_and_backend_admission_and_route(
                            c,
                            self.config.per_chunk_deadline(),
                            crate::hw_probe::ScanBackend::CpuFallback,
                            None,
                            route,
                        )
                    })
                })
                .collect();
            super::boundary::scan_chunk_boundaries_with_route(self, chunks, &mut results, route);
            return results;
        }

        #[cfg(feature = "simd")]
        {
            let Some(prefilter) = &self.simd_prefilter else {
                self.warn_simd_auto_degrade("coalesced scan had no live SIMD prefilter");
                let telemetry = crate::telemetry::capture_scan_telemetry();
                let mut results: Vec<Vec<keyhog_core::RawMatch>> = chunks
                    .par_iter()
                    .map(|c| {
                        crate::telemetry::with_captured_scan_telemetry(telemetry.as_ref(), || {
                            self.scan_with_deadline_and_backend_admission_and_route(
                                c,
                                self.config.per_chunk_deadline(),
                                crate::hw_probe::ScanBackend::CpuFallback,
                                None,
                                route,
                            )
                        })
                    })
                    .collect();
                super::boundary::scan_chunk_boundaries_with_route(
                    self,
                    chunks,
                    &mut results,
                    route,
                );
                return results;
            };

            // Coalesced SIMD bypasses `scan_inner`, so it owns the same scanner
            // telemetry events. Logical profiler input is recorded once by the
            // shared successful coalesced-dispatch boundary above.
            for chunk in chunks {
                crate::telemetry::record_file_scanned(chunk.data.len());
            }
            let triggers = {
                let _g = profile::span(profile::P::Phase1Triggers);
                self.compute_coalesced_triggers(chunks, prefilter, admission_plan)
            };
            return self.scan_coalesced_phase2(chunks, triggers, route);
        }
    }

    /// Phase 1 of the coalesced scan: Hyperscan-confirmed rows plus exact
    /// detector-literal recovery over raw chunk bytes, producing one trigger
    /// bitmap per chunk. GPU region presence is the alternative producer
    /// feeding the same phase 2.
    #[cfg(feature = "simd")]
    pub(crate) fn compute_coalesced_triggers(
        &self,
        chunks: &[keyhog_core::Chunk],
        prefilter: &super::SimdPhase1Prefilter,
        admission_plan: Option<&super::Phase1AdmissionPlan>,
    ) -> Vec<Option<Vec<u64>>> {
        use rayon::prelude::*;
        let ac_len = self.ac_map.len();
        let words_needed = super::trigger_bitmap::words_for(ac_len);
        let triggers: Vec<Option<Vec<u64>>> = chunks
            .par_iter()
            .enumerate()
            .map(|(chunk_index, chunk)| {
                let data = chunk.data.as_bytes();
                let admission = match admission_plan
                    .and_then(|plan| plan.admission_for(chunk_index))
                {
                    Some(admission) => admission,
                    None => self.phase1_admission(data),
                };
                if admission != super::Phase1Admission::Admitted {
                    return None;
                }
                with_trigger_buffer(words_needed, |scratch| {
                    let scanner = prefilter.scanner();
                    let scan_result = scanner.scan_each_result(data, |hs_id| {
                        mark_hs_trigger(scratch, prefilter, ac_len, hs_id);
                    });
                    if let Err(error) = scan_result {
                        tracing::warn!(
                            %error,
                            "hyperscan coalesced phase-1 scan failed; over-marking SIMD-covered patterns for this chunk"
                        );
                        scratch.fill(0);
                        for hs_id in 0..scanner.pattern_count() {
                            mark_hs_trigger(scratch, prefilter, ac_len, hs_id);
                        }
                    }
                    prefilter.for_each_recovery_match(data, |pattern_index| {
                        self.mark_triggered_pattern(scratch, pattern_index);
                    });
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
                triggered_patterns = total_hs_matches,
                "coalesced scan phase 1 complete"
            );
        }
        triggers
    }

    /// No-hit chunk admission: should a chunk that produced no phase-1 trigger
    /// still be driven through the phase-2 / generic / entropy tail?
    pub(crate) fn should_scan_no_hit_chunk(&self, chunk: &keyhog_core::Chunk) -> bool {
        self.should_scan_no_hit_chunk_with_phase2_absence_proof(chunk, false)
    }

    fn should_scan_no_hit_chunk_with_phase2_absence_proof(
        &self,
        chunk: &keyhog_core::Chunk,
        raw_phase2_absence_proven: bool,
    ) -> bool {
        let raw_text = chunk.data.as_ref();
        if self.no_hit_text_admits(chunk, raw_text, raw_phase2_absence_proven) {
            return true;
        }

        if !self.config.unicode_normalization
            || !crate::unicode_hardening::contains_evasion(raw_text)
        {
            return false;
        }

        let prepared = self.prepare_chunk(chunk);
        let normalized = prepared.preprocessed.text.as_ref();
        if normalized.as_bytes() == raw_text.as_bytes() {
            return false;
        }
        let normalized_triggers = self.collect_triggered_patterns_for_backend(
            normalized,
            crate::hw_probe::ScanBackend::SimdCpu,
        );
        normalized_triggers.iter().any(|&word| word != 0)
            || self.no_hit_text_admits(chunk, normalized, false)
    }

    fn no_hit_text_admits(
        &self,
        _chunk: &keyhog_core::Chunk,
        text: &str,
        phase2_absence_proven: bool,
    ) -> bool {
        if !phase2_absence_proven && self.has_active_phase2_patterns_for_chunk(text) {
            return true;
        }
        let data = text.as_bytes();
        #[cfg(feature = "entropy")]
        let small_chunk = text.len() <= NO_HIT_ENTROPY_ADMISSION_MAX_BYTES;
        let keyword_admits = has_generic_assignment_keyword(data) || has_secret_keyword_fast(data);
        #[cfg(feature = "entropy")]
        let isolated_bare_owner_index = self.generic_owning_detector.isolated_bare_owner_index();
        #[cfg(feature = "entropy")]
        let isolated_bare_policy = isolated_bare_owner_index
            .and_then(|index| self.detector_plans.get(index).entropy.as_ref())
            .copied();
        #[cfg(feature = "multiline")]
        if crate::multiline::has_concatenation_indicators(text) {
            if keyword_admits {
                return true;
            }
            #[cfg(feature = "entropy")]
            if let Some(policy) =
                isolated_bare_policy.filter(|_| small_chunk && self.config.entropy_enabled)
            {
                if crate::entropy::scanner::has_isolated_bare_secret_candidate_with_policy(
                    text,
                    self.config.entropy_threshold,
                    &self.config.placeholder_keywords,
                    policy.keyword_free_min_len,
                    &policy,
                ) {
                    return true;
                }
            }
        }
        #[cfg(feature = "entropy")]
        let entropy_admits = small_chunk
            && self.config.entropy_enabled
            && ((crate::entropy::is_entropy_appropriate_with_content(
                _chunk.metadata.path.as_deref(),
                self.config.entropy_in_source_files,
                text,
                &self.config.secret_keywords,
            ) && has_high_entropy_run_fast(data))
                || isolated_bare_policy.is_some_and(|policy| {
                    crate::entropy::scanner::has_isolated_bare_secret_candidate_with_policy(
                        text,
                        self.config.entropy_threshold,
                        &self.config.placeholder_keywords,
                        policy.keyword_free_min_len,
                        &policy,
                    )
                }));
        #[cfg(feature = "entropy")]
        {
            keyword_admits || entropy_admits
        }
        #[cfg(not(feature = "entropy"))]
        {
            keyword_admits
        }
    }

    /// Shared phase-2 tail for the SIMD coalesced producer and GPU
    /// region-presence producer. Both backends feed identical per-chunk trigger
    /// bitmaps into this owner so findings remain backend-invariant.
    #[cfg(feature = "simd")]
    pub(crate) fn scan_coalesced_phase2(
        &self,
        chunks: &[keyhog_core::Chunk],
        triggers: Vec<Option<Vec<u64>>>,
        route: crate::ScanExecutionRoute,
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        self.scan_coalesced_phase2_with_admission(
            chunks, triggers, None, None, None, None, None, None, route,
        )
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
    /// producer-side phase-2 admission bitmap. A complete negative prefixless
    /// row composed with complete fused-anchor absence skips the redundant CPU
    /// always-active prefilter and extraction. Keyword-triggered phase two,
    /// generic, entropy, multiline, decode, normalized text, ML, and recovery
    /// remain under their canonical owners.
    #[cfg(feature = "simd")]
    pub(crate) fn scan_coalesced_phase2_with_admission(
        &self,
        chunks: &[keyhog_core::Chunk],
        triggers: Vec<Option<Vec<u64>>>,
        phase2_admission: Option<&[bool]>,
        phase2_admission_complete: Option<&[bool]>,
        phase2_keyword_hints: Option<&[Vec<u32>]>,
        phase2_always_anchor_presence: Option<&[bool]>,
        confirmed_anchor_literal_matches: Option<&[Vec<(u32, u32)>]>,
        generic_keyword_positions: Option<&[Vec<u32>]>,
        route: crate::ScanExecutionRoute,
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        use crate::hw_probe::ScanBackend;
        use rayon::prelude::*;

        let triggers = self.normalize_coalesced_phase2_triggers(chunks, triggers);
        let phase2_start = std::time::Instant::now();
        let telemetry = crate::telemetry::capture_scan_telemetry();
        struct CoalescedChunkOutput {
            state: Option<crate::types::ScanState>,
            matches: Vec<keyhog_core::RawMatch>,
            needs_postprocess: bool,
        }

        let mut outputs: Vec<CoalescedChunkOutput> = chunks
            .par_iter()
            .zip(triggers.into_par_iter())
            .enumerate()
            .map(|(chunk_index, (chunk, triggered_opt))| {
                crate::telemetry::with_captured_scan_telemetry(telemetry.as_ref(), || {
                    let keyword_hints = phase2_keyword_hints
                        .and_then(|rows| rows.get(chunk_index))
                        .map(Vec::as_slice);
                    let always_anchor_present = phase2_always_anchor_presence
                        .and_then(|rows| rows.get(chunk_index).copied());
                    let admitted_by_phase2_gpu = match phase2_admission
                        .and_then(|admission| admission.get(chunk_index))
                        .copied()
                    {
                        Some(admitted) => admitted,
                        None => false,
                    };
                    let phase2_gpu_complete = match phase2_admission_complete
                        .and_then(|complete| complete.get(chunk_index))
                        .copied()
                    {
                        Some(complete) => complete,
                        None => false,
                    };
                    let phase2_always_active_gpu_evidence =
                        always_anchor_present.map(|anchor_present| Phase2AlwaysActiveGpuEvidence {
                            prefixless_admitted: admitted_by_phase2_gpu,
                            prefixless_complete: phase2_gpu_complete,
                            anchor_present,
                        });
                    let confirmed_anchor_matches = confirmed_anchor_literal_matches
                        .and_then(|rows| rows.get(chunk_index))
                        .map(Vec::as_slice);
                    let generic_keyword_positions = generic_keyword_positions
                        .and_then(|rows| rows.get(chunk_index))
                        .map(Vec::as_slice);
                    if let Some(triggered) = triggered_opt {
                        if chunk.data.len() > MAX_SCAN_CHUNK_BYTES {
                            let matches = self.scan_windowed_with_triggered(
                                chunk,
                                &triggered,
                                None,
                                keyword_hints,
                                phase2_always_active_gpu_evidence,
                                confirmed_anchor_matches,
                                generic_keyword_positions,
                                route,
                            );
                            return CoalescedChunkOutput {
                                state: None,
                                matches,
                                needs_postprocess: true,
                            };
                        } else {
                            let prepared = self.prepare_chunk(chunk);
                            let state = self.scan_prepared_state_with_triggered(
                                prepared,
                                ScanBackend::SimdCpu,
                                &triggered,
                                None,
                                keyword_hints,
                                phase2_always_active_gpu_evidence,
                                confirmed_anchor_matches,
                                generic_keyword_positions,
                                route,
                            );
                            return CoalescedChunkOutput {
                                state: Some(state),
                                matches: Vec::new(),
                                needs_postprocess: true,
                            };
                        }
                    }
                    let raw_phase2_absence_proven = phase2_always_active_gpu_evidence
                        .is_some_and(|evidence| evidence.absence_proven())
                        && phase2_keyword_hints
                            .and_then(|rows| rows.get(chunk_index))
                            .is_some();
                    let admitted_by_phase2_keyword_hint =
                        keyword_hints.is_some_and(|hints| !hints.is_empty());
                    let admitted_by_phase2_always_anchor = match always_anchor_present {
                        Some(present) => present,
                        None => false,
                    };
                    let admitted_by_generic_keyword_hint =
                        generic_keyword_positions.is_some_and(|positions| !positions.is_empty());
                    // An absent positioned row is not evidence that the active
                    // detector corpus has no generic assignment keyword. When
                    // a producer cannot supply the compiled plan's positioned
                    // rows, run the shared stem prefilter instead of composing
                    // that gap with unrelated complete phase-2 absence.
                    let generic_assignment_absence_proven =
                        self.generic_assignment_re.is_none() || generic_keyword_positions.is_some();
                    if !admitted_by_phase2_gpu
                        && !admitted_by_phase2_keyword_hint
                        && !admitted_by_phase2_always_anchor
                        && !admitted_by_generic_keyword_hint
                        && generic_assignment_absence_proven
                        && !self.should_scan_no_hit_chunk_with_phase2_absence_proof(
                            chunk,
                            raw_phase2_absence_proven,
                        )
                    {
                        if let Some(matches) = self.decode_only_coalesced_matches(chunk, route) {
                            return CoalescedChunkOutput {
                                state: None,
                                matches,
                                needs_postprocess: false,
                            };
                        }
                        return CoalescedChunkOutput {
                            state: None,
                            matches: Vec::new(),
                            needs_postprocess: false,
                        };
                    }

                    let prepared = self.prepare_chunk(chunk);
                    let state = self.scan_prepared_state_with_triggered(
                        prepared,
                        ScanBackend::SimdCpu,
                        &[],
                        None,
                        keyword_hints,
                        phase2_always_active_gpu_evidence,
                        confirmed_anchor_matches,
                        generic_keyword_positions,
                        route,
                    );
                    CoalescedChunkOutput {
                        state: Some(state),
                        matches: Vec::new(),
                        needs_postprocess: true,
                    }
                })
            })
            .collect();

        #[cfg(feature = "ml")]
        {
            let mut output_indices = Vec::new();
            let mut scan_states = Vec::new();
            for (output_index, output) in outputs.iter_mut().enumerate() {
                if let Some(state) = output.state.take() {
                    output_indices.push(output_index);
                    scan_states.push(state);
                }
            }
            let _g = profile::span(profile::P::Ml);
            self.apply_ml_batch_scores_across(&mut scan_states);
            for (output_index, state) in output_indices.into_iter().zip(scan_states) {
                outputs[output_index].matches = state.into_matches();
            }
        }
        #[cfg(not(feature = "ml"))]
        for output in &mut outputs {
            if let Some(state) = output.state.take() {
                output.matches = state.into_matches();
            }
        }

        let mut results: Vec<Vec<keyhog_core::RawMatch>> = outputs
            .into_par_iter()
            .zip(chunks.par_iter())
            .map(|(mut output, chunk)| {
                if output.needs_postprocess {
                    self.post_process_coalesced_matches(chunk, &mut output.matches, route);
                }
                output.matches
            })
            .collect();

        let phase2_elapsed = phase2_start.elapsed();
        let boundary_start = std::time::Instant::now();
        super::boundary::scan_chunk_boundaries_with_route(self, chunks, &mut results, route);
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

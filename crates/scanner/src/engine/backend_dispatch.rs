use super::*;
use crate::hw_probe::ScanBackend;
use keyhog_core::Chunk;

impl CompiledScanner {
    pub(crate) fn scan_chunks_with_backend_internal_admission_and_route(
        &self,
        chunks: &[Chunk],
        backend: ScanBackend,
        admission_plan: Option<&Phase1AdmissionPlan>,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<Vec<Vec<RawMatch>>> {
        if chunks.iter().all(|chunk| chunk.data.is_empty()) {
            for _ in chunks {
                crate::telemetry::record_file_scanned(0);
            }
            return Ok(vec![Vec::new(); chunks.len()]);
        }

        // Non-GPU backends (and empty batches) run the parallel CPU path. rayon's
        // global pool is configured by the CLI orchestrator (--threads /
        // [scan].threads / physical cores); Hyperscan + AC scans are CPU-bound
        // and independent per-chunk, so par_iter() saturates cores. The
        // `scan_chunk_boundaries` pass reassembles secrets straddling the seam
        // between adjacent gapless chunks of the same file (a per-chunk scan sees
        // each half too short to match) (load-bearing recall, not optional).
        let gpu_path = backend.is_gpu();
        if !gpu_path || chunks.is_empty() {
            return self.scan_chunks_cpu_parallel(chunks, backend, admission_plan, route);
        }

        // The batched region-presence literal set is the SINGLE on-GPU trigger
        // producer. Dispatch failures remain structured and never substitute
        // CPU/SIMD for the selected route.
        #[cfg(feature = "gpu")]
        {
            self.scan_coalesced_gpu_region_presence(chunks, backend, route)
                .map_err(|error| {
                    self.record_gpu_runtime_fault(error.reason());
                    crate::error::ScanError::Gpu(error.to_string())
                })
        }
        #[cfg(not(feature = "gpu"))]
        {
            let _ = (chunks, admission_plan, route); // LAW10: parameters are consumed only to keep the unsupported cfg branch warning-free before returning its structured error.
            Err(crate::error::ScanError::Gpu(format!(
                "{} selected but this scanner build has no GPU support",
                backend.label()
            )))
        }
    }

    /// Parallel per-chunk CPU scan + cross-chunk boundary reassembly. The single
    /// owner of this path: it is taken only for non-GPU routes. GPU routes never
    /// enter it; a GPU route compiled without GPU support returns a structured
    /// [`crate::error::ScanError::Gpu`] from the caller instead of substituting a
    /// CPU scan or taking process-exit ownership.
    fn scan_chunks_cpu_parallel(
        &self,
        chunks: &[Chunk],
        backend: ScanBackend,
        admission_plan: Option<&Phase1AdmissionPlan>,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<Vec<Vec<RawMatch>>> {
        use rayon::prelude::*;
        let telemetry = crate::telemetry::capture_scan_telemetry();
        let recovery_receipts = crate::gpu::capture_recovery_receipts();
        let profile_runtime = keyhog_profile::current_runtime();
        let entropy_config_digest = self.entropy_evidence_config_digest();
        if backend == ScanBackend::CpuFallback {
            if let Some(plan) = admission_plan {
                let all_proven_absent = chunks.iter().enumerate().all(|(index, chunk)| {
                    plan.admission_for(index) == Some(Phase1Admission::Admitted)
                        && plan
                            .direct_scan_absence_for(
                                index,
                                self.config.unicode_normalization,
                                entropy_config_digest,
                                self.decoder_admission_context_key(chunk),
                            )
                            // LAW10: missing exact absence evidence disables the shortcut and performs the full direct scan.
                            .unwrap_or(false)
                        && crate::structured::preprocessing_is_impossible_for_path(
                            chunk.metadata.path.as_deref(),
                        )
                });
                if all_proven_absent {
                    #[cfg(debug_assertions)]
                    self.direct_scan_absence_batches
                        .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    let mut results = Vec::with_capacity(chunks.len());
                    for chunk in chunks {
                        results.push(self.scan_proven_direct_absence(
                            chunk,
                            self.config.per_chunk_deadline(),
                            route,
                            true,
                        )?);
                    }
                    super::boundary::scan_chunk_boundaries_with_route(
                        self,
                        chunks,
                        &mut results,
                        route,
                    )?;
                    return Ok(results);
                }
            }
        }
        let scan_one = |index: usize, chunk: &Chunk| {
            let _profile_context = profile_runtime.as_ref().map(keyhog_profile::Runtime::enter);
            crate::gpu::with_captured_recovery_receipts(recovery_receipts.as_ref(), || {
                crate::telemetry::with_captured_scan_telemetry(telemetry.as_ref(), || {
                    let admission = admission_plan.and_then(|plan| plan.admission_for(index));
                    let cpu_trigger_hints = match backend {
                        ScanBackend::CpuFallback => {
                            admission_plan.and_then(|plan| plan.cpu_trigger_hints_for(index))
                        }
                        _ => None,
                    };
                    let normalization_passthrough = admission_plan
                        .and_then(|plan| {
                            plan.normalization_passthrough_for(
                                index,
                                self.config.unicode_normalization,
                            )
                        })
                        // LAW10: missing passthrough evidence runs normalization instead of skipping it.
                        .unwrap_or(false);
                    let multiline_absence = normalization_passthrough
                        && admission_plan
                            .and_then(|plan| {
                                plan.multiline_absence_for(index, entropy_config_digest)
                            })
                            // LAW10: missing multiline-absence evidence runs multiline admission in full.
                            .unwrap_or(false);
                    let line_context_index = normalization_passthrough
                        .then(|| admission_plan.and_then(|plan| plan.line_context_index_for(index)))
                        .flatten();
                    let phase2_keyword_hints =
                        admission_plan.and_then(|plan| plan.phase2_keyword_hints_for(index));
                    let generic_keyword_positions =
                        admission_plan.and_then(|plan| plan.generic_keyword_positions_for(index));
                    let phase2_always_active_evidence = admission_plan
                        .and_then(|plan| plan.phase2_always_active_absence_for(index))
                        .and_then(|absence| {
                            absence.then_some(
                                super::phase2::Phase2AlwaysActiveGpuEvidence::exact_absence(),
                            )
                        });
                    let confirmed_patterns_absence = admission_plan
                        .and_then(|plan| plan.confirmed_patterns_absence_for(index))
                        // LAW10: missing confirmed-pattern absence evidence keeps confirmed matching enabled.
                        .unwrap_or(false);
                    let entropy_absence = admission_plan
                        .and_then(|plan| plan.entropy_absence_for(index, entropy_config_digest))
                        // LAW10: missing entropy absence evidence keeps entropy matching enabled.
                        .unwrap_or(false);
                    let decoder_admission_context = self.decoder_admission_context_key(chunk);
                    let decoder_absence = admission_plan
                        .and_then(|plan| plan.decoder_absence_for(index, decoder_admission_context))
                        // LAW10: missing decoder absence evidence keeps decode generation enabled.
                        .unwrap_or(false);
                    let direct_scan_absence = matches!(backend, ScanBackend::CpuFallback)
                        && admission_plan
                            .and_then(|plan| {
                                plan.direct_scan_absence_for(
                                    index,
                                    self.config.unicode_normalization,
                                    entropy_config_digest,
                                    decoder_admission_context,
                                )
                            })
                            // LAW10: missing complete direct-scan absence evidence runs the full matcher.
                            .unwrap_or(false);
                    self.scan_with_deadline_and_backend_admission_route_and_hints(
                        chunk,
                        self.config.per_chunk_deadline(),
                        backend,
                        admission,
                        normalization_passthrough,
                        multiline_absence,
                        line_context_index,
                        confirmed_patterns_absence,
                        entropy_absence,
                        decoder_absence,
                        direct_scan_absence,
                        cpu_trigger_hints,
                        phase2_keyword_hints,
                        phase2_always_active_evidence,
                        generic_keyword_positions,
                        route,
                    )
                })
            })
        };
        let threshold = self.tuning.chunk_lane_threshold();
        let workers = rayon::current_num_threads().max(1);

        let mut results: Vec<Vec<RawMatch>> =
            if chunks.len() <= workers || chunks.iter().all(|chunk| chunk.data.len() > threshold) {
                chunks
                    .par_iter()
                    .enumerate()
                    .map(|(index, chunk)| scan_one(index, chunk))
                    .collect::<crate::error::Result<Vec<_>>>()?
            } else {
                let work_lanes = super::batch_topology::coalesced_work_lanes(chunks, threshold);
                let lane_results: Vec<Vec<(usize, Vec<RawMatch>)>> = work_lanes
                    .par_iter()
                    .map(|lane| {
                        let indices: &[usize] = match lane {
                            super::batch_topology::CoalescedLane::Small(indices) => indices,
                            super::batch_topology::CoalescedLane::Large(index) => {
                                std::slice::from_ref(index)
                            }
                        };
                        indices
                            .iter()
                            .map(|&index| Ok((index, scan_one(index, &chunks[index])?)))
                            .collect::<crate::error::Result<Vec<_>>>()
                    })
                    .collect::<crate::error::Result<Vec<_>>>()?;

                let mut combined = vec![Vec::new(); chunks.len()];
                for lane_res in lane_results {
                    for (index, result) in lane_res {
                        combined[index] = result;
                    }
                }
                combined
            };
        super::boundary::scan_chunk_boundaries_with_route(self, chunks, &mut results, route)?;
        Ok(results)
    }

    pub(crate) fn prepare_chunk<'a>(&'a self, chunk: &'a Chunk) -> PreparedChunk<'a> {
        self.prepare_chunk_with_normalization_passthrough(chunk, false, false, None)
    }

    pub(crate) fn prepare_chunk_with_normalization_passthrough<'a>(
        &'a self,
        chunk: &'a Chunk,
        normalization_passthrough: bool,
        multiline_absence: bool,
        line_context_index: Option<&std::sync::Arc<crate::context::LineContextIndex>>,
    ) -> PreparedChunk<'a> {
        let _g = super::profile::span(keyhog_profile::Stage::Preprocess);
        // Note: non-ASCII normalization used to swap `chunk` to an
        // owned `Chunk` via `normalize_scannable_chunk`. That path
        // is rarely-hit (most source code is pure ASCII) and the
        // returned Chunk was immediately consumed via clone into the
        // owned PreparedChunk anyway, so the borrow design works:
        // for non-ASCII inputs we still feed the normalization
        // through `unicode_hardening::normalize_homoglyphs` Cow
        // below, which lands the normalized text in
        // `preprocessed.text`. The raw `chunk.data` borrow remains
        // intact for the few downstream consumers that read it
        // (extract_confirmed_patterns uses preprocessed.text by
        // default; raw `chunk.data` only via the drift fallback).

        // Homoglyph normalization: zero-allocation Cow fast path. Pure-ASCII
        // and evasion-free inputs (the 99% case) borrow `chunk.data` directly.
        // Only inputs containing actual homoglyphs/zero-width/RTL allocate.
        //
        // The Cow MUST borrow `chunk.data` (lifetime `'a`) on the no-op path,
        // not a local, so the borrowed passthrough text below can outlive this
        // call inside `PreparedChunk<'a>`. We therefore chain the two
        // normalization stages explicitly: a stage that rewrites bytes yields
        // `Cow::Owned`; a no-op stage preserves the `&'a chunk.data` borrow.
        #[cfg(debug_assertions)]
        if self.config.unicode_normalization && !normalization_passthrough {
            self.normalization_scanned_bytes.fetch_add(
                // LAW10: debug accounting saturates on impossible usize-to-u64 overflow; scan behavior is unchanged.
                u64::try_from(chunk.data.len()).unwrap_or(u64::MAX),
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        let data_to_pp: std::borrow::Cow<'a, str> = if normalization_passthrough {
            std::borrow::Cow::Borrowed(&chunk.data)
        } else if self.config.unicode_normalization {
            match crate::unicode_hardening::normalize_homoglyphs(&chunk.data) {
                // Homoglyph stage rewrote the bytes: the owned String is the
                // canonical text. The interior-control strip then operates on
                // that owned buffer; either outcome stays owned.
                std::borrow::Cow::Owned(normalized) => {
                    match crate::unicode_hardening::strip_interior_evasion_controls(&normalized) {
                        std::borrow::Cow::Owned(stripped) => std::borrow::Cow::Owned(stripped),
                        std::borrow::Cow::Borrowed(_) => std::borrow::Cow::Owned(normalized),
                    }
                }
                // Homoglyph stage was a no-op: bytes are still `chunk.data`.
                // Run the interior-control strip against `chunk.data` itself so
                // a no-op there preserves the `'a` borrow on the chunk.
                std::borrow::Cow::Borrowed(_) => {
                    crate::unicode_hardening::strip_interior_evasion_controls(&chunk.data)
                }
            }
        } else {
            std::borrow::Cow::Borrowed(&chunk.data)
        };

        // For the structured / multiline-join paths the preprocessed text is
        // freshly synthesized (owned regardless of `data_to_pp`), so they read
        // it through a plain `&str`. The passthrough path, by contrast, is
        // byte-identical to `data_to_pp` and carries the Cow through unchanged
        // so a borrowed chunk stays borrowed (no full-body copy).
        // A chunk the decode-through pipeline produced carries `decoded_span`;
        // on such a derived buffer a structured-format parse failure is expected
        // and loses nothing (the encoded surface was already decoded + scanned),
        // so it must not be counted/announced as a lost decode surface.
        let decode_derived = chunk.metadata.decoded_span.is_some();
        let preprocessed = if let Some(pp) = crate::structured::preprocess(
            &data_to_pp,
            chunk.metadata.path.as_deref(),
            decode_derived,
        ) {
            pp
        } else {
            #[cfg(feature = "multiline")]
            {
                #[cfg(debug_assertions)]
                if !multiline_absence {
                    self.multiline_admission_scanned_bytes.fetch_add(
                        // LAW10: debug accounting saturates on impossible usize-to-u64 overflow; scan behavior is unchanged.
                        u64::try_from(data_to_pp.len()).unwrap_or(u64::MAX),
                        std::sync::atomic::Ordering::Relaxed,
                    );
                }
                let has_multiline_candidate = !multiline_absence
                    && crate::multiline::config::has_concatenation_indicators_with_keyword_gate(
                        &data_to_pp,
                        |bytes| {
                            let matcher = self
                                .assignment_keyword_matcher
                                .lock()
                                // LAW10: recall-preserving; Mutex poison does not invalidate the matcher cache value, so resolution continues with the complete cached matcher.
                                .unwrap_or_else(|poisoned| poisoned.into_inner())
                                .resolve(
                                    &self.config.secret_keywords,
                                    self.detector_plans.generic_ownership().policy_keywords(),
                                );
                            matcher.matches(bytes)
                        },
                    );
                if has_multiline_candidate {
                    crate::multiline::preprocess_multiline_admitted(
                        data_to_pp,
                        &self.config.multiline,
                        &self.fragment_cache,
                    )
                } else {
                    ScannerPreprocessedText::passthrough(data_to_pp)
                }
            }
            #[cfg(not(feature = "multiline"))]
            ScannerPreprocessedText::passthrough(data_to_pp)
        };

        let line_index = line_context_index
            .filter(|_| {
                preprocessed.text.as_ptr() == chunk.data.as_ptr()
                    && preprocessed.text.len() == chunk.data.len()
            })
            .map_or_else(std::sync::OnceLock::new, |index| {
                std::sync::OnceLock::from(std::sync::Arc::clone(index))
            });
        PreparedChunk {
            chunk,
            preprocessed,
            line_index,
            #[cfg(debug_assertions)]
            line_index_scanned_bytes: Some(&self.line_index_scanned_bytes),
        }
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn reset_normalization_scanned_bytes_for_diagnostics(&self) {
        self.normalization_scanned_bytes
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn normalization_scanned_bytes_for_diagnostics(&self) -> u64 {
        self.normalization_scanned_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn reset_line_index_scanned_bytes_for_diagnostics(&self) {
        self.line_index_scanned_bytes
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn line_index_scanned_bytes_for_diagnostics(&self) -> u64 {
        self.line_index_scanned_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn reset_multiline_admission_scanned_bytes_for_diagnostics(&self) {
        self.multiline_admission_scanned_bytes
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn multiline_admission_scanned_bytes_for_diagnostics(&self) -> u64 {
        self.multiline_admission_scanned_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

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
        let scan_one = |index: usize, chunk: &Chunk| {
            let _profile_context = profile_runtime.as_ref().map(keyhog_profile::Runtime::enter);
            crate::gpu::with_captured_recovery_receipts(recovery_receipts.as_ref(), || {
                crate::telemetry::with_captured_scan_telemetry(telemetry.as_ref(), || {
                    let admission = admission_plan.and_then(|plan| plan.admission_for(index));
                    self.scan_with_deadline_and_backend_admission_and_route(
                        chunk,
                        self.config.per_chunk_deadline(),
                        backend,
                        admission,
                        route,
                    )
                })
            })
        };
        let lane_width = super::batch_topology::coalesced_lane_width(chunks);
        let mut results: Vec<Vec<RawMatch>> = if lane_width == 1 {
            chunks
                .par_iter()
                .enumerate()
                .map(|(index, chunk)| scan_one(index, chunk))
                .collect::<crate::error::Result<Vec<_>>>()?
        } else {
            chunks
                .par_chunks(lane_width)
                .enumerate()
                .map(|(lane_index, lane)| {
                    let base = lane_index * lane_width;
                    lane.iter()
                        .enumerate()
                        .map(|(offset, chunk)| scan_one(base + offset, chunk))
                        .collect::<crate::error::Result<Vec<_>>>()
                })
                .collect::<crate::error::Result<Vec<_>>>()?
                .into_iter()
                .flatten()
                .collect()
        };
        super::boundary::scan_chunk_boundaries_with_route(self, chunks, &mut results, route)?;
        Ok(results)
    }

    pub(crate) fn prepare_chunk<'a>(&self, chunk: &'a Chunk) -> PreparedChunk<'a> {
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
        let data_to_pp: std::borrow::Cow<'a, str> = if self.config.unicode_normalization {
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
                let has_multiline_candidate =
                    crate::multiline::config::has_concatenation_indicators_with_keyword_gate(
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

        PreparedChunk {
            chunk,
            preprocessed,
            line_index: std::sync::OnceLock::new(),
        }
    }
}

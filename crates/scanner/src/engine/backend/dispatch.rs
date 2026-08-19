use super::super::*;
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

        let gpu_path = backend.is_gpu();
        if !gpu_path || chunks.is_empty() {
            return self.scan_chunks_cpu_parallel(chunks, backend, admission_plan, route);
        }

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

    /// Parallel per-chunk CPU scan + cross-chunk boundary reassembly.
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
                    .lanes()
                    .par_iter()
                    .map(|lane| {
                        let indices = work_lanes.indices(lane);
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
}

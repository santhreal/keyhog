// `scan_filters` is consumed by `should_scan_no_hit_chunk` (the no-phase-1-hit
// admission gate) on the shared phase-2 tail. SIMD and GPU use it after their
// trigger pass. Portable builds use it before their phase-2 tail so no-hit
// chunks are not dropped before anchorless detection.
#[cfg(any(feature = "simd", feature = "gpu", test))]
use super::phase2::Phase2AlwaysActiveGpuEvidence;
use super::scan_filters::*;
use super::*;

pub(crate) mod trigger_cache;

#[cfg(feature = "simd")]
pub(crate) use trigger_cache::{mark_hs_trigger, ReusableSimdTriggerCache};

impl CompiledScanner {
    // The coalesced phase-2 tail is only reachable from the SIMD producer
    // (`scan_coalesced_simd`) and the GPU region-presence producer. A portable
    // build compiles neither producer, so gate the tail to match rather than
    // ship code no dispatch can reach.
    #[cfg(any(feature = "simd", feature = "gpu", test))]
    #[inline]
    fn post_process_coalesced_matches(
        &self,
        chunk: &keyhog_core::Chunk,
        matches: &mut Vec<keyhog_core::RawMatch>,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<()> {
        if self.chunk_needs_decode_postprocess(chunk) {
            self.post_process_matches(chunk, matches, None, route)
        } else {
            self.scan_cross_chunk_fragments(chunk, matches, None, route)
        }
    }

    #[cfg(any(feature = "simd", feature = "gpu", test))]
    #[inline]
    fn decode_only_coalesced_matches(
        &self,
        chunk: &keyhog_core::Chunk,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<Option<Vec<keyhog_core::RawMatch>>> {
        if !self.chunk_needs_decode_postprocess(chunk) {
            return Ok(None);
        }
        let mut matches = Vec::new();
        self.post_process_matches(chunk, &mut matches, None, route)?;
        Ok(Some(matches))
    }
    /// Materialize lazy literal automata before a non-empty batch allocates
    /// per-chunk scratch. Returns whether new automata were built.
    #[doc(hidden)]
    pub fn prepare_anchor_batch(&self, route: crate::ScanExecutionRoute) -> bool {
        let phase2 = self
            .phase2_anchor_index
            .as_ref()
            .is_some_and(|index| index.materialize_for_batch(route.phase2_plain_localizer));
        let confirmed = self.confirmed_anchor_index.as_ref().is_some_and(
            super::scan_postprocess::confirmed_anchor::ConfirmedAnchorIndex::materialize,
        );
        let suffix = self.tuning.confirmed_suffix_gate_enabled()
            && self.suffix_gate_ac.as_ref().is_some_and(
                super::scan_postprocess_suffix_gate::LazyConfirmedSuffixGate::materialize,
            );
        phase2 || confirmed || suffix
    }

    /// High-throughput coalesced scan using exactly the selected backend.
    ///
    /// Initialization and dispatch failures return `ScanError`; the library
    /// never terminates the host or substitutes a different backend.
    pub fn scan_coalesced_with_backend(
        &self,
        chunks: &[keyhog_core::Chunk],
        backend: crate::hw_probe::ScanBackend,
    ) -> crate::error::Result<Vec<Vec<keyhog_core::RawMatch>>> {
        self.scan_coalesced_with_backend_and_admission(chunks, backend, None)
    }

    /// Coalesced scan using admission evidence computed by the autoroute key
    /// builder. This receipt-blind boundary fails closed when identity recovery
    /// is required; callers retaining recomputed findings use the recovery-aware
    /// outcome boundary.
    pub fn scan_coalesced_with_backend_and_admission(
        &self,
        chunks: &[keyhog_core::Chunk],
        backend: crate::hw_probe::ScanBackend,
        plan: Option<&super::Phase1AdmissionPlan>,
    ) -> crate::error::Result<Vec<Vec<keyhog_core::RawMatch>>> {
        self.scan_coalesced_with_backend_admission_and_route(
            chunks,
            backend,
            plan,
            self.execution_route_for_backend(backend),
        )
    }

    /// Coalesced scan with an explicit recall-equivalent execution route.
    /// Recovery metadata is never discarded; completed recovery requires the
    /// recovery-aware boundary that returns its receipt.
    pub fn scan_coalesced_with_backend_admission_and_route(
        &self,
        chunks: &[keyhog_core::Chunk],
        backend: crate::hw_probe::ScanBackend,
        plan: Option<&super::Phase1AdmissionPlan>,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<Vec<Vec<keyhog_core::RawMatch>>> {
        self.scan_coalesced_with_backend_admission_route_and_recovery(
            chunks, backend, plan, route, false,
        )
        .and_then(|outcome| {
            if outcome.gpu_recovery_receipts != 0 {
                return Err(crate::error::ScanError::Gpu(format!(
                    "{} GPU recovery receipt(s) were emitted by this dispatch; use the recovery-aware scan boundary",
                    outcome.gpu_recovery_receipts
                )));
            }
            match outcome.recovery {
                Some(receipt) if receipt.is_phase1_admission_recovery() => Err(
                    crate::error::ScanError::AdmissionPlanIdentity(receipt.reason),
                ),
                Some(receipt) => Err(crate::error::ScanError::Config(format!(
                    "recovery-aware dispatch returned an unexpected {} -> {} receipt: {}",
                    receipt.failed_backend.label(),
                    receipt.recovery_backend.label(),
                    receipt.reason,
                ))),
                None => Ok(outcome.matches),
            }
        })
    }

    /// Dispatch that returns an exact recovery receipt when untrusted admission
    /// evidence must be recomputed, and may recover exact failed GPU dispatch
    /// ranges when the caller owns a stable input snapshot.
    pub fn scan_coalesced_with_backend_admission_route_and_recovery(
        &self,
        chunks: &[keyhog_core::Chunk],
        backend: crate::hw_probe::ScanBackend,
        plan: Option<&super::Phase1AdmissionPlan>,
        route: crate::ScanExecutionRoute,
        #[cfg(feature = "gpu")] recover_gpu_dispatch_faults: bool,
        #[cfg(not(feature = "gpu"))] _recover_gpu_dispatch_faults: bool,
    ) -> crate::error::Result<super::CoalescedScanOutcome> {
        if let Some(materialized) = self.selected_backend() {
            if materialized != backend {
                return Err(crate::error::ScanError::BackendPlanMismatch {
                    materialized: materialized.label(),
                    requested: backend.label(),
                });
            }
        }
        let expected_residual_backend = if backend.is_gpu() {
            crate::hw_probe::ScanBackend::CpuFallback
        } else {
            backend
        };
        if route.decode_backend != expected_residual_backend {
            return Err(crate::error::ScanError::Config(format!(
                "{} route declares {} residual execution, expected {}. Rebuild the execution route from the selected backend",
                backend.label(),
                route.decode_backend.label(),
                expected_residual_backend.label(),
            )));
        }
        if !chunks.is_empty() {
            self.prepare_anchor_batch(route);
        }
        let (validated_plan, admission_recovery) = if backend.is_gpu() {
            // GPU region-presence dispatch owns trigger admission and does not
            // consume the CPU/SIMD admission plan.
            (None, None)
        } else {
            match plan {
                Some(plan) => match plan.validate_chunks(chunks) {
                    Ok(()) => (Some(plan), None),
                    Err(error) => (
                        None,
                        Some(super::BackendRecoveryReceipt::phase1_admission(
                            backend, chunks, error,
                        )),
                    ),
                },
                None => (None, None),
            }
        };
        let (result, gpu_recovery_receipts) = crate::gpu::with_recovery_receipt_scope(|| {
            let result = if backend == crate::hw_probe::ScanBackend::SimdCpu {
                self.try_initialize_simd_backend().map_err(|error| {
                    crate::error::ScanError::Simd(format!(
                        "selected Hyperscan backend initialization failed: {error}"
                    ))
                })?;
                Ok(super::CoalescedScanOutcome {
                    matches: self.scan_coalesced_simd(chunks, validated_plan, route)?,
                    recovery: None,
                    gpu_recovery_receipts: 0,
                })
            } else if backend.is_gpu() {
                #[cfg(feature = "gpu")]
                {
                    self.scan_coalesced_gpu_region_presence_recovering(
                        chunks,
                        backend,
                        route,
                        recover_gpu_dispatch_faults,
                        None,
                    )
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
                Ok(super::CoalescedScanOutcome {
                    matches: self.scan_chunks_with_backend_internal_admission_and_route(
                        chunks,
                        backend,
                        validated_plan,
                        route,
                    )?,
                    recovery: None,
                    gpu_recovery_receipts: 0,
                })
            };
            result
        });
        let result = result.and_then(|mut outcome| {
            if admission_recovery.is_some() && outcome.recovery.is_some() {
                return Err(crate::error::ScanError::Config(
                    "admission-plan recovery and backend recovery completed in one dispatch, but the status model cannot represent both receipts"
                        .to_string(),
                ));
            }
            if admission_recovery.is_some() {
                outcome.recovery = admission_recovery;
            }
            Ok(outcome)
        });
        let result = result.map(|mut outcome| {
            outcome.gpu_recovery_receipts = gpu_recovery_receipts;
            outcome
        });
        // Count logical input only after a complete route succeeds. A failed GPU
        // attempt followed by visible CPU replay therefore records the input
        // once, while every successful coalesced backend reports the same bytes.
        if result.is_ok() {
            profile::add_bytes(chunks.iter().map(|chunk| chunk.data.len() as u64).sum());
        }
        result
    }

    #[cfg(feature = "gpu")]
    pub fn scan_coalesced_on_ordered_gpu_device(
        &self,
        chunks: &[keyhog_core::Chunk],
        backend: crate::hw_probe::ScanBackend,
        route: &crate::gpu::device_set::OrderedGpuDeviceRoute,
        acquired: &crate::gpu::AcquiredGpuDeviceSet,
        device_index: usize,
        execution_route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<Vec<Vec<keyhog_core::RawMatch>>> {
        route.validate().map_err(crate::error::ScanError::Config)?;
        let device = route.devices.get(device_index).ok_or_else(|| {
            crate::error::ScanError::Config(format!(
                "ordered GPU calibration names missing device {device_index}"
            ))
        })?;
        if device.api.scan_backend() != backend {
            return Err(crate::error::ScanError::Config(format!(
                "ordered GPU calibration device {device_index} does not use {}",
                backend.label()
            )));
        }
        if acquired.device_set_identity_digest() != route.device_set_identity_digest()
            || acquired.len() != route.devices.len()
        {
            return Err(crate::error::ScanError::Gpu(
                "acquired GPU device set does not match the authenticated calibration route"
                    .to_string(),
            ));
        }
        let device_backend = acquired.backend(device_index).ok_or_else(|| {
            crate::error::ScanError::Gpu(format!(
                "ordered GPU acquisition is missing device {device_index}"
            ))
        })?;
        let resident_slot = acquired.resident_literal(device_index).ok_or_else(|| {
            crate::error::ScanError::Gpu(format!(
                "ordered GPU acquisition is missing resident slot {device_index}"
            ))
        })?;
        let resident_timed_dispatch_supported = acquired
            .resident_timed_dispatch_supported(device_index)
            .ok_or_else(|| {
                crate::error::ScanError::Gpu(format!(
                    "ordered GPU acquisition is missing capability evidence for device {device_index}"
                ))
            })?;
        self.prepare_anchor_batch(execution_route);
        let (outcome, recovery_receipts) = crate::gpu::with_recovery_receipt_scope(|| {
            self.scan_coalesced_gpu_region_presence_recovering(
                chunks,
                backend,
                execution_route,
                false,
                Some((
                    device_backend,
                    resident_slot,
                    device.resident_budget_bytes,
                    resident_timed_dispatch_supported,
                )),
            )
        });
        let outcome = outcome.map_err(|error| crate::error::ScanError::Gpu(error.to_string()))?;
        if outcome.recovery.is_some()
            || outcome.gpu_recovery_receipts != 0
            || recovery_receipts != 0
        {
            return Err(crate::error::ScanError::Gpu(format!(
                "ordered GPU calibration device {device_index} emitted a recovery receipt"
            )));
        }
        if outcome.matches.len() != chunks.len() {
            return Err(crate::error::ScanError::Gpu(format!(
                "ordered GPU calibration device {device_index} returned {} chunk result(s), expected {}",
                outcome.matches.len(),
                chunks.len()
            )));
        }
        Ok(outcome.matches)
    }

    #[cfg(feature = "gpu")]
    pub fn scan_coalesced_with_ordered_gpu_device_route(
        &self,
        chunks: &[keyhog_core::Chunk],
        backend: crate::hw_probe::ScanBackend,
        route: &crate::gpu::device_set::OrderedGpuDeviceRoute,
        acquired: &crate::gpu::AcquiredGpuDeviceSet,
        execution_route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<Vec<Vec<keyhog_core::RawMatch>>> {
        route.validate().map_err(crate::error::ScanError::Config)?;
        if route.devices.len() < 2 {
            return Err(crate::error::ScanError::Config(
                "ordered multi-device scan requires at least two authenticated devices".to_string(),
            ));
        }
        if route
            .devices
            .iter()
            .any(|device| device.api.scan_backend() != backend)
        {
            return Err(crate::error::ScanError::Config(format!(
                "ordered device set does not use {} on every device",
                backend.label()
            )));
        }
        if acquired.device_set_identity_digest() != route.device_set_identity_digest()
            || acquired.len() != route.devices.len()
        {
            return Err(crate::error::ScanError::Gpu(
                "acquired GPU device set does not match the authenticated route".to_string(),
            ));
        }
        if !backend.is_gpu() || execution_route.decode_backend != crate::ScanBackend::CpuFallback {
            return Err(crate::error::ScanError::Config(
                "ordered GPU device-set scan requires a GPU route with scalar residual execution"
                    .to_string(),
            ));
        }
        if let Some(materialized) = self.selected_backend() {
            if materialized != backend {
                return Err(crate::error::ScanError::BackendPlanMismatch {
                    materialized: materialized.label(),
                    requested: backend.label(),
                });
            }
        }
        if chunks.is_empty() {
            return Ok(Vec::new());
        }
        let _dispatch_guard = acquired
            .lock_complete_dispatch()
            .map_err(crate::error::ScanError::Gpu)?;
        self.prepare_anchor_batch(execution_route);

        let shards = chunks
            .iter()
            .enumerate()
            .map(|(index, chunk)| crate::gpu::device_set::ExactShard {
                index,
                bytes: u64::try_from(chunk.data.len()).unwrap_or(u64::MAX),
            })
            .collect::<Vec<_>>();
        let crate::gpu::device_set::WeightedShardPlan::MultiDevice(assignments) =
            crate::gpu::device_set::partition_exact_shards(route, &shards)
                .map_err(crate::error::ScanError::Config)?
        else {
            return Err(crate::error::ScanError::Config(
                "ordered multi-device route produced a single-device plan".to_string(),
            ));
        };
        if assignments.len() != chunks.len()
            || assignments
                .iter()
                .enumerate()
                .any(|(index, assignment)| assignment.shard_index != index)
        {
            return Err(crate::error::ScanError::Config(
                "ordered GPU shard plan does not cover each input chunk exactly once".to_string(),
            ));
        }

        let mut ranges = Vec::new();
        ranges
            .try_reserve_exact(route.devices.len())
            .map_err(|error| {
                crate::error::ScanError::Gpu(format!(
                    "ordered GPU device-range allocation failed: {error}"
                ))
            })?;
        let mut start = 0usize;
        while start < assignments.len() {
            let device_index = assignments[start].device_index;
            let mut end = start + 1;
            while end < assignments.len() && assignments[end].device_index == device_index {
                end += 1;
            }
            if ranges
                .last()
                .is_some_and(|(prior_device, _, _)| *prior_device >= device_index)
            {
                return Err(crate::error::ScanError::Config(
                    "ordered GPU shard plan assigned non-contiguous device ranges".to_string(),
                ));
            }
            ranges.push((device_index, start, end));
            start = end;
        }

        let telemetry = crate::telemetry::capture_scan_telemetry();
        let matches = std::thread::scope(|scope| {
            let mut handles = Vec::new();
            handles.try_reserve_exact(ranges.len()).map_err(|error| {
                crate::error::ScanError::Gpu(format!(
                    "ordered GPU worker allocation failed: {error}"
                ))
            })?;
            for &(device_index, start, end) in &ranges {
                let device = route.devices.get(device_index).ok_or_else(|| {
                    crate::error::ScanError::Config(format!(
                        "ordered GPU shard plan names missing device {device_index}"
                    ))
                })?;
                let device_backend = acquired.backend(device_index).ok_or_else(|| {
                    crate::error::ScanError::Gpu(format!(
                        "ordered GPU acquisition is missing device {device_index}"
                    ))
                })?;
                let resident_slot = acquired.resident_literal(device_index).ok_or_else(|| {
                    crate::error::ScanError::Gpu(format!(
                        "ordered GPU acquisition is missing resident slot {device_index}"
                    ))
                })?;
                let resident_timed_dispatch_supported = acquired
                    .resident_timed_dispatch_supported(device_index)
                    .ok_or_else(|| {
                        crate::error::ScanError::Gpu(format!(
                            "ordered GPU acquisition is missing capability evidence for device {device_index}"
                        ))
                    })?;
                let chunk_range = &chunks[start..end];
                let telemetry = telemetry.clone();
                let handle = std::thread::Builder::new()
                    .spawn_scoped(scope, move || {
                        crate::telemetry::with_captured_scan_telemetry(
                            telemetry.as_ref(),
                            || {
                                let (outcome, recovery_receipts) =
                                    crate::gpu::with_recovery_receipt_scope(|| {
                                        self.scan_coalesced_gpu_region_presence_recovering(
                                            chunk_range,
                                            backend,
                                            execution_route,
                                            false,
                                            Some((
                                                device_backend,
                                                resident_slot,
                                                device.resident_budget_bytes,
                                                resident_timed_dispatch_supported,
                                            )),
                                        )
                                    });
                                outcome
                                    .map_err(|error| error.to_string())
                                    .and_then(|outcome| {
                                        if outcome.recovery.is_some()
                                            || outcome.gpu_recovery_receipts != 0
                                            || recovery_receipts != 0
                                        {
                                            return Err(
                                                "ordered GPU device emitted a recovery receipt"
                                                    .to_string(),
                                            );
                                        }
                                        if outcome.matches.len() != chunk_range.len() {
                                            return Err(format!(
                                                "ordered GPU device returned {} chunk result(s), expected {}",
                                                outcome.matches.len(),
                                                chunk_range.len()
                                            ));
                                        }
                                        Ok(outcome.matches)
                                    })
                            },
                        )
                    })
                    .map_err(|error| {
                        crate::error::ScanError::Gpu(format!(
                            "ordered GPU device {device_index} worker creation failed: {error}"
                        ))
                    })?;
                handles.push((device_index, start, handle));
            }

            let mut retirement = crate::gpu::device_set::DeterministicRetirement::new(chunks.len())
                .map_err(crate::error::ScanError::Gpu)?;
            for (device_index, start, handle) in handles {
                match handle.join() {
                    Ok(Ok(device_matches)) => {
                        for (offset, matches) in device_matches.into_iter().enumerate() {
                            if let Err(error) = retirement.record_success(start + offset, matches) {
                                retirement.record_failure(device_index, "retire", &error);
                                break;
                            }
                        }
                    }
                    Ok(Err(error)) => {
                        retirement.record_failure(device_index, "dispatch/retire", &error);
                    }
                    Err(panic) => {
                        let detail = crate::error::panic_payload_detail(panic);
                        retirement.record_failure(device_index, "worker", &detail);
                    }
                }
            }
            retirement.finish().map_err(crate::error::ScanError::Gpu)
        })?;
        profile::add_bytes(chunks.iter().map(|chunk| chunk.data.len() as u64).sum());
        Ok(matches)
    }

    /// Deterministic portable reference scan over several chunks.
    ///
    /// Accelerated callers use [`Self::scan_coalesced_with_backend`] with an
    /// explicit measured backend. Keeping the no-backend API on `CpuFallback`
    /// makes library results independent of host hardware and calibration state.
    pub fn scan_coalesced(
        &self,
        chunks: &[keyhog_core::Chunk],
    ) -> crate::error::Result<Vec<Vec<keyhog_core::RawMatch>>> {
        let backend = crate::hw_probe::ScanBackend::CpuFallback;
        let matches = self.scan_chunks_with_backend_internal_admission_and_route(
            chunks,
            backend,
            None,
            self.execution_route_for_backend(backend),
        )?;
        profile::add_bytes(chunks.iter().map(|chunk| chunk.data.len() as u64).sum());
        Ok(matches)
    }

    /// Explicit Hyperscan coalesced path: all files scanned in parallel, zero
    /// overhead for non-hit files. Only reached for `ScanBackend::SimdCpu`.
    #[allow(clippy::needless_return)] // return needed under non-simd cfg branch
    fn scan_coalesced_simd(
        &self,
        chunks: &[keyhog_core::Chunk],
        admission_plan: Option<&super::Phase1AdmissionPlan>,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<Vec<Vec<keyhog_core::RawMatch>>> {
        #[cfg(not(feature = "simd"))]
        {
            // LAW10: no-runtime-effect; this cfg-only binding precedes a fail-closed unsupported-backend error.
            let _ = (chunks, admission_plan, route);
            return Err(crate::error::ScanError::Simd(
                "selected SimdCpu/Hyperscan backend but this binary was built without the `simd` feature; rebuild with simd or choose --backend cpu".to_string(),
            ));
        }

        #[cfg(feature = "simd")]
        {
            let prefilter = self.try_simd_prefilter().map_err(|error| {
                crate::error::ScanError::Simd(format!(
                    "selected Hyperscan backend was not initialized: {error}"
                ))
            })?;

            // Coalesced SIMD bypasses `scan_inner`, so it owns the same scanner
            // telemetry events. Logical profiler input is recorded once by the
            // shared successful coalesced-dispatch boundary above.
            //
            // `record_decode_size_decline` MUST stay paired with
            // `record_file_scanned` here and at every other site. It was
            // originally only in `scan_inner`, which made the decode-oversize
            // coverage gap BACKEND-DEPENDENT: on `crates/` the cpu-fallback
            // route reported one declined chunk and the coalesced SIMD route
            // reported none, for byte-identical findings. The gap is a property
            // of the chunk and the configured cap, never of the route that
            // scanned it, so an operator must not lose the warning by having
            // autoroute pick a different backend.
            for chunk in chunks {
                crate::telemetry::record_file_scanned(chunk.data.len());
                self.record_decode_size_decline(chunk);
            }
            let triggers = {
                let _g = profile::span(keyhog_profile::Stage::Phase1Triggers);
                self.compute_coalesced_triggers(chunks, prefilter, admission_plan)
                    .map_err(crate::error::ScanError::Simd)?
            };
            return self.scan_coalesced_phase2_with_admission(
                chunks,
                triggers,
                None,
                None,
                None,
                0,
                None,
                None,
                None,
                None,
                None,
                None,
                admission_plan,
                crate::hw_probe::ScanBackend::SimdCpu,
                route,
            );
        }
    }

    #[cfg(feature = "simd")]
    fn compute_one_coalesced_simd_trigger(
        &self,
        data: &[u8],
        prefilter: &super::SimdPhase1Prefilter,
        ac_len: usize,
    ) -> Result<Option<Vec<u64>>, String> {
        #[cfg(debug_assertions)]
        self.phase1_trigger_scanned_bytes.fetch_add(
            // LAW10: debug accounting saturates on impossible usize-to-u64 overflow; scan behavior is unchanged.
            u64::try_from(data.len()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        super::trigger_bitmap::with_scratch(ac_len, |scratch| {
            let scanner = prefilter.scanner();
            scanner.scan_each_result(data, |hs_id| {
                mark_hs_trigger(scratch, prefilter, ac_len, hs_id);
            })?;
            prefilter.for_each_recovery_match(data, |pattern_index| {
                self.mark_triggered_pattern(scratch, pattern_index);
            });
            if scratch.iter().any(|&word| word != 0) {
                Ok(Some(scratch.to_vec()))
            } else {
                Ok(None)
            }
        })
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
    ) -> Result<Vec<Option<Vec<u64>>>, String> {
        let ac_len = self.ac_map.len();
        let words_needed = super::trigger_bitmap::words_for(ac_len);
        let profile_runtime = keyhog_profile::current_runtime();
        let reusable_triggers = admission_plan.map(|plan| {
            (0..plan.payload_evidence_row_count())
                .map(|_| std::sync::OnceLock::new())
                .collect::<Vec<std::sync::OnceLock<Result<Option<std::sync::Arc<[u64]>>, String>>>>(
                )
        });
        let representative_indices = admission_plan.map(|plan| {
            let mut representatives = vec![None; plan.payload_evidence_row_count()];
            for chunk_index in 0..chunks.len() {
                if plan.admission_for(chunk_index) != Some(super::Phase1Admission::Admitted) {
                    continue;
                }
                let Some(row) = plan.payload_evidence_row_for(chunk_index) else {
                    continue;
                };
                if let Some(representative) = representatives.get_mut(row) {
                    representative.get_or_insert(chunk_index);
                }
            }
            representatives
        });
        if let (Some(rows), Some(representatives)) =
            (reusable_triggers.as_ref(), representative_indices.as_ref())
        {
            let mut cache = self.reusable_simd_triggers.lock();
            for (row, representative) in representatives.iter().enumerate() {
                let Some(chunk_index) = *representative else {
                    continue;
                };
                if let Some(cached) = cache.get(&chunks[chunk_index].data) {
                    let _ = rows[row].set(Ok(cached));
                }
            }
        }
        let is_representative = |chunk_index: usize| {
            admission_plan
                .and_then(|plan| plan.payload_evidence_row_for(chunk_index))
                .and_then(|row| {
                    representative_indices
                        .as_ref()
                        .and_then(|representatives| representatives.get(row))
                        .copied()
                        .flatten()
                })
                .is_none_or(|representative| representative == chunk_index)
        };
        let compute_single_trigger = |chunk_index: usize, chunk: &keyhog_core::Chunk| {
            let _profile_context = profile_runtime.as_ref().map(keyhog_profile::Runtime::enter);
            let data = chunk.data.as_bytes();
            let admission = match admission_plan.and_then(|plan| plan.admission_for(chunk_index)) {
                Some(admission) => admission,
                None => self.phase1_admission(data),
            };
            if admission != super::Phase1Admission::Admitted {
                return Ok(None);
            }
            let reusable =
                admission_plan
                    .zip(reusable_triggers.as_ref())
                    .and_then(|(plan, rows)| {
                        let row = plan.payload_evidence_row_for(chunk_index)?;
                        rows.get(row)
                    });
            if let Some(reusable) = reusable {
                return reusable
                    .get_or_init(|| {
                        self.reusable_simd_triggers
                            .lock()
                            .get_or_compute(&chunk.data, || {
                                self.compute_one_coalesced_simd_trigger(data, prefilter, ac_len)
                            })
                    })
                    .as_ref()
                    .map(|triggers| triggers.as_ref().map(|row| row.as_ref().to_vec()))
                    .map_err(Clone::clone);
            }
            self.compute_one_coalesced_simd_trigger(data, prefilter, ac_len)
        };

        let threshold = self.tuning.chunk_lane_threshold();
        let workers = keyhog_profile::logical_cpus() as usize;

        let triggers =
            if chunks.len() <= workers || chunks.iter().all(|chunk| chunk.data.len() > threshold) {
                chunks
                    .iter()
                    .enumerate()
                    .map(|(chunk_index, chunk)| compute_single_trigger(chunk_index, chunk))
                    .collect::<Result<Vec<_>, String>>()?
            } else {
                let work_lanes = super::batch_topology::coalesced_work_lanes(chunks, threshold);
                let lane_triggers: Vec<Vec<(usize, Option<Vec<u64>>)>> = work_lanes
                    .lanes()
                    .iter()
                    .map(|lane| match lane {
                        super::batch_topology::CoalescedLane::Large(index) => {
                            if is_representative(*index) {
                                Ok(vec![(
                                    *index,
                                    compute_single_trigger(*index, &chunks[*index])?,
                                )])
                            } else {
                                Ok(vec![(*index, None)])
                            }
                        }
                        super::batch_topology::CoalescedLane::Small(_) => {
                            let indices = work_lanes.indices(lane);
                            let _profile_context =
                                profile_runtime.as_ref().map(keyhog_profile::Runtime::enter);
                            if admission_plan.is_some() {
                                return indices
                                    .iter()
                                    .map(|&index| {
                                        let trigger = if is_representative(index) {
                                            compute_single_trigger(index, &chunks[index])?
                                        } else {
                                            None
                                        };
                                        Ok((index, trigger))
                                    })
                                    .collect::<Result<Vec<_>, String>>();
                            }
                            let admitted = |index: usize, data: &[u8]| {
                                admission_plan
                                    .and_then(|plan| plan.admission_for(index))
                                    .unwrap_or_else(|| self.phase1_admission(data))
                                    == super::Phase1Admission::Admitted
                            };
                            let mut lane_triggers = vec![None; indices.len()];
                            let should_compute = |index: usize, data: &[u8]| {
                                if !admitted(index, data) || !is_representative(index) {
                                    return false;
                                }
                                admission_plan
                                    .zip(reusable_triggers.as_ref())
                                    .and_then(|(plan, rows)| {
                                        let row = plan.payload_evidence_row_for(index)?;
                                        rows.get(row)
                                    })
                                    .is_none_or(|reusable| reusable.get().is_none())
                            };
                            #[cfg(debug_assertions)]
                            {
                                let scanned_bytes = indices
                                    .iter()
                                    .filter_map(|&index| {
                                        let data = chunks[index].data.as_bytes();
                                        should_compute(index, data).then_some(data.len())
                                    })
                                    .fold(0usize, usize::saturating_add);
                                self.phase1_trigger_scanned_bytes.fetch_add(
                                    u64::try_from(scanned_bytes).unwrap_or(u64::MAX),
                                    std::sync::atomic::Ordering::Relaxed,
                                );
                            }
                            prefilter.scanner().scan_many_each_result(
                                indices
                                    .iter()
                                    .enumerate()
                                    .filter_map(|(lane_offset, &index)| {
                                        let data = chunks[index].data.as_bytes();
                                        should_compute(index, data).then_some((lane_offset, data))
                                    }),
                                |lane_offset, hs_id| {
                                    let scratch = lane_triggers[lane_offset]
                                        .get_or_insert_with(|| vec![0u64; words_needed]);
                                    mark_hs_trigger(scratch, prefilter, ac_len, hs_id);
                                },
                            )?;
                            for (lane_offset, &index) in indices.iter().enumerate() {
                                let data = chunks[index].data.as_bytes();
                                if should_compute(index, data) {
                                    prefilter.for_each_recovery_match(data, |pattern_index| {
                                        let scratch = lane_triggers[lane_offset]
                                            .get_or_insert_with(|| vec![0u64; words_needed]);
                                        self.mark_triggered_pattern(scratch, pattern_index);
                                    });
                                }
                            }
                            Ok(indices.iter().copied().zip(lane_triggers).collect())
                        }
                    })
                    .collect::<Result<Vec<_>, String>>()?;

                let mut combined = vec![None; chunks.len()];
                for lane in lane_triggers {
                    for (index, trigger) in lane {
                        combined[index] = trigger;
                    }
                }
                if let (Some(plan), Some(rows)) = (admission_plan, reusable_triggers.as_ref()) {
                    for (index, trigger) in combined.iter_mut().enumerate() {
                        if plan.admission_for(index) != Some(super::Phase1Admission::Admitted) {
                            continue;
                        }
                        let Some(row) = plan.payload_evidence_row_for(index) else {
                            continue;
                        };
                        let cached = rows
                            .get(row)
                            .and_then(std::sync::OnceLock::get)
                            .ok_or_else(|| {
                                format!("missing reusable SIMD trigger row {row} for chunk {index}")
                            })?;
                        *trigger = cached.clone()?.map(|row| row.as_ref().to_vec());
                    }
                }
                combined
            };

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
        Ok(triggers)
    }

    /// No-hit chunk admission: should a chunk that produced no phase-1 trigger
    /// still be driven through the phase-2 / generic / entropy tail?
    pub(crate) fn should_scan_no_hit_chunk(
        &self,
        chunk: &keyhog_core::Chunk,
        route: crate::ScanExecutionRoute,
    ) -> bool {
        self.should_scan_no_hit_chunk_with_phase2_absence_proof(chunk, false, route)
    }

    fn should_scan_no_hit_chunk_with_phase2_absence_proof(
        &self,
        chunk: &keyhog_core::Chunk,
        raw_phase2_absence_proven: bool,
        route: crate::ScanExecutionRoute,
    ) -> bool {
        let raw_text = chunk.data.as_ref();
        if self.no_hit_text_admits(chunk, raw_text, raw_phase2_absence_proven, route) {
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
        let normalized_triggers = self.collect_triggered_patterns_cpu(normalized);
        normalized_triggers.iter().any(|&word| word != 0)
            || self.no_hit_text_admits(chunk, normalized, false, route)
    }

    fn no_hit_text_admits(
        &self,
        _chunk: &keyhog_core::Chunk,
        text: &str,
        phase2_absence_proven: bool,
        route: crate::ScanExecutionRoute,
    ) -> bool {
        if !phase2_absence_proven && self.has_active_phase2_patterns_for_chunk(text, route) {
            return true;
        }
        let data = text.as_bytes();
        let keyword_admits = self
            .detector_plans
            .generic_assignment()
            .is_some_and(|plan| plan.stems().is_match(data))
            || has_secret_keyword_fast(data);
        if keyword_admits {
            return true;
        }
        #[cfg(feature = "entropy")]
        let isolated_bare_owner_index = self
            .detector_plans
            .generic_ownership()
            .isolated_bare_owner_index();
        #[cfg(feature = "entropy")]
        let isolated_bare_policy = isolated_bare_owner_index
            .and_then(|index| self.detector_plans.entropy(index))
            .copied();
        #[cfg(feature = "entropy")]
        let keyword_free_min_len = self
            .detector_plans
            .generic_ownership()
            .keyword_free_owner_index()
            .and_then(|index| self.detector_plans.entropy(index))
            .and_then(|policy| {
                let sensitive_path = _chunk
                    .metadata
                    .path
                    .as_deref()
                    .is_some_and(crate::confidence::is_sensitive_path);
                policy.keyword_free_admission_run_min_len(
                    self.config.entropy_threshold,
                    sensitive_path,
                )
            });
        #[cfg(feature = "multiline")]
        if crate::multiline::has_concatenation_indicators(text) {
            #[cfg(feature = "entropy")]
            if let Some(policy) = isolated_bare_policy.filter(|_| self.config.entropy_enabled) {
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
        let entropy_admits = self.config.entropy_enabled
            && ((keyword_free_min_len
                .is_some_and(|minimum| has_high_entropy_run_at_least(data, minimum))
                && crate::entropy::is_entropy_appropriate_with_content(
                    _chunk.metadata.path.as_deref(),
                    self.config.entropy_in_source_files,
                    text,
                    &self.config.secret_keywords,
                ))
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
            entropy_admits
        }
        #[cfg(not(feature = "entropy"))]
        {
            false
        }
    }

    #[cfg(any(feature = "simd", feature = "gpu", test))]
    fn normalize_coalesced_phase2_triggers(
        &self,
        chunks: &[keyhog_core::Chunk],
        triggers: Vec<Option<Vec<u64>>>,
        _route: crate::ScanExecutionRoute,
    ) -> Vec<Option<Vec<u64>>> {
        let chunk_count = chunks.len();
        let trigger_count = triggers.len();
        if trigger_count == chunk_count {
            return triggers;
        }

        // KH-1431: cardinality mismatch used to warn-and-truncate/pad. Truncation
        // can drop trigger rows (recall loss). Fail closed: recompute every row
        // from chunk bytes so no trigger is silently discarded, and surface on
        // stderr so the operator sees the invariant break without RUST_LOG.
        eprintln!(
            "keyhog: ERROR coalesced phase-2 trigger row count mismatch \
             (chunks={chunk_count}, trigger_rows={trigger_count}); recomputing \
             all trigger rows from chunk bytes (KH-1431)"
        );
        tracing::error!(
            chunks = chunk_count,
            trigger_rows = trigger_count,
            "coalesced phase-2 trigger row count mismatch; recomputing all rows (fail closed)"
        );
        crate::telemetry::record_boundary_result_cardinality_mismatch();
        drop(triggers);
        let mut recomputed = Vec::with_capacity(chunk_count);
        for chunk in chunks {
            let triggered = self.collect_triggered_patterns_cpu(&chunk.data);
            if triggered.iter().any(|&word| word != 0) {
                recomputed.push(Some(triggered));
            } else {
                recomputed.push(None);
            }
        }
        recomputed
    }

    /// Shared coalesced phase-two tail with optional GPU admission rows or an
    /// exact CPU/SIMD phase-one plan. Complete negative evidence skips redundant
    /// prefixless, generic, confirmed, entropy, multiline, and decode work while
    /// triggered rows, normalization, ML, recovery, and path-sensitive handling
    /// remain under their canonical owners.
    #[cfg(any(feature = "simd", feature = "gpu", test))]
    pub(crate) fn scan_coalesced_phase2_with_admission(
        &self,
        chunks: &[keyhog_core::Chunk],
        triggers: Vec<Option<Vec<u64>>>,
        phase2_admission: Option<&[bool]>,
        phase2_admission_complete: Option<&[bool]>,
        phase2_candidate_bits: Option<&[u32]>,
        phase2_candidate_words_per_region: usize,
        phase2_candidate_map: Option<&[u32]>,
        phase2_keyword_hints: Option<&[Vec<u32>]>,
        phase2_always_anchor_presence: Option<&[bool]>,
        phase2_always_anchor_literal_matches: Option<&[Vec<(u32, u32)>]>,
        confirmed_anchor_literal_matches: Option<&[Vec<(u32, u32)>]>,
        generic_keyword_positions: Option<&[Vec<u32>]>,
        phase1_plan: Option<&super::Phase1AdmissionPlan>,
        backend: crate::hw_probe::ScanBackend,
        route: crate::ScanExecutionRoute,
    ) -> crate::error::Result<Vec<Vec<keyhog_core::RawMatch>>> {
        let triggers = self.normalize_coalesced_phase2_triggers(chunks, triggers, route);
        // No stopwatch here. The phase-2 region below is the profiler's phase-2
        // leaves, and the seam rescan that follows is `Stage::BoundaryScan`,
        // opened inside `boundary::scan_chunk_boundaries_with_route`. Two
        // private `Instant`s used to time both and print a `perf-trace
        // scan_coalesced_phase2` line that no other output could be reconciled
        // against.
        let telemetry = crate::telemetry::capture_scan_telemetry();
        let recovery_receipts = crate::gpu::capture_recovery_receipts();
        let profile_runtime = keyhog_profile::current_runtime();
        let entropy_config_digest = self.entropy_evidence_config_digest();
        let phase2_candidate_layout =
            phase2_candidate_bits
                .zip(phase2_candidate_map)
                .filter(|(bits, map)| {
                    phase2_candidate_words_per_region
                        .checked_mul(chunks.len())
                        .is_some_and(|expected| expected == bits.len())
                        && phase2_candidate_words_per_region
                            .checked_mul(u32::BITS as usize)
                            .is_some_and(|expected| expected == map.len())
                });
        struct CoalescedChunkOutput {
            state: Option<crate::types::ScanState>,
            matches: Vec<keyhog_core::RawMatch>,
            needs_postprocess: bool,
        }

        let mut outputs: Vec<CoalescedChunkOutput> = chunks
            .iter()
            .zip(triggers.into_iter())
            .enumerate()
            .map(|(chunk_index, (chunk, triggered_opt))| {
                let _profile_context = profile_runtime.as_ref().map(keyhog_profile::Runtime::enter);
                crate::gpu::with_captured_recovery_receipts(recovery_receipts.as_ref(), || {
                    crate::telemetry::with_captured_scan_telemetry(telemetry.as_ref(), || {
                        let keyword_hints = phase1_plan
                            .and_then(|plan| plan.phase2_keyword_hints_for(chunk_index))
                            .or_else(|| {
                                phase2_keyword_hints
                                    .and_then(|rows| rows.get(chunk_index))
                                    .map(Vec::as_slice)
                            });
                        let always_anchor_present = phase2_always_anchor_presence
                            .and_then(|rows| rows.get(chunk_index).copied());
                        let always_anchor_literal_matches = phase2_always_anchor_literal_matches
                            .and_then(|rows| rows.get(chunk_index))
                            .map(Vec::as_slice);
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
                        let phase2_candidate_row =
                            phase2_candidate_layout.and_then(|(bits, map)| {
                                let start =
                                    chunk_index.checked_mul(phase2_candidate_words_per_region)?;
                                let end = start.checked_add(phase2_candidate_words_per_region)?;
                                bits.get(start..end).map(|row| (row, map))
                            });
                        let phase2_gpu_complete =
                            phase2_gpu_complete && phase2_candidate_row.is_some();
                        let phase2_always_active_gpu_evidence = phase1_plan
                            .and_then(|plan| plan.phase2_always_active_absence_for(chunk_index))
                            .and_then(|absence| {
                                absence.then_some(Phase2AlwaysActiveGpuEvidence::exact_absence())
                            })
                            .or_else(|| {
                                always_anchor_present.map(|anchor_present| {
                                    Phase2AlwaysActiveGpuEvidence {
                                        prefixless_admitted: admitted_by_phase2_gpu,
                                        prefixless_complete: phase2_gpu_complete,
                                        prefixless_candidate_bits: phase2_candidate_row
                                            .map(|(bits, _)| bits),
                                        prefixless_candidate_map: phase2_candidate_row
                                            .map(|(_, map)| map),
                                        anchor_present,
                                        anchor_literal_matches: always_anchor_literal_matches,
                                    }
                                })
                            });
                        let confirmed_anchor_matches = confirmed_anchor_literal_matches
                            .and_then(|rows| rows.get(chunk_index))
                            .map(Vec::as_slice);
                        let generic_keyword_positions = phase1_plan
                            .and_then(|plan| plan.generic_keyword_positions_for(chunk_index))
                            .or_else(|| {
                                generic_keyword_positions
                                    .and_then(|rows| rows.get(chunk_index))
                                    .map(Vec::as_slice)
                            });
                        let normalization_passthrough = phase1_plan
                            .and_then(|plan| {
                                plan.normalization_passthrough_for(
                                    chunk_index,
                                    self.config.unicode_normalization,
                                )
                            })
                            // LAW10: missing passthrough evidence runs normalization instead of skipping it.
                            .unwrap_or(false);
                        let multiline_absence = normalization_passthrough
                            && phase1_plan
                                .and_then(|plan| {
                                    plan.multiline_absence_for(chunk_index, entropy_config_digest)
                                })
                                // LAW10: missing multiline-absence evidence runs multiline admission in full.
                                .unwrap_or(false);
                        let line_context_index = normalization_passthrough
                            .then(|| {
                                phase1_plan
                                    .and_then(|plan| plan.line_context_index_for(chunk_index))
                            })
                            .flatten();
                        let simd_phase2_tail_absence = phase1_plan
                            .and_then(|plan| {
                                plan.simd_phase2_tail_absence_for(
                                    chunk_index,
                                    self.config.unicode_normalization,
                                    entropy_config_digest,
                                    self.decoder_admission_context_key(chunk),
                                )
                            })
                            // LAW10: missing complete tail-absence evidence keeps SIMD phase-two work enabled.
                            .unwrap_or(false)
                            && crate::structured::preprocessing_is_impossible_for_path(
                                chunk.metadata.path.as_deref(),
                            );
                        if simd_phase2_tail_absence {
                            #[cfg(debug_assertions)]
                            self.simd_phase2_tail_absence_skipped_bytes.fetch_add(
                                // LAW10: debug accounting saturates on impossible usize-to-u64 overflow; scan behavior is unchanged.
                                u64::try_from(chunk.data.len()).unwrap_or(u64::MAX),
                                std::sync::atomic::Ordering::Relaxed,
                            );
                        }
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
                                    backend,
                                    route,
                                )?;
                                return Ok(CoalescedChunkOutput {
                                    state: None,
                                    matches,
                                    needs_postprocess: true,
                                });
                            } else {
                                let prepared = self.prepare_chunk_with_normalization_passthrough(
                                    chunk,
                                    normalization_passthrough,
                                    multiline_absence,
                                    line_context_index,
                                );
                                let state = self.scan_prepared_state_with_triggered(
                                    prepared,
                                    &triggered,
                                    None,
                                    // Plan absence is scalar-trigger evidence. SIMD-triggered rows
                                    // must execute confirmation for their producer's candidate set.
                                    false,
                                    phase1_plan
                                        .and_then(|plan| {
                                            plan.entropy_absence_for(
                                                chunk_index,
                                                entropy_config_digest,
                                            )
                                        })
                                        // LAW10: missing entropy absence evidence keeps entropy matching enabled.
                                        .unwrap_or(false),
                                    keyword_hints,
                                    phase2_always_active_gpu_evidence,
                                    confirmed_anchor_matches,
                                    generic_keyword_positions,
                                    route,
                                )?;
                                return Ok(CoalescedChunkOutput {
                                    state: Some(state),
                                    matches: Vec::new(),
                                    needs_postprocess: true,
                                });
                            }
                        }
                        if simd_phase2_tail_absence {
                            let mut matches = Vec::new();
                            self.post_process_matches_with_decoder_absence(
                                chunk,
                                &mut matches,
                                None,
                                route,
                                true,
                            )?;
                            return Ok(CoalescedChunkOutput {
                                state: None,
                                matches,
                                needs_postprocess: false,
                            });
                        }
                        let raw_phase2_absence_proven = chunk.data.is_ascii()
                            && phase2_always_active_gpu_evidence.is_some_and(|evidence| {
                                !evidence.anchor_present
                                    && self.phase2_prefixless_gpu_absence_proven(evidence)
                            })
                            && keyword_hints.is_some();
                        let admitted_by_phase2_keyword_hint =
                            keyword_hints.is_some_and(|hints| !hints.is_empty());
                        let admitted_by_phase2_always_anchor = match always_anchor_present {
                            Some(present) => present,
                            None => false,
                        };
                        let admitted_by_generic_keyword_hint = generic_keyword_positions
                            .is_some_and(|positions| !positions.is_empty());
                        // An absent positioned row is not evidence that the active
                        // detector corpus has no generic assignment keyword. When
                        // a producer cannot supply the compiled plan's positioned
                        // rows, run the shared stem prefilter instead of composing
                        // that gap with unrelated complete phase-2 absence.
                        let generic_assignment_absence_proven =
                            self.detector_plans.generic_assignment().is_none()
                                || generic_keyword_positions.is_some();
                        if !admitted_by_phase2_gpu
                            && !admitted_by_phase2_keyword_hint
                            && !admitted_by_phase2_always_anchor
                            && !admitted_by_generic_keyword_hint
                            && generic_assignment_absence_proven
                            && !self.should_scan_no_hit_chunk_with_phase2_absence_proof(
                                chunk,
                                raw_phase2_absence_proven,
                                route,
                            )
                        {
                            if let Some(matches) =
                                self.decode_only_coalesced_matches(chunk, route)?
                            {
                                return Ok(CoalescedChunkOutput {
                                    state: None,
                                    matches,
                                    needs_postprocess: false,
                                });
                            }
                            return Ok(CoalescedChunkOutput {
                                state: None,
                                matches: Vec::new(),
                                needs_postprocess: false,
                            });
                        }

                        let prepared = self.prepare_chunk_with_normalization_passthrough(
                            chunk,
                            normalization_passthrough,
                            multiline_absence,
                            line_context_index,
                        );
                        let state = self.scan_prepared_state_with_triggered(
                            prepared,
                            &[],
                            None,
                            phase1_plan
                                .and_then(|plan| plan.confirmed_patterns_absence_for(chunk_index))
                                // LAW10: missing confirmed-pattern absence evidence keeps confirmed matching enabled.
                                .unwrap_or(false),
                            phase1_plan
                                .and_then(|plan| {
                                    plan.entropy_absence_for(chunk_index, entropy_config_digest)
                                })
                                // LAW10: missing entropy absence evidence keeps entropy matching enabled.
                                .unwrap_or(false),
                            keyword_hints,
                            phase2_always_active_gpu_evidence,
                            confirmed_anchor_matches,
                            generic_keyword_positions,
                            route,
                        )?;
                        Ok(CoalescedChunkOutput {
                            state: Some(state),
                            matches: Vec::new(),
                            needs_postprocess: true,
                        })
                    })
                })
            })
            .collect::<crate::error::Result<Vec<_>>>()?;

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
            let _g = profile::span(keyhog_profile::Stage::MachineLearning);
            self.apply_ml_batch_scores_across(&mut scan_states, backend)?;
            for (output_index, state) in output_indices.into_iter().zip(scan_states) {
                outputs[output_index].matches = state.into_matches(self.detector_digest);
            }
        }
        #[cfg(not(feature = "ml"))]
        for output in &mut outputs {
            if let Some(state) = output.state.take() {
                output.matches = state.into_matches(self.detector_digest);
            }
        }

        let mut results: Vec<Vec<keyhog_core::RawMatch>> = outputs
            .into_iter()
            .zip(chunks.iter())
            .map(|(mut output, chunk)| {
                let _profile_context = profile_runtime.as_ref().map(keyhog_profile::Runtime::enter);
                crate::gpu::with_captured_recovery_receipts(recovery_receipts.as_ref(), || {
                    crate::telemetry::with_captured_scan_telemetry(telemetry.as_ref(), || {
                        if output.needs_postprocess {
                            self.post_process_coalesced_matches(chunk, &mut output.matches, route)?;
                        }
                        Ok(output.matches)
                    })
                })
            })
            .collect::<crate::error::Result<Vec<_>>>()?;

        super::boundary::scan_chunk_boundaries_with_route(self, chunks, &mut results, route)?;
        Ok(results)
    }
}

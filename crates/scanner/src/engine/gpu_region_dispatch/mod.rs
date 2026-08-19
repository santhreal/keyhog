//! Live wiring of the coalesced GPU literal-region trigger path.
//!
//! Resident VYRE dispatches produce detector presence, positions, and equivalent trigger bitmaps.
//! Positions replace CPU localization; extraction, entropy, ML, suppression, deduplication,
//! recovery, and boundary scans retain one owner.
//!
//! Recall + precision: GPU presence only admits candidate detector bits and GPU
//! positions only replace equivalent CPU localization. Phase 2 still validates
//! every candidate with the real detector regex. The full CPU
//! Hyperscan trigger floor is not part of the default fast path; it is enabled
//! only for explicit parity/debug runs.

use super::gpu_region_batch::{
    for_each_region_presence_batch, for_each_region_presence_window,
    region_presence_batch_byte_limit, region_presence_batch_byte_limit_for_depth, set_trigger_bit,
    trigger_bit_is_set, validate_detector_match, validate_region_presence_request_plan,
    RegionPresenceBatchMode, MAX_REGION_PRESENCE_REQUEST_DISPATCHES,
};
#[cfg(test)]
use super::gpu_region_dispatch_helpers::record_test_window_reduction_allocation;
#[cfg(test)]
pub(super) use super::gpu_region_dispatch_helpers::{
    append_phase2_gpu_admission, reset_test_window_reduction_allocations,
    test_window_reduction_allocations,
};
use super::gpu_region_dispatch_helpers::{
    mib_per_second, scan_phase2_gpu_chunks_sharded, scan_phase2_gpu_refs_sharded,
};
#[cfg(test)]
use super::phase2_gpu_dfa::{build_phase2_gpu_admission_workload, Phase2GpuDfaAdmission};
use super::phase2_gpu_dfa::{
    build_phase2_gpu_admission_workload_filtered, expand_phase2_gpu_admission,
    validate_phase2_gpu_trigger_rows, Phase2GpuAdmissionWorkload,
};
use super::*;

impl CompiledScanner {
    pub(crate) fn phase2_gpu_dfa_catalog(
        &self,
        backend_id: Option<&'static str>,
    ) -> Option<&super::phase2_gpu_dfa::Phase2GpuDfaCatalog> {
        self.phase2_gpu_dfa.catalog(
            &self.phase2_patterns,
            &self.phase2_always_active_indices,
            backend_id,
        )
    }

    /// Coalesced GPU region-presence scan: bounded GPU dispatches produce the
    /// per-chunk trigger bitmap, then the shared coalesced phase-2 tail runs the
    /// same extraction as every backend. Dispatch failures remain structured.
    pub(crate) fn scan_coalesced_gpu_region_presence(
        &self,
        chunks: &[keyhog_core::Chunk],
        route: crate::hw_probe::ScanBackend,
        execution_route: crate::ScanExecutionRoute,
    ) -> std::result::Result<
        Vec<Vec<keyhog_core::RawMatch>>,
        super::gpu_forced::SelectedGpuDispatchError,
    > {
        self.scan_coalesced_gpu_region_presence_recovering(
            chunks,
            route,
            execution_route,
            false,
            None,
        )
        .map(|outcome| outcome.matches)
    }

    pub(crate) fn scan_coalesced_gpu_region_presence_recovering(
        &self,
        chunks: &[keyhog_core::Chunk],
        route: crate::hw_probe::ScanBackend,
        execution_route: crate::ScanExecutionRoute,
        recover_dispatch_faults: bool,
        device: Option<(
            &std::sync::Arc<dyn vyre::VyreBackend>,
            &std::sync::Mutex<crate::gpu::GpuResidentLiteralSlot>,
            u64,
            bool,
        )>,
    ) -> std::result::Result<super::CoalescedScanOutcome, super::gpu_forced::SelectedGpuDispatchError>
    {
        if chunks.is_empty() {
            return Ok(super::CoalescedScanOutcome {
                matches: Vec::new(),
                recovery: None,
                gpu_recovery_receipts: 0,
            });
        }
        let _direct_dispatch_guard = if device.is_none() {
            Some(self.direct_gpu_resident_dispatch.lock().map_err(|_| {
                super::gpu_forced::SelectedGpuDispatchError::new(
                    "direct GPU resident dispatch lock is unavailable after an internal panic",
                )
            })?)
        } else {
            None
        };

        let dispatch_failure =
            |reason: String| Err(super::gpu_forced::SelectedGpuDispatchError::new(reason));

        let kh = super::profile::diagnostic();
        let t_matcher = kh.then(std::time::Instant::now);
        let Some(matcher) = self.gpu_matcher() else {
            return dispatch_failure(
                "gpu literal matcher not built for coalesced region scan".to_string(),
            );
        };
        let matcher_s = t_matcher.map_or(std::time::Duration::ZERO, |t| t.elapsed());
        let backend = match device {
            Some((backend, _, _, _)) => backend,
            None => {
                let Some(backend) = self.gpu_backend(route) else {
                    return dispatch_failure(self.gpu_backend_unavailable_reason(route));
                };
                backend
            }
        };
        let device_resident_budget = device.map(|(_, _, budget, _)| budget);
        let resident_timed_dispatch_supported = device.map_or_else(
            || {
                self.backend_state
                    .gpu_resident_timed_dispatch_supported(route)
            },
            |(_, _, _, supported)| supported,
        );
        let pipeline_depth = execution_route.gpu_pipeline_depth;
        let dispatch_capability = if device.is_some() {
            if backend.supports_async_compute() {
                "async-submit-retire"
            } else {
                "synchronous"
            }
        } else {
            self.gpu_resident_dispatch_capability(route)
                .map_err(super::gpu_forced::SelectedGpuDispatchError::new)?
        };
        if pipeline_depth > 1 && dispatch_capability != "async-submit-retire" {
            return dispatch_failure(format!(
                "{} selected resident pipeline depth {pipeline_depth}, but its VYRE capability is {dispatch_capability}; recalibrate autoroute for this exact device/runtime",
                route.label()
            ));
        }
        let resident_submit_supported = dispatch_capability != "synchronous";
        let backend_code = crate::gpu::evidence::backend_code(backend.id());
        // Typed identity + capability evidence on the first dispatch under
        // each profile runtime; string facets ride the daemon warm identity.
        if let Some((vendor, device, is_software, name)) =
            self.backend_state.gpu_backend_adapter_identity(route)
        {
            crate::gpu::evidence::record_adapter_identity(&crate::gpu::evidence::AdapterIdentity {
                backend_code,
                vendor,
                device,
                is_software,
                // LAW10: absent optional adapter names use the selected backend's stable identifier.
                name: name.unwrap_or(backend.id()),
                driver: "",
                driver_info: "",
            });
        }
        crate::gpu::evidence::report_counter_caps_unsupported(backend_code);
        if !resident_timed_dispatch_supported {
            crate::gpu::evidence::report_capability_unsupported(
                backend_code,
                crate::gpu::evidence::capability::KERNEL_TIMESTAMPS,
            );
        }
        let resident_slot = match device {
            Some((_, resident_slot, _, _)) => resident_slot,
            None => {
                let Some(resident_slot) = self.gpu_resident_literal_slot(route) else {
                    return dispatch_failure(format!(
                        "{} has no scanner-owned resident pipeline slot",
                        route.label()
                    ));
                };
                resident_slot
            }
        };

        let words = self.ac_map.len().div_ceil(64).max(1);
        let gpu_literal_count = self.gpu_literal_count();
        let presence_words = gpu_literal_count.div_ceil(32).max(1);
        let region_source_bytes = chunks.iter().try_fold(0usize, |total, chunk| {
            total.checked_add(chunk.data.len()).ok_or_else(|| {
                super::gpu_forced::SelectedGpuDispatchError::new(
                    "GPU region-presence source-byte accounting overflows host usize".to_string(),
                )
            })
        })?;
        let t_co = kh.then(std::time::Instant::now);
        let mut dis_s = std::time::Duration::ZERO;
        let mut derive_s_total = std::time::Duration::ZERO;
        let region_dispatch_profile = super::profile::span(keyhog_profile::Stage::BackendDispatch);
        let mut triggers: Vec<Option<Vec<u64>>> = Vec::new();
        let mut phase2_keyword_hints: Vec<Vec<u32>> = Vec::new();
        let mut phase2_always_anchor_presence: Vec<bool> = Vec::new();
        let positioned_base = self.ac_map.len() + self.phase2_keyword_count;
        let phase2_always_position_end = positioned_base + self.phase2_always_anchor_literal_count;
        let confirmed_position_end =
            phase2_always_position_end + self.confirmed_anchor_literal_count;
        let generic_position_end = confirmed_position_end + self.generic_keyword_literal_count;
        let mut phase2_always_anchor_literal_matches = (self.phase2_always_anchor_literal_count
            > 0)
        .then(|| vec![Vec::<(u32, u32)>::new(); chunks.len()]);
        let mut confirmed_anchor_literal_matches = (self.confirmed_anchor_literal_count > 0)
            .then(|| vec![Vec::<(u32, u32)>::new(); chunks.len()]);
        let mut generic_keyword_positions =
            (self.generic_keyword_literal_count > 0).then(|| vec![Vec::<u32>::new(); chunks.len()]);
        triggers.try_reserve(chunks.len()).map_err(|error| {
            super::gpu_forced::SelectedGpuDispatchError::new(format!(
                "GPU region-presence trigger-row reserve failed: {error}"
            ))
        })?;
        phase2_keyword_hints
            .try_reserve(chunks.len())
            .map_err(|error| {
                super::gpu_forced::SelectedGpuDispatchError::new(format!(
                    "GPU phase-2 keyword-hint row reserve failed: {error}"
                ))
            })?;
        phase2_always_anchor_presence
            .try_reserve(chunks.len())
            .map_err(|error| {
                super::gpu_forced::SelectedGpuDispatchError::new(format!(
                    "GPU phase-2 anchor-presence row reserve failed: {error}"
                ))
            })?;
        triggers.resize_with(chunks.len(), || None);
        phase2_keyword_hints.resize_with(chunks.len(), Vec::new);
        phase2_always_anchor_presence.resize(chunks.len(), false);
        let mut gpu_presence_bits = 0usize;
        let mut logical_derive_s = std::time::Duration::ZERO;
        let mut derive_presence_row = |row_idx: usize,
                                       row: &[u32]|
         -> std::result::Result<(), String> {
            let whole_presence_words = phase2_always_position_end / 32;
            let tail_presence_bits = phase2_always_position_end % 32;
            let whole_bits = row
                .iter()
                .take(whole_presence_words)
                .map(|word| word.count_ones() as usize)
                .sum::<usize>();
            let tail_bits = if tail_presence_bits == 0 {
                0
            } else {
                row.get(whole_presence_words).map_or(0, |word| {
                    (word & ((1u32 << tail_presence_bits) - 1)).count_ones() as usize
                })
            };
            gpu_presence_bits = gpu_presence_bits
                .checked_add(whole_bits + tail_bits)
                .ok_or_else(|| {
                    "region-presence reduced bit count overflows host usize".to_string()
                })?;
            let bits = self.triggered_patterns_from_gpu_presence(row);
            let keyword_hints = self.phase2_keyword_hints_from_gpu_presence(row);
            let always_anchor_present = self.phase2_always_anchor_present_from_gpu_presence(row);
            let trigger_count = triggers.len();
            *triggers.get_mut(row_idx).ok_or_else(|| {
                format!("region-presence logical row {row_idx} exceeds {trigger_count} chunk(s)")
            })? = bits.iter().any(|&word| word != 0).then_some(bits);
            let keyword_count = phase2_keyword_hints.len();
            *phase2_keyword_hints.get_mut(row_idx).ok_or_else(|| {
                format!("GPU phase-two keyword row {row_idx} exceeds {keyword_count} chunk(s)")
            })? = keyword_hints;
            let anchor_count = phase2_always_anchor_presence.len();
            *phase2_always_anchor_presence
                .get_mut(row_idx)
                .ok_or_else(|| {
                    format!("GPU phase-two anchor row {row_idx} exceeds {anchor_count} chunk(s)")
                })? = always_anchor_present;
            Ok(())
        };
        let mut recovery_ranges = Vec::new();
        let mut gpu_dispatch_fault: Option<String> = None;
        let mut recovered_dispatches = 0usize;
        #[derive(Clone)]
        struct RegionDispatchMetadata {
            region_starts: std::sync::Arc<[u32]>,
            haystack_len: usize,
            logical_start: usize,
            rows: usize,
            logical_byte_base: usize,
        }
        let mut resident_overlap =
            crate::gpu::GpuResidentLiteralOverlap::new(pipeline_depth, presence_words)
                .map_err(super::gpu_forced::SelectedGpuDispatchError::new)?;
        let mut dispatch_presence = |haystack: &[u8],
                                     region_starts: &[u32],
                                     logical_start: usize,
                                     rows: usize,
                                     logical_byte_base: usize,
                                     flush_current: bool,
                                     consume: &mut dyn FnMut(
            usize,
            &[u32],
        )
            -> std::result::Result<(), String>| {
            let t_dis = kh.then(std::time::Instant::now);
            if let Some(limit) = device_resident_budget {
                let required = crate::gpu::gpu_resident_literal_required_device_bytes(
                    haystack.len(),
                    region_starts.len(),
                    presence_words,
                    pipeline_depth,
                )?;
                if required > limit {
                    return Err(format!(
                        "ordered GPU device requires {required} resident byte(s), above its authenticated {limit}-byte budget"
                    ));
                }
            }
            let current_metadata = RegionDispatchMetadata {
                region_starts: std::sync::Arc::from(region_starts),
                haystack_len: haystack.len(),
                logical_start,
                rows,
                logical_byte_base,
            };
            let consume = std::cell::RefCell::new(consume);
            let mut derive_s = std::time::Duration::ZERO;
            let mut consume_evidence = |metadata: RegionDispatchMetadata,
                                        presence: &[u32],
                                        literal_matches: &[vyre::scan::LiteralMatch]|
             -> std::result::Result<(), String> {
                let t_derive = kh.then(std::time::Instant::now);
                let region_starts = metadata.region_starts.as_ref();
                let expected_presence_words =
                    metadata.rows.checked_mul(presence_words).ok_or_else(|| {
                        "region-presence physical readback size overflows host usize".to_string()
                    })?;
                let logical_end = metadata
                    .logical_start
                    .checked_add(metadata.rows)
                    .ok_or_else(|| {
                        "region-presence logical row range overflows host usize".to_string()
                    })?;
                if presence.len() != expected_presence_words {
                    return Err(format!(
                            "region-presence readback for logical chunks {}..{logical_end} returned {} u32 word(s), need {expected_presence_words}",
                            metadata.logical_start,
                            presence.len()
                        ));
                }
                for (shard_row, row) in presence.chunks_exact(presence_words).enumerate() {
                    let row_idx =
                        metadata
                            .logical_start
                            .checked_add(shard_row)
                            .ok_or_else(|| {
                                "region-presence logical row index overflows host usize".to_string()
                            })?;
                    if let Some((word_idx, stray_bits)) = self.gpu_presence_stray_tail_bits(row) {
                        return Err(format!(
                                "region-presence readback row {row_idx} has out-of-range detector bit(s): word {word_idx} bits 0x{stray_bits:08x} beyond {gpu_literal_count} literal(s)"
                            ));
                    }
                    (consume.borrow_mut())(row_idx, row)?;
                }
                for literal_match in literal_matches {
                    let pattern_id = literal_match.pattern_id as usize;
                    if pattern_id >= gpu_literal_count {
                        return Err(format!(
                                "resident fused literal match returned out-of-range pattern id {pattern_id} for {gpu_literal_count} compiled literal(s)"
                            ));
                    }
                    if pattern_id < positioned_base {
                        continue;
                    }
                    let Some(region) = super::phase2_gpu_dfa::match_region(
                        region_starts,
                        metadata.haystack_len,
                        literal_match.start,
                        literal_match.end,
                    ) else {
                        return Err(format!(
                                "resident fused literal match ({}, {}, {}) does not belong to one complete input region",
                                literal_match.pattern_id, literal_match.start, literal_match.end,
                            ));
                    };
                    let row_idx = metadata.logical_start.checked_add(region).ok_or_else(|| {
                        "resident fused positioned row index overflows host usize".to_string()
                    })?;
                    let region_start = region_starts[region];
                    let relative_start = literal_match.start.checked_sub(region_start).ok_or_else(
                        || {
                            "resident fused positioned match starts before its attributed region"
                                .to_string()
                        },
                    )?;
                    let relative_start = usize::try_from(relative_start).map_err(|_| {
                        "resident fused positioned match offset exceeds host usize".to_string()
                    })?;
                    let local_start = relative_start
                        .checked_add(metadata.logical_byte_base)
                        .ok_or_else(|| {
                            "resident fused positioned logical offset overflows host usize"
                                .to_string()
                        })?;
                    let local_start = u32::try_from(local_start).map_err(|_| {
                        "resident fused positioned match offset exceeds the u32 chunk ABI"
                            .to_string()
                    })?;
                    if pattern_id < phase2_always_position_end {
                        let rows =
                                phase2_always_anchor_literal_matches.as_mut().ok_or_else(|| {
                                    "resident fused phase-two always-anchor match has no compiled output owner"
                                        .to_string()
                                })?;
                        let literal_id = u32::try_from(pattern_id - positioned_base).map_err(
                                |_| {
                                    "resident fused phase-two always-anchor literal id exceeds the u32 scanner ABI"
                                        .to_string()
                                },
                            )?;
                        let row_count = rows.len();
                        rows.get_mut(row_idx)
                                .ok_or_else(|| {
                                    format!(
                                        "resident fused phase-two always-anchor row {row_idx} exceeds {row_count} logical chunk row(s)"
                                    )
                                })?
                                .push((literal_id, local_start));
                    } else if pattern_id < confirmed_position_end {
                        let rows = confirmed_anchor_literal_matches.as_mut().ok_or_else(|| {
                            "resident fused confirmed-anchor match has no compiled output owner"
                                .to_string()
                        })?;
                        let literal_id =
                                u32::try_from(pattern_id - phase2_always_position_end).map_err(
                                    |_| {
                                        "resident fused confirmed-anchor literal id exceeds the u32 scanner ABI"
                                            .to_string()
                                    },
                                )?;
                        let row_count = rows.len();
                        rows.get_mut(row_idx)
                                .ok_or_else(|| {
                                    format!(
                                        "resident fused confirmed-anchor row {row_idx} exceeds {row_count} logical chunk row(s)"
                                    )
                                })?
                                .push((literal_id, local_start));
                    } else if pattern_id < generic_position_end {
                        if let Some(rows) = generic_keyword_positions.as_mut() {
                            let row_count = rows.len();
                            rows.get_mut(row_idx)
                                    .ok_or_else(|| {
                                        format!(
                                            "resident fused generic-keyword row {row_idx} exceeds {row_count} logical chunk row(s)"
                                        )
                                    })?
                                    .push(local_start);
                        }
                    }
                }
                derive_s = derive_s
                    .saturating_add(t_derive.map_or(std::time::Duration::ZERO, |t| t.elapsed()));
                Ok(())
            };
            let quarantined_error = gpu_dispatch_fault.clone();
            let mut recover_evidence = |metadata: &RegionDispatchMetadata,
                                        error: String|
             -> std::result::Result<(), String> {
                if !recover_dispatch_faults {
                    return Err(error);
                }
                if gpu_dispatch_fault.is_none() {
                    gpu_dispatch_fault = Some(error.clone());
                }
                let region_starts = metadata.region_starts.as_ref();
                if region_starts.len() != metadata.rows {
                    return Err(format!(
                            "cannot recover GPU dispatch with {} region start(s) for {} logical row(s): {error}",
                            region_starts.len(),
                            metadata.rows
                        ));
                }
                recovered_dispatches = recovered_dispatches.checked_add(1).ok_or_else(|| {
                    "GPU recovered-dispatch accounting overflows host usize".to_string()
                })?;
                crate::gpu::evidence::record_recovery(backend_code);
                crate::gpu::evidence::record_residual_batch();
                for region in 0..metadata.rows {
                    let dispatch_start = usize::try_from(region_starts[region])
                        .map_err(|_| "GPU recovery region start exceeds host usize".to_string())?;
                    let dispatch_end = if let Some(next) = region_starts.get(region + 1) {
                        usize::try_from(*next)
                            .map_err(|_| {
                                "GPU recovery next-region start exceeds host usize".to_string()
                            })?
                            .checked_sub(1)
                            .ok_or_else(|| "GPU recovery region separator underflows".to_string())?
                    } else {
                        metadata.haystack_len
                    };
                    let source_len = dispatch_end
                        .checked_sub(dispatch_start)
                        .ok_or_else(|| "GPU recovery region end precedes its start".to_string())?;
                    let chunk_index =
                        metadata.logical_start.checked_add(region).ok_or_else(|| {
                            "GPU recovery logical chunk index overflows host usize".to_string()
                        })?;
                    let chunk = chunks.get(chunk_index).ok_or_else(|| {
                        format!(
                            "GPU recovery logical chunk index {chunk_index} exceeds {} chunk(s)",
                            chunks.len()
                        )
                    })?;
                    let byte_start = metadata.logical_byte_base;
                    let byte_end = byte_start
                        .checked_add(source_len)
                        .ok_or_else(|| "GPU recovery byte end overflows host usize".to_string())?;
                    let source =
                            chunk
                                .data
                                .as_bytes()
                                .get(byte_start..byte_end)
                                .ok_or_else(|| {
                                    format!(
                                        "GPU recovery byte range {byte_start}..{byte_end} exceeds {} source byte(s)",
                                        chunk.data.len()
                                    )
                                })?;
                    let triggered = self.collect_triggered_patterns_cpu_bytes(source);
                    let mut recovered_presence = vec![0u32; presence_words];
                    for (word_index, word) in triggered.iter().copied().enumerate() {
                        let mut remaining = word;
                        while remaining != 0 {
                            let bit = remaining.trailing_zeros() as usize;
                            remaining &= remaining - 1;
                            let pattern_index = word_index * 64 + bit;
                            if pattern_index < self.ac_map.len() {
                                recovered_presence[pattern_index / 32] |=
                                    1u32 << (pattern_index % 32);
                            }
                        }
                    }
                    (consume.borrow_mut())(chunk_index, &recovered_presence).map_err(|recovery_error| {
                            format!(
                                "GPU dispatch failed ({error}); exact CPU trigger recovery also failed: {recovery_error}"
                            )
                        })?;
                    recovery_ranges.push(super::RecoveredInputRange::new(
                        chunk_index,
                        byte_start,
                        byte_end,
                    ));
                }
                Ok(())
            };
            let result = if let Some(error) = quarantined_error {
                recover_evidence(
                    &current_metadata,
                    format!(
                        "selected GPU route was quarantined after an earlier dispatch fault: {error}"
                    ),
                )
            } else if resident_submit_supported {
                resident_overlap.dispatch(
                    resident_slot,
                    matcher,
                    backend,
                    haystack,
                    region_starts,
                    current_metadata.clone(),
                    flush_current,
                    &mut consume_evidence,
                    &mut recover_evidence,
                )
            } else {
                crate::gpu::scan_gpu_literal_evidence_by_region_resident(
                    resident_slot,
                    matcher,
                    backend,
                    resident_timed_dispatch_supported,
                    haystack,
                    region_starts,
                    presence_words,
                    |presence, literal_matches| {
                        consume_evidence(current_metadata.clone(), presence, literal_matches)
                    },
                )
            };
            dis_s += t_dis
                .map_or(std::time::Duration::ZERO, |t| t.elapsed())
                .saturating_sub(derive_s);
            derive_s_total += derive_s;
            match result {
                Ok(()) => Ok(()),
                Err(error) => recover_evidence(&current_metadata, error),
            }
        };
        let byte_limit = region_presence_batch_byte_limit_for_depth(backend.id(), pipeline_depth)
            .map_err(super::gpu_forced::SelectedGpuDispatchError::new)?;
        let planned_dispatches =
            validate_region_presence_request_plan(chunks, byte_limit, self.gpu_max_literal_len)
                .map_err(super::gpu_forced::SelectedGpuDispatchError::new)?;
        let mut region_dispatches = 0usize;
        let mut region_coalesced_bytes = 0usize;
        let mut region_max_dispatch_bytes = 0usize;
        let mut region_batch_mode = RegionPresenceBatchMode::RawScratch;
        let mut cursor = 0usize;
        while cursor < chunks.len() {
            let oversized = chunks[cursor].data.len() > byte_limit;
            let (summary, next_cursor) = if oversized {
                let logical_row = cursor;
                #[cfg(test)]
                record_test_window_reduction_allocation();
                let mut reduced = Vec::new();
                reduced.try_reserve_exact(presence_words).map_err(|error| {
                    super::gpu_forced::SelectedGpuDispatchError::new(format!(
                        "GPU region-presence window reduction reserve failed: {error}"
                    ))
                })?;
                reduced.resize(presence_words, 0u32);
                let summary = for_each_region_presence_window(
                    chunks[cursor].data.as_bytes(),
                    byte_limit,
                    self.gpu_max_literal_len,
                    |haystack, range| {
                        let mut reduce =
                            |_row_idx: usize, row: &[u32]| -> std::result::Result<(), String> {
                                for (target, &word) in reduced.iter_mut().zip(row) {
                                    *target |= word;
                                }
                                Ok(())
                            };
                        let flush_current = range.end == chunks[cursor].data.len();
                        dispatch_presence(
                            haystack,
                            &[0],
                            logical_row,
                            1,
                            range.start,
                            flush_current,
                            &mut reduce,
                        )
                    },
                );
                if summary.is_ok() {
                    let t_derive = kh.then(std::time::Instant::now);
                    derive_presence_row(logical_row, &reduced)
                        .map_err(super::gpu_forced::SelectedGpuDispatchError::new)?;
                    logical_derive_s += t_derive.map_or(std::time::Duration::ZERO, |t| t.elapsed());
                }
                (summary, cursor + 1)
            } else {
                let run_start = cursor;
                let run_end = chunks[run_start..]
                    .iter()
                    .position(|chunk| chunk.data.len() > byte_limit)
                    .map_or(chunks.len(), |offset| run_start + offset);
                (
                    for_each_region_presence_batch(
                        &chunks[run_start..run_end],
                        byte_limit,
                        |haystack, region_starts, _mode, shard| {
                            let logical_start =
                                run_start.checked_add(shard.chunks.start).ok_or_else(|| {
                                    "region-presence logical shard start overflows host usize"
                                        .to_string()
                                })?;
                            dispatch_presence(
                                haystack,
                                region_starts,
                                logical_start,
                                shard.chunks.len(),
                                0,
                                shard.chunks.end == run_end - run_start,
                                &mut derive_presence_row,
                            )
                        },
                    ),
                    run_end,
                )
            };
            let summary = match summary {
                Ok(summary) => summary,
                Err(error) => {
                    drop(region_dispatch_profile);
                    return dispatch_failure(error);
                }
            };
            region_dispatches = region_dispatches
                .checked_add(summary.dispatches)
                .ok_or_else(|| {
                    super::gpu_forced::SelectedGpuDispatchError::new(
                        "GPU region-presence dispatch accounting overflows host usize",
                    )
                })?;
            if region_dispatches > MAX_REGION_PRESENCE_REQUEST_DISPATCHES {
                drop(region_dispatch_profile);
                return dispatch_failure(format!(
                        "GPU region-presence executed {region_dispatches} dispatches, above the preflight request safety limit of {MAX_REGION_PRESENCE_REQUEST_DISPATCHES}"
                    ));
            }
            region_coalesced_bytes = region_coalesced_bytes
                .checked_add(summary.coalesced_bytes)
                .ok_or_else(|| {
                    super::gpu_forced::SelectedGpuDispatchError::new(
                        "GPU region-presence byte accounting overflows host usize",
                    )
                })?;
            region_max_dispatch_bytes = region_max_dispatch_bytes.max(summary.max_dispatch_bytes);
            if oversized {
                region_batch_mode = RegionPresenceBatchMode::Windowed;
            } else {
                region_batch_mode = if region_batch_mode == RegionPresenceBatchMode::Windowed {
                    region_batch_mode
                } else {
                    summary.mode
                };
            }
            cursor = next_cursor;
        }
        drop(dispatch_presence);
        drop(derive_presence_row);
        let gpu_evidence_complete = gpu_dispatch_fault.is_none();
        if let Some(rows) = phase2_always_anchor_literal_matches.as_mut() {
            for row in rows.iter_mut() {
                row.sort_unstable();
                row.dedup();
            }
            if let Some((row_idx, (present, matches))) = phase2_always_anchor_presence
                .iter()
                .copied()
                .zip(rows.iter())
                .enumerate()
                .find(|(_, (present, matches))| *present != !matches.is_empty())
            {
                drop(region_dispatch_profile);
                return dispatch_failure(format!(
                        "GPU phase-two always-anchor evidence row {row_idx} disagrees: presence={present}, positioned_matches={}. Refusing incomplete fused evidence.",
                        matches.len()
                    ));
            }
        }
        if let Some(rows) = confirmed_anchor_literal_matches.as_mut() {
            for row in rows {
                row.sort_unstable();
                row.dedup();
            }
        }
        if let Some(rows) = generic_keyword_positions.as_mut() {
            for row in rows {
                row.sort_unstable();
                row.dedup();
            }
        }
        derive_s_total += logical_derive_s;
        if region_dispatches != planned_dispatches {
            drop(region_dispatch_profile);
            return dispatch_failure(format!(
                    "GPU region-presence executed {region_dispatches} dispatches after preflighting {planned_dispatches}"
                ));
        }
        if triggers.len() != chunks.len()
            || phase2_keyword_hints.len() != chunks.len()
            || phase2_always_anchor_presence.len() != chunks.len()
        {
            drop(region_dispatch_profile);
            return dispatch_failure(format!(
                    "GPU region-presence derived {} trigger row(s), {} keyword-hint row(s), and {} anchor row(s) for {} logical chunk(s)",
                    triggers.len(),
                    phase2_keyword_hints.len(),
                    phase2_always_anchor_presence.len(),
                    chunks.len()
                ));
        }
        let co_s = t_co
            .map_or(std::time::Duration::ZERO, |t| t.elapsed())
            .saturating_sub(dis_s)
            .saturating_sub(derive_s_total);
        drop(region_dispatch_profile);
        let t_floor = kh.then(std::time::Instant::now);
        let full_recall_floor = self.tuning.gpu_recall_floor_enabled();
        #[cfg(feature = "simd")]
        let cpu_triggers = if full_recall_floor {
            match self.try_simd_prefilter() {
                Ok(prefilter) => match self.compute_coalesced_triggers(chunks, prefilter, None) {
                    Ok(triggers) => Some(triggers),
                    Err(error) => {
                        return dispatch_failure(format!(
                            "gpu_recall_floor Hyperscan scan failed: {error}"
                        ));
                    }
                },
                Err(error) => {
                    return dispatch_failure(format!(
                        "gpu_recall_floor requested but Hyperscan initialization failed: {error}"
                    ));
                }
            }
        } else {
            None
        };
        #[cfg(not(feature = "simd"))]
        let cpu_triggers: Option<Vec<Option<Vec<u64>>>> = if full_recall_floor {
            return dispatch_failure(
                    "gpu_recall_floor requires a build with Hyperscan/SIMD support; disable gpu_recall_floor or install a SIMD-enabled KeyHog build".to_string(),
                );
        } else {
            None
        };

        if triggers.len() != chunks.len() {
            return dispatch_failure(format!(
                "region-presence readback length mismatch: got {} row(s), need {} row(s)",
                triggers.len(),
                chunks.len()
            ));
        }

        let mut gpu_underfire_recovered = 0usize;
        if let Some(cpu_triggers) = cpu_triggers.as_ref() {
            let prepared_text: Vec<std::cell::OnceCell<String>> = (0..chunks.len())
                .map(|_| std::cell::OnceCell::new())
                .collect();
            for (ci, cpu_opt) in cpu_triggers.iter().enumerate() {
                let Some(cpu_bits) = cpu_opt else { continue };
                if ci >= chunks.len() {
                    break;
                }
                for (w, &word) in cpu_bits.iter().enumerate() {
                    let mut rest = word;
                    while rest != 0 {
                        let lo = rest.trailing_zeros() as usize;
                        rest &= rest - 1;
                        let det = w * 64 + lo;
                        if det >= self.ac_map.len() || trigger_bit_is_set(&triggers, ci, det) {
                            continue;
                        }
                        let text = prepared_text[ci].get_or_init(|| {
                            self.prepare_chunk(&chunks[ci])
                                .preprocessed
                                .text
                                .as_ref()
                                .to_string()
                        });
                        let rx = self.ac_map[det].regex.get();
                        if validate_detector_match(
                            text.as_str(),
                            rx,
                            None,
                            self.ac_match_upper_bounds
                                .as_ref()
                                .and_then(|bounds| bounds.get(det).copied().flatten()),
                        ) {
                            set_trigger_bit(&mut triggers, ci, det, words);
                            gpu_underfire_recovered += 1;
                        }
                    }
                }
            }
        }
        let floor_s = t_floor.map_or(std::time::Duration::ZERO, |t| t.elapsed());

        // Surface a GPU under-fire LOUDLY: the GPU DFA missed a real
        // detector match the CPU floor recovered. This is a VYRE literal-set
        // recall bug (region attribution / byte-class edge / divergence) the
        // floor papered over, record it so it is fixed at the source, never
        // hidden (Law 10). One-shot per process to avoid log spam.
        if gpu_underfire_recovered > 0 {
            self.record_gpu_runtime_fault(format!(
                "GPU region-presence under-fire recovered {gpu_underfire_recovered} \
                     (chunk, detector) pair(s) via CPU recall floor"
            ));
            static UNDERFIRE_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
            if UNDERFIRE_WARNED.set(()).is_ok() {
                eprintln!(
                    "keyhog: GPU region-presence under-fired on {gpu_underfire_recovered} \
                         (chunk, detector) pair(s) recovered by gpu_recall_floor coverage - fix \
                         the VYRE literal-set path before treating GPU-only as parity-safe."
                );
            }
            tracing::warn!(
                target: "keyhog::gpu",
                recovered = gpu_underfire_recovered,
                "GPU region-presence under-fire recovered by CPU recall floor (vyre recall bug)",
            );
        }

        if let Err(error) = validate_phase2_gpu_trigger_rows(chunks.len(), triggers.len()) {
            return dispatch_failure(error.to_string());
        }
        let mut phase2_gpu_row_needed = Vec::with_capacity(chunks.len());
        let phase2_gpu_byte_limit = region_presence_batch_byte_limit(backend.id());
        let mut phase2_gpu_excluded_oversized = 0usize;
        let mut phase2_gpu_excluded_non_ascii = 0usize;
        for (idx, chunk) in chunks.iter().enumerate() {
            let row_has_trigger = triggers
                .get(idx)
                .and_then(|trigger| trigger.as_ref())
                .is_some_and(|bits| bits.iter().any(|&word| word != 0));
            if chunk.data.len() > phase2_gpu_byte_limit {
                phase2_gpu_excluded_oversized += 1;
                phase2_gpu_row_needed.push(false);
                continue;
            }
            // The GPU catalog's proof is ASCII-specific. Raw non-ASCII
            // rows may normalize before phase 2 and therefore remain under
            // the canonical CPU admission owner.
            if !chunk.data.is_ascii() {
                phase2_gpu_excluded_non_ascii += 1;
                phase2_gpu_row_needed.push(false);
                continue;
            }
            // Encoded-only rows that CPU admission would route straight to
            // decode-only recovery do not need the prefixless phase-2 GPU
            // DFA. The shared phase-2 tail still runs decode-only on those
            // rows; this just avoids a redundant GPU admission dispatch.
            let decode_only_row = self.chunk_needs_decode_postprocess(chunk)
                && !self.should_scan_no_hit_chunk(chunk, execution_route);
            phase2_gpu_row_needed.push(row_has_trigger || !decode_only_row);
        }
        let phase2_gpu_workload = if gpu_evidence_complete {
            build_phase2_gpu_admission_workload_filtered(chunks, |idx, _| {
                phase2_gpu_row_needed[idx]
            })
        } else {
            Phase2GpuAdmissionWorkload::Empty
        };
        let phase2_dispatch_profile = super::profile::span(keyhog_profile::Stage::BackendDispatch);
        let t_phase2_gpu = kh.then(std::time::Instant::now);
        let mut phase2_gpu_empty_complete = false;
        let mut phase2_gpu_coverage = None;
        let mut phase2_gpu_haystack_uploads = 0usize;
        let phase2_gpu_admission = match phase2_gpu_workload {
            Phase2GpuAdmissionWorkload::Empty => {
                phase2_gpu_empty_complete = chunks.is_empty();
                None
            }
            Phase2GpuAdmissionWorkload::Full { chunks: gpu_chunks } => {
                match self.phase2_gpu_dfa_catalog(Some(backend.id())) {
                    Some(catalog) => {
                        phase2_gpu_coverage = Some(catalog.coverage());
                        match scan_phase2_gpu_chunks_sharded(
                            catalog,
                            backend,
                            gpu_chunks,
                            recover_dispatch_faults,
                        ) {
                            Ok(outcome) => {
                                phase2_gpu_haystack_uploads = outcome.haystack_uploads;
                                if let Some(fault) = outcome.fault.as_ref() {
                                    if gpu_dispatch_fault.is_none() {
                                        gpu_dispatch_fault = Some(format!(
                                            "phase-2 GPU admission dispatch failed: {fault}"
                                        ));
                                    }
                                    for recovered in &outcome.recovered_rows {
                                        for chunk_index in recovered.clone() {
                                            recovery_ranges.push(super::RecoveredInputRange::new(
                                                chunk_index,
                                                0,
                                                chunks[chunk_index].data.len(),
                                            ));
                                        }
                                    }
                                }
                                Some(outcome.admission)
                            }
                            Err(error) => {
                                let reason =
                                    format!("phase-2 GPU admission dispatch failed: {error}");
                                return dispatch_failure(reason);
                            }
                        }
                    }
                    None => None,
                }
            }
            Phase2GpuAdmissionWorkload::Subset {
                indices,
                chunks: gpu_chunks,
                full_len,
            } => match self.phase2_gpu_dfa_catalog(Some(backend.id())) {
                Some(catalog) => {
                    phase2_gpu_coverage = Some(catalog.coverage());
                    match scan_phase2_gpu_refs_sharded(
                        catalog,
                        backend,
                        gpu_chunks.as_slice(),
                        recover_dispatch_faults,
                    ) {
                        Ok(outcome) => {
                            phase2_gpu_haystack_uploads = outcome.haystack_uploads;
                            if let Some(fault) = outcome.fault.as_ref() {
                                if gpu_dispatch_fault.is_none() {
                                    gpu_dispatch_fault = Some(format!(
                                        "phase-2 GPU admission dispatch failed: {fault}"
                                    ));
                                }
                                for recovered in &outcome.recovered_rows {
                                    for subset_index in recovered.clone() {
                                        let chunk_index = indices[subset_index];
                                        recovery_ranges.push(super::RecoveredInputRange::new(
                                            chunk_index,
                                            0,
                                            chunks[chunk_index].data.len(),
                                        ));
                                    }
                                }
                            }
                            let admission =
                                expand_phase2_gpu_admission(outcome.admission, &indices, full_len);
                            Some(admission)
                        }
                        Err(error) => {
                            let reason = format!("phase-2 GPU admission dispatch failed: {error}");
                            return dispatch_failure(reason);
                        }
                    }
                }
                None => None,
            },
        };
        let phase2_gpu_s = t_phase2_gpu.map_or(std::time::Duration::ZERO, |t| t.elapsed());
        drop(phase2_dispatch_profile);

        let trigger_bits: usize = triggers
            .iter()
            .filter_map(|t| t.as_ref())
            .map(|w| w.iter().map(|x| x.count_ones() as usize).sum::<usize>())
            .sum();

        let t_p2 = kh.then(std::time::Instant::now);
        let phase2_gpu_admitted = phase2_gpu_admission.as_ref().map_or(0usize, |admission| {
            admission.admitted.iter().filter(|&&v| v).count()
        });
        let phase2_gpu_evidence_bits = phase2_gpu_admission
            .as_ref()
            .map_or(0usize, |admission| admission.matches_seen);
        let phase2_gpu_complete = phase2_gpu_empty_complete
            || phase2_gpu_admission
                .as_ref()
                .is_some_and(|admission| admission.complete.iter().all(|&value| value));
        let phase2_gpu_complete_rows = phase2_gpu_admission.as_ref().map_or(0usize, |admission| {
            admission.complete.iter().filter(|&&value| value).count()
        });
        let results = self
            .scan_coalesced_phase2_with_admission(
                chunks,
                triggers,
                phase2_gpu_admission
                    .as_ref()
                    .map(|admission| admission.admitted.as_slice()),
                phase2_gpu_admission
                    .as_ref()
                    .map(|admission| admission.complete.as_slice()),
                phase2_gpu_admission
                    .as_ref()
                    .map(|admission| admission.candidate_bits.as_slice()),
                phase2_gpu_admission
                    .as_ref()
                    .map_or(0, |admission| admission.candidate_words_per_region),
                phase2_gpu_admission
                    .as_ref()
                    .map(|admission| admission.candidate_phase2_indices.as_slice()),
                gpu_evidence_complete.then_some(phase2_keyword_hints.as_slice()),
                gpu_evidence_complete.then_some(phase2_always_anchor_presence.as_slice()),
                gpu_evidence_complete
                    .then_some(phase2_always_anchor_literal_matches.as_deref())
                    .flatten(),
                gpu_evidence_complete
                    .then_some(confirmed_anchor_literal_matches.as_deref())
                    .flatten(),
                gpu_evidence_complete
                    .then_some(generic_keyword_positions.as_deref())
                    .flatten(),
                None,
                route,
                execution_route,
            )
            .map_err(|error| super::gpu_forced::SelectedGpuDispatchError::new(error.to_string()))?;
        if kh {
            let phase2_always_anchor_chunks = phase2_always_anchor_presence
                .iter()
                .filter(|&&present| present)
                .count();
            let phase2_always_anchor_candidate_rows = phase2_always_anchor_literal_matches
                .as_ref()
                .map_or(0usize, |rows| {
                    rows.iter().filter(|row| !row.is_empty()).count()
                });
            let phase2_always_anchor_candidate_count = phase2_always_anchor_literal_matches
                .as_ref()
                .map_or(0usize, |rows| rows.iter().map(Vec::len).sum());
            let phase2_always_anchor_positions_complete =
                phase2_always_anchor_literal_matches.is_some();
            let confirmed_anchor_candidate_rows = confirmed_anchor_literal_matches
                .as_ref()
                .map_or(0usize, |rows| {
                    rows.iter().filter(|row| !row.is_empty()).count()
                });
            let confirmed_anchor_candidate_count = confirmed_anchor_literal_matches
                .as_ref()
                .map_or(0usize, |rows| rows.iter().map(Vec::len).sum());
            let confirmed_anchor_gpu_complete = confirmed_anchor_literal_matches.is_some();
            let generic_keyword_candidate_rows =
                generic_keyword_positions.as_ref().map_or(0usize, |rows| {
                    rows.iter().filter(|row| !row.is_empty()).count()
                });
            let generic_keyword_candidate_count = generic_keyword_positions
                .as_ref()
                .map_or(0usize, |rows| rows.iter().map(Vec::len).sum());
            let generic_keyword_gpu_complete = generic_keyword_positions.is_some();
            eprintln!(
                    "perf-trace {}: chunks={} source_bytes={} coalesced_bytes={} max_dispatch_bytes={} dispatches={} recovered_dispatches={} batch_mode={} matcher={:.3}s coalesce={:.6}s coalesce_mib_s={:.3} dispatch={:.3}s derive={:.6}s floor={:.3}s phase2_gpu={:.3}s phase2={:.3}s gpu_presence_bits={} underfire_recovered={} trigger_bits={} phase2_gpu_admitted={} phase2_gpu_evidence_bits={} phase2_gpu_haystack_uploads={} phase2_gpu_complete={} phase2_gpu_complete_rows={} phase2_gpu_excluded_oversized={} phase2_gpu_excluded_non_ascii={} phase2_gpu_ascii_patterns={} phase2_gpu_uncovered_ascii_patterns={} phase2_gpu_excluded_redundant_patterns={} phase2_gpu_shards={} phase2_always_anchor_chunks={} phase2_always_anchor_positions_complete={} phase2_always_anchor_candidate_rows={} phase2_always_anchor_candidates={} confirmed_anchor_gpu_complete={} confirmed_anchor_candidate_rows={} confirmed_anchor_candidates={} generic_keyword_gpu_complete={} generic_keyword_candidate_rows={} generic_keyword_candidates={} full_recall_floor={}",
                    route.label(),
                    chunks.len(),
                    region_source_bytes,
                    region_coalesced_bytes,
                    region_max_dispatch_bytes,
                    region_dispatches,
                    recovered_dispatches,
                    region_batch_mode.label(),
                    matcher_s.as_secs_f64(),
                    co_s.as_secs_f64(),
                    mib_per_second(region_source_bytes, co_s),
                    dis_s.as_secs_f64(),
                    derive_s_total.as_secs_f64(),
                    floor_s.as_secs_f64(),
                    phase2_gpu_s.as_secs_f64(),
                    t_p2.map_or(0.0, |t| t.elapsed().as_secs_f64()),
                    gpu_presence_bits,
                    gpu_underfire_recovered,
                    trigger_bits,
                    phase2_gpu_admitted,
                    phase2_gpu_evidence_bits,
                    phase2_gpu_haystack_uploads,
                    phase2_gpu_complete,
                    phase2_gpu_complete_rows,
                    phase2_gpu_excluded_oversized,
                    phase2_gpu_excluded_non_ascii,
                    phase2_gpu_coverage.map_or(0, |coverage| coverage.covered_ascii_patterns),
                    phase2_gpu_coverage.map_or(0, |coverage| coverage.uncovered_ascii_patterns),
                    phase2_gpu_coverage
                        .map_or(0, |coverage| coverage.excluded_ascii_redundant_patterns),
                    phase2_gpu_coverage.map_or(0, |coverage| coverage.shards),
                    phase2_always_anchor_chunks,
                    phase2_always_anchor_positions_complete,
                    phase2_always_anchor_candidate_rows,
                    phase2_always_anchor_candidate_count,
                    confirmed_anchor_gpu_complete,
                    confirmed_anchor_candidate_rows,
                    confirmed_anchor_candidate_count,
                    generic_keyword_gpu_complete,
                    generic_keyword_candidate_rows,
                    generic_keyword_candidate_count,
                    full_recall_floor,
                );
        }
        let recovery = gpu_dispatch_fault.map(|reason| {
            self.record_gpu_runtime_fault(format!(
                "{} recovered {} exact input range(s) after GPU dispatch fault: {reason}",
                route.label(),
                recovery_ranges.len()
            ));
            super::BackendRecoveryReceipt::new(
                route,
                crate::hw_probe::ScanBackend::CpuFallback,
                recovery_ranges,
                reason,
            )
        });
        Ok(super::CoalescedScanOutcome {
            matches: results,
            recovery,
            gpu_recovery_receipts: 0,
        })
    }
}

#[cfg(test)]
#[path = "../../../tests/unit/engine_gpu_region_dispatch.rs"]
mod tests;

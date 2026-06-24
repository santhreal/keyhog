//! Live wiring of the coalesced GPU literal-region trigger path.
//!
//! Trigger production is the ONLY thing this path changes. It builds the rule
//! matcher from `ac_map` once, dispatches the whole chunk batch in ONE GPU
//! launch, and turns the resulting per-region presence rows into the SAME
//! per-chunk `Option<Vec<u64>>` trigger bitmap the Hyperscan prefilter produces
//! - then hands it to the SHARED `scan_coalesced_phase2`. So windowing,
//! confirmed extraction, fallback, generic, entropy, ML, suppression, dedup,
//! cross-file reassembly and cross-chunk boundary scan are byte-for-byte the
//! coalesced CPU path: the GPU only replaces phase 1.
//!
//! Recall + precision: GPU presence only admits candidate detector bits. Phase 2
//! still validates every candidate with the real detector regex. The full CPU
//! Hyperscan trigger floor is not part of the default fast path; it is enabled
//! only for explicit parity/debug runs.

use super::gpu_region_batch::{
    set_trigger_bit, trigger_bit_is_set, validate_detector_match, with_region_presence_batch,
    RegionPresenceBatchMode,
};
use super::gpu_region_dispatch_helpers::{
    mib_per_second, report_phase2_gpu_admission_loss, report_positioned_gpu_candidate_loss,
};
#[cfg(test)]
use super::phase2_gpu_dfa::build_phase2_gpu_admission_workload;
#[cfg(test)]
use super::phase2_gpu_dfa::Phase2GpuDfaAdmission;
use super::phase2_gpu_dfa::{
    build_phase2_gpu_admission_workload_filtered, expand_phase2_gpu_admission,
    validate_phase2_gpu_trigger_rows, Phase2GpuAdmissionWorkload,
};
use super::*;
use crate::hw_probe::ScanBackend;

const GPU_POSITIONED_LITERAL_MAX_MATCHES: u32 = 65_536;

struct GpuRegionPresenceEvidence {
    presence: Vec<u32>,
    confirmed_anchor_literal_matches: Option<Vec<Vec<(u32, u32)>>>,
    generic_keyword_positions: Option<Vec<Vec<u32>>>,
}

#[derive(Default)]
struct GpuPositionEvidence {
    confirmed_anchor_literal_matches: Option<Vec<Vec<(u32, u32)>>>,
    generic_keyword_positions: Option<Vec<Vec<u32>>>,
}

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

    /// Coalesced GPU region-presence scan: one GPU dispatch over the whole
    /// `chunks` batch produces the per-chunk trigger bitmap, then the SHARED
    /// coalesced phase-2 tail runs the identical per-chunk extraction every
    /// other backend uses. Degrades LOUDLY to the per-chunk SIMD/CPU path when
    /// the matcher/backend is unavailable, or dispatch errors - never a silent
    /// empty result.
    pub(crate) fn scan_coalesced_gpu_region_presence(
        &self,
        chunks: &[keyhog_core::Chunk],
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        if chunks.is_empty() {
            return Vec::new();
        }

        let degrade = |reason: String| -> Vec<Vec<keyhog_core::RawMatch>> {
            super::gpu_forced::deny_silent_gpu_degrade(self, ScanBackend::Gpu);
            // Degrade to the backend that is ACTUALLY live, not a hardcoded
            // `SimdCpu`: with the `simd` feature compiled but no Hyperscan
            // prefilter built (`simd_prefilter == None`), routing through
            // `SimdCpu` would itself silently re-degrade to the pure-CPU AC
            // path inside `scan_with_backend`. `degraded_backend_after_gpu_failure`
            // returns `SimdCpu` only when the prefilter is live and
            // `CpuFallback` otherwise, so the operator-visible backend matches
            // what runs (Law 10).
            let degraded = self.degraded_backend_after_gpu_failure();
            // Record the reason so operators (and the GPU self-test) can see WHY
            // the GPU path fell back, not just that it did.
            self.record_gpu_degrade(reason.clone());
            tracing::warn!(
                target: "keyhog::gpu",
                %reason,
                ?degraded,
                "coalesced GPU region-presence scan degraded off GPU (loud, recall-preserving)",
            );
            use rayon::prelude::*;
            let mut results: Vec<Vec<keyhog_core::RawMatch>> = chunks
                .par_iter()
                .map(|chunk| self.scan_with_backend(chunk, degraded))
                .collect();
            super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
            results
        };

        // The shared coalesced phase-2 tail is `#[cfg(feature = "simd")]` (it is
        // the Hyperscan path's extraction). `gpu` implies `simd` at the feature
        // level (see keyhog-scanner Cargo.toml: `gpu = ["simd", ...]`), so this
        // body is ALWAYS compiled under `gpu` and the region-presence path always
        // has its tail. The `#[cfg(feature = "simd")]` is retained as a fail-closed
        // assertion of that invariant: were the dependency ever dropped, this
        // function would fail to compile rather than silently lose its tail.
        #[cfg(feature = "simd")]
        {
            let kh = super::profile::perf_trace_enabled();
            let t_matcher = std::time::Instant::now();
            let Some(matcher) = self.gpu_matcher() else {
                return degrade(
                    "gpu literal matcher not built for coalesced region scan".to_string(),
                );
            };
            let matcher_s = t_matcher.elapsed();
            let Some(backend) = self.gpu_backend.as_ref() else {
                return degrade(
                    "no gpu backend acquired for coalesced region dispatch".to_string(),
                );
            };

            let words = self.ac_map.len().div_ceil(64).max(1);
            let gpu_literal_count = self.gpu_presence_literal_count();
            let presence_words = gpu_literal_count.div_ceil(32).max(1);
            let region_source_bytes: usize = chunks.iter().map(|chunk| chunk.data.len()).sum();

            let t_co = std::time::Instant::now();
            let mut co_s = std::time::Duration::ZERO;
            let mut dis_s = std::time::Duration::ZERO;
            let mut positioned_literal_gpu_s = std::time::Duration::ZERO;
            let mut region_coalesced_bytes = 0usize;
            let mut region_batch_mode = RegionPresenceBatchMode::FoldedScratch;
            let evidence = match with_region_presence_batch(
                chunks,
                |haystack, region_starts, batch_mode| {
                    co_s = t_co.elapsed();
                    region_coalesced_bytes = haystack.len();
                    region_batch_mode = batch_mode;
                    let t_dis = std::time::Instant::now();
                    let result =
                        super::gpu_literal_scratch::scan_gpu_literal_presence_by_region_with_scratch(
                            matcher,
                            &**backend,
                            haystack,
                            region_starts,
                        )
                        .map_err(|error| format!("region-presence dispatch error: {error}"));
                    dis_s = t_dis.elapsed();
                    let presence = result?;
                    let t_positioned_literal_gpu = std::time::Instant::now();
                    let positioned = self.positioned_literal_evidence_from_gpu(
                        &**backend,
                        haystack,
                        region_starts,
                    );
                    positioned_literal_gpu_s = t_positioned_literal_gpu.elapsed();
                    Ok(GpuRegionPresenceEvidence {
                        presence,
                        confirmed_anchor_literal_matches: positioned
                            .confirmed_anchor_literal_matches,
                        generic_keyword_positions: positioned.generic_keyword_positions,
                    })
                },
            ) {
                Ok(evidence) => evidence,
                Err(error) => return degrade(error),
            };
            let presence = evidence.presence;
            let confirmed_anchor_literal_matches = evidence.confirmed_anchor_literal_matches;
            let generic_keyword_positions = evidence.generic_keyword_positions;

            let t_floor = std::time::Instant::now();
            let full_recall_floor = self.tuning.gpu_recall_floor_enabled();
            let cpu_triggers = if full_recall_floor {
                match self.simd_prefilter.as_ref() {
                    Some(scanner) => Some(self.compute_coalesced_triggers(chunks, scanner)),
                    None => {
                        return degrade(
                            "gpu_recall_floor requested but no SIMD prefilter is live".to_string(),
                        );
                    }
                }
            } else {
                None
            };

            let expected_presence_words = chunks.len().saturating_mul(presence_words);
            if presence.len() != expected_presence_words {
                return degrade(format!(
                    "region-presence readback length mismatch: got {} u32 word(s), need {}",
                    presence.len(),
                    expected_presence_words
                ));
            }

            let mut triggers: Vec<Option<Vec<u64>>> = Vec::with_capacity(chunks.len());
            let mut phase2_keyword_hints: Vec<Vec<u32>> = Vec::with_capacity(chunks.len());
            let mut phase2_always_anchor_presence: Vec<bool> = Vec::with_capacity(chunks.len());
            let mut gpu_presence_bits = 0usize;
            for (row_idx, row) in presence
                .chunks_exact(presence_words)
                .take(chunks.len())
                .enumerate()
            {
                if let Some((word_idx, stray_bits)) = self.gpu_presence_stray_tail_bits(row) {
                    return degrade(format!(
                        "region-presence readback row {row_idx} has out-of-range detector bit(s): word {word_idx} bits 0x{stray_bits:08x} beyond {} literal(s)",
                        gpu_literal_count
                    ));
                }
                gpu_presence_bits += row
                    .iter()
                    .map(|word| word.count_ones() as usize)
                    .sum::<usize>();
                let bits = self.triggered_patterns_from_gpu_presence(row);
                phase2_keyword_hints.push(self.phase2_keyword_hints_from_gpu_presence(row));
                phase2_always_anchor_presence
                    .push(self.phase2_always_anchor_present_from_gpu_presence(row));
                if bits.iter().any(|&word| word != 0) {
                    triggers.push(Some(bits));
                } else {
                    triggers.push(None);
                }
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
                                self.ac_match_upper_bounds.get(det).copied().flatten(),
                            ) {
                                set_trigger_bit(&mut triggers, ci, det, words);
                                gpu_underfire_recovered += 1;
                            }
                        }
                    }
                }
            }
            let floor_s = t_floor.elapsed();

            // Surface a GPU under-fire LOUDLY: the GPU DFA missed a real
            // detector match the CPU floor recovered. This is a vyre literal-set
            // recall bug (region attribution / byte-class edge / divergence) the
            // floor papered over — record it so it is fixed at the source, never
            // hidden (Law 10). One-shot per process to avoid log spam.
            if gpu_underfire_recovered > 0 {
                self.record_gpu_degrade(format!(
                    "GPU region-presence under-fire recovered {gpu_underfire_recovered} \
                     (chunk, detector) pair(s) via CPU recall floor"
                ));
                static UNDERFIRE_WARNED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
                if UNDERFIRE_WARNED.set(()).is_ok() {
                    eprintln!(
                        "keyhog: GPU region-presence under-fired on {gpu_underfire_recovered} \
                         (chunk, detector) pair(s) recovered by gpu_recall_floor coverage - fix \
                         the vyre literal-set path before treating GPU-only as parity-safe."
                    );
                }
                tracing::warn!(
                    target: "keyhog::gpu",
                    recovered = gpu_underfire_recovered,
                    "GPU region-presence under-fire recovered by CPU recall floor (vyre recall bug)",
                );
            }

            let t_phase2_gpu = std::time::Instant::now();
            if let Err(error) = validate_phase2_gpu_trigger_rows(chunks.len(), triggers.len()) {
                return degrade(error.to_string());
            }
            let mut phase2_gpu_row_needed = Vec::with_capacity(chunks.len());
            for (idx, chunk) in chunks.iter().enumerate() {
                let row_has_trigger = triggers
                    .get(idx)
                    .and_then(|trigger| trigger.as_ref())
                    .is_some_and(|bits| bits.iter().any(|&word| word != 0));
                if row_has_trigger {
                    phase2_gpu_row_needed.push(true);
                    continue;
                }
                // Encoded-only rows that CPU admission would route straight to
                // decode-only recovery do not need the prefixless phase-2 GPU
                // DFA. The shared phase-2 tail still runs decode-only on those
                // rows; this just avoids a redundant GPU admission dispatch.
                let decode_only_row = self.chunk_needs_decode_postprocess(chunk)
                    && !self.should_scan_no_hit_chunk(chunk);
                phase2_gpu_row_needed.push(!decode_only_row);
            }
            let phase2_gpu_workload =
                build_phase2_gpu_admission_workload_filtered(chunks, &triggers, |idx, _| {
                    phase2_gpu_row_needed[idx]
                });
            let mut phase2_gpu_empty_complete = false;
            let phase2_gpu_admission = match phase2_gpu_workload {
                Phase2GpuAdmissionWorkload::Empty => {
                    phase2_gpu_empty_complete = true;
                    None
                }
                Phase2GpuAdmissionWorkload::Full { chunks: gpu_chunks } => {
                    match self.phase2_gpu_dfa_catalog(Some(backend.id())) {
                        Some(catalog) => {
                            match catalog.scan_admission_chunks(&**backend, gpu_chunks) {
                                Ok(admission) => Some(admission),
                                Err(error) => {
                                    report_phase2_gpu_admission_loss(error);
                                    None
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
                        match catalog.scan_admission_refs(&**backend, gpu_chunks.as_slice()) {
                            Ok(admission) => {
                                Some(expand_phase2_gpu_admission(admission, &indices, full_len))
                            }
                            Err(error) => {
                                report_phase2_gpu_admission_loss(error);
                                None
                            }
                        }
                    }
                    None => None,
                },
            };
            let phase2_gpu_s = t_phase2_gpu.elapsed();

            let trigger_bits: usize = triggers
                .iter()
                .filter_map(|t| t.as_ref())
                .map(|w| w.iter().map(|x| x.count_ones() as usize).sum::<usize>())
                .sum();

            let t_p2 = std::time::Instant::now();
            let phase2_gpu_admitted = phase2_gpu_admission.as_ref().map_or(0usize, |admission| {
                admission.admitted.iter().filter(|&&v| v).count()
            });
            let phase2_gpu_matches = phase2_gpu_admission
                .as_ref()
                .map_or(0usize, |admission| admission.matches_seen);
            let phase2_gpu_complete = phase2_gpu_empty_complete
                || phase2_gpu_admission
                    .as_ref()
                    .is_some_and(|admission| admission.complete);
            let results = self.scan_coalesced_phase2_with_admission(
                chunks,
                triggers,
                phase2_gpu_admission
                    .as_ref()
                    .map(|admission| admission.admitted.as_slice()),
                Some(phase2_keyword_hints.as_slice()),
                Some(phase2_always_anchor_presence.as_slice()),
                confirmed_anchor_literal_matches.as_deref(),
                generic_keyword_positions.as_deref(),
            );
            if kh {
                let phase2_always_anchor_chunks = phase2_always_anchor_presence
                    .iter()
                    .filter(|&&present| present)
                    .count();
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
                    "perf-trace gpu-region-presence: chunks={} source_bytes={} coalesced_bytes={} batch_mode={} matcher={:.3}s coalesce={:.6}s coalesce_mib_s={:.3} dispatch={:.3}s positioned_literal_gpu={:.3}s floor={:.3}s phase2_gpu={:.3}s phase2={:.3}s gpu_presence_bits={} underfire_recovered={} trigger_bits={} phase2_gpu_admitted={} phase2_gpu_matches={} phase2_gpu_complete={} phase2_always_anchor_chunks={} confirmed_anchor_gpu_complete={} confirmed_anchor_candidate_rows={} confirmed_anchor_candidates={} generic_keyword_gpu_complete={} generic_keyword_candidate_rows={} generic_keyword_candidates={} full_recall_floor={}",
                    chunks.len(),
                    region_source_bytes,
                    region_coalesced_bytes,
                    region_batch_mode.label(),
                    matcher_s.as_secs_f64(),
                    co_s.as_secs_f64(),
                    mib_per_second(region_source_bytes, co_s),
                    dis_s.as_secs_f64(),
                    positioned_literal_gpu_s.as_secs_f64(),
                    floor_s.as_secs_f64(),
                    phase2_gpu_s.as_secs_f64(),
                    t_p2.elapsed().as_secs_f64(),
                    gpu_presence_bits,
                    gpu_underfire_recovered,
                    trigger_bits,
                    phase2_gpu_admitted,
                    phase2_gpu_matches,
                    phase2_gpu_complete,
                    phase2_always_anchor_chunks,
                    confirmed_anchor_gpu_complete,
                    confirmed_anchor_candidate_rows,
                    confirmed_anchor_candidate_count,
                    generic_keyword_gpu_complete,
                    generic_keyword_candidate_rows,
                    generic_keyword_candidate_count,
                    full_recall_floor,
                );
            }
            // Diagnostic: dump the phase-2 leaf breakdown (confirmed / phase2:prefilter /
            // Generic / Entropy / Ml …) so the localizable-vs-whole-chunk cost split
            // is visible — the data Part B (localized phase 2) is designed against.
            // Gated through the single profiler owner, so dispatch does not grow
            // a second environment-control path.
            if super::profile::enabled() {
                super::profile::dump("gpu-region-presence-phase2");
            }
            results
        }
    }

    fn positioned_literal_evidence_from_gpu(
        &self,
        backend: &dyn vyre::VyreBackend,
        haystack: &[u8],
        region_starts: &[u32],
    ) -> GpuPositionEvidence {
        let confirmed_count = self.confirmed_anchor_literal_count;
        let generic_count = self.generic_keyword_literal_count;
        if confirmed_count == 0 && generic_count == 0 {
            return GpuPositionEvidence::default();
        }
        let Some(matcher) = self.gpu_position_matcher() else {
            let reason = "positioned literal matcher not built for this scanner";
            self.record_gpu_degrade(reason);
            report_positioned_gpu_candidate_loss(reason);
            return GpuPositionEvidence::default();
        };
        let matches = match super::gpu_literal_scratch::scan_gpu_literal_matches_with_scratch(
            matcher,
            backend,
            haystack,
            GPU_POSITIONED_LITERAL_MAX_MATCHES,
        ) {
            Ok(matches) => matches,
            Err(error) => {
                let reason = error.to_string();
                self.record_gpu_degrade(format!(
                    "positioned GPU candidate collection failed: {reason}"
                ));
                report_positioned_gpu_candidate_loss(reason);
                return GpuPositionEvidence::default();
            }
        };
        if matches.len() >= GPU_POSITIONED_LITERAL_MAX_MATCHES as usize {
            let reason = format!(
                "positioned literal scan reached cap {GPU_POSITIONED_LITERAL_MAX_MATCHES}; \
                 refusing incomplete positioned candidates"
            );
            self.record_gpu_degrade(reason.clone());
            report_positioned_gpu_candidate_loss(reason);
            return GpuPositionEvidence::default();
        }
        let confirmed_base = 0usize;
        let confirmed_end = confirmed_count;
        let generic_base = confirmed_end;
        let generic_end = generic_base + generic_count;
        let mut confirmed_rows =
            (confirmed_count > 0).then(|| vec![Vec::new(); region_starts.len()]);
        let mut generic_rows = (generic_count > 0).then(|| vec![Vec::new(); region_starts.len()]);
        for m in matches {
            let pattern_id = m.pattern_id as usize;
            let is_confirmed = pattern_id >= confirmed_base && pattern_id < confirmed_end;
            let is_generic = pattern_id >= generic_base && pattern_id < generic_end;
            if !is_confirmed && !is_generic {
                continue;
            }
            let Some(region) =
                super::phase2_gpu_dfa::match_region(region_starts, haystack.len(), m.start, m.end)
            else {
                continue;
            };
            let region_start = region_starts[region] as usize;
            let start = m.start as usize;
            if start < region_start {
                continue;
            }
            let local_start = start - region_start;
            if let Ok(local_start) = u32::try_from(local_start) {
                // LAW10: impossible local offsets outside GPU u32 space are not emitted to GPU row buffers; CPU/SIMD paths retain recall.
                if is_confirmed {
                    if let Some(rows) = confirmed_rows.as_mut() {
                        rows[region].push(((pattern_id - confirmed_base) as u32, local_start));
                    }
                } else if let Some(rows) = generic_rows.as_mut() {
                    rows[region].push(local_start);
                }
            }
        }
        if let Some(rows) = confirmed_rows.as_mut() {
            for row in rows {
                row.sort_unstable();
                row.dedup();
            }
        }
        if let Some(rows) = generic_rows.as_mut() {
            for row in rows {
                row.sort_unstable();
                row.dedup();
            }
        }
        GpuPositionEvidence {
            confirmed_anchor_literal_matches: confirmed_rows,
            generic_keyword_positions: generic_rows,
        }
    }
}

#[cfg(all(test, feature = "gpu"))]
mod tests {
    use super::super::gpu_region_batch::{
        build_region_presence_batch, validation_window_range, with_region_presence_batch,
        RegionPresenceBatchMode, RegionPresenceScratch, ZeroRegionPresenceScratch,
    };
    use super::*;

    #[test]
    fn region_presence_batch_lowercases_separates_and_clears_scratch() {
        let chunks = [
            keyhog_core::Chunk::from("GhP_TOKEN"),
            keyhog_core::Chunk::from("Zz9"),
        ];
        let mut scratch = RegionPresenceScratch::default();

        {
            let mut guard = ZeroRegionPresenceScratch::new(&mut scratch);
            build_region_presence_batch(&chunks, guard.as_mut()).expect("batch");
            assert_eq!(guard.haystack(), b"ghp_token\0zz9");
            assert_eq!(guard.region_starts(), &[0, 10]);
        }

        assert!(scratch.is_empty());
    }

    #[test]
    fn region_presence_batch_borrows_single_chunk_when_folded_source_is_identical() {
        let chunks = [keyhog_core::Chunk::from("ghp_lowercase_token_123")];
        let source_ptr = chunks[0].data.as_bytes().as_ptr();

        with_region_presence_batch(&chunks, |haystack, region_starts, mode| {
            assert_eq!(mode, RegionPresenceBatchMode::BorrowedSingleChunk);
            assert_eq!(haystack, chunks[0].data.as_bytes());
            assert_eq!(haystack.as_ptr(), source_ptr);
            assert_eq!(region_starts, &[0]);
            Ok(())
        })
        .expect("borrowed single-chunk batch");
    }

    #[test]
    fn region_presence_batch_uses_folded_scratch_when_case_fold_changes_bytes() {
        let chunks = [keyhog_core::Chunk::from("GhP_TOKEN")];
        let source_ptr = chunks[0].data.as_bytes().as_ptr();

        with_region_presence_batch(&chunks, |haystack, region_starts, mode| {
            assert_eq!(mode, RegionPresenceBatchMode::FoldedScratch);
            assert_eq!(haystack, b"ghp_token");
            assert_ne!(haystack.as_ptr(), source_ptr);
            assert_eq!(region_starts, &[0]);
            Ok(())
        })
        .expect("folded single-chunk batch");
    }

    #[test]
    fn validation_window_range_preserves_utf8_boundaries() {
        let text = "αβghp_secretδ";
        let (start, end) = validation_window_range(text, 6, 5).expect("window");

        assert!(text.is_char_boundary(start));
        assert!(text.is_char_boundary(end));
        assert!(text[start..end].contains("ghp"));
    }

    #[test]
    fn bounded_gpu_firing_rejects_window_miss_without_full_chunk_scan() {
        let rx = regex::Regex::new(r"SECRET-[0-9]{4}").expect("regex");
        let text = "prefix bait hit here\n\nlots of filler\n\nSECRET-1234";
        let distant_match_offset = text.find("SECRET-1234").expect("match");

        assert!(
            validate_detector_match(
                text,
                &rx,
                Some(distant_match_offset),
                Some("SECRET-1234".len())
            ),
            "bounded validator must accept a real local match"
        );
        assert!(
            !validate_detector_match(text, &rx, Some(0), Some("SECRET-1234".len())),
            "bounded GPU over-fire validation must not fall back to a full-chunk \
             regex scan after the local window misses"
        );
    }

    #[test]
    fn unbounded_and_cpu_floor_validation_keep_full_chunk_oracle() {
        let rx = regex::Regex::new(r"SECRET=.*END").expect("regex");
        let text = "prefix bait hit here\nSECRET=abc123END";

        assert!(
            validate_detector_match(text, &rx, Some(0), None),
            "unbounded detector validation keeps the full prepared-chunk oracle"
        );
        assert!(
            validate_detector_match(text, &rx, None, Some(8)),
            "CPU recall-floor validation has no GPU offset, so it keeps the full \
             prepared-chunk oracle"
        );
    }

    #[test]
    fn bounded_validation_source_has_no_old_full_chunk_regex_scan() {
        let src = include_str!("gpu_region_dispatch.rs");
        let old_full_chunk_regex_scan = ["rx.is_match", "(text.as_str())"].concat();
        assert!(
            !src.contains(&old_full_chunk_regex_scan),
            "bounded GPU firing validation must not run a full prepared-chunk regex \
             scan after its local proof window misses"
        );
    }

    #[test]
    fn coalesce_rate_reports_zero_for_zero_duration() {
        assert_eq!(
            mib_per_second(8 * 1024 * 1024, std::time::Duration::ZERO),
            0.0
        );
        assert_eq!(mib_per_second(0, std::time::Duration::from_secs(1)), 0.0);
    }

    #[test]
    fn phase2_gpu_admission_workload_keeps_only_no_trigger_chunks() {
        let chunks = [
            keyhog_core::Chunk::from("already-triggered"),
            keyhog_core::Chunk::from("no-trigger-none"),
            keyhog_core::Chunk::from("no-trigger-zero-row"),
            keyhog_core::Chunk::from("also-triggered"),
        ];
        let triggers = vec![Some(vec![1]), None, Some(vec![0]), Some(vec![0, 8])];

        let workload = build_phase2_gpu_admission_workload(&chunks, &triggers);

        let Phase2GpuAdmissionWorkload::Subset {
            indices,
            chunks: selected_chunks,
            full_len,
        } = workload
        else {
            panic!("mixed triggered/no-trigger batch must build subset workload");
        };
        assert_eq!(full_len, 4);
        assert_eq!(indices, vec![1, 2]);
        assert_eq!(selected_chunks.len(), 2);
        assert_eq!(selected_chunks[0].data.as_ref(), "no-trigger-none");
        assert_eq!(selected_chunks[1].data.as_ref(), "no-trigger-zero-row");
    }

    #[test]
    fn phase2_gpu_admission_workload_uses_original_slice_for_all_no_trigger_chunks() {
        let chunks = [
            keyhog_core::Chunk::from("no-trigger-none"),
            keyhog_core::Chunk::from("no-trigger-zero-row"),
        ];
        let triggers = vec![None, Some(vec![0])];

        let workload = build_phase2_gpu_admission_workload(&chunks, &triggers);

        let Phase2GpuAdmissionWorkload::Full {
            chunks: selected_chunks,
        } = workload
        else {
            panic!("all no-trigger batch must use full-slice workload");
        };
        assert_eq!(selected_chunks.as_ptr(), chunks.as_ptr());
        assert_eq!(selected_chunks.len(), chunks.len());
    }

    #[test]
    fn phase2_gpu_admission_workload_preserves_prefix_no_trigger_chunks() {
        let chunks = [
            keyhog_core::Chunk::from("no-trigger-before"),
            keyhog_core::Chunk::from("triggered"),
        ];
        let triggers = vec![None, Some(vec![1])];

        let workload = build_phase2_gpu_admission_workload(&chunks, &triggers);

        let Phase2GpuAdmissionWorkload::Subset {
            indices,
            chunks: selected_chunks,
            full_len,
        } = workload
        else {
            panic!("no-trigger prefix before a triggered chunk must remain in subset workload");
        };
        assert_eq!(full_len, chunks.len());
        assert_eq!(indices, vec![0]);
        assert_eq!(selected_chunks.len(), 1);
        assert_eq!(selected_chunks[0].data.as_ref(), "no-trigger-before");
    }

    #[test]
    fn phase2_gpu_admission_workload_filter_skips_decode_only_rows() {
        let chunks = [
            keyhog_core::Chunk::from("decode-only-unicode-escape"),
            keyhog_core::Chunk::from("ordinary-no-trigger"),
            keyhog_core::Chunk::from("already-triggered"),
        ];
        let triggers = vec![None, None, Some(vec![1])];

        let workload =
            build_phase2_gpu_admission_workload_filtered(&chunks, &triggers, |idx, _| idx != 0);

        let Phase2GpuAdmissionWorkload::Subset {
            indices,
            chunks: selected_chunks,
            full_len,
        } = workload
        else {
            panic!("filtered no-trigger batch must build subset workload");
        };
        assert_eq!(full_len, chunks.len());
        assert_eq!(indices, vec![1]);
        assert_eq!(selected_chunks.len(), 1);
        assert_eq!(selected_chunks[0].data.as_ref(), "ordinary-no-trigger");
    }

    #[test]
    fn phase2_gpu_admission_workload_filter_empty_when_all_no_trigger_rows_skipped() {
        let chunks = [
            keyhog_core::Chunk::from("decode-only-a"),
            keyhog_core::Chunk::from("decode-only-b"),
        ];
        let triggers = vec![None, Some(vec![0])];

        let workload =
            build_phase2_gpu_admission_workload_filtered(&chunks, &triggers, |_, _| false);

        let Phase2GpuAdmissionWorkload::Empty = workload else {
            panic!("all filtered no-trigger rows must skip phase-2 GPU DFA dispatch");
        };
    }

    #[test]
    fn phase2_gpu_admission_workload_skips_gpu_dfa_when_every_chunk_already_triggered() {
        let chunks = [
            keyhog_core::Chunk::from("triggered"),
            keyhog_core::Chunk::from("also-triggered"),
        ];
        let triggers = vec![Some(vec![1]), Some(vec![0, 8])];

        let workload = build_phase2_gpu_admission_workload(&chunks, &triggers);

        let Phase2GpuAdmissionWorkload::Empty = workload else {
            panic!("all-triggered batch must skip phase-2 GPU DFA dispatch");
        };
    }

    #[test]
    fn phase2_gpu_trigger_row_mismatch_is_rejected() {
        let error = validate_phase2_gpu_trigger_rows(4, 3).expect_err("mismatched rows rejected");

        assert!(
            error
                .to_string()
                .contains("refusing to run mismatched phase-2 admission"),
            "trigger/chunk cardinality drift must be a loud GPU route failure"
        );
    }

    #[test]
    fn phase2_gpu_admission_expands_subset_bits_to_original_batch() {
        let subset = Phase2GpuDfaAdmission {
            admitted: vec![true, false, true],
            complete: true,
            matches_seen: 7,
        };

        let full = expand_phase2_gpu_admission(subset, &[1, 3, 4], 5);

        assert_eq!(full.admitted, vec![false, true, false, false, true]);
        assert!(full.complete);
        assert_eq!(full.matches_seen, 7);
    }

    #[test]
    fn phase2_gpu_admission_length_mismatch_marks_evidence_incomplete() {
        let subset = Phase2GpuDfaAdmission {
            admitted: vec![true],
            complete: true,
            matches_seen: 1,
        };

        let full = expand_phase2_gpu_admission(subset, &[0, 2], 3);

        assert_eq!(full.admitted, vec![true, false, false]);
        assert!(
            !full.complete,
            "mismatched subset evidence must not claim complete GPU admission coverage"
        );
    }
}

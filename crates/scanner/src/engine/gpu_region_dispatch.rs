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
};
use super::phase2_gpu_dfa::Phase2GpuDfaAdmission;
use super::*;
use crate::hw_probe::ScanBackend;

struct Phase2GpuAdmissionWorkload<'a> {
    indices: Vec<usize>,
    chunks: Vec<&'a keyhog_core::Chunk>,
}

fn trigger_has_bits(trigger: Option<&[u64]>) -> bool {
    trigger.is_some_and(|bits| bits.iter().any(|&word| word != 0))
}

fn validate_phase2_gpu_trigger_rows(
    chunk_count: usize,
    trigger_count: usize,
) -> std::result::Result<(), String> {
    if chunk_count == trigger_count {
        return Ok(());
    }
    Err(format!(
        "coalesced GPU region presence produced {trigger_count} trigger row(s) for {chunk_count} chunk(s); refusing to run mismatched phase-2 admission"
    ))
}

fn build_phase2_gpu_admission_workload<'a>(
    chunks: &'a [keyhog_core::Chunk],
    triggers: &[Option<Vec<u64>>],
) -> Phase2GpuAdmissionWorkload<'a> {
    let mut indices = Vec::new();
    let mut selected_chunks = Vec::new();
    for (idx, chunk) in chunks.iter().enumerate() {
        if trigger_has_bits(
            triggers
                .get(idx)
                .and_then(|trigger| trigger.as_ref().map(Vec::as_slice)),
        ) {
            continue;
        }
        indices.push(idx);
        selected_chunks.push(chunk);
    }
    Phase2GpuAdmissionWorkload {
        indices,
        chunks: selected_chunks,
    }
}

fn expand_phase2_gpu_admission(
    subset: Phase2GpuDfaAdmission,
    workload_indices: &[usize],
    full_len: usize,
) -> Phase2GpuDfaAdmission {
    let mut admitted = vec![false; full_len];
    let length_mismatch = subset.admitted.len() != workload_indices.len();
    for (&is_admitted, &full_idx) in subset.admitted.iter().zip(workload_indices.iter()) {
        if is_admitted {
            if let Some(slot) = admitted.get_mut(full_idx) {
                *slot = true;
            }
        }
    }
    if length_mismatch {
        tracing::warn!(
            target: "keyhog::gpu",
            subset_len = subset.admitted.len(),
            workload_len = workload_indices.len(),
            "phase-2 GPU regex-DFA admission length mismatch; CPU admission remains authoritative for missing slots"
        );
    }
    Phase2GpuDfaAdmission {
        admitted,
        complete: subset.complete && !length_mismatch,
        matches_seen: subset.matches_seen,
    }
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
            if let Ok(mut slot) = self.gpu_last_degrade_reason.lock() {
                *slot = Some(reason.clone());
            }
            self.gpu_degrade_count
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
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
            let presence_words = self.ac_map.len().div_ceil(32).max(1);

            let t_co = std::time::Instant::now();
            let mut co_s = std::time::Duration::ZERO;
            let mut dis_s = std::time::Duration::ZERO;
            let presence = match with_region_presence_batch(chunks, |haystack, region_starts| {
                co_s = t_co.elapsed();
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
                result
            }) {
                Ok(presence) => presence,
                Err(error) => return degrade(error),
            };

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
            let mut gpu_presence_bits = 0usize;
            for (row_idx, row) in presence
                .chunks_exact(presence_words)
                .take(chunks.len())
                .enumerate()
            {
                if let Some((word_idx, stray_bits)) = self.gpu_presence_stray_tail_bits(row) {
                    return degrade(format!(
                        "region-presence readback row {row_idx} has out-of-range detector bit(s): word {word_idx} bits 0x{stray_bits:08x} beyond {} literal(s)",
                        self.ac_map.len()
                    ));
                }
                gpu_presence_bits += row
                    .iter()
                    .map(|word| word.count_ones() as usize)
                    .sum::<usize>();
                let bits = self.triggered_patterns_from_gpu_presence(row);
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
            let phase2_gpu_workload = build_phase2_gpu_admission_workload(chunks, &triggers);
            let phase2_gpu_admission = if phase2_gpu_workload.chunks.is_empty() {
                Some(Phase2GpuDfaAdmission {
                    admitted: vec![false; chunks.len()],
                    complete: true,
                    matches_seen: 0,
                })
            } else {
                match self.phase2_gpu_dfa_catalog(Some(backend.id())) {
                    Some(catalog) => match catalog
                        .scan_admission_refs(&**backend, phase2_gpu_workload.chunks.as_slice())
                    {
                        Ok(admission) => Some(expand_phase2_gpu_admission(
                            admission,
                            &phase2_gpu_workload.indices,
                            chunks.len(),
                        )),
                        Err(error) => {
                            tracing::warn!(
                                target: "keyhog::gpu",
                                %error,
                                "phase-2 GPU regex-DFA admission failed; CPU admission remains authoritative"
                            );
                            None
                        }
                    },
                    None => None,
                }
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
            let phase2_gpu_complete = phase2_gpu_admission
                .as_ref()
                .is_some_and(|admission| admission.complete);
            let results = self.scan_coalesced_phase2_with_admission(
                chunks,
                triggers,
                phase2_gpu_admission
                    .as_ref()
                    .map(|admission| admission.admitted.as_slice()),
            );
            if kh {
                eprintln!(
                    "perf-trace gpu-region-presence: chunks={} matcher={:.3}s coalesce={:.3}s dispatch={:.3}s floor={:.3}s phase2_gpu={:.3}s phase2={:.3}s gpu_presence_bits={} underfire_recovered={} trigger_bits={} phase2_gpu_admitted={} phase2_gpu_matches={} phase2_gpu_complete={} full_recall_floor={}",
                    chunks.len(),
                    matcher_s.as_secs_f64(),
                    co_s.as_secs_f64(),
                    dis_s.as_secs_f64(),
                    floor_s.as_secs_f64(),
                    phase2_gpu_s.as_secs_f64(),
                    t_p2.elapsed().as_secs_f64(),
                    gpu_presence_bits,
                    gpu_underfire_recovered,
                    trigger_bits,
                    phase2_gpu_admitted,
                    phase2_gpu_matches,
                    phase2_gpu_complete,
                    full_recall_floor,
                );
            }
            // Diagnostic: dump the phase-2 leaf breakdown (Confirmed / FbPrefilter /
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
}

#[cfg(all(test, feature = "gpu"))]
mod tests {
    use super::super::gpu_region_batch::{
        build_region_presence_batch, validation_window_range, RegionPresenceScratch,
        ZeroRegionPresenceScratch,
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
    fn bounded_validation_source_has_no_old_full_chunk_fallback() {
        let src = include_str!("gpu_region_dispatch.rs");
        let old_full_chunk_regex_scan = ["rx.is_match", "(text.as_str())"].concat();
        assert!(
            !src.contains(&old_full_chunk_regex_scan),
            "bounded GPU firing validation must not fall back to a full prepared-chunk \
             regex scan after its local proof window misses"
        );
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

        assert_eq!(workload.indices, vec![1, 2]);
        assert_eq!(workload.chunks.len(), 2);
        assert_eq!(workload.chunks[0].data.as_ref(), "no-trigger-none");
        assert_eq!(workload.chunks[1].data.as_ref(), "no-trigger-zero-row");
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

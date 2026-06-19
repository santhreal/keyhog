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

use super::*;
use crate::hw_probe::ScanBackend;

#[cfg(feature = "gpu")]
struct RegionPresenceBatch {
    haystack: Vec<u8>,
    region_starts: Vec<u32>,
}

#[cfg(feature = "gpu")]
impl Drop for RegionPresenceBatch {
    fn drop(&mut self) {
        self.haystack.fill(0);
    }
}

#[cfg(feature = "gpu")]
fn build_region_presence_batch(
    chunks: &[keyhog_core::Chunk],
) -> std::result::Result<RegionPresenceBatch, String> {
    let mut total = chunks.len().saturating_sub(1);
    for chunk in chunks {
        total = total.checked_add(chunk.data.len()).ok_or_else(|| {
            "coalesced GPU region-presence batch length overflows host usize".to_string()
        })?;
    }
    if total > u32::MAX as usize {
        return Err(format!(
            "coalesced GPU region-presence batch is {total} byte(s), above the u32 GPU ABI; split the batch before dispatch"
        ));
    }

    let mut haystack = Vec::new();
    haystack
        .try_reserve(total)
        .map_err(|error| format!("coalesced GPU region-presence reserve failed: {error}"))?;
    let mut region_starts = Vec::with_capacity(chunks.len());
    for (idx, chunk) in chunks.iter().enumerate() {
        let start = u32::try_from(haystack.len()).map_err(|_| {
            "coalesced GPU region-presence start offset exceeds the u32 GPU ABI".to_string()
        })?;
        region_starts.push(start);
        let region_start = haystack.len();
        haystack.extend_from_slice(chunk.data.as_bytes());
        haystack[region_start..].make_ascii_lowercase();
        if idx + 1 != chunks.len() {
            haystack.push(0);
        }
    }
    Ok(RegionPresenceBatch {
        haystack,
        region_starts,
    })
}

#[cfg(feature = "gpu")]
fn trigger_bit_is_set(triggers: &[Option<Vec<u64>>], ci: usize, det: usize) -> bool {
    triggers
        .get(ci)
        .and_then(|slot| slot.as_ref())
        .and_then(|words| words.get(det / 64))
        .is_some_and(|word| ((word >> (det % 64)) & 1) == 1)
}

#[cfg(feature = "gpu")]
fn set_trigger_bit(triggers: &mut [Option<Vec<u64>>], ci: usize, det: usize, words: usize) {
    if let Some(slot) = triggers.get_mut(ci) {
        let bits = slot.get_or_insert_with(|| vec![0u64; words]);
        if bits.len() < words {
            bits.resize(words, 0);
        }
        bits[det / 64] |= 1u64 << (det % 64);
    }
}

#[cfg(feature = "gpu")]
fn validation_window_range(
    text: &str,
    match_offset: usize,
    max_match_width: usize,
) -> Option<(usize, usize)> {
    if text.is_empty() || max_match_width == 0 {
        return None;
    }
    let hit = match_offset.min(text.len());
    let start = super::floor_char_boundary(text, hit.saturating_sub(max_match_width));
    let end = super::ceil_char_boundary(text, hit.saturating_add(max_match_width).min(text.len()));
    (start < end).then_some((start, end))
}

#[cfg(feature = "gpu")]
fn validate_detector_match(
    text: &str,
    rx: &regex::Regex,
    match_offset: Option<usize>,
    max_match_width: Option<usize>,
) -> bool {
    let Some(match_offset) = match_offset else {
        return rx.is_match(text);
    };
    let Some(max_match_width) = max_match_width else {
        return rx.is_match(text);
    };
    let Some((start, end)) = validation_window_range(text, match_offset, max_match_width) else {
        return false;
    };
    rx.is_match(&text[start..end])
}

impl CompiledScanner {
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
            let batch = match build_region_presence_batch(chunks) {
                Ok(batch) => batch,
                Err(error) => return degrade(error),
            };
            let co_s = t_co.elapsed();

            let t_dis = std::time::Instant::now();
            let presence = match super::gpu_lazy::scan_gpu_literal_presence_by_region_with_scratch(
                matcher,
                &**backend,
                &batch.haystack,
                &batch.region_starts,
            ) {
                Ok(presence) => presence,
                Err(error) => return degrade(format!("region-presence dispatch error: {error}")),
            };
            let dis_s = t_dis.elapsed();

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
            for row in presence.chunks_exact(presence_words).take(chunks.len()) {
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

            let trigger_bits: usize = triggers
                .iter()
                .filter_map(|t| t.as_ref())
                .map(|w| w.iter().map(|x| x.count_ones() as usize).sum::<usize>())
                .sum();

            let t_p2 = std::time::Instant::now();
            let results = self.scan_coalesced_phase2(chunks, triggers);
            if kh {
                eprintln!(
                    "perf-trace gpu-region-presence: chunks={} matcher={:.3}s coalesce={:.3}s dispatch={:.3}s floor={:.3}s phase2={:.3}s gpu_presence_bits={} underfire_recovered={} trigger_bits={} full_recall_floor={}",
                    chunks.len(),
                    matcher_s.as_secs_f64(),
                    co_s.as_secs_f64(),
                    dis_s.as_secs_f64(),
                    floor_s.as_secs_f64(),
                    t_p2.elapsed().as_secs_f64(),
                    gpu_presence_bits,
                    gpu_underfire_recovered,
                    trigger_bits,
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
    use super::*;

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
}

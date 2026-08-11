use super::super::*;
use crate::hw_probe::ScanBackend;

impl CompiledScanner {
    pub(crate) fn collect_triggered_patterns_for_backend(
        &self,
        text: &str,
        backend: ScanBackend,
    ) -> crate::error::Result<Vec<u64>> {
        let _g = profile::span(keyhog_profile::Stage::Phase1Triggers);
        match backend {
            ScanBackend::GpuCuda | ScanBackend::GpuMetal | ScanBackend::GpuWgpu => {
                self.collect_triggered_patterns_gpu(text, backend)
            }
            ScanBackend::SimdCpu => self.collect_triggered_patterns_simd(text),
            ScanBackend::CpuFallback => Ok(self.collect_triggered_patterns_cpu(text)),
        }
    }

    fn collect_triggered_patterns_gpu(
        &self,
        text: &str,
        route: ScanBackend,
    ) -> crate::error::Result<Vec<u64>> {
        let dispatch_failure = |reason: String| {
            self.record_gpu_runtime_fault(reason.clone());
            Err(crate::error::ScanError::Gpu(reason))
        };

        let Some(matcher) = self.gpu_matcher() else {
            return dispatch_failure("gpu literal matcher not built for this scanner".to_string());
        };
        let Some(gpu_backend) = self.gpu_backend(route) else {
            return dispatch_failure(self.gpu_backend_unavailable_reason(route));
        };
        match super::gpu_literal_scratch::scan_gpu_literal_presence_with_scratch(
            matcher,
            &**gpu_backend,
            text.as_bytes(),
        ) {
            Ok(presence) => {
                let expected_presence_words = self.gpu_literal_count().div_ceil(32).max(1);
                if presence.len() != expected_presence_words {
                    return dispatch_failure(format!(
                        "per-chunk GPU presence readback length mismatch: got {} u32 word(s), need {}",
                        presence.len(),
                        expected_presence_words
                    ));
                }
                if let Some((word_idx, stray_bits)) = self.gpu_presence_stray_tail_bits(&presence) {
                    return dispatch_failure(format!(
                        "per-chunk GPU presence readback has out-of-range detector bit(s): word {word_idx} bits 0x{stray_bits:08x} beyond {} literal(s)",
                        self.gpu_literal_count()
                    ));
                }
                let mut triggered = self.collect_triggered_patterns_cpu(text);
                self.mark_gpu_presence_into(&mut triggered, &presence);
                Ok(triggered)
            }
            Err(error) => dispatch_failure(format!("gpu presence scan failed: {error}")),
        }
    }

    fn collect_triggered_patterns_simd(&self, _text: &str) -> crate::error::Result<Vec<u64>> {
        #[cfg(feature = "simd")]
        {
            let prefilter = self.try_simd_prefilter().map_err(|error| {
                crate::error::ScanError::Simd(format!(
                    "selected Hyperscan trigger backend was not initialized: {error}"
                ))
            })?;
            let scanner = prefilter.scanner();
            let mut triggered_patterns =
                super::trigger_bitmap::new_trigger_bitmap(self.ac_map.len());
            scanner
                .scan_matches_result(_text.as_bytes(), |hs_id, _start, _end| {
                    if let Some(original_indices) = prefilter.original_indices(hs_id) {
                        for &pattern_index in original_indices {
                            self.mark_triggered_pattern(
                                &mut triggered_patterns,
                                pattern_index as usize,
                            );
                        }
                    }
                })
                .map_err(|error| {
                    crate::error::ScanError::Simd(format!(
                        "selected Hyperscan trigger scan failed: {error}. The scan did not complete; rerun with `--backend cpu` or recalibrate autoroute"
                    ))
                })?;
            prefilter.for_each_recovery_match(_text.as_bytes(), |pattern_index| {
                self.mark_triggered_pattern(&mut triggered_patterns, pattern_index);
            });
            return Ok(triggered_patterns);
        }

        #[cfg(not(feature = "simd"))]
        Err(crate::error::ScanError::Simd(
            "simd-regex trigger collection reached without a live SIMD/Hyperscan prefilter; \
             silent cpu-fallback execution is forbidden. Run `keyhog backend --self-test` or \
             choose `--backend cpu` explicitly."
                .to_owned(),
        ))
    }

    pub(crate) fn collect_triggered_patterns_cpu(&self, text: &str) -> Vec<u64> {
        self.collect_triggered_patterns_cpu_bytes(text.as_bytes())
    }

    pub(crate) fn collect_triggered_patterns_cpu_bytes(&self, bytes: &[u8]) -> Vec<u64> {
        let mut triggered_patterns = super::trigger_bitmap::new_trigger_bitmap(self.ac_map.len());
        self.mark_triggered_patterns_cpu_bytes(&mut triggered_patterns, bytes);
        triggered_patterns
    }

    /// Return an empty allocation-free row when CPU phase 1 found no trigger.
    ///
    /// Admission plans treat an empty row as exact no-trigger evidence. Hit rows
    /// retain the full bitmap because downstream extraction consumes its indices.
    pub(crate) fn collect_triggered_patterns_cpu_compact(&self, text: &str) -> Vec<u64> {
        let words = super::trigger_bitmap::words_for(self.ac_map.len());
        super::scan_coalesced::with_trigger_buffer(words, |scratch| {
            self.mark_triggered_patterns_cpu_bytes(scratch, text.as_bytes());
            scratch
                .iter()
                .any(|&word| word != 0)
                .then(|| scratch.to_vec())
                .unwrap_or_default()
        })
    }

    fn mark_triggered_patterns_cpu_bytes(&self, triggered_patterns: &mut [u64], bytes: &[u8]) {
        #[cfg(debug_assertions)]
        self.phase1_trigger_scanned_bytes.fetch_add(
            // LAW10: debug accounting saturates on impossible usize-to-u64 overflow; scan behavior is unchanged.
            u64::try_from(bytes.len()).unwrap_or(u64::MAX),
            std::sync::atomic::Ordering::Relaxed,
        );
        if let Some(ac) = &self.ac {
            for ac_match in ac.find_overlapping_iter(bytes) {
                self.mark_triggered_pattern(triggered_patterns, ac_match.pattern().as_usize());
            }
        }
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn reset_phase1_trigger_scanned_bytes_for_diagnostics(&self) {
        self.phase1_trigger_scanned_bytes
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn phase1_trigger_scanned_bytes_for_diagnostics(&self) -> u64 {
        self.phase1_trigger_scanned_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[inline]
    pub(crate) fn gpu_literal_count(&self) -> usize {
        let shared_literal_count =
            self.ac_map.len() + self.phase2_keyword_count + self.phase2_always_anchor_literal_count;
        #[cfg(feature = "gpu")]
        {
            shared_literal_count
                + self.confirmed_anchor_literal_count
                + self.generic_keyword_literal_count
        }
        #[cfg(not(feature = "gpu"))]
        {
            shared_literal_count
        }
    }

    pub(crate) fn gpu_presence_stray_tail_bits(&self, presence: &[u32]) -> Option<(usize, u32)> {
        let literal_count = self.gpu_literal_count();
        let used_tail_bits = literal_count % 32;
        if literal_count != 0 && used_tail_bits == 0 {
            return None;
        }
        let tail_word_idx = literal_count / 32;
        let valid_mask = if used_tail_bits == 0 {
            0
        } else {
            (1u32 << used_tail_bits) - 1
        };
        let stray_bits = *presence.get(tail_word_idx)? & !valid_mask;
        (stray_bits != 0).then_some((tail_word_idx, stray_bits))
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn triggered_patterns_from_gpu_presence(&self, presence: &[u32]) -> Vec<u64> {
        let mut triggered = super::trigger_bitmap::new_trigger_bitmap(self.ac_map.len());
        self.mark_gpu_presence_into(&mut triggered, presence);
        triggered
    }

    pub(crate) fn mark_gpu_presence_into(&self, triggered: &mut [u64], presence: &[u32]) {
        for (word_idx, &word) in presence.iter().enumerate() {
            let mut bits = word;
            while bits != 0 {
                let bit = bits.trailing_zeros() as usize;
                let literal_idx = word_idx * 32 + bit;
                if literal_idx < self.ac_map.len() {
                    self.mark_triggered_pattern(triggered, literal_idx);
                }
                bits &= bits - 1;
            }
        }
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn phase2_keyword_hints_from_gpu_presence(&self, presence: &[u32]) -> Vec<u32> {
        if self.phase2_keyword_count == 0 {
            return Vec::new();
        }
        let base = self.ac_map.len();
        (0..self.phase2_keyword_count)
            .filter(|&kw_idx| {
                let idx = base + kw_idx;
                presence
                    .get(idx / 32)
                    .is_some_and(|w| (w & (1u32 << (idx % 32))) != 0)
            })
            .map(|kw_idx| kw_idx as u32)
            .collect()
    }

    #[cfg(feature = "gpu")]
    pub(crate) fn phase2_always_anchor_present_from_gpu_presence(&self, presence: &[u32]) -> bool {
        if self.phase2_always_anchor_literal_count == 0 {
            return false;
        }
        let base = self.ac_map.len() + self.phase2_keyword_count;
        (0..self.phase2_always_anchor_literal_count).any(|anchor_idx| {
            let idx = base + anchor_idx;
            presence
                .get(idx / 32)
                .is_some_and(|w| (w & (1u32 << (idx % 32))) != 0)
        })
    }

    pub(crate) fn mark_triggered_pattern(
        &self,
        triggered_patterns: &mut [u64],
        pattern_index: usize,
    ) {
        if pattern_index / 64 >= triggered_patterns.len() {
            return;
        }
        triggered_patterns[pattern_index / 64] |= 1u64 << (pattern_index % 64);
        if let Some(propagated_indices) = self.prefix_propagation.get(pattern_index) {
            for &propagated_index in propagated_indices {
                let propagated_index = propagated_index as usize;
                if propagated_index / 64 < triggered_patterns.len() {
                    triggered_patterns[propagated_index / 64] |= 1u64 << (propagated_index % 64);
                }
            }
        }
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn reset_confirmed_pattern_scanned_bytes_for_diagnostics(&self) {
        self.confirmed_pattern_scanned_bytes
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn confirmed_pattern_scanned_bytes_for_diagnostics(&self) -> u64 {
        self.confirmed_pattern_scanned_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    pub fn reset_entropy_scanned_bytes_for_diagnostics(&self) {
        self.entropy_scanned_bytes
            .store(0, std::sync::atomic::Ordering::Relaxed);
    }

    #[doc(hidden)]
    #[cfg(debug_assertions)]
    #[must_use]
    pub fn entropy_scanned_bytes_for_diagnostics(&self) -> u64 {
        self.entropy_scanned_bytes
            .load(std::sync::atomic::Ordering::Relaxed)
    }
}

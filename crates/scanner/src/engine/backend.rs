use super::*;
use crate::hw_probe::ScanBackend;
use keyhog_core::Chunk;

pub(crate) struct PreparedChunk {
    /// Owned copy of the (possibly-normalized) chunk we're about to
    /// scan. Was `Arc<Chunk>` historically, but every consumer of
    /// `PreparedChunk` only ever borrows via `&prepared.chunk` —
    /// the Arc never shared ownership across threads, it just paid
    /// for a heap header on every chunk. Plain owned `Chunk` drops
    /// one allocation per chunk.
    pub(crate) chunk: Chunk,
    pub(crate) preprocessed: ScannerPreprocessedText,
}

#[cfg(feature = "simd")]
pub(crate) fn build_simd_scanner(
    ac_map: &[CompiledPattern],
    _fallback: &[(CompiledPattern, Vec<String>)],
) -> Option<(crate::simd::backend::HsScanner, Vec<Vec<usize>>)> {
    use std::collections::HashMap;

    let mut regex_to_hs_id: HashMap<String, usize> = HashMap::new();
    let mut hs_patterns: Vec<(usize, usize, String, bool)> = Vec::new();
    let mut index_map: Vec<Vec<usize>> = Vec::new();

    for (idx, entry) in ac_map.iter().enumerate() {
        let regex_str = entry.regex.as_str();
        let hs_id = *regex_to_hs_id
            .entry(regex_str.to_string())
            .or_insert_with(|| {
                let id = hs_patterns.len();
                hs_patterns.push((
                    entry.detector_index,
                    id,
                    regex_str.to_string(),
                    entry.group.is_some(),
                ));
                index_map.push(Vec::new());
                id
            });
        index_map[hs_id].push(idx);
    }

    let pattern_refs: Vec<(usize, usize, &str, bool)> = hs_patterns
        .iter()
        .map(|(a, b, c, d)| (*a, *b, c.as_str(), *d))
        .collect();

    tracing::info!(
        unique = hs_patterns.len(),
        raw = ac_map.len(),
        "compiling deduplicated AC regexes into Hyperscan"
    );

    match crate::simd::backend::HsScanner::compile(&pattern_refs) {
        Ok((scanner, unsupported)) => {
            tracing::info!(
                compiled = scanner.pattern_count(),
                unsupported = unsupported.len(),
                "HS ready"
            );
            Some((scanner, index_map))
        }
        Err(error) => {
            tracing::warn!("HS compilation failed: {error}");
            None
        }
    }
}

impl CompiledScanner {
    pub(crate) fn scan_chunks_with_backend_internal(
        &self,
        chunks: &[Chunk],
        backend: ScanBackend,
    ) -> Vec<Vec<RawMatch>> {
        // GPU paths: literal-set (Gpu) and regex-NFA (MegaScan). Both
        // require a working GPU adapter + compiled matchers; the lazy
        // compile is gated below so a missing GPU silently degrades to
        // SIMD via `scan_with_backend` per chunk.
        let gpu_path = matches!(backend, ScanBackend::Gpu | ScanBackend::MegaScan);
        if !gpu_path || chunks.is_empty() {
            // Parallel CPU path: rayon's global pool is configured by the
            // CLI orchestrator with --threads / KEYHOG_THREADS / physical
            // core count. Hyperscan + AC scans are CPU-bound and trivially
            // independent per-chunk, so par_iter() saturates cores cleanly
            // — was previously a serial iter().map() that pinned to one
            // worker even on 32-core boxes.
            use rayon::prelude::*;
            return chunks
                .par_iter()
                .map(|chunk| self.scan_with_backend(chunk, backend))
                .collect();
        }

        // GPU batch path: `scan_coalesced_gpu` produces full per-chunk
        // RawMatch results in one device dispatch + parallel post-process.
        // The previous `populate_gpu_batch_triggers` was a comment-only TODO
        // that threw the GPU results away — see audit release-2026-04-26.
        if self.gpu_literals.is_none() || self.wgpu_backend.is_none() {
            let fallback_backend = self.degraded_backend_after_gpu_failure();
            tracing::debug!(
                fallback = fallback_backend.label(),
                "gpu matcher unavailable, using non-gpu backend"
            );
            use rayon::prelude::*;
            return chunks
                .par_iter()
                .map(|chunk| self.scan_with_backend(chunk, fallback_backend))
                .collect();
        }
        match backend {
            ScanBackend::MegaScan => self.scan_coalesced_megascan(chunks),
            _ => self.scan_coalesced_gpu(chunks),
        }
    }

    pub(crate) fn prepare_chunk(&self, chunk: &Chunk) -> PreparedChunk {
        let mut owned_normalized = None;
        let chunk = if chunk.data.is_ascii() {
            chunk
        } else {
            normalize_scannable_chunk(chunk, &mut owned_normalized)
        };

        // Homoglyph normalization: zero-allocation Cow fast path. Pure-ASCII
        // and evasion-free inputs (the 99% case) borrow `chunk.data` directly.
        // Only inputs containing actual homoglyphs/zero-width/RTL allocate.
        let data_to_pp: std::borrow::Cow<'_, str> = if self.config.unicode_normalization {
            unicode_hardening::normalize_homoglyphs(&chunk.data)
        } else {
            std::borrow::Cow::Borrowed(&chunk.data)
        };
        let data_ref: &str = &data_to_pp;

        let preprocessed = if let Some(pp) =
            crate::structured::preprocess(data_ref, chunk.metadata.path.as_deref())
        {
            pp
        } else {
            #[cfg(feature = "multiline")]
            if crate::multiline::has_concatenation_indicators(data_ref) {
                crate::multiline::preprocess_multiline(
                    data_ref,
                    &self.config.multiline,
                    &self.fragment_cache,
                )
            } else {
                ScannerPreprocessedText::passthrough(data_ref)
            }
            #[cfg(not(feature = "multiline"))]
            ScannerPreprocessedText::passthrough(data_ref)
        };

        PreparedChunk {
            chunk: chunk.clone(),
            preprocessed,
        }
    }

    pub(crate) fn scan_prepared_with_triggered(
        &self,
        prepared: PreparedChunk,
        _backend: ScanBackend,
        triggered_patterns: Vec<u64>,
        deadline: Option<std::time::Instant>,
    ) -> Vec<RawMatch> {
        let line_offsets = compute_line_offsets(&prepared.preprocessed.text);
        let code_lines: Vec<&str> = prepared.chunk.data.lines().collect();
        let mut scan_state = ScanState::with_static_intern(self.static_intern.clone());

        #[cfg(feature = "simdsieve")]
        self.scan_hot_patterns_fast(
            &prepared.preprocessed.text,
            &line_offsets,
            &prepared.chunk,
            &mut scan_state,
        );

        let expanded_patterns = self.expand_triggered_patterns(&triggered_patterns);
        // No-trigger fast path: when no AC pattern fired, the entire
        // confirmed-pattern extraction pipeline is dead work. Skip
        // building the `confirmed_patterns: Vec<usize>` (allocation
        // saved), the per-line `documentation_line_flags` scan
        // (~6 µs saved on profile), and the `extract_confirmed_patterns`
        // call. The downstream fallbacks (`scan_generic_assignments`,
        // `scan_entropy_fallback`, `apply_ml_batch_scores`) run
        // unchanged since they have their own input shapes.
        if expanded_patterns.iter().any(|&w| w != 0) {
            let confirmed_patterns: Vec<usize> = (0..self.ac_map.len())
                .filter(|&i| (expanded_patterns[i / 64] & (1 << (i % 64))) != 0)
                .collect();
            let documentation_lines = context::documentation_line_flags(&code_lines);

            self.extract_confirmed_patterns(
                &confirmed_patterns,
                &prepared.preprocessed,
                &line_offsets,
                &code_lines,
                &documentation_lines,
                &prepared.chunk,
                &mut scan_state,
                deadline,
            );
        }

        self.scan_generic_assignments(&code_lines, &line_offsets, &prepared.chunk, &mut scan_state);

        #[cfg(feature = "entropy")]
        self.scan_entropy_fallback(
            &prepared.preprocessed,
            &line_offsets,
            &prepared.chunk,
            &mut scan_state,
        );

        #[cfg(feature = "ml")]
        self.apply_ml_batch_scores(&mut scan_state);

        scan_state.into_matches()
    }

    pub(crate) fn collect_triggered_patterns_for_backend(
        &self,
        text: &str,
        backend: ScanBackend,
    ) -> Vec<u64> {
        match backend {
            // MegaScan reuses the literal-set trigger collection until
            // the regex-NFA pipeline is wired in (task #105). The
            // trigger bitmask shape is identical across both engines so
            // the upstream consumers do not branch.
            ScanBackend::Gpu | ScanBackend::MegaScan => self.collect_triggered_patterns_gpu(text),
            ScanBackend::SimdCpu => self.collect_triggered_patterns_simd(text),
            ScanBackend::CpuFallback => self.collect_triggered_patterns_cpu(text),
        }
    }

    fn collect_triggered_patterns_gpu(&self, text: &str) -> Vec<u64> {
        if let Some(matcher) = self.gpu_matcher() {
            // Graceful fallback if the GPU device went away mid-scan
            // (driver reset, suspend/resume) — never panic.
            let Ok(_dq) = vyre_driver_wgpu::runtime::cached_device() else {
                tracing::debug!("gpu device unavailable, falling back to simd");
                return self.collect_triggered_patterns_simd(text);
            };
            let Some(backend) = self.wgpu_backend.as_ref() else {
                return self.collect_triggered_patterns_simd(text);
            };
            match matcher.scan(&**backend, text.as_bytes(), 10000) {
                Ok(matches) => return self.triggered_patterns_from_gpu_matches(&matches),
                Err(error) => {
                    tracing::debug!("gpu scan failed: {error}");
                }
            }
        }
        self.collect_triggered_patterns_simd(text)
    }

    fn collect_triggered_patterns_simd(&self, text: &str) -> Vec<u64> {
        #[cfg(feature = "simd")]
        if let Some(scanner) = &self.simd_prefilter {
            let mut triggered_patterns = vec![0u64; self.ac_map.len().div_ceil(64)];
            for (hs_id, _start, _end) in scanner.scan(text.as_bytes()) {
                let Some((_detector_index, dedup_id, _has_group)) = scanner.pattern_info(hs_id)
                else {
                    continue;
                };
                if let Some(original_indices) = self.hs_index_map.get(dedup_id) {
                    for &pattern_index in original_indices {
                        self.mark_triggered_pattern(&mut triggered_patterns, pattern_index);
                    }
                }
            }
            return triggered_patterns;
        }

        self.collect_triggered_patterns_cpu(text)
    }

    fn collect_triggered_patterns_cpu(&self, text: &str) -> Vec<u64> {
        let mut triggered_patterns = vec![0u64; self.ac_map.len().div_ceil(64)];
        if let Some(ac) = &self.ac {
            for ac_match in ac.find_iter(text.as_bytes()) {
                self.mark_triggered_pattern(&mut triggered_patterns, ac_match.pattern().as_usize());
            }
        }
        triggered_patterns
    }

    fn triggered_patterns_from_gpu_matches(&self, matches: &[LiteralMatch]) -> Vec<u64> {
        let mut triggered = vec![0u64; self.ac_map.len().div_ceil(64)];
        for matched in matches {
            self.mark_triggered_pattern(&mut triggered, matched.pattern_id as usize);
        }
        triggered
    }

    fn mark_triggered_pattern(&self, triggered_patterns: &mut [u64], pattern_index: usize) {
        if pattern_index / 64 >= triggered_patterns.len() {
            return;
        }
        triggered_patterns[pattern_index / 64] |= 1u64 << (pattern_index % 64);
        if pattern_index < self.prefix_propagation.len() {
            for &propagated_index in &self.prefix_propagation[pattern_index] {
                if propagated_index / 64 < triggered_patterns.len() {
                    triggered_patterns[propagated_index / 64] |= 1u64 << (propagated_index % 64);
                }
            }
        }
    }

    fn degraded_backend_after_gpu_failure(&self) -> ScanBackend {
        #[cfg(feature = "simd")]
        if self.simd_prefilter.is_some() {
            return ScanBackend::SimdCpu;
        }
        ScanBackend::CpuFallback
    }
}

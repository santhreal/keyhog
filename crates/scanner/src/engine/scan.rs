// `scan_filters` is consumed in the `feature = "simd"` arm below (the
// trigger-bitmap / fallback path). Lean builds compile that arm out, so
// gate the glob to match — otherwise rustc warns about an unused import.
#[cfg(feature = "simd")]
use super::scan_filters::*;
use super::*;
#[cfg(feature = "simd")]
use std::cell::RefCell;

// The trigger-buffer pool is only used in the Hyperscan-prefilter
// scratch path of `scan_coalesced` (gated `#[cfg(feature = "simd")]`).
// Without `simd`, both the pool and the helper become dead code,
// so gate them too - otherwise `cargo build --no-default-features`
// (the no-Hyperscan Windows build) emits dead-code warnings.
//
// Note: a previous attempt extended this pool to the per-chunk
// `collect_triggered_patterns_*` builders. That regressed the
// long-lines bench by ~12% because those builders return
// `Vec<u64>` to their callers - the pool can't save the
// allocation, only adds the thread_local + RefCell overhead.
// The pool's win is reuse of buffers that stay inside the pool.
#[cfg(feature = "simd")]
thread_local! {
    /// Per-thread pool of trigger-bitmask vectors. Phase-1 of `scan_coalesced`
    /// allocates one `Vec<u64>` of size `ac_len.div_ceil(64)` per chunk. On a
    /// 100k-file scan with 1500 patterns that's ~2.4M tiny allocations
    /// hammering the global allocator. With this pool, each rayon worker
    /// reuses a single buffer across all the chunks it processes.
    static TRIGGER_POOL: RefCell<Vec<u64>> = const { RefCell::new(Vec::new()) };
}

#[cfg(feature = "simd")]
#[inline]
fn with_trigger_buffer<R>(words_needed: usize, f: impl FnOnce(&mut [u64]) -> R) -> R {
    TRIGGER_POOL.with(|cell| {
        let mut buf = cell.borrow_mut();
        if buf.len() < words_needed {
            buf.resize(words_needed, 0);
        }
        let slice = &mut buf[..words_needed];
        slice.fill(0);
        f(slice)
    })
}

/// Compute the two per-pattern-constant confidence signals.
/// Extracted so both `extract_grouped_matches` and
/// `extract_plain_matches` share the same lazy `OnceCell` init
/// closure body (Rust can't `impl FnOnce<>` to share inline).
/// `pub(super)` so the extract submodule (`engine/extract.rs`) can call
/// it after the scan.rs / extract.rs / process.rs split.
pub(super) fn compute_pattern_signals(detector: &DetectorSpec, chunk: &Chunk) -> (bool, bool) {
    let kw = detector
        .keywords
        .iter()
        .any(|keyword| chunk.data.contains(keyword.as_str()));
    let sf = chunk
        .metadata
        .path
        .as_deref()
        .map(crate::confidence::is_sensitive_path)
        .unwrap_or(false);
    (kw, sf)
}

impl CompiledScanner {
    /// High-throughput coalesced scan: all files scanned in parallel,
    /// zero overhead for non-hit files.
    ///
    /// Architecture:
    ///   Phase 1: Parallel HS prefilter on raw bytes (no prep, no alloc)
    ///   Phase 2: Full extraction only on hit files (~5% of total)
    #[allow(clippy::needless_return)] // return needed under non-simd cfg branch
    pub fn scan_coalesced(&self, chunks: &[keyhog_core::Chunk]) -> Vec<Vec<keyhog_core::RawMatch>> {
        #[cfg(feature = "simd")]
        use crate::hw_probe::ScanBackend;
        use rayon::prelude::*;

        #[cfg(not(feature = "simd"))]
        {
            // Parallel CPU dispatch - same reasoning as scan_chunks_with_backend:
            // the per-chunk scan is independent and CPU-bound.
            let mut results: Vec<Vec<keyhog_core::RawMatch>> =
                chunks.par_iter().map(|c| self.scan(c)).collect();
            super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
            return results;
        }

        #[cfg(feature = "simd")]
        {
            let Some(scanner) = &self.simd_prefilter else {
                // Hyperscan failed to initialize at compile time - fall back
                // to per-chunk parallel SimdCpu (or whichever backend the
                // scanner picks). Was serial; now uses rayon.
                return chunks.par_iter().map(|c| self.scan(c)).collect();
            };

            let ac_len = self.ac_map.len();

            // Phase 1: Parallel HS scan on RAW bytes. No prepare, no Arc, no alloc
            // for non-hit files. Thread-local scratch + a per-worker bitmask
            // POOL eliminate the per-chunk `vec![0u64; …]` alloc - we still
            // need owned Vecs in the result so phase 2 can consume them, but
            // empty-result chunks return `None` and skip the alloc entirely.
            let words_needed = ac_len.div_ceil(64);
            let triggers: Vec<Option<Vec<u64>>> = chunks
                .par_iter()
                .map(|chunk| {
                    let data = chunk.data.as_bytes();
                    with_trigger_buffer(words_needed, |scratch| {
                        for (hs_id, _start, _end) in scanner.scan(data) {
                            let Some((_det, dedup_id, _grp)) = scanner.pattern_info(hs_id) else {
                                continue;
                            };
                            if let Some(orig) = self.hs_index_map.get(dedup_id) {
                                for &idx in orig {
                                    if idx < ac_len {
                                        scratch[idx / 64] |= 1u64 << (idx % 64);
                                    }
                                }
                            }
                        }
                        if scratch.iter().any(|&w| w != 0) {
                            Some(scratch.to_vec())
                        } else {
                            None
                        }
                    })
                })
                .collect();

            let hit_count = triggers.iter().filter(|t| t.is_some()).count();
            let total_hs_matches: usize = triggers
                .iter()
                .filter_map(|t| t.as_ref())
                .map(|t| t.iter().map(|w| w.count_ones() as usize).sum::<usize>())
                .sum();
            tracing::info!(
                files = chunks.len(),
                hits = hit_count,
                hs_matches = total_hs_matches,
                "coalesced scan phase 1 complete"
            );

            // Phase 2: Full extraction on hit files + multiline fallback (parallel).
            let mut results: Vec<Vec<keyhog_core::RawMatch>> = chunks
                .par_iter()
                .zip(triggers.into_par_iter())
                .map(|(chunk, triggered_opt)| {
                    if let Some(triggered) = triggered_opt {
                        let prepared = self.prepare_chunk(chunk);
                        return self.scan_prepared_with_triggered(
                            prepared,
                            ScanBackend::SimdCpu,
                            triggered,
                            None,
                        );
                    }
                    // Multiline fallback: files with concatenation indicators AND
                    // secret-related keywords may contain secrets split across lines
                    // that HS can't match on raw bytes. Only scan these selectively.
                    #[cfg(feature = "multiline")]
                    if crate::multiline::has_concatenation_indicators(&chunk.data)
                        && has_secret_keyword_fast(chunk.data.as_bytes())
                    {
                        return self.scan(chunk);
                    }

                    // Task #69 follow-up: scan_fallback_patterns runs the
                    // keyword-AC-gated prefix-less detectors (kubernetes-
                    // bootstrap-token, asana-pat, mailchimp #3, ...). The
                    // SIMD-hit branch above routes through that call via
                    // scan_prepared_with_triggered; this no-hit branch
                    // historically only ran scan_generic_assignments, so
                    // any chunk WITHOUT a literal-prefix HS hit silently
                    // dropped every fallback detector - including
                    // standalone-on-a-line k8s bootstrap tokens. Fix:
                    // for chunks that plausibly carry a secret (have a
                    // generic-assignment-keyword OR an explicit secret-
                    // prefix substring like ghp_/sk-proj-/etc.) route
                    // through scan_inner, which walks
                    // scan_prepared_with_triggered → scan_fallback_patterns
                    // → scan_generic_assignments → scan_entropy_fallback.
                    //
                    // Bound on plausibility: pure source-code files
                    // without any secret-related keyword stay on the
                    // Vec::new() fast path so the per-chunk prepare +
                    // re-Hyperscan cost doesn't regress monorepo scans
                    // (gitlabhq: 64k mostly-source files would otherwise
                    // pay 64k * ~150µs per-chunk fallback walks). The
                    // gate is intentionally permissive - `token`,
                    // `password`, `secret`, `api_key` cover every config
                    // file shape that planted-credential corpora use.
                    //
                    // Cap stays at 32 KB to match the previous
                    // generic-assignment cap: large source files
                    // (>32 KB) are almost never config and the per-file
                    // fallback walk on Go/Java/Python framework code is
                    // dead work.
                    // Third gate (added 2026-05-29): chunks containing a
                    // contiguous base62 run >= 32 chars - the
                    // generic-high-entropy-string corpus shape (a bare
                    // entropy token with NO keyword anchor). Without
                    // this, that category sat at recall 0.36 on the
                    // SecretBench mirror; the entropy fallback never
                    // saw the chunk because no keyword admitted it.
                    // Hash/UUID FPs are still suppressed downstream by
                    // looks_like_hash_digest / is_uuid_v4_shape, so the
                    // wider gate trades pipeline cost for recall, not
                    // FPs. Cost cap stays at 32 KB so monorepo scans
                    // (gitlabhq, etc.) don't pay per-chunk fallback
                    // walks on >32 KB source files.
                    if chunk.data.len() <= 32 * 1024
                        && (has_generic_assignment_keyword(chunk.data.as_bytes())
                            || has_secret_keyword_fast(chunk.data.as_bytes())
                            || has_high_entropy_run_fast(chunk.data.as_bytes()))
                    {
                        let mut matches = self.scan_inner(chunk, ScanBackend::SimdCpu, None);
                        // KH-01: Pre-allocate raw match output vectors with a capacity of 16 entries to avoid resizing
                        if matches.capacity() < 16 {
                            matches.reserve(16 - matches.len());
                        }
                        // Preserve cross-file fragment reassembly that
                        // the previous no-hit branch did. The fragment
                        // cache is mostly populated by named-detector
                        // matches that scan_inner now produces (e.g.
                        // an `AWS_ACCESS_KEY=` match in one .env file
                        // gets recorded for later reassembly with an
                        // `AWS_SECRET=` match in another).
                        self.record_and_reassemble_for_no_hit_chunk(chunk, &mut matches);
                        return matches;
                    }

                    Vec::new()
                })
                .collect();

            // Cross-chunk reassembly: synthesize a thin boundary buffer
            // from the tail of each chunk + head of its right neighbour
            // (same file, gapless) and scan it. Catches secrets split
            // across the 64 MiB scan-window boundary that in-chunk scan
            // can't see.
            super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
            results
        } // #[cfg(feature = "simd")] block
    } // scan_coalesced

    pub(crate) fn scan_inner(
        &self,
        chunk: &Chunk,
        backend: crate::hw_probe::ScanBackend,
        deadline: Option<std::time::Instant>,
    ) -> Vec<RawMatch> {
        // KH-116: Record scan metrics atomically
        crate::telemetry::record_file_scanned(chunk.data.len());
        if backend == crate::hw_probe::ScanBackend::Gpu
            || backend == crate::hw_probe::ScanBackend::MegaScan
        {
            crate::telemetry::record_gpu_dispatch();
        }
        let prepared = self.prepare_chunk(chunk);
        let triggered =
            self.collect_triggered_patterns_for_backend(&prepared.preprocessed.text, backend);
        self.scan_prepared_with_triggered(prepared, backend, triggered, deadline)
    }

    /// Record each match as a SecretFragment in the cross-file
    /// reassembly cache and scan any reassembled candidates. Lifted
    /// from the inline no-hit branch in scan_coalesced when that branch
    /// was rerouted through scan_inner: scan_inner produces the matches,
    /// and this helper continues the previous fragment-cache flow on
    /// top of them so monorepo scans still pair AWS_ACCESS_KEY in one
    /// .env with AWS_SECRET in another.
    #[cfg(feature = "simd")]
    fn record_and_reassemble_for_no_hit_chunk(&self, chunk: &Chunk, matches: &mut Vec<RawMatch>) {
        // KH-01: Pre-allocate raw match output vectors with a capacity of 16 entries to avoid resizing
        let mut reassembled_candidates = Vec::with_capacity(16);
        // Pre-allocate the path Arc once per chunk: every match in a
        // single chunk shares the same path, so cloning an Arc<str>
        // reference is cheaper than cloning the owned String per-match.
        let path_arc: Option<std::sync::Arc<str>> = chunk
            .metadata
            .path
            .as_deref()
            .map(std::sync::Arc::<str>::from);
        if matches.capacity() < matches.len() + 16 {
            matches.reserve(16);
        }
        for m in matches.iter() {
            if let Some(path) = path_arc.as_ref() {
                let fragment = crate::fragment_cache::SecretFragment {
                    prefix: m.detector_id.to_string(),
                    var_name: m.detector_name.to_string(),
                    value: zeroize::Zeroizing::new(m.credential.to_string()),
                    line: m.location.line.unwrap_or(0),
                    path: Some(std::sync::Arc::clone(path)),
                };
                let reassembled = self.fragment_cache.record_and_reassemble(fragment);
                reassembled_candidates.extend(reassembled);
            }
        }
        for candidate in reassembled_candidates {
            // candidate is Zeroizing<String> - scrubbed when this
            // iteration ends.
            let entropy = crate::pipeline::match_entropy(candidate.as_bytes());
            if entropy < 3.0 || candidate.len() < 16 {
                continue;
            }
            let mut dummy_data = String::with_capacity(candidate.len() + 24);
            dummy_data.push_str("reassembled_key = \"");
            dummy_data.push_str(candidate.as_str());
            dummy_data.push('"');
            let dummy_chunk = Chunk {
                data: dummy_data.into(),
                metadata: chunk.metadata.clone(),
            };
            // Tiny synthesized chunk; skip GPU unconditionally -
            // per-dispatch overhead dwarfs the work. Matches the
            // scan_cross_chunk_fragments rationale.
            let backend = crate::hw_probe::ScanBackend::SimdCpu;
            let mut reassembled_matches = self.scan_inner(&dummy_chunk, backend, None);
            matches.append(&mut reassembled_matches);
        }
    }
}

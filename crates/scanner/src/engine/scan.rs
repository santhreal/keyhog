// `scan_filters` is consumed by `should_scan_no_hit_chunk` (the no-phase-1-hit
// admission gate) on the shared phase-2 tail. That tail is reached by the
// coalesced producer (`simd`) and the GPU megakernel — and `gpu` implies `simd`
// at the feature level (the megakernel reuses this very tail), so `simd` is the
// exact reachability of the tail. A no-`simd` build (portable / ci / full)
// compiles the gate out entirely, so gating the glob to match keeps the import
// from going unused there (no warning).
#[cfg(feature = "simd")]
use super::scan_filters::*;
use super::scan_inner_profile::{
    scan_inner_prof_enabled, SCAN_INNER_CALLS, SCAN_PHASE1_NS, SCAN_PREPARE_NS,
};
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

impl CompiledScanner {
    /// High-throughput coalesced scan: all files scanned in parallel,
    /// zero overhead for non-hit files.
    ///
    /// Architecture:
    ///   Phase 1: Parallel HS prefilter on raw bytes (no prep, no alloc)
    ///   Phase 2: Full extraction only on hit files (~5% of total)
    #[allow(clippy::needless_return)] // return needed under non-simd cfg branch
    pub fn scan_coalesced(&self, chunks: &[keyhog_core::Chunk]) -> Vec<Vec<keyhog_core::RawMatch>> {
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
                // scanner picks), then preserve cross-window boundary recall.
                let mut results: Vec<Vec<keyhog_core::RawMatch>> =
                    chunks.par_iter().map(|c| self.scan(c)).collect();
                super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
                return results;
            };

            // Phase 1 (trigger production) is the swappable backend boundary:
            // the Hyperscan literal prefilter here, or the GPU DFA megakernel in
            // `scan_coalesced_megakernel`. Both yield the same per-chunk
            // `Option<Vec<u64>>` bitmap and feed the SAME `scan_coalesced_phase2`.
            let triggers = self.compute_coalesced_triggers(chunks, scanner);
            return self.scan_coalesced_phase2(chunks, triggers);
        } // #[cfg(feature = "simd")] block
    } // scan_coalesced

    /// Phase 1 of the coalesced scan: the Hyperscan literal prefilter over raw
    /// chunk bytes, producing one `Option<Vec<u64>>` trigger bitmap per chunk
    /// (`None` = no detector literal present → routes to the keyword/entropy
    /// no-hit branch in phase 2). This is the CPU trigger-production backend; the
    /// GPU megakernel is the alternative producer feeding the same phase 2.
    #[cfg(feature = "simd")]
    pub(crate) fn compute_coalesced_triggers(
        &self,
        chunks: &[keyhog_core::Chunk],
        scanner: &crate::simd::backend::HsScanner,
    ) -> Vec<Option<Vec<u64>>> {
        use rayon::prelude::*;
        let ac_len = self.ac_map.len();

        // Parallel HS scan on RAW bytes. No prepare, no Arc, no alloc for
        // non-hit files. Thread-local scratch + a per-worker bitmask POOL
        // eliminate the per-chunk `vec![0u64; …]` alloc - we still need owned
        // Vecs in the result so phase 2 can consume them, but empty-result
        // chunks return `None` and skip the alloc entirely.
        let words_needed = ac_len.div_ceil(64);
        let triggers: Vec<Option<Vec<u64>>> = chunks
            .par_iter()
            .map(|chunk| {
                let data = chunk.data.as_bytes();
                // Cheap O(n) content prefilters before the Hyperscan automaton
                // walk: alphabet set + bigram bloom. The bloom (a single
                // 4096-bit pass) rejects the majority of files that carry no
                // detector literal-prefix, eliding the Hyperscan scratch scan.
                // Same gates, ordering, and `>= 64`-byte bloom guard as the
                // per-chunk mod.rs path, so behaviour is identical. A rejected
                // chunk returns `None` (no trigger), routing phase 2 down the
                // keyword/entropy fallback branch like a genuine no-hit chunk.
                let alphabet_rejected = self
                    .alphabet_screen
                    .as_ref()
                    .is_some_and(|screen| !screen.screen(data));
                if alphabet_rejected
                    || (data.len() >= 64 && !self.bigram_bloom.maybe_overlaps(data))
                {
                    return None;
                }
                with_trigger_buffer(words_needed, |scratch| {
                    for (hs_id, _start, _end) in scanner.scan(data) {
                        let Some((_det, dedup_id, _grp)) = scanner.pattern_info(hs_id) else {
                            continue;
                        };
                        if let Some(orig) = self.hs_index_map.get(dedup_id) {
                            for &idx in orig {
                                let idx = idx as usize;
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

        // The phase-1 telemetry is purely a tracing::info! line, off at the
        // default log level. `total_hs_matches` is a full popcount pass over
        // every hit bitmap; gate the whole summary behind an enabled check so
        // the default path pays nothing.
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
                hs_matches = total_hs_matches,
                "coalesced scan phase 1 complete"
            );
        }
        triggers
    }

    #[cfg(feature = "simd")]
    /// No-hit chunk admission: should a chunk that produced NO phase-1 trigger
    /// (no Hyperscan literal-prefix hit) still be driven through the phase-2
    /// fallback / generic / entropy tail?
    ///
    /// A `false` here drops the chunk to `Vec::new()` BEFORE any preprocessing —
    /// so this gate is the only thing between a no-literal chunk and the silent
    /// loss of every prefix-less / keyword-less fallback detector on it (asana-pat
    /// and ~3100 similar, issue #69). It is therefore recall-load-bearing, and is
    /// shared verbatim by the SIMD-coalesced and GPU-megakernel paths (both feed
    /// `scan_coalesced_phase2`) so a finding can never depend on which backend
    /// produced the triggers (Law 10).
    ///
    /// Admit when ANY holds:
    ///   1. the chunk activates an always-active / keyword fallback pattern
    ///      (`has_active_fallback_patterns_for_chunk` runs the real active-set
    ///      prefilter — the exact, cheap necessary condition for a fallback
    ///      match, with no 32 KiB cap because anchorless detectors are size-blind);
    ///   2. multiline-concatenated secrets are plausible (concatenation
    ///      indicators + a secret keyword) — these split across lines so no single
    ///      literal fires;
    ///   3. the chunk is ≤32 KiB and carries a generic-assignment or secret
    ///      keyword, or a high-entropy run on an entropy-appropriate path — the
    ///      generic-assignment and entropy stages' own admission policy.
    //
    // Gated `simd` (on the doc attr above): this is consumed only by
    // `scan_coalesced_phase2`, the SHARED no-hit tail fed by BOTH the
    // SIMD-coalesced producer AND the GPU megakernel dispatch. `gpu` implies
    // `simd` (the megakernel reuses this very tail — see keyhog-scanner
    // Cargo.toml), so `simd` is the exact reachability of the tail under both
    // backends; a no-`simd` build (portable / ci / full) never reaches it.
    pub(crate) fn should_scan_no_hit_chunk(&self, chunk: &keyhog_core::Chunk) -> bool {
        // (1) Recall gate: does any fallback pattern actually activate here?
        if self.has_active_fallback_patterns_for_chunk(&chunk.data) {
            return true;
        }
        let data = chunk.data.as_bytes();
        // (2) Multiline-concatenated secret plausibility (no size cap).
        #[cfg(feature = "multiline")]
        if crate::multiline::has_concatenation_indicators(&chunk.data)
            && has_secret_keyword_fast(data)
        {
            return true;
        }
        // (3) Generic-assignment / secret-keyword / entropy admission, ≤32 KiB.
        let entropy_admits = self.config.entropy_enabled
            && crate::entropy::is_entropy_appropriate(
                chunk.metadata.path.as_deref(),
                self.config.entropy_in_source_files,
            )
            && has_high_entropy_run_fast(data);
        chunk.data.len() <= 32 * 1024
            && (has_generic_assignment_keyword(data)
                || has_secret_keyword_fast(data)
                || entropy_admits)
    }

    /// The SHARED phase-2 tail: both the SIMD-coalesced producer
    /// (`scan_coalesced`, `#[cfg(simd)]`) and the GPU megakernel dispatch
    /// (`megakernel_dispatch`, `#[cfg(gpu)]`) feed their per-chunk trigger
    /// bitmaps into THIS one function, so findings are backend-invariant.
    /// `gpu` implies `simd` (the megakernel reuses this tail — see
    /// keyhog-scanner Cargo.toml), so it (and its exclusive helpers
    /// `should_scan_no_hit_chunk` / `record_and_reassemble_for_no_hit_chunk`) is
    /// gated on `simd` — compiled exactly when it has a caller. A no-`simd`
    /// profile (`portable` / `full` / `ci`) scans through the AC+fallback path
    /// and never reaches here, so compiling this tail there would be dead code
    /// that references the `simd`-only helpers and breaks the build outright.
    #[cfg(feature = "simd")]
    pub(crate) fn scan_coalesced_phase2(
        &self,
        chunks: &[keyhog_core::Chunk],
        triggers: Vec<Option<Vec<u64>>>,
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        use crate::hw_probe::ScanBackend;
        use rayon::prelude::*;

        let _p2 = std::time::Instant::now();
        let mut results: Vec<Vec<keyhog_core::RawMatch>> = chunks
            .par_iter()
            .zip(triggers.into_par_iter())
            .map(|(chunk, triggered_opt)| {
                    if let Some(triggered) = triggered_opt {
                        // Shared windowing contract (see `scan_chunk_or_window`):
                        // a >1 MiB chunk is windowed so the per-chunk match cap
                        // can't silently truncate it, exactly like the per-file
                        // and GPU phase-2 paths. (This is also where the GPU AC
                        // dense-prefix reroute lands, so it fixes forced-GPU
                        // recall on large files.)
                        return self.scan_chunk_or_window(chunk, None, || {
                            let prepared = self.prepare_chunk(chunk);
                            self.scan_prepared_with_triggered(
                                prepared,
                                ScanBackend::SimdCpu,
                                triggered,
                                None,
                            )
                        });
                    }
                    // No phase-1 trigger fired. The shared no-hit admission gate
                    // (`should_scan_no_hit_chunk` — recall-load-bearing, see its
                    // doc) decides whether the prefix-less / keyword-less fallback
                    // detectors, generic-assignment and entropy stages get a shot
                    // on this chunk; a `false` drops to the zero-work fast path
                    // WITHOUT preprocessing. The gate consults
                    // `has_active_fallback_patterns_for_chunk` FIRST, so a chunk
                    // that activates an anchorless / keyword-less detector (asana-
                    // pat and ~3100 similar, issue #69) is admitted even with no
                    // generic-assignment keyword — closing the silent recall drop
                    // the bare keyword gate left open (Law 10). Identical contract
                    // for the SIMD-coalesced and GPU-megakernel producers (both
                    // feed this tail), so findings are backend-invariant.
                    if !self.should_scan_no_hit_chunk(chunk) {
                        return Vec::new();
                    }

                    // Admitted. Reuse phase 1's empty Hyperscan result rather than
                    // re-running the automaton: prepare the chunk and drive
                    // `scan_prepared_with_triggered` with an EMPTY trigger bitmap,
                    // so the keyword-AC fallback, generic-assignment and entropy
                    // stages run off `code_lines` / preprocessed text with no
                    // second HS pass. Confirmed-pattern extraction is correctly
                    // skipped (no AC pattern fired). Recollect triggers ONLY on the
                    // rare structured-preprocessor drift where the preprocessed
                    // text differs from the raw bytes phase 1 scanned (decoded /
                    // appended credential lines can carry named-detector literal
                    // roots — this also covers the multiline-concatenation case).
                    let prepared = self.prepare_chunk(chunk);
                    let triggered =
                        if prepared.preprocessed.text.as_bytes() == chunk.data.as_bytes() {
                            Vec::new()
                        } else {
                            self.collect_triggered_patterns_for_backend(
                                &prepared.preprocessed.text,
                                ScanBackend::SimdCpu,
                            )
                        };
                    let mut matches = self.scan_prepared_with_triggered(
                        prepared,
                        ScanBackend::SimdCpu,
                        triggered,
                        None,
                    );
                    // Preserve cross-file fragment reassembly the previous no-hit
                    // branch did: named-detector matches feed cross-`.env`
                    // reassembly (e.g. an `AWS_ACCESS_KEY=` match in one file is
                    // recorded for reassembly with an `AWS_SECRET=` match in
                    // another).
                    self.record_and_reassemble_for_no_hit_chunk(chunk, &mut matches);
                    matches
                })
                .collect();

        let _p2e = _p2.elapsed();
        // Cross-chunk reassembly: synthesize a thin boundary buffer from the
        // tail of each chunk + head of its right neighbour (same file, gapless)
        // and scan it. Catches secrets split across the 64 MiB scan-window
        // boundary that in-chunk scan can't see.
        let _bt = std::time::Instant::now();
        super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
        if std::env::var_os("KH_PERF").is_some() {
            eprintln!(
                "KH_PERF scan_coalesced_phase2: chunks={} p2={:.3}s boundary={:.3}s",
                chunks.len(),
                _p2e.as_secs_f64(),
                _bt.elapsed().as_secs_f64()
            );
        }
        results
    }

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
        let prof = scan_inner_prof_enabled();
        let t0 = prof.then(std::time::Instant::now);
        let prepared = self.prepare_chunk(chunk);
        if let Some(t) = t0 {
            SCAN_PREPARE_NS.fetch_add(
                t.elapsed().as_nanos() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
        }
        let t1 = prof.then(std::time::Instant::now);
        let triggered =
            self.collect_triggered_patterns_for_backend(&prepared.preprocessed.text, backend);
        if let Some(t) = t1 {
            SCAN_PHASE1_NS.fetch_add(
                t.elapsed().as_nanos() as u64,
                std::sync::atomic::Ordering::Relaxed,
            );
            SCAN_INNER_CALLS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
        self.scan_prepared_with_triggered(prepared, backend, triggered, deadline)
    }

    /// Record each match as a SecretFragment in the cross-file
    /// reassembly cache and scan any reassembled candidates. Lifted
    /// from the inline no-hit branch in scan_coalesced when that branch
    /// was rerouted through scan_inner: scan_inner produces the matches,
    /// and this helper continues the previous fragment-cache flow on
    /// top of them so monorepo scans still pair AWS_ACCESS_KEY in one
    /// .env with AWS_SECRET in another.
    // `simd`: exclusive helper of `scan_coalesced_phase2` (the shared tail).
    // `gpu` implies `simd`, so the megakernel path carries it too — `simd` is
    // the exact reachability under both backends.
    #[cfg(feature = "simd")]
    fn record_and_reassemble_for_no_hit_chunk(&self, chunk: &Chunk, matches: &mut Vec<RawMatch>) {
        if matches.is_empty() {
            return;
        }
        // Fast plausibility gate before paying three String allocs per
        // match (prefix/var_name/value) and the sharded fragment-cache
        // mutex per record. Cross-file reassembly only fires for fragments
        // that carry assignment-like syntax (a `=`/`:` plus a quote, the
        // `var = "value"` shape the fragment cache pairs on). A chunk with
        // no such syntax cannot contribute a poolable fragment, so the
        // record + lock + reassemble work is dead. Mirrors the
        // `has_fragment_assignment_syntax` check in scan_postprocess.rs;
        // inlined here (it is private to that module) to keep this on a
        // single cheap memchr pass.
        let data = chunk.data.as_bytes();
        let has_assignment =
            memchr::memchr(b'=', data).is_some() || memchr::memchr(b':', data).is_some();
        let has_quote = memchr::memchr(b'"', data).is_some()
            || memchr::memchr(b'\'', data).is_some()
            || memchr::memchr(b'`', data).is_some();
        if !(has_assignment && has_quote) {
            return;
        }
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
                // Stamped variant: cross-file pooling is impossible now
                // (scoped_key keys on the full path), and each candidate
                // carries the anchor fragment's real path/line so the
                // synthesized finding is attributed to the contributing
                // file rather than to the current chunk's metadata.
                let reassembled = self.fragment_cache.record_and_reassemble_stamped(fragment);
                reassembled_candidates.extend(reassembled);
            }
        }
        for candidate in reassembled_candidates {
            // candidate.value is Zeroizing<String> - scrubbed when this
            // iteration ends.
            let entropy = crate::pipeline::match_entropy(candidate.value.as_bytes());
            if entropy < 3.0 || candidate.value.len() < 16 {
                continue;
            }
            let mut dummy_data = String::with_capacity(candidate.value.len() + 24);
            dummy_data.push_str("reassembled_key = \"");
            dummy_data.push_str(candidate.value.as_str());
            dummy_data.push('"');
            // Stamp the dummy chunk's metadata from the ANCHOR fragment's
            // path, not chunk.metadata.clone(): the contributing
            // fragment may have come from a different file than the chunk
            // currently being scanned (same coalesced batch). Falling
            // back to chunk.metadata is only for the shouldn't-happen
            // case where the anchor lost its path.
            let mut dummy_metadata = chunk.metadata.clone();
            if let Some(frag_path) = candidate.path.as_deref() {
                dummy_metadata.path = Some(frag_path.to_string());
            }
            let dummy_chunk = Chunk {
                data: dummy_data.into(),
                metadata: dummy_metadata,
            };
            // Tiny synthesized chunk; skip GPU unconditionally -
            // per-dispatch overhead dwarfs the work. Matches the
            // scan_cross_chunk_fragments rationale.
            let backend = crate::hw_probe::ScanBackend::SimdCpu;
            let mut reassembled_matches = self.scan_inner(&dummy_chunk, backend, None);
            // Point each reassembled finding at the anchor fragment's
            // real source line so the finding's location matches the file
            // its metadata now names.
            for rm in &mut reassembled_matches {
                rm.location.line = Some(candidate.line);
            }
            matches.append(&mut reassembled_matches);
        }
    }
}

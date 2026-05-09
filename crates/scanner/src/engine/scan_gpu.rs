use super::*;

impl CompiledScanner {
    /// GPU coalesced scan via one vyre `RulePipeline` (regex-NFA)
    /// dispatch. When the regex compile failed (vyre's
    /// per-subgroup state cap or unsupported regex syntax) or the
    /// coalesced buffer exceeds the pipeline's pre-built input_len
    /// cap, gracefully degrades to the literal-set GPU dispatch
    /// (`scan_coalesced_gpu`). Same per-chunk extraction phase as
    /// the literal-set path, same trigger-bitmask shape — the only
    /// thing that changes is which GPU primitive produced the raw
    /// `(pattern_id, start, end)` triples.
    pub fn scan_coalesced_megascan(
        &self,
        chunks: &[keyhog_core::Chunk],
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        use crate::hw_probe::ScanBackend;

        let Some(pipeline) = self.rule_pipeline() else {
            tracing::debug!(
                "MegaScan: regex pipeline unavailable, dispatching via literal-set GPU"
            );
            return self.scan_coalesced_gpu(chunks);
        };
        let Ok(_dq) = vyre_driver_wgpu::runtime::cached_device() else {
            return self.scan_coalesced_gpu(chunks);
        };
        let Some(backend) = self.wgpu_backend.as_ref() else {
            return self.scan_coalesced_gpu(chunks);
        };

        let (entries, buffer) = coalesce_chunks(chunks);

        // Pipeline was pre-built for at most MEGASCAN_INPUT_LEN bytes;
        // bigger batches can't dispatch. Auto-degrade rather than
        // truncate (truncation = silent false negatives).
        if buffer.len() > MEGASCAN_INPUT_LEN {
            tracing::debug!(
                buffer_bytes = buffer.len(),
                input_len = MEGASCAN_INPUT_LEN,
                "MegaScan: batch exceeds RulePipeline input_len cap, falling back to literal-set GPU"
            );
            return self.scan_coalesced_gpu(chunks);
        }

        #[cfg(target_os = "linux")]
        // SAFETY: same contract as scan_coalesced_gpu — `buffer` is a
        // live owned Vec describing a valid range; madvise is advisory.
        unsafe {
            libc::madvise(
                buffer.as_ptr() as *mut libc::c_void,
                buffer.len(),
                libc::MADV_DONTDUMP,
            );
        }

        // Same buffer-scaled cap as the literal-set path.
        const MIN_CAP: u32 = 100_000;
        const MAX_CAP: u32 = 16_000_000;
        let buffer_cap = (buffer.len() / 64) as u64;
        let cap: u32 = buffer_cap.clamp(MIN_CAP as u64, MAX_CAP as u64) as u32;
        let max_matches = cap.saturating_add(1);

        let started = std::time::Instant::now();
        let raw_matches = match pipeline.scan(&**backend, &buffer, max_matches) {
            Ok(matches) => matches,
            Err(error) => {
                tracing::error!(
                    %error,
                    "MegaScan dispatch failed — falling back to literal-set GPU"
                );
                return self.scan_coalesced_gpu(chunks);
            }
        };
        let elapsed_ms = started.elapsed().as_millis();
        tracing::debug!(
            target: "keyhog::routing",
            chunks = chunks.len(),
            buffer_bytes = buffer.len(),
            matches = raw_matches.len(),
            cap,
            elapsed_ms,
            "MegaScan RulePipeline scan completed"
        );

        if raw_matches.len() > cap as usize {
            tracing::warn!(
                cap,
                "MegaScan exceeded cap — truncation possible; dispatching via literal-set GPU"
            );
            return self.scan_coalesced_gpu(chunks);
        }

        let mut matches: Vec<vyre_libs::matching::LiteralMatch> = {
            use vyre_libs::matching::{dedup_regions_inplace, LiteralMatch, RegionTriple};
            let mut triples: Vec<RegionTriple> = raw_matches
                .iter()
                .map(|m| RegionTriple::new(m.pattern_id, m.start, m.end))
                .collect();
            dedup_regions_inplace(&mut triples);
            triples
                .into_iter()
                .map(|t| LiteralMatch::new(t.pid, t.start, t.end))
                .collect()
        };
        matches.sort_unstable_by_key(|m| m.start);

        let total_patterns = self.ac_map.len() + self.fallback.len();
        let mut per_chunk_triggers: Vec<Vec<u64>> = chunks
            .iter()
            .map(|_| vec![0u64; total_patterns.div_ceil(64)])
            .collect();
        let mut cursor = 0usize;
        for matched in &matches {
            let global_start = matched.start as usize;
            let global_end = matched.end as usize;
            while cursor < entries.len() {
                let (_, offset, len) = entries[cursor];
                if global_start < offset + len {
                    break;
                }
                cursor += 1;
            }
            if cursor >= entries.len() {
                break;
            }
            let (chunk_index, offset, len) = entries[cursor];
            if global_start < offset || global_end > offset + len {
                continue;
            }
            let pattern_index = matched.pattern_id as usize;
            if pattern_index < total_patterns {
                per_chunk_triggers[chunk_index][pattern_index / 64] |= 1u64 << (pattern_index % 64);
            }
        }

        use rayon::prelude::*;
        let mut results: Vec<Vec<keyhog_core::RawMatch>> = chunks
            .par_iter()
            .zip(per_chunk_triggers.into_par_iter())
            .map(|(chunk, triggered)| {
                let prepared = self.prepare_chunk(chunk);
                let mut matches = self.scan_prepared_with_triggered(
                    prepared,
                    ScanBackend::MegaScan,
                    triggered,
                    None,
                );
                self.post_process_matches(chunk, &mut matches, None);
                matches
            })
            .collect();

        // Same boundary reassembly as the literal-set path.
        super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
        results
    }

    /// GPU coalesced scan via the vyre megakernel `BatchDispatcher`.
    /// Single persistent kernel launch handles every chunk × every
    /// detector literal, replacing the N-shard `GpuLiteralSet::scan`
    /// loop in `scan_coalesced_gpu`. Per-chunk extraction phase still
    /// runs CPU-side after the trigger bitmask is decoded — the
    /// architectural step that moves extraction onto GPU is a
    /// separate megakernel opcode handler set, tracked in
    /// `docs/vyre-usage.md` next-wires #8 step 7.
    ///
    /// Falls back to `scan_coalesced_gpu` when the megakernel can't
    /// be initialised (no adapter, no literals, dispatcher init
    /// failure, dispatch error mid-batch).
    pub fn scan_coalesced_megakernel(
        &self,
        chunks: &[keyhog_core::Chunk],
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        use crate::hw_probe::ScanBackend;

        let Some(megakernel) = self.megakernel_scanner() else {
            tracing::debug!(
                "Megakernel: not initialised, falling back to literal-set GPU"
            );
            return self.scan_coalesced_gpu(chunks);
        };

        let triggers_opt = {
            let mut guard = megakernel.lock();
            guard.dispatch_triggers(chunks)
        };
        let Some(per_chunk_triggers) = triggers_opt else {
            return self.scan_coalesced_gpu(chunks);
        };

        // Same per-chunk extraction phase as scan_coalesced_gpu: rayon
        // par_iter over (chunk, triggers), prepare_chunk,
        // scan_prepared_with_triggered, post_process_matches, then
        // boundary reassembly across contiguous chunks.
        use rayon::prelude::*;
        let mut results: Vec<Vec<keyhog_core::RawMatch>> = chunks
            .par_iter()
            .zip(per_chunk_triggers.into_par_iter())
            .map(|(chunk, triggered)| {
                let prepared = self.prepare_chunk(chunk);
                let mut matches = self.scan_prepared_with_triggered(
                    prepared,
                    ScanBackend::Gpu,
                    triggered,
                    None,
                );
                self.post_process_matches(chunk, &mut matches, None);
                matches
            })
            .collect();

        super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
        results
    }

    /// GPU coalesced scan via one Vyre literal-set dispatch.
    pub fn scan_coalesced_gpu(
        &self,
        chunks: &[keyhog_core::Chunk],
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        use crate::hw_probe::ScanBackend;

        // Auto-degrade to the next-best backend when the GPU stack is not
        // ready: no compiled matcher (no adapter at probe time), the cached
        // device went away, or the persistent backend is missing.
        let Some(matcher) = self.gpu_matcher() else {
            return self.scan_coalesced_non_gpu(chunks);
        };
        let Ok(_dq) = vyre_driver_wgpu::runtime::cached_device() else {
            tracing::debug!("gpu device unavailable, falling back to non-gpu coalesced scan");
            return self.scan_coalesced_non_gpu(chunks);
        };
        let Some(backend) = self.wgpu_backend.as_ref() else {
            return self.scan_coalesced_non_gpu(chunks);
        };

        let (entries, buffer) = coalesce_chunks(chunks);

        #[cfg(target_os = "linux")]
        // SAFETY: `buffer` is a live `Vec<u8>` whose `as_ptr()` and
        // `len()` describe a valid memory range owned by this scope.
        // `madvise` is advisory — the kernel may ignore it on
        // non-page-aligned ranges; we treat the call as best-effort
        // and don't check the return value.
        unsafe {
            // Senior Audit §Phase 7.4: Prevent GPU buffers from leaking into core dumps.
            libc::madvise(
                buffer.as_ptr() as *mut libc::c_void,
                buffer.len(),
                libc::MADV_DONTDUMP,
            );
        }

        // Adaptive match cap that scales with the actual buffer size
        // rather than chunk count. Real-world ceiling: roughly one
        // literal hit per 64 input bytes is already implausibly dense
        // for production source code (the densest fixture in the
        // performance regression suite is ~1 hit per 1 KiB). The
        // chunk-count formula systematically under-sized batches that
        // had a few large files, leading to spurious truncation and
        // the full-CPU re-scan that wastes the GPU dispatch we just
        // paid for.
        //
        // Keeps the kimi-wave2 `cap+1` sentinel-slot trick: ask the
        // GPU for one more than the cap, and only treat `> cap` as
        // truncation. A batch that lands EXACTLY at the cap is by
        // definition complete (would have written into the sentinel
        // slot otherwise).
        const MIN_CAP: u32 = 100_000;
        const MAX_CAP: u32 = 16_000_000;
        let buffer_cap = (buffer.len() / 64) as u64;
        let cap: u32 = buffer_cap.clamp(MIN_CAP as u64, MAX_CAP as u64) as u32;

        // wgpu caps each compute dispatch at 65535 workgroups per
        // dimension (WebGPU spec). Vyre's GpuLiteralSet uses
        // workgroup_size_x = 32, so a single dispatch can handle at
        // most 65535 × 32 = 2,097,120 input bytes. For coalesced
        // batches larger than this (which is now typical with the
        // tier-aware 2 MiB activation threshold + the orchestrator's
        // 256 MiB BATCH_BYTES_BUDGET), shard the buffer into
        // 2-MiB-or-less pieces, dispatch each, and merge the matches
        // with a `start` offset added to put them back into the
        // global buffer's coordinate space.
        //
        // Shard size: 65535 (max workgroups per dim) × 32 (vyre's
        // workgroup_size_x) = 2,097,120 bytes. Exactly 2 MiB =
        // 2,097,152 bytes overflows by one workgroup. Use the
        // exact-aligned value to maximise per-shard throughput
        // without tripping the wgpu dispatch validator.
        //
        // Extra dispatches add ~100 µs each on a high-tier GPU; for
        // a 256 MiB batch that's ~12 ms of overhead vs SIMD's ~70 s
        // — still a 5800× win.
        const GPU_DISPATCH_MAX_BYTES: usize = 65_535 * 32;
        let started = std::time::Instant::now();
        let mut matches: Vec<vyre_libs::matching::LiteralMatch> = Vec::new();
        let mut shard_count = 0usize;
        let mut shard_start = 0usize;
        while shard_start < buffer.len() {
            let shard_end = (shard_start + GPU_DISPATCH_MAX_BYTES).min(buffer.len());
            let shard = &buffer[shard_start..shard_end];
            // Per-shard cap scales the same way: hits / 64 bytes.
            let shard_cap_u64 = (shard.len() / 64) as u64;
            let shard_cap = shard_cap_u64.clamp(MIN_CAP as u64, MAX_CAP as u64) as u32;
            let shard_max = shard_cap.saturating_add(1);
            let shard_matches = match matcher.scan(&**backend, shard, shard_max) {
                Ok(m) => m,
                Err(e) => {
                    tracing::error!(
                        shard_start,
                        shard_len = shard.len(),
                        "GPU shard scan failed, falling back to CPU: {e}"
                    );
                    return self.scan_coalesced_non_gpu(chunks);
                }
            };
            if shard_matches.len() > shard_cap as usize {
                tracing::warn!(
                    cap = shard_cap,
                    shard_start,
                    shard_len = shard.len(),
                    "GPU shard exceeded its cap — truncation possible; falling back to CPU"
                );
                return self.scan_coalesced_non_gpu(chunks);
            }
            // Re-base shard-local offsets into global buffer coords.
            let offset = shard_start as u32;
            for m in &shard_matches {
                matches.push(vyre_libs::matching::LiteralMatch::new(
                    m.pattern_id,
                    m.start.saturating_add(offset),
                    m.end.saturating_add(offset),
                ));
            }
            shard_count += 1;
            shard_start = shard_end;
        }
        let elapsed_ms = started.elapsed().as_millis();
        tracing::debug!(
            target: "keyhog::routing",
            chunks = chunks.len(),
            buffer_bytes = buffer.len(),
            matches = matches.len(),
            shards = shard_count,
            cap,
            elapsed_ms,
            "vyre GPU scan completed"
        );
        // (Sharded path handles per-shard truncation above; no
        // whole-buffer truncation check needed here.)
        // Per-pid region dedup via the shared vyre primitive instead of
        // re-implementing span coalescing here. `dedup_regions_inplace`
        // sorts by `(pid, start, end)` and folds same-pid overlapping
        // spans, eliminating the redundant downstream trigger-bitmask
        // bumps that duplicate `(pid, start, end)` triples used to
        // cause. We then re-sort by `start` for the chunk-attribution
        // walk that follows.
        {
            use vyre_libs::matching::{dedup_regions_inplace, RegionTriple};
            let mut triples: Vec<RegionTriple> = matches
                .iter()
                .map(|m| RegionTriple::new(m.pattern_id, m.start, m.end))
                .collect();
            dedup_regions_inplace(&mut triples);
            matches.clear();
            matches.extend(
                triples
                    .into_iter()
                    .map(|t| vyre_libs::matching::LiteralMatch::new(t.pid, t.start, t.end)),
            );
        }
        matches.sort_unstable_by_key(|matched| matched.start);

        let total_patterns = self.ac_map.len() + self.fallback.len();
        let mut per_chunk_triggers: Vec<Vec<u64>> = chunks
            .iter()
            .map(|_| vec![0u64; total_patterns.div_ceil(64)])
            .collect();

        let mut cursor = 0usize;
        for matched in &matches {
            let global_start = matched.start as usize;
            let global_end = matched.end as usize;
            while cursor < entries.len() {
                let (_, offset, len) = entries[cursor];
                if global_start < offset + len {
                    break;
                }
                cursor += 1;
            }
            if cursor >= entries.len() {
                break;
            }

            let (chunk_index, offset, len) = entries[cursor];
            if global_start < offset || global_end > offset + len {
                continue;
            }
            let pattern_index = matched.pattern_id as usize;
            if pattern_index < total_patterns {
                per_chunk_triggers[chunk_index][pattern_index / 64] |= 1u64 << (pattern_index % 64);
            }
        }

        use rayon::prelude::*;
        let mut results: Vec<Vec<keyhog_core::RawMatch>> = chunks
            .par_iter()
            .zip(per_chunk_triggers.into_par_iter())
            .map(|(chunk, triggered)| {
                let prepared = self.prepare_chunk(chunk);
                let mut matches =
                    self.scan_prepared_with_triggered(prepared, ScanBackend::Gpu, triggered, None);
                self.post_process_matches(chunk, &mut matches, None);
                matches
            })
            .collect();

        // Cross-chunk boundary reassembly: identical contract to the
        // SIMD path. Without this, a secret straddling the seam between
        // two adjacent windows of one big file slips through the GPU
        // dispatch (the inter-chunk separator bytes intentionally make
        // the literal-set engine ignore the seam) AND through the
        // per-chunk extraction loop above (each chunk only sees its
        // own slice). The boundary helper synthesises a thin tail+head
        // buffer per gapless pair and rescans it on the CPU path, so
        // GPU users get the same recall as SIMD users on big files.
        super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
        results
    }
}

impl CompiledScanner {
    /// Non-GPU coalesced fallback path used when the GPU stack is unavailable.
    fn scan_coalesced_non_gpu(
        &self,
        chunks: &[keyhog_core::Chunk],
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        #[cfg(feature = "simd")]
        {
            self.scan_coalesced(chunks)
        }
        #[cfg(not(feature = "simd"))]
        {
            chunks.iter().map(|c| self.scan(c)).collect()
        }
    }
}

/// Length of the inter-chunk separator inserted into the coalesced GPU
/// buffer. Eight 0xFF bytes — long enough that no production secret
/// regex/literal can match across the boundary (the longest detector
/// literal in the corpus is `github_pat_` at 11 chars; a window of 8
/// 0xFF bytes between chunks guarantees no literal can straddle).
const COALESCE_SEPARATOR_LEN: usize = 8;
const COALESCE_SEPARATOR_BYTE: u8 = 0xFF;

fn coalesce_chunks(chunks: &[keyhog_core::Chunk]) -> (Vec<(usize, usize, usize)>, Vec<u8>) {
    // Reserve once: data + (n-1) separators. Empirically this single big
    // allocation is the main cost of `coalesce_chunks` on a 256 MiB batch;
    // pre-sizing avoids the geometric `Vec::push` regrowth path entirely.
    let total_bytes: usize = chunks.iter().map(|chunk| chunk.data.len()).sum();
    let separators_total = chunks.len().saturating_sub(1) * COALESCE_SEPARATOR_LEN;
    let mut entries = Vec::with_capacity(chunks.len());
    let mut buffer = Vec::with_capacity(total_bytes + separators_total);

    for (index, chunk) in chunks.iter().enumerate() {
        if index > 0 {
            // Sentinel between chunks. Without this a literal that spans
            // chunk-N's tail and chunk-N+1's head would phantom-match on
            // GPU and have to be filtered out post-hoc. The 0xFF bytes
            // are guaranteed-non-text (>0x7F, not valid UTF-8 lead) so
            // they cannot produce spurious matches against any of the
            // detector literals (all ASCII).
            buffer.resize(
                buffer.len() + COALESCE_SEPARATOR_LEN,
                COALESCE_SEPARATOR_BYTE,
            );
        }
        let start = buffer.len();
        buffer.extend_from_slice(chunk.data.as_bytes());
        entries.push((index, start, chunk.data.len()));
    }

    (entries, buffer)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk_chunk(data: &str) -> keyhog_core::Chunk {
        keyhog_core::Chunk {
            data: data.into(),
            metadata: keyhog_core::ChunkMetadata::default(),
        }
    }

    #[test]
    fn coalesce_inserts_separators_between_chunks() {
        let chunks = vec![mk_chunk("AKIA"), mk_chunk("XYZ"), mk_chunk("ghp_")];
        let (entries, buffer) = coalesce_chunks(&chunks);

        // 4 + 8 + 3 + 8 + 4 = 27 bytes
        assert_eq!(buffer.len(), 4 + 8 + 3 + 8 + 4);
        // Each entry's offset points at the start of that chunk's data, not
        // a separator.
        assert_eq!(entries[0], (0, 0, 4));
        assert_eq!(entries[1], (1, 4 + 8, 3));
        assert_eq!(entries[2], (2, 4 + 8 + 3 + 8, 4));
        // Separator bytes are non-ASCII, so they can't false-match.
        assert!(buffer[4..12].iter().all(|&b| b == 0xFF));
        assert!(buffer[15..23].iter().all(|&b| b == 0xFF));
    }

    #[test]
    fn coalesce_single_chunk_has_no_separator() {
        let chunks = vec![mk_chunk("only")];
        let (_entries, buffer) = coalesce_chunks(&chunks);
        assert_eq!(buffer, b"only");
    }

    #[test]
    fn coalesce_empty_input_is_empty() {
        let (entries, buffer) = coalesce_chunks(&[]);
        assert!(entries.is_empty());
        assert!(buffer.is_empty());
    }
}

use super::*;

impl CompiledScanner {
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
        unsafe {
            // Senior Audit §Phase 7.4: Prevent GPU buffers from leaking into core dumps.
            // Best-effort; ignore errors on non-page-aligned buffers.
            libc::madvise(
                buffer.as_ptr() as *mut libc::c_void,
                buffer.len(),
                libc::MADV_DONTDUMP,
            );
        }

        // Adaptive match cap: hardcoding 10_000 capped large batches.
        // Allow up to (chunks * max_matches_per_chunk) with a hard ceiling.
        // Most chunks have <50 matches; assume worst case is 256/chunk before
        // falling back to CPU validation per chunk.
        //
        // kimi-wave2 §Critical: ask the GPU for `cap+1` matches and treat
        // the off-by-one slot as the truncation sentinel. The previous
        // `==` test at the cap fired even when the true count *equaled*
        // the cap (no truncation), wasting a full CPU re-scan. With the
        // sentinel slot, only `> cap` triggers fallback, so a batch that
        // happens to land exactly at the cap is accepted as complete.
        let cap: u32 = (chunks.len().saturating_mul(256)).clamp(10_000, 1_000_000) as u32;
        let max_matches = cap.saturating_add(1);

        let started = std::time::Instant::now();
        let mut matches: Vec<vyre_libs::matching::LiteralMatch> =
            match matcher.scan(&**backend, &buffer, max_matches) {
                Ok(matches) => matches,
                Err(e) => {
                    tracing::error!("GPU scan failed, falling back to CPU: {e}");
                    return self.scan_coalesced_non_gpu(chunks);
                }
            };
        let elapsed_ms = started.elapsed().as_millis();
        tracing::debug!(
            target: "keyhog::routing",
            chunks = chunks.len(),
            buffer_bytes = buffer.len(),
            matches = matches.len(),
            cap,
            elapsed_ms,
            "vyre GPU scan completed"
        );
        // Truncation only when the GPU produced strictly more than `cap`
        // results (i.e., used the +1 sentinel slot). Counts equal to or
        // below `cap` are by definition complete.
        if matches.len() > cap as usize {
            tracing::warn!(
                cap,
                chunks = chunks.len(),
                "GPU scan exceeded the match cap — truncation possible; falling back to CPU"
            );
            return self.scan_coalesced_non_gpu(chunks);
        }
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
        chunks
            .par_iter()
            .zip(per_chunk_triggers.into_par_iter())
            .map(|(chunk, triggered)| {
                let prepared = self.prepare_chunk(chunk);
                let mut matches =
                    self.scan_prepared_with_triggered(prepared, ScanBackend::Gpu, triggered, None);
                self.post_process_matches(chunk, &mut matches, None);
                matches
            })
            .collect()
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

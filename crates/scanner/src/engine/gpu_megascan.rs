use super::*;

impl CompiledScanner {
    pub fn scan_coalesced_megascan(
        &self,
        chunks: &[keyhog_core::Chunk],
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        use crate::hw_probe::ScanBackend;

        let Some(pipeline) = self.rule_pipeline() else {
            super::gpu_forced::deny_silent_megascan_degrade(
                "regex pipeline compile rejected the detector set",
            );
            tracing::debug!(
                "MegaScan: regex pipeline unavailable, dispatching via literal-set GPU"
            );
            return self.scan_coalesced_gpu(chunks);
        };
        let Some(backend) = self.gpu_backend.as_ref() else {
            super::gpu_forced::deny_silent_megascan_degrade(
                "no GPU backend acquired at compile time",
            );
            return self.scan_coalesced_gpu(chunks);
        };

        let (entries, buffer) = super::gpu_coalesce::coalesce_chunks(chunks);

        // Pipeline was pre-built for at most `megascan_input_len()` bytes;
        // bigger batches can't dispatch. Auto-degrade rather than
        // truncate (truncation = silent false negatives).
        let input_cap = super::rule_pipeline::megascan_input_len();
        if buffer.len() > input_cap {
            super::gpu_forced::deny_silent_megascan_degrade(
                "coalesced batch exceeds RulePipeline input_len cap",
            );
            tracing::debug!(
                buffer_bytes = buffer.len(),
                input_len = input_cap,
                "MegaScan: batch exceeds RulePipeline input_len cap, falling back to literal-set GPU"
            );
            return self.scan_coalesced_gpu(chunks);
        }

        #[cfg(target_os = "linux")]
        // SAFETY: same contract as scan_coalesced_gpu - `buffer` is a
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
                    "MegaScan dispatch failed: falling back to literal-set GPU"
                );
                super::gpu_forced::deny_silent_megascan_degrade(
                    "MegaScan dispatch returned an error at runtime",
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
                "MegaScan exceeded cap: truncation possible; dispatching via literal-set GPU"
            );
            super::gpu_forced::deny_silent_megascan_degrade(
                "match count exceeded MegaScan dispatch cap (truncation risk)",
            );
            return self.scan_coalesced_gpu(chunks);
        }

        let mut matches: Vec<vyre_libs::scan::LiteralMatch> = raw_matches
            .iter()
            .map(|m| vyre_libs::scan::LiteralMatch::new(m.pattern_id, m.start, m.end))
            .collect();
        // In-place dedup: sort by (pattern_id, start, end) and fold overlapping spans.
        matches.sort_unstable_by(|a, b| {
            a.pattern_id
                .cmp(&b.pattern_id)
                .then(a.start.cmp(&b.start))
                .then(a.end.cmp(&b.end))
        });
        {
            let mut write = 0;
            for read in 1..matches.len() {
                if matches[read].pattern_id == matches[write].pattern_id
                    && matches[read].start <= matches[write].end
                {
                    if matches[read].end > matches[write].end {
                        matches[write] = vyre_libs::scan::LiteralMatch::new(
                            matches[write].pattern_id,
                            matches[write].start,
                            matches[read].end,
                        );
                    }
                } else {
                    write += 1;
                    matches[write] = matches[read];
                }
            }
            if !matches.is_empty() {
                matches.truncate(write + 1);
            }
        }
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
}

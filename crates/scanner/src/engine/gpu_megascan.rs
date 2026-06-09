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
        // Resident dispatch keeps the NFA transition/epsilon tables GPU-resident
        // across batches, so only the haystack transfers per dispatch (the static
        // tables can be tens of MB; re-uploading them every batch was a measured
        // per-batch tax). The resident output is bit-identical to the borrowed
        // path — same program, tables, grid, decode — so an unavailable or
        // over-capacity resident session falls back to borrowed dispatch with
        // ZERO recall change. That is a pure performance fallback, NOT the
        // recall-affecting megascan→literal-set degrade reached on a true error.
        let mut matches: Vec<vyre_libs::scan::LiteralMatch> =
            match self.megascan_resident_matches(pipeline, &**backend, &buffer) {
                Some(resident_matches) => resident_matches,
                None => match pipeline.scan(&**backend, &buffer, max_matches) {
                    Ok(raw_matches) => raw_matches
                        .iter()
                        .map(|m| vyre_libs::scan::LiteralMatch::new(m.pattern_id, m.start, m.end))
                        .collect(),
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
                },
            };
        let elapsed_ms = started.elapsed().as_millis();
        tracing::debug!(
            target: "keyhog::routing",
            chunks = chunks.len(),
            buffer_bytes = buffer.len(),
            matches = matches.len(),
            cap,
            elapsed_ms,
            "MegaScan RulePipeline scan completed"
        );

        if matches.len() > cap as usize {
            tracing::warn!(
                cap,
                "MegaScan exceeded cap: truncation possible; dispatching via literal-set GPU"
            );
            super::gpu_forced::deny_silent_megascan_degrade(
                "match count exceeded MegaScan dispatch cap (truncation risk)",
            );
            return self.scan_coalesced_gpu(chunks);
        }

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
                // Shared windowing contract (see `scan_chunk_or_window`): a
                // >1 MiB chunk is windowed so the per-chunk match cap can't
                // silently truncate it, exactly like the per-file, coalesced
                // SIMD, and GPU literal/AC phase-2 paths.
                let mut matches = self.scan_chunk_or_window(chunk, None, || {
                    let prepared = self.prepare_chunk(chunk);
                    self.scan_prepared_with_triggered(
                        prepared,
                        ScanBackend::MegaScan,
                        triggered,
                        None,
                    )
                });
                self.post_process_matches(chunk, &mut matches, None);
                matches
            })
            .collect();

        // Same boundary reassembly as the literal-set path.
        super::boundary::scan_chunk_boundaries(self, chunks, &mut results);
        results
    }

    /// Scan `buffer` through the GPU-resident MegaScan pipeline, lazily preparing
    /// the resident session (NFA tables uploaded once) on first use.
    ///
    /// Returns `Some(matches)` on a successful resident dispatch and `None` when
    /// the resident path cannot serve this batch — no backend resident support,
    /// prepare failed, the batch exceeds the resident haystack capacity, or a
    /// runtime dispatch/readback error. In every `None` case the caller runs the
    /// recall-identical borrowed `RulePipeline::scan`: resident and borrowed
    /// decode the same program against the same tables, so this is a pure
    /// performance layer with no effect on which matches are produced.
    ///
    /// The returned matches are already lowered to [`LiteralMatch`] (the wire
    /// form the borrowed path also converts to), so both branches converge on one
    /// type without naming the foundation `Match` (not a keyhog dependency).
    fn megascan_resident_matches(
        &self,
        pipeline: &vyre_libs::scan::RulePipeline,
        backend: &dyn vyre::VyreBackend,
        buffer: &[u8],
    ) -> Option<Vec<vyre_libs::scan::LiteralMatch>> {
        let session = self
            .resident_megascan
            .get_or_init(|| Self::prepare_resident_megascan(pipeline, backend, buffer.len()))
            .as_ref()?;
        // Serialise the single per-batch GPU dispatch: the resident haystack/hit
        // buffers are shared mutable device state, so two concurrent dispatches
        // would race. Megascan batches already run one-at-a-time, so this lock is
        // uncontended in production and only guards stray concurrent callers.
        let resident = session.lock().ok()?;
        if buffer.len() > resident.haystack_capacity() {
            // Loud + recall-preserving: this batch is larger than the resident
            // haystack buffer (sized from the first batch). Borrowed dispatch
            // handles it with identical matches; surface it so an operator
            // scanning unusually large batches can see why resident isn't engaged.
            tracing::warn!(
                target: "keyhog::routing",
                batch_bytes = buffer.len(),
                resident_capacity = resident.haystack_capacity(),
                "MegaScan batch exceeds resident haystack capacity; borrowed dispatch (recall-identical)"
            );
            return None;
        }
        let mut raw = Vec::new();
        let mut scratch = Vec::new();
        match resident.scan_into(backend, buffer, &mut raw, &mut scratch) {
            Ok(()) => Some(
                raw.iter()
                    .map(|m| vyre_libs::scan::LiteralMatch::new(m.pattern_id, m.start, m.end))
                    .collect(),
            ),
            Err(error) => {
                // Loud + recall-preserving: a resident dispatch/readback error (or
                // the resident hit-count truncation guard firing) falls back to the
                // borrowed path, which re-sizes per batch. Same matches, no degrade.
                tracing::warn!(
                    target: "keyhog::routing",
                    %error,
                    "MegaScan resident dispatch error; borrowed dispatch (recall-identical)"
                );
                None
            }
        }
    }

    /// Prepare the resident MegaScan session sized to the first observed batch.
    ///
    /// Capacity is rounded up to a 16 MiB granule (so minor batch-size variation
    /// between batches doesn't force a fallback) and capped at the pipeline's
    /// `megascan_input_len()` — the same ceiling the borrowed path enforces before
    /// dispatch. `max_matches` mirrors the borrowed path's buffer-scaled cap but is
    /// derived from the resident *capacity*, so any batch that fits the haystack
    /// buffer also fits the hit buffer (the resident hit-count guard is never the
    /// truncation point for an in-capacity batch).
    fn prepare_resident_megascan(
        pipeline: &vyre_libs::scan::RulePipeline,
        backend: &dyn vyre::VyreBackend,
        first_batch_bytes: usize,
    ) -> Option<std::sync::Mutex<vyre_libs::scan::ResidentRulePipeline>> {
        const GRANULE: usize = 16 * 1024 * 1024;
        let capacity = first_batch_bytes
            .max(1)
            .div_ceil(GRANULE)
            .saturating_mul(GRANULE)
            .min(super::rule_pipeline::megascan_input_len());
        // Mirror the borrowed path's buffer-scaled match cap (MIN_CAP/MAX_CAP in
        // `scan_coalesced_megascan`), derived from capacity rather than one batch.
        const MIN_CAP: u64 = 100_000;
        const MAX_CAP: u64 = 16_000_000;
        let max_matches =
            ((capacity as u64 / 64).clamp(MIN_CAP, MAX_CAP) as u32).saturating_add(1);
        match pipeline.prepare_resident(backend, capacity, max_matches) {
            Ok(resident) => {
                tracing::debug!(
                    target: "keyhog::routing",
                    resident_capacity = capacity,
                    max_matches,
                    "MegaScan resident session prepared (NFA tables uploaded once)"
                );
                Some(std::sync::Mutex::new(resident))
            }
            Err(error) => {
                // Loud + recall-preserving: resident unavailable (backend lacks
                // resident support, or allocation/upload failed). The borrowed path
                // is fully correct; this only forgoes the table-upload amortization.
                // NOT the megascan→literal-set recall degrade.
                tracing::warn!(
                    target: "keyhog::routing",
                    %error,
                    "MegaScan resident prepare failed; borrowed dispatch for all batches (recall-identical)"
                );
                None
            }
        }
    }
}

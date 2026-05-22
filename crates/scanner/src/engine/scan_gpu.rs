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

        let mut matches: Vec<vyre_libs::matching::LiteralMatch> = raw_matches
            .iter()
            .map(|m| vyre_libs::matching::LiteralMatch::new(m.pattern_id, m.start, m.end))
            .collect();
        // In-place dedup: sort by (pattern_id, start, end) and fold overlapping spans.
        matches.sort_unstable_by(|a, b| {
            a.pattern_id.cmp(&b.pattern_id)
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
                        matches[write] = vyre_libs::matching::LiteralMatch::new(
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

    /// GPU coalesced scan — legacy megakernel entry point.
    ///
    /// Previously attempted to dispatch via a `MegakernelScanner` stub
    /// that always returned `None`, falling through to `scan_coalesced_gpu`.
    /// The stub has been removed (see audit 2026-05-11); this function
    /// now delegates directly. Kept as a named entry point so the
    /// `scan_chunks_with_backend` routing table and the megakernel
    /// parity test continue to compile without churn.
    pub fn scan_coalesced_megakernel(
        &self,
        chunks: &[keyhog_core::Chunk],
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        self.scan_coalesced_gpu(chunks)
    }

    /// GPU coalesced scan via one Vyre literal-set dispatch.
    pub fn scan_coalesced_gpu(
        &self,
        chunks: &[keyhog_core::Chunk],
    ) -> Vec<Vec<keyhog_core::RawMatch>> {

        // Per-call kernel select. `KEYHOG_GPU_KERNEL=ac` swaps the
        // O(N×L) literal-set program for the O(L_max) AC kernel that
        // shares the same DFA. Default stays on literal_set until the
        // bench shows AC wins on real corpora; once it does, this gate
        // flips. Bottom-of-call cost only — the kernel choice doesn't
        // change coalesce/post-process behaviour, so flipping it back
        // is a one-env-var rollback if recall ever drifts.
        if matches!(std::env::var("KEYHOG_GPU_KERNEL").as_deref(), Ok("ac")) {
            return self.scan_coalesced_gpu_ac(chunks);
        }

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

        let (entries, mut buffer) = coalesce_chunks(chunks);

        // 4-byte align the coalesced buffer so every shard slice can be
        // passed to vyre's u32-typed haystack input WITHOUT a per-shard
        // `pack_haystack_u32` call. The pack helper is a 2x memcopy
        // (Vec<u32> intermediate + Vec<u8> output) that produces bytes
        // byte-identical to the input on 4-aligned slices (see
        // `vyre_foundation::byte_pack::pack_haystack_u32`). On a 1 GiB
        // scan with 2 MiB shards that's 512 shards x 2x = ~4 GiB of
        // throwaway allocations — load-bearing on the 25s gap GPU
        // currently loses to SIMD at scale. Padding the source buffer
        // once and slicing each shard collapses that to zero alloc per
        // shard. Padding bytes are NUL, which no detector literal can
        // match (extract_literal_prefixes drops NUL), so the trailing
        // zero-extension is recall-safe.
        while !buffer.len().is_multiple_of(4) {
            buffer.push(0);
        }

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
        // Dynamic per-vyre-workgroup: each shard covers
        // (max_workgroups_per_dim × workgroup_size_x) bytes.
        // wgpu caps workgroups per dimension at 65 535; vyre's
        // literal-set program reports its `workgroup_size_x` via
        // `matcher.program.workgroup_size[0]`. Was hard-coded at
        // 65_535 × 32 when vyre's literal-set used
        // workgroup_size_x = 32; now scales automatically when
        // the vyre side is tuned (e.g. to 128 to cut shard count
        // by 4×).
        let workgroup_x = matcher.program.workgroup_size[0] as usize;
        let gpu_dispatch_max_bytes: usize = 65_535 * workgroup_x;
        let started = std::time::Instant::now();

        // Slice the coalesced buffer into wgpu-dispatch-sized shards.
        // The shard boundary itself is wgpu's `dispatch_workgroups`
        // limit (65 535 workgroups per dimension × 32-byte workgroup
        // size). The previous flow dispatched these one-by-one with
        // `matcher.scan` — each call records its own encoder,
        // submits, and `device.poll(Wait)`s. On a 1 GiB batch with
        // 512 shards that adds up to ~50 ms × 512 = 25 s of pure
        // host-side dispatch overhead, *not* GPU compute.
        //
        // `WgpuBackend::dispatch_borrowed_batch` records *all* shard
        // dispatches into one command encoder, single submit, single
        // poll. For 512 shards the wait collapses from ~25 s to
        // a single GPU drain — close to the actual compute time.
        let mut shard_ranges: Vec<(usize, usize)> = Vec::new();
        let mut shard_start = 0usize;
        while shard_start < buffer.len() {
            let shard_end = (shard_start + gpu_dispatch_max_bytes).min(buffer.len());
            shard_ranges.push((shard_start, shard_end));
            shard_start = shard_end;
        }
        let shard_count = shard_ranges.len();

        // Constants across all shards: pattern offsets/lengths/bytes
        // and pattern_count. Pre-packed ONCE per process via the
        // CompiledScanner-level OnceLock and borrowed every dispatch.
        // Before this cache, `pack_u32_slice` ran four times per scan
        // producing identical bytes; a process scanning 10 k files
        // burned 40 k throwaway Vec<u8> allocations on data that never
        // changes after compile.
        let const_packs = self.gpu_const_packs.get_or_init(|| {
            crate::engine::GpuConstPacks {
                pattern_offsets: vyre_libs::matching::dispatch_io::pack_u32_slice(
                    &matcher.pattern_offsets,
                ),
                pattern_lengths: vyre_libs::matching::dispatch_io::pack_u32_slice(
                    &matcher.pattern_lengths,
                ),
                pattern_bytes: vyre_libs::matching::dispatch_io::pack_u32_slice(
                    &matcher.pattern_bytes,
                ),
                pattern_count: vyre_libs::matching::dispatch_io::pack_u32_slice(&[
                    matcher.pattern_lengths.len() as u32,
                ]),
            }
        });

        // Per-shard tiny bytes (shard_len scalar + the two atomic
        // counters + dispatch config). The haystack input is the
        // 4-byte-aligned source buffer sliced in place — no Vec<u8>
        // packing allocation per shard (see the buffer padding above
        // for the rationale).
        struct ShardOwned {
            haystack_len: Vec<u8>,
            atomic_count: Vec<u8>,
            atomic_overflow: Vec<u8>,
            config: vyre::DispatchConfig,
            cap: u32,
        }
        let mut shard_owned: Vec<ShardOwned> = Vec::with_capacity(shard_count);
        for (start, end) in &shard_ranges {
            let shard_len = (*end - *start) as u32;
            let shard_cap_u64 = ((*end - *start) / 64) as u64;
            let shard_cap =
                shard_cap_u64.clamp(MIN_CAP as u64, MAX_CAP as u64) as u32;
            shard_owned.push(ShardOwned {
                haystack_len: vyre_libs::matching::dispatch_io::pack_u32_slice(
                    &[shard_len],
                ),
                atomic_count: vec![0u8; 4],
                atomic_overflow: vec![0u8; 4],
                config: vyre_libs::matching::dispatch_io::byte_scan_dispatch_config(
                    shard_len,
                    matcher.program.workgroup_size[0],
                ),
                cap: shard_cap,
            });
        }

        // Build borrowed input arrays per shard. Order must match
        // `GpuLiteralSet::scan` because the buffer-decl order is the
        // contract between host inputs and GPU kernel binding. The
        // haystack slot is now a direct slice into the padded source
        // buffer — no per-shard packing allocation.
        let shard_input_arrays: Vec<[&[u8]; 8]> = shard_owned
            .iter()
            .zip(shard_ranges.iter())
            .map(|(s, (start, end))| {
                [
                    &buffer[*start..*end],
                    const_packs.pattern_offsets.as_slice(),
                    const_packs.pattern_lengths.as_slice(),
                    const_packs.pattern_bytes.as_slice(),
                    s.haystack_len.as_slice(),
                    const_packs.pattern_count.as_slice(),
                    s.atomic_count.as_slice(),
                    s.atomic_overflow.as_slice(),
                ]
            })
            .collect();

        // vyre's wgpu readback ring is sized at DEFAULT_RING_SLOTS
        // (lifted to 2048 in vendor/vyre — see
        // `runtime/readback_ring.rs` for the rationale). Each
        // GpuLiteralSet dispatch produces 2 readback buffers,
        // and we pre-pack each shard's haystack into a Vec<u8>
        // of ~shard_size before issuing the batch. Capping at
        // 64 shards/batch keeps the transient host-side packing
        // memory bounded to ~128 MiB even on multi-GiB scans,
        // and leaves the 2048-slot ring deeply under-subscribed
        // so back-to-back batches don't ever stall on slot
        // collection. A 1 GiB scan now issues 8 sequential
        // batched dispatches (vs 512 sequential individual ones
        // pre-fix), which is the practical sweet spot.
        const MAX_SHARDS_PER_GPU_BATCH: usize = 64;
        let mut matches: Vec<vyre_libs::matching::LiteralMatch> = Vec::new();
        for sub_start in (0..shard_count).step_by(MAX_SHARDS_PER_GPU_BATCH) {
            let sub_end = (sub_start + MAX_SHARDS_PER_GPU_BATCH).min(shard_count);
            let jobs: Vec<_> = (sub_start..sub_end)
                .map(|i| {
                    (
                        &matcher.program,
                        &shard_input_arrays[i][..],
                        &shard_owned[i].config,
                    )
                })
                .collect();

            let batch_results = match backend.dispatch_borrowed_batch(&jobs) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(
                        shards = sub_end - sub_start,
                        "GPU batched dispatch failed, falling back to CPU: {e}"
                    );
                    return self.scan_coalesced_non_gpu(chunks);
                }
            };

            for (offset_in_sub, result) in batch_results.into_iter().enumerate() {
                let i = sub_start + offset_in_sub;
                let outputs = match result {
                    Ok(o) => o,
                    Err(e) => {
                        tracing::error!(
                            shard_index = i,
                            "GPU shard within batch failed, falling back to CPU: {e}"
                        );
                        return self.scan_coalesced_non_gpu(chunks);
                    }
                };
                if outputs.len() < 2 {
                    tracing::error!(
                        shard_index = i,
                        outputs = outputs.len(),
                        "GPU shard output buffer count too small; falling back to CPU"
                    );
                    return self.scan_coalesced_non_gpu(chunks);
                }
                let count_bytes = &outputs[0];
                let matches_bytes = &outputs[1];
                if count_bytes.len() < 4 {
                    tracing::error!(
                        shard_index = i,
                        "GPU shard count buffer truncated; falling back to CPU"
                    );
                    return self.scan_coalesced_non_gpu(chunks);
                }
                let count = u32::from_le_bytes([
                    count_bytes[0],
                    count_bytes[1],
                    count_bytes[2],
                    count_bytes[3],
                ]);
                let shard_cap = shard_owned[i].cap;
                if count > shard_cap {
                    tracing::warn!(
                        cap = shard_cap,
                        count,
                        shard_index = i,
                        "GPU shard exceeded its cap — truncation possible; falling back to CPU"
                    );
                    return self.scan_coalesced_non_gpu(chunks);
                }
                let shard_matches =
                    vyre_libs::matching::dispatch_io::unpack_match_triples(
                        matches_bytes,
                        count.min(shard_cap),
                    );
                let offset = shard_ranges[i].0 as u32;
                for m in &shard_matches {
                    matches.push(vyre_libs::matching::LiteralMatch::new(
                        m.pattern_id,
                        m.start.saturating_add(offset),
                        m.end.saturating_add(offset),
                    ));
                }
            }
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
            "vyre GPU batched scan completed"
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
        // Per-pid region dedup: sort by (pattern_id, start, end) and fold
        // overlapping same-pid spans in-place. Avoids the intermediate
        // Vec<RegionTriple> → Vec<LiteralMatch> round-trip that doubled
        // the allocation cost of this path.
        {
            matches.sort_unstable_by(|a, b| {
                a.pattern_id.cmp(&b.pattern_id)
                    .then(a.start.cmp(&b.start))
                    .then(a.end.cmp(&b.end))
            });
            // Fold overlapping same-pid spans
            let mut write = 0;
            for read in 1..matches.len() {
                if matches[read].pattern_id == matches[write].pattern_id
                    && matches[read].start <= matches[write].end
                {
                    // Extend the current region
                    if matches[read].end > matches[write].end {
                        matches[write] = vyre_libs::matching::LiteralMatch::new(
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
        matches.sort_unstable_by_key(|matched| matched.start);

        let total_patterns = self.ac_map.len() + self.fallback.len();
        // Per-chunk hit list (pattern_id, chunk-local-start, chunk-local-end).
        // Replaces the per-chunk bitmap so the downstream regex
        // confirmation can run *anchored* at each hit instead of
        // sweeping the entire chunk for every triggered pattern. See
        // `scan_prepared_with_pattern_hits` for the rationale.
        let mut per_chunk_hits: Vec<Vec<(u32, u32, u32)>> =
            chunks.iter().map(|_| Vec::new()).collect();

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
                let local_start = (global_start - offset) as u32;
                let local_end = (global_end - offset) as u32;
                per_chunk_hits[chunk_index].push((matched.pattern_id, local_start, local_end));
            }
        }

        use rayon::prelude::*;
        let mut results: Vec<Vec<keyhog_core::RawMatch>> = chunks
            .par_iter()
            .zip(per_chunk_hits.into_par_iter())
            .map(|(chunk, hits)| {
                let prepared = self.prepare_chunk(chunk);
                let mut matches =
                    self.scan_prepared_with_pattern_hits(prepared, hits, None);
                // Parity with SIMD's `scan_chunks_with_backend` path:
                // `scan_with_backend` → `scan_with_deadline_and_backend`
                // calls `post_process_matches` after the in-chunk scan,
                // which decode-recurses (base64/hex/url) and reassembles
                // cross-chunk-fragment secrets. The GPU path previously
                // skipped this — the gpu_parity test catches the
                // missed StackBlitz finding extracted from the
                // base64-decoded sub-chunk of the stripe-aws fixture.
                // A prior comment here claimed SIMD's `scan_coalesced`
                // also skips post-process; that's true for the bulk-
                // scan entry point but NOT for `scan_chunks_with_backend`,
                // which is the API the parity test (and operators
                // forcing `--backend gpu`) actually call.
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

    /// GPU coalesced scan via the `classic_ac_bounded_ranges_program`
    /// kernel. Same input/output contract as
    /// [`Self::scan_coalesced_gpu`] (per-chunk `Vec<RawMatch>` results,
    /// byte-identical to SIMD on the bench corpora once parity tests
    /// pass) — the only thing that changes is the GPU primitive that
    /// produces the raw `(pattern_id, start, end)` triples.
    ///
    /// Per-byte cost drops from `O(N × L_anchor)` (literal-set walks
    /// every detector pattern × every literal byte at every offset)
    /// to `O(L_max)` (AC walks the suffix window once and emits every
    /// pattern in the accepting state's flat output_links). For
    /// keyhog's `N = 6 316`, `L_anchor ≈ 10`, `L_max ≈ 50`, that's
    /// roughly a 1 200× per-byte op reduction.
    ///
    /// Caller picks this via `KEYHOG_GPU_KERNEL=ac`; the dispatch
    /// router in [`Self::scan_coalesced_gpu`] forwards to here. Any
    /// dispatch error falls back to the literal-set path (via
    /// `scan_coalesced_non_gpu` for now — the simplest safe fallback
    /// since we already know SIMD/literal_set produce parity output).
    pub fn scan_coalesced_gpu_ac(
        &self,
        chunks: &[keyhog_core::Chunk],
    ) -> Vec<Vec<keyhog_core::RawMatch>> {
        let Some(matcher) = self.gpu_matcher() else {
            return self.scan_coalesced_non_gpu(chunks);
        };
        let Some(program) = self.ac_gpu_program() else {
            return self.scan_coalesced_non_gpu(chunks);
        };
        let Ok(_dq) = vyre_driver_wgpu::runtime::cached_device() else {
            tracing::debug!("AC gpu: device unavailable, falling back to non-gpu coalesced scan");
            return self.scan_coalesced_non_gpu(chunks);
        };
        let Some(backend) = self.wgpu_backend.as_ref() else {
            return self.scan_coalesced_non_gpu(chunks);
        };

        let (entries, mut buffer) = coalesce_chunks(chunks);

        // Same buffer 4-alignment trick as `scan_coalesced_gpu`: lets
        // every shard pass `&buffer[start..end]` straight to vyre's
        // u32-typed haystack input instead of running pack_haystack_u32
        // (a 2x memcopy producing byte-identical output for aligned
        // slices). Eliminates ~2x buffer.len() of transient allocations
        // per scan. NUL padding is recall-safe (literals can't contain
        // NUL).
        while !buffer.len().is_multiple_of(4) {
            buffer.push(0);
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

        let workgroup_x = program.workgroup_size[0] as usize;
        // WGSL workgroups-per-dim ceiling is 65 535. At workgroup_x = 64
        // that's a ~4 MiB shard. The shard cap is here so we never feed
        // the dispatch a workgroup count > 65 535 (validation error).
        const GPU_DISPATCH_MAX_WORKGROUPS_AC: usize = 65_535;
        let gpu_dispatch_max_bytes: usize = GPU_DISPATCH_MAX_WORKGROUPS_AC * workgroup_x;
        let started = std::time::Instant::now();

        let mut shard_ranges: Vec<(usize, usize)> = Vec::new();
        let mut shard_start = 0usize;
        while shard_start < buffer.len() {
            let shard_end = (shard_start + gpu_dispatch_max_bytes).min(buffer.len());
            shard_ranges.push((shard_start, shard_end));
            shard_start = shard_end;
        }
        let shard_count = shard_ranges.len();

        // Constants packed ONCE per process via the scanner-level
        // OnceLock. Same rationale as `scan_coalesced_gpu`: AC kernel
        // re-ran four `pack_u32_slice` calls on identical bytes every
        // dispatch.
        // The AC program's binding layout:
        //   0: haystack (per shard, slice into padded buffer)
        //   1: transitions
        //   2: output_offsets
        //   3: output_records
        //   4: pattern_lengths
        //   5: haystack_len (per shard, packed)
        //   6: match_count (per shard, atomic counter)
        //   7: matches (output, backend-allocated from BufferDecl)
        let ac_packs = self.gpu_ac_const_packs.get_or_init(|| {
            crate::engine::AcConstPacks {
                transitions: vyre_libs::matching::dispatch_io::pack_u32_slice(
                    &matcher.dfa.transitions,
                ),
                output_offsets: vyre_libs::matching::dispatch_io::pack_u32_slice(
                    &matcher.dfa.output_offsets,
                ),
                output_records: vyre_libs::matching::dispatch_io::pack_u32_slice(
                    &matcher.dfa.output_records,
                ),
                pattern_lengths: vyre_libs::matching::dispatch_io::pack_u32_slice(
                    &matcher.pattern_lengths,
                ),
            }
        });

        struct ShardOwnedAc {
            haystack_len: Vec<u8>,
            atomic_count: Vec<u8>,
            config: vyre::DispatchConfig,
        }
        let mut shard_owned: Vec<ShardOwnedAc> = Vec::with_capacity(shard_count);
        for &(s_start, s_end) in &shard_ranges {
            let shard_len = (s_end - s_start) as u32;
            shard_owned.push(ShardOwnedAc {
                haystack_len: vyre_libs::matching::dispatch_io::pack_u32_slice(&[shard_len]),
                atomic_count: vec![0u8; 4],
                config: vyre_libs::matching::dispatch_io::byte_scan_dispatch_config(
                    shard_len,
                    program.workgroup_size[0],
                ),
            });
        }

        let shard_input_arrays: Vec<[&[u8]; 7]> = shard_owned
            .iter()
            .zip(shard_ranges.iter())
            .map(|(s, &(start, end))| {
                [
                    &buffer[start..end],
                    ac_packs.transitions.as_slice(),
                    ac_packs.output_offsets.as_slice(),
                    ac_packs.output_records.as_slice(),
                    ac_packs.pattern_lengths.as_slice(),
                    s.haystack_len.as_slice(),
                    s.atomic_count.as_slice(),
                ]
            })
            .collect();

        // Sub-batched dispatch: same MAX_SHARDS_PER_GPU_BATCH=64 budget
        // as the literal-set path keeps the transient host-side packing
        // memory bounded on multi-GiB scans while leaving vyre's
        // 2048-slot readback ring deeply under-subscribed.
        const MAX_SHARDS_PER_GPU_BATCH: usize = 64;
        let mut matches: Vec<vyre_libs::matching::LiteralMatch> = Vec::new();
        for sub_start in (0..shard_count).step_by(MAX_SHARDS_PER_GPU_BATCH) {
            let sub_end = (sub_start + MAX_SHARDS_PER_GPU_BATCH).min(shard_count);
            let jobs: Vec<_> = (sub_start..sub_end)
                .map(|i| (program, &shard_input_arrays[i][..], &shard_owned[i].config))
                .collect();

            let batch_results = match backend.dispatch_borrowed_batch(&jobs) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(
                        shards = sub_end - sub_start,
                        "AC GPU batched dispatch failed, falling back to CPU: {e}"
                    );
                    return self.scan_coalesced_non_gpu(chunks);
                }
            };

            for (offset_in_sub, result) in batch_results.into_iter().enumerate() {
                let i = sub_start + offset_in_sub;
                let outputs = match result {
                    Ok(o) => o,
                    Err(e) => {
                        tracing::error!(
                            shard_index = i,
                            "AC GPU shard within batch failed, falling back to CPU: {e}"
                        );
                        return self.scan_coalesced_non_gpu(chunks);
                    }
                };
                if outputs.len() < 2 {
                    tracing::error!(
                        shard_index = i,
                        outputs = outputs.len(),
                        "AC GPU shard output buffer count too small; falling back to CPU"
                    );
                    return self.scan_coalesced_non_gpu(chunks);
                }
                let count_bytes = &outputs[0];
                let matches_bytes = &outputs[1];
                if count_bytes.len() < 4 {
                    tracing::error!(
                        shard_index = i,
                        "AC GPU shard count buffer truncated; falling back to CPU"
                    );
                    return self.scan_coalesced_non_gpu(chunks);
                }
                let count = u32::from_le_bytes([
                    count_bytes[0],
                    count_bytes[1],
                    count_bytes[2],
                    count_bytes[3],
                ]);
                if count > super::AC_GPU_MAX_MATCHES_PER_DISPATCH {
                    tracing::warn!(
                        cap = super::AC_GPU_MAX_MATCHES_PER_DISPATCH,
                        count,
                        shard_index = i,
                        "AC GPU shard exceeded program cap — truncation possible; falling back to CPU"
                    );
                    return self.scan_coalesced_non_gpu(chunks);
                }
                let shard_matches = vyre_libs::matching::dispatch_io::unpack_match_triples(
                    matches_bytes,
                    count.min(super::AC_GPU_MAX_MATCHES_PER_DISPATCH),
                );
                let offset = shard_ranges[i].0 as u32;
                for m in &shard_matches {
                    matches.push(vyre_libs::matching::LiteralMatch::new(
                        m.pattern_id,
                        m.start.saturating_add(offset),
                        m.end.saturating_add(offset),
                    ));
                }
            }
        }
        let elapsed_ms = started.elapsed().as_millis();
        tracing::debug!(
            target: "keyhog::routing",
            chunks = chunks.len(),
            buffer_bytes = buffer.len(),
            matches = matches.len(),
            shards = shard_count,
            elapsed_ms,
            "AC GPU batched scan completed"
        );

        // Per-pid region dedup: identical to the literal-set path.
        // Sort by `(pid, start, end)`, fold same-pid overlapping spans,
        // re-sort by start for the chunk-attribution walk.
        {
            matches.sort_unstable_by(|a, b| {
                a.pattern_id
                    .cmp(&b.pattern_id)
                    .then(a.start.cmp(&b.start))
                    .then(a.end.cmp(&b.end))
            });
            let mut write = 0;
            for read in 1..matches.len() {
                if matches[read].pattern_id == matches[write].pattern_id
                    && matches[read].start <= matches[write].end
                {
                    if matches[read].end > matches[write].end {
                        matches[write] = vyre_libs::matching::LiteralMatch::new(
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
        matches.sort_unstable_by_key(|matched| matched.start);

        let total_patterns = self.ac_map.len() + self.fallback.len();
        let mut per_chunk_hits: Vec<Vec<(u32, u32, u32)>> =
            chunks.iter().map(|_| Vec::new()).collect();

        let mut cursor = 0usize;
        for matched in &matches {
            let global_start = matched.start as usize;
            let global_end = matched.end as usize;
            while cursor < entries.len() {
                let (_, off, len) = entries[cursor];
                if global_start < off + len {
                    break;
                }
                cursor += 1;
            }
            if cursor >= entries.len() {
                break;
            }
            let (chunk_index, off, len) = entries[cursor];
            if global_start < off || global_end > off + len {
                continue;
            }
            let pattern_index = matched.pattern_id as usize;
            if pattern_index < total_patterns {
                let local_start = (global_start - off) as u32;
                let local_end = (global_end - off) as u32;
                per_chunk_hits[chunk_index].push((matched.pattern_id, local_start, local_end));
            }
        }

        use rayon::prelude::*;
        let mut results: Vec<Vec<keyhog_core::RawMatch>> = chunks
            .par_iter()
            .zip(per_chunk_hits.into_par_iter())
            .map(|(chunk, hits)| {
                let prepared = self.prepare_chunk(chunk);
                let mut matches = self.scan_prepared_with_pattern_hits(prepared, hits, None);
                // Same parity-with-SIMD post-process the literal-set
                // path now runs (see scan_coalesced_gpu comment).
                self.post_process_matches(chunk, &mut matches, None);
                matches
            })
            .collect();

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

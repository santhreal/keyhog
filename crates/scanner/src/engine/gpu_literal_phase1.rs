use super::*;

impl CompiledScanner {
    pub fn scan_coalesced_gpu_phase1(&self, chunks: &[keyhog_core::Chunk]) -> GpuPhase1Output {
        // The literal_set program embeds `append_match_subgroup`
        // (subgroup_ballot + subgroup_shuffle), and vyre's canonical
        // pre-emit lowering rejects that subgroup form regardless of
        // the downstream emitter ("variable `_vyre_match_leader` is
        // referenced before binding"). This was previously gated to
        // CUDA only, but the rejection happens BEFORE driver-specific
        // emission, so WGPU hosts (Apple Silicon, Intel Mac, Windows)
        // hit the same rejection on the literal_set path and silently
        // dropped to CPU.
        //
        // Until the vyre pre-emit lowering accepts the subgroup form
        // (tracked separately), the AC kernel path is the working
        // GPU code path for both CUDA and WGPU. KEYHOG_GPU_KERNEL=
        // literal-set forces the broken path for diagnostic /
        // bisection use; the default is now AC for every GPU backend.
        // Cache the env-var lookup. `scan_coalesced_gpu_phase1` is called
        // per batched chunk group; reading env::var on the hot path costs
        // ~200 ns per call which adds up to milliseconds across 1k+
        // chunks. The diagnostic override is process-static so caching
        // once is exact.
        static FORCE_LITERAL_SET: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
        let force_literal_set = *FORCE_LITERAL_SET.get_or_init(|| {
            matches!(
                std::env::var("KEYHOG_GPU_KERNEL").ok().as_deref(),
                Some("literal-set") | Some("literal_set")
            )
        });
        if !force_literal_set {
            return self.scan_coalesced_gpu_ac_phase1(chunks);
        }

        // Auto-degrade to the next-best backend when the GPU stack is not
        // ready: no compiled matcher (no adapter at probe time), the cached
        // device went away, or the persistent backend is missing.
        let Some(matcher) = self.gpu_matcher() else {
            return self.gpu_degrade_done_with_reason(
                chunks,
                crate::hw_probe::ScanBackend::Gpu,
                Some("GPU literal-set matcher unavailable"),
            );
        };
        if self.gpu_backend.is_none() {
            return self.gpu_degrade_done_with_reason(
                chunks,
                crate::hw_probe::ScanBackend::Gpu,
                Some("GPU backend handle unavailable for literal-set dispatch"),
            );
        }

        let (entries, mut buffer) = super::gpu_coalesce::coalesce_chunks(chunks);

        // ASCII-lowercase the coalesced haystack so the literal-set automaton
        // matches case-INSENSITIVELY, matching the SIMD Hyperscan path (CASELESS
        // for every pattern) and the lowercased literal set from
        // `build_gpu_literals`. Prefilter-only buffer (phase 2 re-confirms on
        // original bytes); ASCII fold is position-preserving so offsets are
        // unchanged. See PERF-07 / gpu_ac_phase1 for the full rationale.
        buffer.make_ascii_lowercase();

        // 4-byte align the coalesced buffer so every shard slice can be
        // passed to vyre's u32-typed haystack input WITHOUT a per-shard
        // `pack_haystack_u32` call. The pack helper is a 2x memcopy
        // (Vec<u32> intermediate + Vec<u8> output) that produces bytes
        // byte-identical to the input on 4-aligned slices (see
        // `vyre_foundation::byte_pack::pack_haystack_u32`). On a 1 GiB
        // scan with 2 MiB shards that's 512 shards x 2x = ~4 GiB of
        // throwaway allocations - load-bearing on the 25s gap GPU
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
        // `madvise` is advisory - the kernel may ignore it on
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
        // batches larger than this (always true with the tier-aware
        // 2 MiB activation threshold + the orchestrator's adaptive
        // `batch_bytes_budget` - 256 MiB default, up to 1 GiB on
        // 24-GiB-VRAM cards), shard the buffer into 2-MiB-or-less
        // pieces, dispatch each, and merge the matches with a
        // `start` offset added to put them back into the global
        // buffer's coordinate space.
        //
        // Shard size: 65535 (max workgroups per dim) × 32 (vyre's
        // workgroup_size_x) = 2,097,120 bytes. Exactly 2 MiB =
        // 2,097,152 bytes overflows by one workgroup. Use the
        // exact-aligned value to maximise per-shard throughput
        // without tripping the wgpu dispatch validator.
        //
        // Extra dispatches add ~100 µs each on a high-tier GPU; for
        // a 256 MiB batch that's ~12 ms of overhead vs SIMD's ~70 s
        // (a 5800× win). On a 1 GiB batch (5090-class adapter) the
        // shard count rises 4× but the GPU-vs-SIMD ratio widens
        // because per-shard dispatch is amortized over more bytes.
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
        // `matcher.scan` - each call records its own encoder,
        // submits, and `device.poll(Wait)`s. On a 1 GiB batch with
        // 512 shards that adds up to ~50 ms × 512 = 25 s of pure
        // host-side dispatch overhead, *not* GPU compute.
        //
        // `WgpuBackend::dispatch_borrowed_batch` records *all* shard
        // dispatches into one command encoder, single submit, single
        // poll. For 512 shards the wait collapses from ~25 s to
        // a single GPU drain - close to the actual compute time.
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
        let const_packs = self
            .gpu_const_packs
            .get_or_init(|| super::gpu_cache::GpuConstPacks {
                pattern_offsets: vyre_libs::scan::dispatch_io::pack_u32_slice(
                    &matcher.pattern_offsets,
                ),
                pattern_lengths: vyre_libs::scan::dispatch_io::pack_u32_slice(
                    &matcher.pattern_lengths,
                ),
                pattern_bytes: vyre_libs::scan::dispatch_io::pack_u32_slice(&matcher.pattern_bytes),
                pattern_count: vyre_libs::scan::dispatch_io::pack_u32_slice(&[matcher
                    .pattern_lengths
                    .len()
                    as u32]),
            });

        // Per-shard tiny bytes (shard_len scalar + the two atomic
        // counters + dispatch config). The haystack input is the
        // 4-byte-aligned source buffer sliced in place - no Vec<u8>
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
            let shard_cap = shard_cap_u64.clamp(MIN_CAP as u64, MAX_CAP as u64) as u32;
            shard_owned.push(ShardOwned {
                haystack_len: vyre_libs::scan::dispatch_io::pack_u32_slice(&[shard_len]),
                atomic_count: vec![0u8; 4],
                atomic_overflow: vec![0u8; 4],
                config: vyre_libs::scan::dispatch_io::byte_scan_dispatch_config(
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
        // buffer - no per-shard packing allocation.
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
        // (lifted to 2048 in vendor/vyre - see
        // `runtime/readback_ring.rs` for the rationale). Each
        // GpuLiteralSet dispatch produces 2 readback buffers, so
        // a batch of N shards burns 2N slots from the 2048-slot
        // ring. The other constraint is host-side memory: each
        // shard's haystack is borrowed (no copy), but its
        // per-dispatch config + atomic counters still allocate
        // ~24 bytes per shard. The real cost is the input-arrays
        // Vec<[&[u8]; 8]> at ~64 bytes per entry.
        //
        // Adaptive batch cap: a bigger batch flattens the
        // command-encoder cost across more shards and shortens
        // the wall-clock for a multi-GiB scan, but climbs
        // the ring-slot occupancy. 64 was the original safe
        // value for small hosts; 256 still leaves the 2048-slot
        // ring deeply under-subscribed and matches the workload
        // a 24 GiB-VRAM card actually wants.
        //
        //   total RAM   shards/batch   1-GiB-scan sequential batches
        //   < 16 GiB        64           ≥ 8
        //   16-32 GiB      128             4
        //   ≥ 32 GiB       256             2
        //
        // The 96-GiB-RAM RTX-5090 workstation case drops from
        // 8 sequential batched dispatches to 2, cutting GPU
        // pipeline-drain stalls roughly 4x on a 1-GiB batch.
        let max_shards_per_gpu_batch: usize = {
            let total_ram_mb = crate::hw_probe::probe_hardware()
                .total_memory_mb
                .unwrap_or(0);
            if total_ram_mb >= 32 * 1024 {
                256
            } else if total_ram_mb >= 16 * 1024 {
                128
            } else {
                64
            }
        };
        let mut matches: Vec<vyre_libs::scan::LiteralMatch> = Vec::new();
        for sub_start in (0..shard_count).step_by(max_shards_per_gpu_batch) {
            let sub_end = (sub_start + max_shards_per_gpu_batch).min(shard_count);
            let sub_inputs: Vec<&[&[u8]]> = (sub_start..sub_end)
                .map(|i| &shard_input_arrays[i][..])
                .collect();
            let sub_configs: Vec<vyre::DispatchConfig> = (sub_start..sub_end)
                .map(|i| shard_owned[i].config.clone())
                .collect();

            let batch_results =
                match self.dispatch_gpu_shards(&matcher.program, &sub_inputs, &sub_configs) {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::error!(
                            shards = sub_end - sub_start,
                            "GPU batched dispatch failed, falling back to CPU: {e}"
                        );
                        let reason = format!("GPU literal-set batched dispatch failed: {e}");
                        return self.gpu_degrade_done_with_reason(
                            chunks,
                            crate::hw_probe::ScanBackend::Gpu,
                            Some(&reason),
                        );
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
                        let reason = format!("GPU literal-set shard {i} dispatch failed: {e}");
                        return self.gpu_degrade_done_with_reason(
                            chunks,
                            crate::hw_probe::ScanBackend::Gpu,
                            Some(&reason),
                        );
                    }
                };
                if outputs.len() < 2 {
                    tracing::error!(
                        shard_index = i,
                        outputs = outputs.len(),
                        "GPU shard output buffer count too small; falling back to CPU"
                    );
                    let reason = format!(
                        "GPU literal-set shard {i} returned {} output buffer(s), expected at least 2",
                        outputs.len()
                    );
                    return self.gpu_degrade_done_with_reason(
                        chunks,
                        crate::hw_probe::ScanBackend::Gpu,
                        Some(&reason),
                    );
                }
                let count_bytes = &outputs[0];
                let matches_bytes = &outputs[1];
                if count_bytes.len() < 4 {
                    tracing::error!(
                        shard_index = i,
                        "GPU shard count buffer truncated; falling back to CPU"
                    );
                    let reason = format!(
                        "GPU literal-set shard {i} returned truncated count buffer ({} byte(s), expected 4)",
                        count_bytes.len()
                    );
                    return self.gpu_degrade_done_with_reason(
                        chunks,
                        crate::hw_probe::ScanBackend::Gpu,
                        Some(&reason),
                    );
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
                        "GPU shard exceeded its cap: truncation possible; falling back to CPU"
                    );
                    let reason = format!(
                        "GPU literal-set shard {i} reported {count} matches, exceeding cap {shard_cap}"
                    );
                    return self.gpu_degrade_done_with_reason(
                        chunks,
                        crate::hw_probe::ScanBackend::Gpu,
                        Some(&reason),
                    );
                }
                let shard_matches = vyre_libs::scan::dispatch_io::unpack_match_triples(
                    matches_bytes,
                    count.min(shard_cap),
                );
                let offset = shard_ranges[i].0 as u32;
                for m in &shard_matches {
                    matches.push(vyre_libs::scan::LiteralMatch::new(
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
        if self.has_simd_prefilter()
            && super::gpu_postprocess::gpu_phase2_hits_are_dense(
                matches.len(),
                buffer.len(),
                chunks.len(),
            )
        {
            tracing::warn!(
                target: "keyhog::routing",
                raw_matches = matches.len(),
                buffer_bytes = buffer.len(),
                chunks = chunks.len(),
                "GPU literal prefix output is too dense for phase 2; rerouting this batch through SIMD coalesced scan",
            );
            if std::env::var_os("KH_PERF").is_some() {
                eprintln!(
                    "KH_PERF gpu_literal_dense_phase2_reroute: chunks={} buffer_bytes={} raw_matches={} bytes_per_hit={:.1}",
                    chunks.len(),
                    buffer.len(),
                    matches.len(),
                    buffer.len() as f64 / matches.len().max(1) as f64
                );
            }
            return GpuPhase1Output::Done(self.scan_coalesced_non_gpu(chunks));
        }
        // Per-pid dedup + chunk attribution lives in `gpu_postprocess`,
        // shared with the AC kernel phase-1 path. The downstream
        // `scan_prepared_with_pattern_hits` consumer requires matches
        // anchored to chunk-local `(pid, local_start, local_end)`
        // triples sorted by start so the regex confirmation step runs
        // anchored at each hit rather than re-sweeping each chunk.
        super::gpu_postprocess::fold_overlapping_same_pid_inplace(&mut matches);
        let total_patterns = self.ac_map.len() + self.fallback.len();
        let per_chunk_hits = super::gpu_postprocess::attribute_matches_to_chunks(
            &matches,
            &entries,
            total_patterns,
            chunks.len(),
        );

        GpuPhase1Output::Hits(per_chunk_hits)
    }
}

// Phase 2 (CPU post-process that runs after this file's GPU
// literal-set dispatch produces per-chunk hits) lives in
// `gpu_phase2.rs`. The orphan doc-comment that previously trailed
// here described that function and was stranded when the body moved.

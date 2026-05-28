use super::*;

impl CompiledScanner {
    pub fn scan_coalesced_gpu_ac_phase1(&self, chunks: &[keyhog_core::Chunk]) -> GpuPhase1Output {
        let Some(matcher) = self.gpu_matcher() else {
            return self.gpu_degrade_done(chunks, crate::hw_probe::ScanBackend::Gpu);
        };
        let Some(program) = self.ac_gpu_program() else {
            return self.gpu_degrade_done(chunks, crate::hw_probe::ScanBackend::Gpu);
        };
        if self.gpu_backend.is_none() {
            return self.gpu_degrade_done(chunks, crate::hw_probe::ScanBackend::Gpu);
        }

        let (entries, mut buffer) = super::gpu_coalesce::coalesce_chunks(chunks);

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
        // SAFETY: same contract as scan_coalesced_gpu - `buffer` is a
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
        let ac_packs = self
            .gpu_ac_const_packs
            .get_or_init(|| super::gpu_cache::AcConstPacks {
                transitions: vyre_libs::scan::dispatch_io::pack_u32_slice(&matcher.dfa.transitions),
                output_offsets: vyre_libs::scan::dispatch_io::pack_u32_slice(
                    &matcher.dfa.output_offsets,
                ),
                output_records: vyre_libs::scan::dispatch_io::pack_u32_slice(
                    &matcher.dfa.output_records,
                ),
                pattern_lengths: vyre_libs::scan::dispatch_io::pack_u32_slice(
                    &matcher.pattern_lengths,
                ),
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
                haystack_len: vyre_libs::scan::dispatch_io::pack_u32_slice(&[shard_len]),
                atomic_count: vec![0u8; 4],
                config: vyre_libs::scan::dispatch_io::byte_scan_dispatch_config(
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

        // Sub-batched dispatch: dynamically scaled MAX_SHARDS_PER_GPU_BATCH
        // budget based on system RAM keeps transient host-side memory
        // bounded while maximizing dispatch concurrency for high-tier GPUs
        // and leaving vyre's 2048-slot readback ring deeply under-subscribed.
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

            let batch_results = match self.dispatch_gpu_shards(program, &sub_inputs, &sub_configs) {
                Ok(r) => r,
                Err(e) => {
                    tracing::error!(
                        shards = sub_end - sub_start,
                        "AC GPU batched dispatch failed, falling back to CPU: {e}"
                    );
                    return self.gpu_degrade_done(chunks, crate::hw_probe::ScanBackend::Gpu);
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
                        return self.gpu_degrade_done(chunks, crate::hw_probe::ScanBackend::Gpu);
                    }
                };
                if outputs.len() < 2 {
                    tracing::error!(
                        shard_index = i,
                        outputs = outputs.len(),
                        "AC GPU shard output buffer count too small; falling back to CPU"
                    );
                    return self.gpu_degrade_done(chunks, crate::hw_probe::ScanBackend::Gpu);
                }
                let count_bytes = &outputs[0];
                let matches_bytes = &outputs[1];
                if count_bytes.len() < 4 {
                    tracing::error!(
                        shard_index = i,
                        "AC GPU shard count buffer truncated; falling back to CPU"
                    );
                    return self.gpu_degrade_done(chunks, crate::hw_probe::ScanBackend::Gpu);
                }
                let count = u32::from_le_bytes([
                    count_bytes[0],
                    count_bytes[1],
                    count_bytes[2],
                    count_bytes[3],
                ]);
                if count > super::rule_pipeline::AC_GPU_MAX_MATCHES_PER_DISPATCH {
                    tracing::warn!(
                        cap = super::rule_pipeline::AC_GPU_MAX_MATCHES_PER_DISPATCH,
                        count,
                        shard_index = i,
                        "AC GPU shard exceeded program cap: truncation possible; falling back to CPU"
                    );
                    return self.gpu_degrade_done(chunks, crate::hw_probe::ScanBackend::Gpu);
                }
                let shard_matches = vyre_libs::scan::dispatch_io::unpack_match_triples(
                    matches_bytes,
                    count.min(super::rule_pipeline::AC_GPU_MAX_MATCHES_PER_DISPATCH),
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
            elapsed_ms,
            "AC GPU batched scan completed"
        );

        super::gpu_postprocess::fold_overlapping_same_pid_inplace(&mut matches);
        let total_patterns = self.ac_map.len() + self.fallback.len();
        let per_chunk_hits = super::gpu_postprocess::attribute_matches_to_chunks(
            &matches,
            &entries,
            total_patterns,
            chunks.len(),
        );

        // Hand the hits back to the orchestrator so it can run phase 2
        // on a separate thread (pipelined). Combined-wrapper callers
        // (`scan_coalesced_gpu_ac`) call phase 2 inline immediately
        // after this returns, preserving the original synchronous
        // behaviour.
        GpuPhase1Output::Hits(per_chunk_hits)
    }
}

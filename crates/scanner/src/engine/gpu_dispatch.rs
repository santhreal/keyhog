use super::CompiledScanner;

pub(crate) type ShardDispatchResult = std::result::Result<Vec<Vec<u8>>, vyre::BackendError>;

impl CompiledScanner {

/// Two-phase output of [`CompiledScanner::scan_coalesced_gpu_phase1`].
///
/// `Hits` is the headline path: GPU dispatch succeeded, per-chunk hit
/// triples are ready, and the caller (or
/// [`CompiledScanner::scan_coalesced_gpu_phase2`]) needs to run the
/// CPU per-chunk extract to produce `RawMatch` outputs.
///
/// `Done` means the dispatch detoured to a degraded backend
/// (`scan_coalesced_gpu_ac` / `scan_coalesced_non_gpu`) and the final
/// match list is already computed — no phase 2 work remains.
pub enum GpuPhase1Output {
    Hits(Vec<Vec<(u32, u32, u32)>>),
    Done(Vec<Vec<keyhog_core::RawMatch>>),
}

impl CompiledScanner {
    /// Dispatch `N` shards of the same program through whichever GPU
    /// backend is active.
    ///
    /// - wgpu path: `WgpuBackend::dispatch_borrowed_batch` records all
    ///   shards into one command encoder, one submit, one poll.
    /// - CUDA path: `rayon::par_iter` over per-shard sync
    ///   `dispatch_borrowed` calls — CUDA's driver pipelines kernel
    ///   launches on the default stream while host threads enqueue
    ///   the next shard, giving roughly the same overlap with no
    ///   wgpu-specific batched API on the trait.
    ///
    /// Returns one `Result<Vec<Vec<u8>>>` per shard in input order.
    /// The outer `Result` is `Err` only on a setup-time failure
    /// (e.g. no backend); per-shard dispatch errors land inside the
    /// inner Result so partial-failure handling stays per-shard.
    pub(crate) fn dispatch_gpu_shards(
        &self,
        program: &vyre::Program,
        shard_inputs: &[&[&[u8]]],
        configs: &[vyre::DispatchConfig],
    ) -> std::result::Result<Vec<ShardDispatchResult>, vyre::BackendError> {
        debug_assert_eq!(shard_inputs.len(), configs.len());
        if let Some(wgpu) = &self.wgpu_backend {
            let jobs: Vec<(&vyre::Program, &[&[u8]], &vyre::DispatchConfig)> = shard_inputs
                .iter()
                .zip(configs.iter())
                .map(|(inputs, config)| (program, *inputs, config))
                .collect();
            return wgpu.dispatch_borrowed_batch(&jobs);
        }
        let Some(backend) = self.gpu_backend.as_ref() else {
            return Err(vyre::BackendError::new(
                "no GPU backend acquired — keyhog should have routed to non-GPU before dispatch_gpu_shards. \
                 Fix: check select_backend() and the gpu_backend field after compile()."
                    .to_string(),
            ));
        };
        // CUDA / generic-trait path. rayon par_iter lets host threads
        // submit kernel launches concurrently. The fire-async-then-
        // await-all variant was measured slower on 1 GiB on RTX 5090
        // (23.5 s vs 21.9 s for plain par_iter) because vyre's
        // dispatch_borrowed_async sequentially queues onto the
        // default CUDA stream — no real device-side concurrency until
        // a multi-stream API is exposed at this layer.
        use rayon::prelude::*;
        let results: Vec<ShardDispatchResult> = shard_inputs
            .par_iter()
            .zip(configs.par_iter())
            .map(|(inputs, config)| backend.dispatch_borrowed(program, inputs, config))
            .collect();
        Ok(results)
    }

    /// GPU coalesced scan via one vyre `RulePipeline` (regex-NFA)
    /// dispatch. When the regex compile failed (vyre's
    /// per-subgroup state cap or unsupported regex syntax) or the
    /// coalesced buffer exceeds the pipeline's pre-built input_len
    /// cap, gracefully degrades to the literal-set GPU dispatch
    /// (`scan_coalesced_gpu`). Same per-chunk extraction phase as
    /// the literal-set path, same trigger-bitmask shape — the only
    /// thing that changes is which GPU primitive produced the raw
    /// `(pattern_id, start, end)` triples.
}

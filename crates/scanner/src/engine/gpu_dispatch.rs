use super::CompiledScanner;

pub(crate) type ShardDispatchResult = std::result::Result<Vec<Vec<u8>>, vyre::BackendError>;

// `GpuPhase1Output` (the {Hits, Done} two-phase return type used by
// the GPU scan_coalesced_* wrappers) is defined canonically in
// `gpu_scan_wrappers.rs`. A duplicate copy used to live here wrapped
// in a malformed outer `impl CompiledScanner {` opener (an enum can't
// be a member of an impl), which left the file unparseable and broke
// `cargo check` for the whole scanner crate - and via the dependency
// chain, every CI job in the repo. The orphan brace was removed and
// the duplicate enum dropped on 2026-05-26 (v0.5.17 prep).

impl CompiledScanner {
    /// Dispatch `N` shards of the same program through whichever GPU
    /// backend is active.
    ///
    /// - wgpu path: `WgpuBackend::dispatch_borrowed_batch` records all
    ///   shards into one command encoder, one submit, one poll.
    /// - CUDA path: `rayon::par_iter` over per-shard sync
    ///   `dispatch_borrowed` calls - CUDA's driver pipelines kernel
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
                "no GPU backend acquired - keyhog should have routed to non-GPU before dispatch_gpu_shards. \
                 Fix: check select_backend() and the gpu_backend field after compile()."
                    .to_string(),
            ));
        };
        // CUDA / generic-trait path. rayon par_iter lets host threads
        // submit kernel launches concurrently. The fire-async-then-
        // await-all variant was measured slower on 1 GiB on RTX 5090
        // (23.5 s vs 21.9 s for plain par_iter) because vyre's
        // dispatch_borrowed_async sequentially queues onto the
        // default CUDA stream - no real device-side concurrency until
        // a multi-stream API is exposed at this layer.
        use rayon::prelude::*;
        let results: Vec<ShardDispatchResult> = shard_inputs
            .par_iter()
            .zip(configs.par_iter())
            .map(|(inputs, config)| backend.dispatch_borrowed(program, inputs, config))
            .collect();
        Ok(results)
    }
}

// Note: the doc-comment describing `scan_coalesced_megascan` formerly
// trailed here as an orphan. Its target function lives in
// `gpu_megascan.rs`; the doc was stranded when the file was split. Do
// not re-add `///` blocks at module scope without an item below them
// - rustc demands a binding for outer doc comments and the broken
// state cost a whole day of red CI.

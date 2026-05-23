//! Replay helpers for captured CUDA graphs.

use std::sync::Arc;

use vyre_driver::BackendError;

use super::allocations::cuda_check;
use super::cuda_graph::CachedCudaGraph;
use super::dispatch::CudaBackend;
use super::staging_reserve::{reserve_vec, reserved_vec};

impl CachedCudaGraph {
    pub(crate) fn input_shape_matches(&self, inputs: &[&[u8]]) -> bool {
        inputs.len() == self.expected_input_lens.len()
            && inputs
                .iter()
                .zip(self.expected_input_lens.iter())
                .all(|(input, expected)| input.len() == *expected)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CudaGraphReplayStats {
    input_bytes: u64,
    output_bytes: u64,
    host_upload_operations: u64,
    device_readback_operations: u64,
}

impl CudaBackend {
    pub(crate) fn enqueue_cuda_graph_replay(
        &self,
        cached: &mut CachedCudaGraph,
        inputs: &[&[u8]],
    ) -> Result<CudaGraphReplayStats, BackendError> {
        validate_cached_graph_inputs(cached, inputs)?;

        for (slot, src) in cached.input_host_bufs.iter_mut().zip(inputs.iter()) {
            slot.copy_from_slice(src)?;
        }
        let stats = CudaGraphReplayStats::from_cached(cached);

        // SAFETY: FFI to libcuda.so. Pointer args were validated by the
        // matching graph-record path; `cached.stream` and `cached.graph_exec`
        // are owned by `CachedCudaGraph` and remain live until the replay is
        // synchronized or the graph is dropped.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuGraphLaunch(
                    cached.graph_exec.ptr().as_ptr(),
                    cached.stream.ptr().as_ptr(),
                ),
                "cuGraphLaunch",
            )?;
        }
        self.telemetry.record_cuda_graph_launch();
        Ok(stats)
    }

    pub(crate) fn finish_cuda_graph_replay_into(
        &self,
        cached: &CachedCudaGraph,
        stats: CudaGraphReplayStats,
        outputs: &mut Vec<Vec<u8>>,
    ) -> Result<(), BackendError> {
        // SAFETY: the stream belongs to this cached graph and all replay work
        // for the graph is enqueued on it.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuStreamSynchronize(cached.stream.ptr().as_ptr()),
                "cuStreamSynchronize (cuda_graph)",
            )?;
        }
        self.telemetry.record_sync_point();
        self.record_cuda_graph_replay_stats(stats);
        collect_cuda_graph_outputs(cached, outputs)?;
        Ok(())
    }

    pub(crate) fn record_cuda_graph_batched_replay_chunk(&self, lanes: u64) {
        self.telemetry.record_cuda_graph_batched_replay(lanes);
    }

    /// Replay a cached CUDA graph with new input bytes.
    pub fn dispatch_via_cuda_graph_into(
        &self,
        cached: &mut CachedCudaGraph,
        inputs: &[&[u8]],
        outputs: &mut Vec<Vec<u8>>,
    ) -> Result<(), BackendError> {
        let stats = self.enqueue_cuda_graph_replay(cached, inputs)?;
        self.finish_cuda_graph_replay_into(cached, stats, outputs)
    }

    /// Replay a cached CUDA graph with CUDA event timing.
    pub(crate) fn dispatch_via_cuda_graph_timed_into(
        &self,
        cached: &mut CachedCudaGraph,
        inputs: &[&[u8]],
        outputs: &mut Vec<Vec<u8>>,
    ) -> Result<u64, BackendError> {
        self.warmup()?;
        validate_cached_graph_inputs(cached, inputs)?;

        for (slot, src) in cached.input_host_bufs.iter_mut().zip(inputs.iter()) {
            slot.copy_from_slice(src)?;
        }
        let stats = CudaGraphReplayStats::from_cached(cached);

        let timing_events =
            crate::stream::CudaTimingEventPairLease::acquire(Arc::clone(&self.launch_resources))?;
        let (start, end) = timing_events.events()?;
        start.record(cached.stream.ptr().as_ptr())?;
        // SAFETY: FFI to libcuda.so. Pointer args were validated by the
        // matching alloc / store API; lifetimes are documented in the
        // surrounding function. cuda_check (or matching CUresult guard)
        // propagates non-success codes as BackendError.
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuGraphLaunch(
                    cached.graph_exec.ptr().as_ptr(),
                    cached.stream.ptr().as_ptr(),
                ),
                "cuGraphLaunch",
            )?;
        }
        self.telemetry.record_cuda_graph_launch();
        end.record(cached.stream.ptr().as_ptr())?;
        end.synchronize()?;
        self.telemetry.record_sync_point();
        let device_ns = start.elapsed_time_ns(&end)?;
        self.record_cuda_graph_replay_stats(stats);
        collect_cuda_graph_outputs(cached, outputs)?;
        Ok(device_ns)
    }

    /// Convenience wrapper that allocates the output `Vec` internally.
    pub fn dispatch_via_cuda_graph(
        &self,
        cached: &mut CachedCudaGraph,
        inputs: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        let mut outputs = reserved_vec(
            cached.output_host_bufs.len(),
            "cuda graph replay output vector",
        )?;
        self.dispatch_via_cuda_graph_into(cached, inputs, &mut outputs)?;
        Ok(outputs)
    }
}

impl CudaGraphReplayStats {
    fn from_cached(cached: &CachedCudaGraph) -> Self {
        Self {
            input_bytes: cached.replay_input_bytes,
            output_bytes: cached.replay_output_bytes,
            host_upload_operations: cached.replay_host_upload_operations,
            device_readback_operations: cached.replay_device_readback_operations,
        }
    }
}

fn validate_cached_graph_inputs(
    cached: &CachedCudaGraph,
    inputs: &[&[u8]],
) -> Result<(), BackendError> {
    if inputs.len() != cached.expected_input_lens.len() {
        return Err(BackendError::InvalidProgram {
            fix: format!(
                "Fix: cached cuda graph expects {} inputs but received {}.",
                cached.expected_input_lens.len(),
                inputs.len()
            ),
        });
    }
    for (idx, expected_len) in cached.expected_input_lens.iter().enumerate() {
        if inputs[idx].len() != *expected_len {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: cached cuda graph input {idx} expects {expected_len} bytes but \
                     received {} — re-record the graph for this input shape.",
                    inputs[idx].len()
                ),
            });
        }
    }
    Ok(())
}

fn collect_cuda_graph_outputs(
    cached: &CachedCudaGraph,
    outputs: &mut Vec<Vec<u8>>,
) -> Result<(), BackendError> {
    reserve_vec(
        outputs,
        cached.output_host_bufs.len(),
        "cuda graph replay output vector",
    )?;
    if outputs.len() < cached.output_host_bufs.len() {
        outputs.extend(
            std::iter::repeat_with(Vec::new).take(cached.output_host_bufs.len() - outputs.len()),
        );
    } else {
        outputs.truncate(cached.output_host_bufs.len());
    }
    for (output, (buf, byte_len)) in outputs.iter_mut().zip(
        cached
            .output_host_bufs
            .iter()
            .zip(cached.output_lens.iter()),
    ) {
        buf.copy_prefix_into(*byte_len, output)?;
    }
    Ok(())
}

impl CudaBackend {
    fn record_cuda_graph_replay_stats(&self, stats: CudaGraphReplayStats) {
        self.telemetry
            .record_host_to_device_bytes(stats.input_bytes);
        self.telemetry
            .record_device_to_host_readback(stats.output_bytes);
        self.telemetry
            .record_host_upload_operations(stats.host_upload_operations);
        self.telemetry
            .record_device_readback_operations(stats.device_readback_operations);
    }
}

#[cfg(test)]
mod source_contract_tests {
    #[test]
    fn cuda_graph_replay_uses_fallible_output_staging_reservation() {
        let source = include_str!("cuda_graph_replay.rs");
        assert!(source.contains("use super::staging_reserve::reserve_vec;"));
        assert!(source.contains("fn collect_cuda_graph_outputs("));
        assert!(source.contains(") -> Result<(), BackendError>"));
        assert!(!source.contains(concat!(
            "Vec::with_capacity",
            "(cached.output_host_bufs.len())"
        )));
        assert!(
            source.contains("outputs.extend(std::iter::repeat_with(Vec::new)")
                && !source.contains(concat!("outputs", ".resize_with(")),
            "Fix: CUDA graph replay output staging must extend after fallible reservation instead of resize-driven growth."
        );
    }
}

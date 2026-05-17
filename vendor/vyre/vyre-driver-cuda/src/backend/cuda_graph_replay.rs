//! Replay helpers for captured CUDA graphs.

use vyre_driver::BackendError;

use super::allocations::cuda_check;
use super::cuda_graph::CachedCudaGraph;
use super::dispatch::CudaBackend;

impl CachedCudaGraph {
    pub(crate) fn input_shape_matches(&self, inputs: &[&[u8]]) -> bool {
        inputs.len() == self.expected_input_lens.len()
            && inputs
                .iter()
                .zip(self.expected_input_lens.iter())
                .all(|(input, expected)| input.len() == *expected)
    }
}

impl CudaBackend {
    /// Replay a cached CUDA graph with new input bytes.
    pub fn dispatch_via_cuda_graph_into(
        &self,
        cached: &mut CachedCudaGraph,
        inputs: &[&[u8]],
        outputs: &mut Vec<Vec<u8>>,
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

        for (slot, src) in cached.input_host_bufs.iter_mut().zip(inputs.iter()) {
            slot.copy_from_slice(src);
        }

        unsafe {
            cuda_check(
                cudarc::driver::sys::cuGraphLaunch(
                    cached.graph_exec.as_ptr(),
                    cached.stream.as_ptr(),
                ),
                "cuGraphLaunch",
            )?;
            cuda_check(
                cudarc::driver::sys::cuStreamSynchronize(cached.stream.as_ptr()),
                "cuStreamSynchronize (cuda_graph)",
            )?;
        }

        if outputs.len() < cached.output_host_bufs.len() {
            outputs.resize_with(cached.output_host_bufs.len(), Vec::new);
        } else {
            outputs.truncate(cached.output_host_bufs.len());
        }
        for (output, (buf, byte_len)) in outputs.iter_mut().zip(
            cached
                .output_host_bufs
                .iter()
                .zip(cached.output_lens.iter()),
        ) {
            buf.copy_prefix_into(*byte_len, output);
        }
        Ok(())
    }

    /// Replay a cached CUDA graph with CUDA event timing.
    pub(crate) fn dispatch_via_cuda_graph_timed_into(
        &self,
        cached: &mut CachedCudaGraph,
        inputs: &[&[u8]],
        outputs: &mut Vec<Vec<u8>>,
    ) -> Result<u64, BackendError> {
        self.warmup()?;
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

        for (slot, src) in cached.input_host_bufs.iter_mut().zip(inputs.iter()) {
            slot.copy_from_slice(src);
        }

        let start = crate::stream::CudaEvent::timing()?;
        let end = crate::stream::CudaEvent::timing()?;
        start.record(cached.stream.as_ptr())?;
        unsafe {
            cuda_check(
                cudarc::driver::sys::cuGraphLaunch(
                    cached.graph_exec.as_ptr(),
                    cached.stream.as_ptr(),
                ),
                "cuGraphLaunch",
            )?;
        }
        end.record(cached.stream.as_ptr())?;
        end.synchronize()?;
        let device_ns = start.elapsed_time_ns(&end)?;

        if outputs.len() < cached.output_host_bufs.len() {
            outputs.resize_with(cached.output_host_bufs.len(), Vec::new);
        } else {
            outputs.truncate(cached.output_host_bufs.len());
        }
        for (output, (buf, byte_len)) in outputs.iter_mut().zip(
            cached
                .output_host_bufs
                .iter()
                .zip(cached.output_lens.iter()),
        ) {
            buf.copy_prefix_into(*byte_len, output);
        }
        Ok(device_ns)
    }

    /// Convenience wrapper that allocates the output `Vec` internally.
    pub fn dispatch_via_cuda_graph(
        &self,
        cached: &mut CachedCudaGraph,
        inputs: &[&[u8]],
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        let mut outputs = Vec::with_capacity(cached.output_host_bufs.len());
        self.dispatch_via_cuda_graph_into(cached, inputs, &mut outputs)?;
        Ok(outputs)
    }
}

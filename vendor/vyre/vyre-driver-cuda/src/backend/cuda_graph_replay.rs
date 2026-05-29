//! Replay helpers for captured CUDA graphs.

use std::ptr::NonNull;
use std::sync::Arc;

use vyre_driver::BackendError;

use super::allocations::cuda_check;
use super::cuda_graph::{CachedCudaGraph, GraphExecGuard, StreamGuard};
use super::dispatch::CudaBackend;
use super::staging_reserve::{reserved_vec, resize_vec_slots};
use crate::input_identity::{exact_input_key, ExactInputKey};

impl CachedCudaGraph {
    pub(crate) fn input_shape_matches(&self, inputs: &[&[u8]]) -> bool {
        inputs.len() == self.expected_input_lens.len()
            && inputs
                .iter()
                .zip(self.expected_input_lens.iter())
                .all(|(input, expected)| input.len() == *expected)
    }

    pub(crate) fn materialized_output_cache_matches(
        &self,
        inputs: &[&[u8]],
    ) -> Result<bool, BackendError> {
        let input_state = prepare_cuda_graph_replay_input_state(self, inputs)?;
        self.materialized_output_cache_matches_with_input_state(inputs, &input_state)
    }

    pub(crate) fn materialized_output_cache_matches_with_input_state(
        &self,
        inputs: &[&[u8]],
        input_state: &CudaGraphReplayInputState,
    ) -> Result<bool, BackendError> {
        if !(self.resident_input_replay_safe && self.host_outputs_initialized) {
            return Ok(false);
        }
        cached_input_bytes_match_with_key(self, inputs, &input_state.input_key)
    }
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct CudaGraphReplayStats {
    input_bytes: u64,
    output_bytes: u64,
    host_upload_operations: u64,
    device_readback_operations: u64,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct CudaGraphReplayInputState {
    input_key: ExactInputKey,
}

#[derive(Clone, Copy, Debug)]
struct PreparedCudaGraphReplayLaunch {
    stats: CudaGraphReplayStats,
    resident_input_replay: bool,
}

const CUDA_GRAPH_REPLAY_SPIN_QUERY_LIMIT: usize = 4096;

fn launch_cuda_graph_exec(
    graph_exec: &GraphExecGuard,
    stream: &StreamGuard,
    label: &'static str,
) -> Result<(), BackendError> {
    let graph_exec = graph_exec.ptr();
    if graph_exec == NonNull::dangling() {
        return Err(BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA graph replay received a dangling CUgraphExec sentinel before {label}. Re-record the graph before replay."
            ),
        });
    }
    let stream = stream.ptr();
    if stream == NonNull::dangling() {
        return Err(BackendError::InvalidProgram {
            fix: format!(
                "Fix: CUDA graph replay received a dangling CUstream sentinel before {label}. Re-record the graph before replay."
            ),
        });
    }
    // SAFETY: FFI to libcuda.so. `GraphExecGuard` and `StreamGuard` own
    // non-null CUDA handles and the dangling sentinels are rejected above.
    unsafe {
        cuda_check(
            cudarc::driver::sys::cuGraphLaunch(graph_exec.as_ptr(), stream.as_ptr()),
            label,
        )
    }
}

fn synchronize_cuda_graph_replay_stream(cached: &CachedCudaGraph) -> Result<(), BackendError> {
    for _ in 0..CUDA_GRAPH_REPLAY_SPIN_QUERY_LIMIT {
        if crate::stream::query_raw_stream_ready(
            cached.stream.ptr().as_ptr(),
            "cuStreamQuery (cuda_graph)",
        )? {
            return Ok(());
        }
        std::hint::spin_loop();
    }
    crate::stream::synchronize_raw_stream(
        cached.stream.ptr().as_ptr(),
        "cuStreamSynchronize (cuda_graph fallback)",
    )
}

fn cached_input_bytes_match(
    cached: &CachedCudaGraph,
    inputs: &[&[u8]],
) -> Result<bool, BackendError> {
    let input_key = exact_input_key(inputs)?;
    cached_input_bytes_match_with_key(cached, inputs, &input_key)
}

fn cached_input_bytes_match_with_key(
    cached: &CachedCudaGraph,
    inputs: &[&[u8]],
    input_key: &ExactInputKey,
) -> Result<bool, BackendError> {
    if cached.cached_input_key != *input_key {
        return Ok(false);
    }
    cached_input_bytes_match_after_key_match(cached, inputs)
}

fn cached_input_bytes_match_after_key_match(
    cached: &CachedCudaGraph,
    inputs: &[&[u8]],
) -> Result<bool, BackendError> {
    if cached.input_host_bufs.len() != inputs.len() {
        return Err(BackendError::InvalidProgram {
            fix: format!(
                "Fix: cached cuda graph has {} pinned input buffer(s) for {} caller input(s). Re-record the graph; zip-based replay would skip input uploads.",
                cached.input_host_bufs.len(),
                inputs.len()
            ),
        });
    }
    for (slot, src) in cached.input_host_bufs.iter().zip(inputs.iter()) {
        if src.len() > slot.byte_len {
            return Err(BackendError::InvalidProgram {
                fix: format!(
                    "Fix: CUDA graph cached input comparison saw {} byte(s) for a {} byte pinned allocation. Re-record the graph for this input shape.",
                    src.len(),
                    slot.byte_len
                ),
            });
        }
        if src.is_empty() {
            continue;
        }
        let cached_bytes = {
            // SAFETY: `slot` owns a pinned allocation of at least `slot.byte_len`
            // bytes, and the length check above proves `src.len() <= slot.byte_len`.
            unsafe { std::slice::from_raw_parts(slot.as_ptr().cast::<u8>(), src.len()) }
        };
        if cached_bytes != *src {
            return Ok(false);
        }
    }
    Ok(true)
}

impl CudaBackend {
    pub(crate) fn try_cuda_graph_materialized_cache_into(
        &self,
        cached: &mut CachedCudaGraph,
        inputs: &[&[u8]],
        outputs: &mut Vec<Vec<u8>>,
    ) -> Result<bool, BackendError> {
        let input_state = self.prepare_cuda_graph_replay_input_state(cached, inputs)?;
        self.try_cuda_graph_materialized_cache_with_input_state_into(
            cached,
            inputs,
            &input_state,
            outputs,
        )
    }

    pub(crate) fn try_cuda_graph_materialized_cache_with_input_state_into(
        &self,
        cached: &mut CachedCudaGraph,
        inputs: &[&[u8]],
        input_state: &CudaGraphReplayInputState,
        outputs: &mut Vec<Vec<u8>>,
    ) -> Result<bool, BackendError> {
        if cached.materialized_output_cache_matches_with_input_state(inputs, input_state)? {
            collect_cuda_graph_outputs(cached, outputs)?;
            self.telemetry.record_cuda_graph_materialized_cache_hit();
            return Ok(true);
        }
        Ok(false)
    }

    pub(crate) fn enqueue_cuda_graph_replay(
        &self,
        cached: &mut CachedCudaGraph,
        inputs: &[&[u8]],
    ) -> Result<CudaGraphReplayStats, BackendError> {
        let input_state = self.prepare_cuda_graph_replay_input_state(cached, inputs)?;
        self.enqueue_cuda_graph_replay_with_input_state(cached, inputs, &input_state)
    }

    pub(crate) fn enqueue_cuda_graph_replay_with_input_state(
        &self,
        cached: &mut CachedCudaGraph,
        inputs: &[&[u8]],
        input_state: &CudaGraphReplayInputState,
    ) -> Result<CudaGraphReplayStats, BackendError> {
        let prepared = prepare_cuda_graph_replay_launch(cached, inputs, input_state)?;
        launch_prepared_cuda_graph_replay(cached, &prepared, "cuGraphLaunch")?;
        self.telemetry.record_cuda_graph_launch();
        Ok(prepared.stats)
    }

    pub(crate) fn finish_cuda_graph_replay_into(
        &self,
        cached: &mut CachedCudaGraph,
        stats: CudaGraphReplayStats,
        outputs: &mut Vec<Vec<u8>>,
    ) -> Result<(), BackendError> {
        synchronize_cuda_graph_replay_stream(cached)?;
        self.telemetry.record_sync_point();
        self.record_cuda_graph_replay_stats(stats);
        collect_cuda_graph_outputs(cached, outputs)?;
        cached.host_outputs_initialized = true;
        Ok(())
    }

    pub(crate) fn record_cuda_graph_batched_replay_chunk(&self, lanes: u64) {
        self.telemetry.record_cuda_graph_batched_replay(lanes);
    }

    pub(crate) fn prepare_cuda_graph_replay_input_state(
        &self,
        cached: &CachedCudaGraph,
        inputs: &[&[u8]],
    ) -> Result<CudaGraphReplayInputState, BackendError> {
        prepare_cuda_graph_replay_input_state(cached, inputs)
    }

    pub(crate) fn prepare_cuda_graph_replay_input_state_with_key(
        &self,
        cached: &CachedCudaGraph,
        inputs: &[&[u8]],
        input_key: ExactInputKey,
    ) -> Result<CudaGraphReplayInputState, BackendError> {
        prepare_cuda_graph_replay_input_state_with_key(cached, inputs, input_key)
    }

    /// Replay a cached CUDA graph with new input bytes.
    pub fn dispatch_via_cuda_graph_into(
        &self,
        cached: &mut CachedCudaGraph,
        inputs: &[&[u8]],
        outputs: &mut Vec<Vec<u8>>,
    ) -> Result<(), BackendError> {
        let input_state = self.prepare_cuda_graph_replay_input_state(cached, inputs)?;
        if self.try_cuda_graph_materialized_cache_with_input_state_into(
            cached,
            inputs,
            &input_state,
            outputs,
        )? {
            return Ok(());
        }
        let stats =
            self.enqueue_cuda_graph_replay_with_input_state(cached, inputs, &input_state)?;
        self.finish_cuda_graph_replay_into(cached, stats, outputs)
    }

    /// Replay a cached CUDA graph with CUDA event timing.
    pub(crate) fn dispatch_via_cuda_graph_timed_into(
        &self,
        cached: &mut CachedCudaGraph,
        inputs: &[&[u8]],
        outputs: &mut Vec<Vec<u8>>,
    ) -> Result<u64, BackendError> {
        let input_state = self.prepare_cuda_graph_replay_input_state(cached, inputs)?;
        if self.try_cuda_graph_materialized_cache_with_input_state_into(
            cached,
            inputs,
            &input_state,
            outputs,
        )? {
            return Ok(0);
        }
        self.warmup()?;
        let prepared = prepare_cuda_graph_replay_launch(cached, inputs, &input_state)?;

        let timing_events =
            crate::stream::CudaTimingEventPairLease::acquire(Arc::clone(&self.launch_resources))?;
        let (start, end) = timing_events.events()?;
        start.record(cached.stream.ptr().as_ptr())?;
        launch_prepared_cuda_graph_replay(cached, &prepared, "cuGraphLaunch")?;
        self.telemetry.record_cuda_graph_launch();
        end.record(cached.stream.ptr().as_ptr())?;
        end.synchronize()?;
        self.telemetry.record_sync_point();
        let device_ns = start.elapsed_time_ns(&end)?;
        self.record_cuda_graph_replay_stats(prepared.stats);
        collect_cuda_graph_outputs(cached, outputs)?;
        cached.host_outputs_initialized = true;
        Ok(device_ns)
    }

    /// Replay a cached CUDA graph with CUDA event timing and allocated outputs.
    pub fn dispatch_via_cuda_graph_timed(
        &self,
        cached: &mut CachedCudaGraph,
        inputs: &[&[u8]],
    ) -> Result<vyre_driver::TimedDispatchResult, BackendError> {
        let started = std::time::Instant::now();
        let mut outputs = reserved_vec(
            cached.output_host_bufs.len(),
            "timed cuda graph replay output vector",
        )?;
        let device_ns = self.dispatch_via_cuda_graph_timed_into(cached, inputs, &mut outputs)?;
        let wall_ns = crate::numeric::CUDA_NUMERIC
            .elapsed_nanos_u64(started, "timed cuda graph replay wall latency")?;
        self.telemetry
            .record_timed_dispatch(wall_ns, Some(device_ns), None, None);
        Ok(vyre_driver::TimedDispatchResult {
            outputs,
            wall_ns,
            device_ns: Some(device_ns),
            enqueue_ns: None,
            wait_ns: None,
        })
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

fn prepare_cuda_graph_replay(
    cached: &mut CachedCudaGraph,
    inputs: &[&[u8]],
    input_state: &CudaGraphReplayInputState,
) -> Result<(CudaGraphReplayStats, bool), BackendError> {
    let resident_input_replay = cached.resident_input_replay_safe
        && cached.device_inputs_initialized
        && cached_input_bytes_match_with_key(cached, inputs, &input_state.input_key)?;

    if !resident_input_replay {
        for ((slot, src), transfer_len) in cached
            .input_host_bufs
            .iter_mut()
            .zip(inputs.iter())
            .zip(cached.input_transfer_lens.iter())
        {
            slot.copy_from_slice(src)?;
            if *transfer_len > src.len() {
                slot.zero_range(src.len(), transfer_len - src.len())?;
            }
        }
        cached.cached_input_key = input_state.input_key;
        cached.host_outputs_initialized = false;
    }
    let mut stats = CudaGraphReplayStats::from_cached(cached);
    if resident_input_replay {
        stats.input_bytes = 0;
        stats.host_upload_operations = 0;
    }
    Ok((stats, resident_input_replay))
}

fn prepare_cuda_graph_replay_launch(
    cached: &mut CachedCudaGraph,
    inputs: &[&[u8]],
    input_state: &CudaGraphReplayInputState,
) -> Result<PreparedCudaGraphReplayLaunch, BackendError> {
    let (stats, resident_input_replay) = prepare_cuda_graph_replay(cached, inputs, input_state)?;
    Ok(PreparedCudaGraphReplayLaunch {
        stats,
        resident_input_replay,
    })
}

fn launch_prepared_cuda_graph_replay(
    cached: &mut CachedCudaGraph,
    prepared: &PreparedCudaGraphReplayLaunch,
    label: &'static str,
) -> Result<(), BackendError> {
    let graph_exec = if prepared.resident_input_replay {
        &cached.resident_input_graph_exec
    } else {
        &cached.graph_exec
    };
    launch_cuda_graph_exec(graph_exec, &cached.stream, label)?;
    cached.device_inputs_initialized = true;
    Ok(())
}

fn prepare_cuda_graph_replay_input_state(
    cached: &CachedCudaGraph,
    inputs: &[&[u8]],
) -> Result<CudaGraphReplayInputState, BackendError> {
    prepare_cuda_graph_replay_input_state_with_key(cached, inputs, exact_input_key(inputs)?)
}

fn prepare_cuda_graph_replay_input_state_with_key(
    cached: &CachedCudaGraph,
    inputs: &[&[u8]],
    input_key: ExactInputKey,
) -> Result<CudaGraphReplayInputState, BackendError> {
    validate_cached_graph_inputs(cached, inputs)?;
    Ok(CudaGraphReplayInputState { input_key })
}

fn validate_cached_graph_inputs(
    cached: &CachedCudaGraph,
    inputs: &[&[u8]],
) -> Result<(), BackendError> {
    if cached.input_host_bufs.len() != cached.expected_input_lens.len() {
        return Err(BackendError::InvalidProgram {
            fix: format!(
                "Fix: cached cuda graph has {} pinned input buffer(s) but {} expected input length(s). Re-record the graph before replay.",
                cached.input_host_bufs.len(),
                cached.expected_input_lens.len()
            ),
        });
    }
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
                     received {}  -  re-record the graph for this input shape.",
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
    if cached.output_host_bufs.len() != cached.output_lens.len() {
        return Err(BackendError::InvalidProgram {
            fix: format!(
                "Fix: cached cuda graph has {} pinned output buffer(s) but {} output length(s). Re-record the graph before collecting outputs.",
                cached.output_host_bufs.len(),
                cached.output_lens.len()
            ),
        });
    }
    resize_vec_slots(
        outputs,
        cached.output_host_bufs.len(),
        "cuda graph replay output vector",
    )?;
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
        assert!(source.contains("use super::staging_reserve::{reserved_vec, resize_vec_slots};"));
        assert!(source.contains("fn collect_cuda_graph_outputs("));
        assert!(source.contains(") -> Result<(), BackendError>"));
        assert!(!source.contains(concat!(
            "Vec::with_capacity",
            "(cached.output_host_bufs.len())"
        )));
        assert!(
            source.contains("resize_vec_slots(")
                && !source.contains(concat!("outputs", ".extend("))
                && !source.contains(concat!("outputs", ".resize_with(")),
            "Fix: CUDA graph replay output staging must use the shared fallible resize helper instead of bespoke growth."
        );
        assert!(
            source.contains("cached.input_host_bufs.len() != cached.expected_input_lens.len()")
                && source.contains("zip-based replay would skip input uploads")
                && source.contains("cached.output_host_bufs.len() != cached.output_lens.len()"),
            "Fix: CUDA graph replay must validate cached graph input/output metadata before zip-based staging."
        );
        assert_eq!(
            source
                .matches(concat!("cudarc::driver::sys::", "cuGraphLaunch("))
                .count(),
            1,
            "Fix: CUDA graph replay must keep raw cuGraphLaunch behind one checked helper."
        );
        assert!(
            source.contains("fn launch_cuda_graph_exec(")
                && source.contains("dangling CUgraphExec sentinel")
                && source.contains("dangling CUstream sentinel"),
            "Fix: CUDA graph replay launch helper must validate graph and stream handles before FFI."
        );
    }

    #[test]
    fn timed_and_untimed_graph_replay_share_resident_input_skip_copy_path() {
        let source = include_str!("cuda_graph_replay.rs");
        assert!(
            source.contains("fn prepare_cuda_graph_replay(")
                && source.matches("prepare_cuda_graph_replay(cached, inputs,").count() >= 2,
            "Fix: timed and untimed CUDA graph replay must share one resident-input preparation path."
        );
        assert!(
            source.contains("fn prepare_cuda_graph_replay_launch(")
                && source.contains("fn launch_prepared_cuda_graph_replay(")
                && source
                    .matches("launch_prepared_cuda_graph_replay(cached, &prepared, \"cuGraphLaunch\")")
                    .count()
                    == 2,
            "Fix: timed and untimed CUDA graph replay must share prepared launch graph selection and device-input state updates."
        );
        let timed_section = source
            .split("pub(crate) fn dispatch_via_cuda_graph_timed_into")
            .nth(1)
            .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - timed CUDA graph replay entrypoint must exist")
            .split("/// Convenience wrapper")
            .next()
            .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - timed replay section must precede convenience wrapper");
        assert!(
            timed_section.contains("prepare_cuda_graph_replay_launch(cached, inputs, &input_state)?")
                && timed_section.contains("launch_prepared_cuda_graph_replay(cached, &prepared, \"cuGraphLaunch\")")
                && !timed_section.contains("for (slot, src) in cached.input_host_bufs"),
            "Fix: timed CUDA graph replay must use resident-input graph replay when safe instead of always copying host inputs."
        );
    }

    #[test]
    fn materialized_graph_cache_is_shared_by_single_and_batched_replay_paths() {
        let replay_source = include_str!("cuda_graph_replay.rs");
        let compiled_dispatch = include_str!("../pipeline/compiled_dispatch.rs");
        assert!(
            replay_source.contains("pub(crate) fn try_cuda_graph_materialized_cache_with_input_state_into(")
                && replay_source.contains("if self.try_cuda_graph_materialized_cache_with_input_state_into("),
            "Fix: single CUDA graph replay must route materialized output cache hits through the shared helper."
        );
        assert!(
            compiled_dispatch.contains("materialized_output_batch_cache_partition_into")
                && compiled_dispatch.contains("let miss_entries =")
                && compiled_dispatch.contains("for (chunk_index, chunk) in miss_entries.chunks(lane_count).enumerate()")
                && compiled_dispatch.contains("chunk_index")
                && compiled_dispatch.contains(".checked_mul(lane_count)")
                && compiled_dispatch.contains("prepare_cuda_graph_replay_input_state")
                && compiled_dispatch.contains("try_cuda_graph_materialized_cache_with_input_state_into")
                && compiled_dispatch.contains("enqueue_cuda_graph_replay_with_input_state")
                && compiled_dispatch.contains("continue;")
                && compiled_dispatch.contains("[LaunchedMaterializedBatch; MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE]")
                && compiled_dispatch.contains("input_key: miss.input_key"),
            "Fix: batched CUDA graph replay must partition materialized exact-input cache hits before lane planning, reuse precomputed input keys, and only finish lanes that actually launched."
        );
    }

    #[test]
    fn cached_graph_input_key_gates_byte_compare_and_rewrites_invalidate_host_outputs() {
        let replay_source = include_str!("cuda_graph_replay.rs");
        let graph_source = include_str!("cuda_graph.rs");
        assert!(
            replay_source.contains("use crate::input_identity::{exact_input_key, ExactInputKey};")
                && replay_source.contains("fn cached_input_bytes_match_with_key(")
                && replay_source.contains("if cached.cached_input_key != *input_key")
                && replay_source.contains("cached_input_bytes_match_after_key_match"),
            "Fix: raw CUDA graph exact-input checks must use the shared tuple key as a fast reject before expensive pinned-host byte comparison."
        );
        assert!(
            replay_source.contains("let input_key = exact_input_key(inputs)?;")
                && replay_source.contains("cached.cached_input_key = input_state.input_key;")
                && replay_source.contains("cached.host_outputs_initialized = false;"),
            "Fix: rewriting cached graph host inputs must update the exact-input key and immediately invalidate materialized host outputs before graph launch/finish can fail."
        );
        assert!(
            graph_source.contains("pub(crate) cached_input_key: ExactInputKey")
                && graph_source.contains("let cached_input_key = exact_input_key(sample_inputs)?;"),
            "Fix: recorded CUDA graphs must initialize cached_input_key from the captured sample inputs."
        );
    }

    #[test]
    fn raw_graph_replay_prepares_input_state_once_per_dispatch_path() {
        let replay_source = include_str!("cuda_graph_replay.rs");
        assert!(
            replay_source.contains("pub(crate) struct CudaGraphReplayInputState")
                && replay_source.contains("fn prepare_cuda_graph_replay_input_state(")
                && replay_source.contains("validate_cached_graph_inputs(cached, inputs)?;")
                && replay_source.contains("input_key: exact_input_key(inputs)?"),
            "Fix: CUDA graph replay must centralize shape validation and exact-input key creation in a reusable input-state object."
        );
        let untimed_section = replay_source
            .split("pub fn dispatch_via_cuda_graph_into")
            .nth(1)
            .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - untimed CUDA graph replay entrypoint must exist")
            .split("/// Replay a cached CUDA graph with CUDA event timing.")
            .next()
            .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - untimed replay section must precede timed replay");
        assert_eq!(
            untimed_section
                .matches("prepare_cuda_graph_replay_input_state(cached, inputs)?")
                .count(),
            1,
            "Fix: untimed raw CUDA graph replay must validate/hash inputs once and reuse that state for materialized-cache check plus launch preparation."
        );
        assert!(
            untimed_section.contains("try_cuda_graph_materialized_cache_with_input_state_into")
                && untimed_section.contains("enqueue_cuda_graph_replay_with_input_state"),
            "Fix: untimed raw CUDA graph replay must pass the prepared input state through both cache and launch paths."
        );
        let timed_section = replay_source
            .split("pub(crate) fn dispatch_via_cuda_graph_timed_into")
            .nth(1)
            .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - timed CUDA graph replay entrypoint must exist")
            .split("/// Replay a cached CUDA graph with CUDA event timing and allocated outputs.")
            .next()
            .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - timed replay section must precede timed wrapper");
        assert_eq!(
            timed_section
                .matches("prepare_cuda_graph_replay_input_state(cached, inputs)?")
                .count(),
            1,
            "Fix: timed raw CUDA graph replay must validate/hash inputs once and reuse that state before event timing."
        );
        assert!(
            timed_section.contains("try_cuda_graph_materialized_cache_with_input_state_into")
                && timed_section.contains("prepare_cuda_graph_replay_launch(cached, inputs, &input_state)?")
                && timed_section.contains("launch_prepared_cuda_graph_replay(cached, &prepared, \"cuGraphLaunch\")"),
            "Fix: timed raw CUDA graph replay must reuse the prepared input state for materialized and resident-input replay decisions."
        );
    }

    #[test]
    fn compiled_batch_graph_misses_reuse_materialized_cache_input_keys() {
        let replay_source = include_str!("cuda_graph_replay.rs");
        let compiled_dispatch = include_str!("../pipeline/compiled_dispatch.rs");
        assert!(
            replay_source.contains("prepare_cuda_graph_replay_input_state_with_key")
                && replay_source.contains("input_key: ExactInputKey")
                && replay_source.contains("validate_cached_graph_inputs(cached, inputs)?;")
                && replay_source.contains("Ok(CudaGraphReplayInputState { input_key })"),
            "Fix: raw CUDA graph replay must accept a precomputed exact-input key while still validating graph shape."
        );
        assert!(
            compiled_dispatch.contains("struct MaterializedBatchMiss")
                && compiled_dispatch.contains("input_key: MaterializedInputKey")
                && compiled_dispatch.contains("materialized_input_key(inputs)?")
                && compiled_dispatch.contains("cache.snapshot_with_key(inputs, &input_key)")
                && compiled_dispatch.contains("prepare_cuda_graph_replay_input_state_with_key")
                && compiled_dispatch.contains("miss.input_key"),
            "Fix: compiled batched CUDA graph replay must reuse materialized-cache exact-input keys for graph miss replay instead of hashing each miss again."
        );
        let partition_section = compiled_dispatch
            .split("fn materialized_output_batch_cache_partition_into")
            .nth(1)
            .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - compiled materialized batch partition function must exist")
            .split("fn materialized_output_cache_hit_into")
            .next()
            .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - batch partition section must precede single cache helper");
        let key_position = partition_section
            .find("materialized_input_key(inputs)?")
            .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - batch partition must compute exact-input keys");
        let lock_position = partition_section
            .find("let cache = self.lock_materialized_output_cache")
            .expect("Fix: replace expect with fallible API or document caller precondition; panic only on programmer error - batch partition must acquire materialized cache lock");
        assert!(
            partition_section.contains("for (batch_index, inputs) in batches.iter().enumerate()")
                && partition_section.contains("input_keys.push((batch_index, materialized_input_key(inputs)?));")
                && partition_section.contains("let cache = self.lock_materialized_output_cache")
                && key_position < lock_position,
            "Fix: compiled materialized batch replay must compute exact-input keys before acquiring the materialized-output cache lock."
        );
    }
}

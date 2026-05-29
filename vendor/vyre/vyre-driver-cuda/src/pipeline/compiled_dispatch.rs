//! `CompiledPipeline` implementation for precompiled CUDA pipelines.
//!
//! The parent `pipeline` module owns construction and static launch state. This
//! module owns dispatch entrypoints, CUDA graph replay selection, dynamic GPU
//! dispatch when runtime policy changes, and persistent-resource output routing.

use std::sync::MutexGuard;

use smallvec::SmallVec;
use vyre_driver::{
    borrowed_input_batch_shapes_match, dispatch_configs_share_launch_shape, BackendError,
    BindingRole, CompiledPipeline, DispatchConfig, OutputBuffers, Resource,
};

use crate::backend::cuda_graph_replay::CudaGraphReplayStats;
use crate::backend::resident_dispatch::CudaResidentDispatch;
use crate::backend::staging_reserve::{reserve_smallvec, reserved_vec, resize_vec_slots};
use crate::backend::CachedCudaGraph;
use crate::numeric::CUDA_NUMERIC;
use crate::pipeline::materialized_cache::{materialized_input_key, MaterializedInputKey};
use crate::pipeline::{
    cuda_graph_lane_count_for_batch, cuda_graph_replay_enabled, CudaCompiledPipeline,
    MaterializedPipelineOutputCache, MaterializedPipelineOutputCacheEntry,
    MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE,
};

#[derive(Clone, Copy, Debug)]
struct MaterializedBatchMiss {
    batch_index: usize,
    input_key: MaterializedInputKey,
}

#[derive(Clone, Copy, Debug)]
struct LaunchedMaterializedBatch {
    lane: usize,
    batch_index: usize,
    input_key: MaterializedInputKey,
    replay_stats: CudaGraphReplayStats,
}

impl CompiledPipeline for CudaCompiledPipeline {
    fn id(&self) -> &str {
        &self.id
    }

    fn dispatch(
        &self,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        let borrowed = vyre_driver::borrowed_input_slices(inputs, "cuda compiled borrowed input")?;
        self.dispatch_borrowed(&borrowed, config)
    }

    fn dispatch_borrowed(
        &self,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        if !dispatch_configs_share_launch_shape(&self.compiled_config, config) {
            return self
                .backend
                .dispatch_borrowed_async_with_ptx_key(
                    &self.program,
                    inputs,
                    config,
                    &self.ptx_src,
                    self.module_key,
                )?
                .await_result();
        }
        let mut outputs = reserved_vec(self.prepared.output_binding_indices.len(), "output")?;
        self.dispatch_borrowed_into(inputs, config, &mut outputs)?;
        Ok(outputs)
    }

    fn dispatch_borrowed_timed(
        &self,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<vyre_driver::TimedDispatchResult, BackendError> {
        let _profiler_range =
            crate::profiler::cuda_profiler_range(crate::profiler::CUDA_PIPELINE_DISPATCH_RANGE);
        if !dispatch_configs_share_launch_shape(&self.compiled_config, config) {
            return self.backend.dispatch_borrowed_timed_with_ptx_key(
                &self.program,
                inputs,
                config,
                &self.ptx_src,
                self.module_key,
            );
        }
        if !cuda_graph_replay_enabled() || self.prepared.cooperative {
            return self.backend.dispatch_borrowed_timed_with_ptx_key(
                &self.program,
                inputs,
                config,
                &self.ptx_src,
                self.module_key,
            );
        }
        let started = std::time::Instant::now();
        let mut outputs = reserved_vec(self.prepared.output_binding_indices.len(), "timed output")?;
        if self.materialized_output_cache_hit_into(inputs, &mut outputs)? {
            let wall_ns = CUDA_NUMERIC
                .elapsed_nanos_u64(started, "cuda graph materialized timed hit wall latency")?;
            self.backend
                .telemetry
                .record_timed_dispatch(wall_ns, Some(0), None, None);
            return Ok(vyre_driver::TimedDispatchResult {
                outputs,
                wall_ns,
                device_ns: Some(0),
                enqueue_ns: None,
                wait_ns: None,
            });
        }
        let mut cached = match self.take_cached_graph(inputs)? {
            Some(cached) => cached,
            None => self
                .backend
                .record_cuda_graph_borrowed(&self.program, inputs, config)?,
        };
        let replay_result =
            self.backend
                .dispatch_via_cuda_graph_timed_into(&mut cached, inputs, &mut outputs);
        if replay_result.is_ok() {
            self.return_cached_graph(cached)?;
            self.remember_materialized_output_cache(inputs, &outputs)?;
        }
        let device_ns = replay_result?;
        let wall_ns = CUDA_NUMERIC.elapsed_nanos_u64(started, "cuda graph replay wall latency")?;
        self.backend
            .telemetry
            .record_timed_dispatch(wall_ns, Some(device_ns), None, None);
        Ok(vyre_driver::TimedDispatchResult {
            outputs,
            wall_ns,
            device_ns: Some(device_ns),
            enqueue_ns: None,
            wait_ns: None,
        })
    }

    fn dispatch_borrowed_into(
        &self,
        inputs: &[&[u8]],
        config: &DispatchConfig,
        outputs: &mut OutputBuffers,
    ) -> Result<(), BackendError> {
        let _profiler_range =
            crate::profiler::cuda_profiler_range(crate::profiler::CUDA_PIPELINE_DISPATCH_RANGE);
        if !dispatch_configs_share_launch_shape(&self.compiled_config, config) {
            self.backend
                .dispatch_borrowed_async_with_ptx_key(
                    &self.program,
                    inputs,
                    config,
                    &self.ptx_src,
                    self.module_key,
                )?
                .await_result_into(outputs)?;
            return Ok(());
        }
        if !cuda_graph_replay_enabled() || self.prepared.cooperative {
            self.backend
                .dispatch_borrowed_async_with_ptx_key(
                    &self.program,
                    inputs,
                    config,
                    &self.ptx_src,
                    self.module_key,
                )?
                .await_result_into(outputs)?;
            return Ok(());
        }
        if self.materialized_output_cache_hit_into(inputs, outputs)? {
            return Ok(());
        }
        let mut cached = match self.take_cached_graph(inputs)? {
            Some(cached) => cached,
            None => self
                .backend
                .record_cuda_graph_borrowed(&self.program, inputs, config)?,
        };
        let replay_result = self
            .backend
            .dispatch_via_cuda_graph_into(&mut cached, inputs, outputs);
        if replay_result.is_ok() {
            self.return_cached_graph(cached)?;
            self.remember_materialized_output_cache(inputs, outputs)?;
        }
        replay_result
    }

    fn dispatch_borrowed_batched(
        &self,
        batches: &[&[&[u8]]],
        config: &DispatchConfig,
    ) -> Result<Vec<OutputBuffers>, BackendError> {
        let mut outputs = reserved_vec(batches.len(), "batched output")?;
        self.dispatch_borrowed_batched_into(batches, config, &mut outputs)?;
        Ok(outputs)
    }

    fn dispatch_borrowed_batched_into(
        &self,
        batches: &[&[&[u8]]],
        config: &DispatchConfig,
        outputs: &mut Vec<OutputBuffers>,
    ) -> Result<(), BackendError> {
        let _profiler_range = crate::profiler::cuda_profiler_range(
            crate::profiler::CUDA_PIPELINE_BATCH_DISPATCH_RANGE,
        );
        if batches.is_empty() {
            outputs.clear();
            return Ok(());
        }
        if cuda_graph_replay_enabled()
            && !self.prepared.cooperative
            && dispatch_configs_share_launch_shape(&self.compiled_config, config)
            && borrowed_input_batch_shapes_match(batches)
        {
            return self.dispatch_borrowed_batched_via_cuda_graph_lanes(batches, config, outputs);
        }
        let mut pending = SmallVec::<[_; 8]>::new();
        reserve_smallvec(&mut pending, batches.len(), "pending dispatch")?;
        if dispatch_configs_share_launch_shape(&self.compiled_config, config) {
            for inputs in batches {
                pending.push(self.backend.dispatch_prepared_borrowed_async_with_ptx_key(
                    &self.program,
                    inputs,
                    &self.ptx_src,
                    self.module_key,
                    &self.prepared,
                )?);
            }
        } else {
            for inputs in batches {
                pending.push(self.backend.dispatch_borrowed_async_with_ptx_key(
                    &self.program,
                    inputs,
                    config,
                    &self.ptx_src,
                    self.module_key,
                )?);
            }
        }

        resize_vec_slots(outputs, pending.len(), "batched output")?;
        for (dispatch, item_outputs) in pending.into_iter().zip(outputs.iter_mut()) {
            dispatch.await_result_into(item_outputs)?;
        }
        Ok(())
    }

    fn dispatch_persistent_handles(
        &self,
        inputs: &[Resource],
        config: &DispatchConfig,
    ) -> Result<OutputBuffers, BackendError> {
        let mut outputs = reserved_vec(
            self.prepared.output_binding_indices.len(),
            "persistent output",
        )?;
        self.dispatch_persistent_handles_into(inputs, config, &mut outputs)?;
        Ok(outputs)
    }

    fn dispatch_persistent_handles_into(
        &self,
        inputs: &[Resource],
        config: &DispatchConfig,
        outputs: &mut OutputBuffers,
    ) -> Result<(), BackendError> {
        let _profiler_range =
            crate::profiler::cuda_profiler_range(crate::profiler::CUDA_PIPELINE_DISPATCH_RANGE);
        let handles = self.backend.resident_handles_from_resources(inputs)?;
        if dispatch_configs_share_launch_shape(&self.compiled_config, config)
            && !crate::instrumentation::cuda_resident_borrowed_fallback_enabled()
        {
            let dispatch = self.backend.dispatch_resident_async_concrete_with_ptx_key(
                &self.program,
                &handles,
                config,
                &self.ptx_src,
                self.module_key,
                false,
                (self.static_params.ptr != 0).then_some(self.static_params.ptr),
                true,
                &self.prepared,
            )?;
            let (dispatch_outputs, _) = dispatch.pending.await_timed_result()?;
            vyre_driver::replace_output_buffers_preserving_slots(dispatch_outputs, outputs);
            return Ok(());
        }
        self.backend.dispatch_resident_outputs_with_ptx_key_into(
            &self.program,
            &handles,
            config,
            &self.ptx_src,
            self.module_key,
            outputs,
        )
    }

    fn dispatch_persistent_handles_batched(
        &self,
        batches: &[&[Resource]],
        config: &DispatchConfig,
    ) -> Result<Vec<OutputBuffers>, BackendError> {
        let mut outputs = reserved_vec(batches.len(), "persistent batched output")?;
        self.dispatch_persistent_handles_batched_into(batches, config, &mut outputs)?;
        Ok(outputs)
    }

    fn dispatch_persistent_handles_batched_into(
        &self,
        batches: &[&[Resource]],
        config: &DispatchConfig,
        outputs: &mut Vec<OutputBuffers>,
    ) -> Result<(), BackendError> {
        let _profiler_range = crate::profiler::cuda_profiler_range(
            crate::profiler::CUDA_PIPELINE_BATCH_DISPATCH_RANGE,
        );
        if batches.is_empty() {
            outputs.clear();
            return Ok(());
        }
        let mut resident_batches =
            SmallVec::<[SmallVec<[crate::backend::CudaResidentBuffer; 8]>; 8]>::new();
        reserve_smallvec(&mut resident_batches, batches.len(), "resident batch")?;
        for batch in batches {
            resident_batches.push(self.backend.resident_handles_from_resources(batch)?);
        }

        self.dispatch_resident_batches_into(&resident_batches, config, outputs)
    }

    fn dispatch_persistent_handle_rows_into(
        &self,
        rows: &[[Resource; 4]],
        config: &DispatchConfig,
        outputs: &mut Vec<OutputBuffers>,
    ) -> Result<(), BackendError> {
        let _profiler_range = crate::profiler::cuda_profiler_range(
            crate::profiler::CUDA_PIPELINE_BATCH_DISPATCH_RANGE,
        );
        if rows.is_empty() {
            outputs.clear();
            return Ok(());
        }
        let mut resident_batches =
            SmallVec::<[SmallVec<[crate::backend::CudaResidentBuffer; 8]>; 8]>::new();
        reserve_smallvec(&mut resident_batches, rows.len(), "resident row batch")?;
        for row in rows {
            resident_batches.push(
                self.backend
                    .resident_handles_from_resources(row.as_slice())?,
            );
        }

        self.dispatch_resident_batches_into(&resident_batches, config, outputs)
    }

    fn dispatch_persistent_resource_outputs(
        &self,
        inputs: &[Resource],
        config: &DispatchConfig,
    ) -> Result<Vec<Resource>, BackendError> {
        let _profiler_range =
            crate::profiler::cuda_profiler_range(crate::profiler::CUDA_PIPELINE_DISPATCH_RANGE);
        let handles = self.backend.resident_handles_from_resources(inputs)?;
        let borrowed_fallback = crate::instrumentation::cuda_resident_borrowed_fallback_enabled();
        let same_shape = dispatch_configs_share_launch_shape(&self.compiled_config, config);
        let prepared_storage;
        let (prepared, static_params_ptr) = if same_shape {
            (
                &self.prepared,
                (self.static_params.ptr != 0).then_some(self.static_params.ptr),
            )
        } else {
            prepared_storage =
                self.backend
                    .prepare_resident_dispatch(&self.program, &handles, config)?;
            (&prepared_storage, None)
        };
        let mut output_handles = SmallVec::<[crate::backend::CudaResidentBuffer; 8]>::new();
        reserve_smallvec(
            &mut output_handles,
            prepared.output_binding_indices.len(),
            "compiled resident resource output handle",
        )?;
        let mut next_handle = 0usize;
        for binding in &prepared.bindings.bindings {
            if binding.role == BindingRole::Shared {
                continue;
            }
            let handle = handles[next_handle];
            next_handle += 1;
            if binding.output_index.is_some() {
                output_handles.push(handle);
            }
        }
        if borrowed_fallback {
            self.backend
                .dispatch_resident_via_borrowed(&self.program, &handles, config)?;
        } else {
            self.backend
                .dispatch_resident_async_concrete_with_ptx_key(
                    &self.program,
                    &handles,
                    config,
                    &self.ptx_src,
                    self.module_key,
                    false,
                    static_params_ptr,
                    false,
                    prepared,
                )?
                .pending
                .await_timed_result()?;
        }
        let mut resources = reserved_vec(output_handles.len(), "resource output")?;
        for handle in output_handles {
            resources.push(Resource::Resident(handle.id));
        }
        Ok(resources)
    }
}

impl CudaCompiledPipeline {
    fn dispatch_resident_batches_into(
        &self,
        resident_batches: &[SmallVec<[crate::backend::CudaResidentBuffer; 8]>],
        config: &DispatchConfig,
        outputs: &mut Vec<OutputBuffers>,
    ) -> Result<(), BackendError> {
        if resident_batches.is_empty() {
            outputs.clear();
            return Ok(());
        }
        if !dispatch_configs_share_launch_shape(&self.compiled_config, config) {
            return self.dispatch_dynamic_persistent_batches_concurrently(
                resident_batches,
                config,
                outputs,
            );
        }


        let resident_dispatch = self
            .backend
            .dispatch_resident_batch_async_concrete_with_ptx_key(
                &self.program,
                resident_batches,
                config,
                &self.ptx_src,
                self.module_key,
                (self.static_params.ptr != 0).then_some(self.static_params.ptr),
                &self.prepared,
            );
        let resident_dispatch = resident_dispatch?;
        let output_handles = resident_dispatch.output_handles;
        let output_readbacks = resident_dispatch.output_readbacks;
        resident_dispatch.pending.await_timed_result()?;
        self.backend.download_resident_readback_batches_many_into(
            &output_handles,
            &output_readbacks,
            outputs,
        )
    }

    fn dispatch_dynamic_persistent_batches_concurrently(
        &self,
        resident_batches: &[SmallVec<[crate::backend::CudaResidentBuffer; 8]>],
        config: &DispatchConfig,
        outputs: &mut Vec<OutputBuffers>,
    ) -> Result<(), BackendError> {
        let mut dispatches = SmallVec::<[CudaResidentDispatch; 8]>::new();
        reserve_smallvec(
            &mut dispatches,
            resident_batches.len(),
            "dynamic resident dispatch",
        )?;
        for handles in resident_batches {
            let prepared =
                self.backend
                    .prepare_resident_dispatch(&self.program, handles, config)?;
            dispatches.push(self.backend.dispatch_resident_async_concrete_with_ptx_key(
                &self.program,
                handles,
                config,
                &self.ptx_src,
                self.module_key,
                false,
                None,
                true,
                &prepared,
            )?);
        }

        resize_vec_slots(outputs, dispatches.len(), "dynamic resident output")?;
        for (dispatch, item_outputs) in dispatches.into_iter().zip(outputs.iter_mut()) {
            let output_handles = dispatch.output_handles;
            let output_readbacks = dispatch.output_readbacks;
            dispatch.pending.await_timed_result()?;
            self.backend.download_resident_readbacks_many_into(
                &output_handles,
                &output_readbacks,
                item_outputs,
            )?;
        }
        Ok(())
    }

    fn dispatch_borrowed_batched_via_cuda_graph_lanes(
        &self,
        batches: &[&[&[u8]]],
        config: &DispatchConfig,
        outputs: &mut Vec<OutputBuffers>,
    ) -> Result<(), BackendError> {
        let miss_entries = self.materialized_output_batch_cache_partition_into(batches, outputs)?;
        if miss_entries.is_empty() {
            return Ok(());
        }

        let mut miss_batches = SmallVec::<[&[&[u8]]; MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE]>::new();
        reserve_smallvec(
            &mut miss_batches,
            miss_entries.len(),
            "cuda graph miss batch",
        )?;
        for miss in miss_entries.iter().copied() {
            miss_batches.push(batches[miss.batch_index]);
        }
        let lane_count =
            cuda_graph_lane_count_for_batch(&self.backend.caps, &self.prepared, &miss_batches)?;
        let mut lanes = SmallVec::<[CachedCudaGraph; MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE]>::new();
        reserve_smallvec(&mut lanes, lane_count, "cuda graph lane")?;
        for _ in 0..lane_count {
            lanes.push(match self.take_cached_graph(miss_batches[0])? {
                Some(cached) => cached,
                None => self.backend.record_cuda_graph_borrowed(
                    &self.program,
                    miss_batches[0],
                    config,
                )?,
            });
        }

        for (chunk_index, chunk) in miss_entries.chunks(lane_count).enumerate() {
            let mut launched = SmallVec::<
                [LaunchedMaterializedBatch; MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE],
            >::new();
            let chunk_start =
                chunk_index
                    .checked_mul(lane_count)
                    .ok_or_else(|| BackendError::InvalidProgram {
                        fix: format!(
                            "Fix: CUDA graph replay chunk {chunk_index} with {lane_count} lane(s) overflowed miss-entry indexing; split the replay batch."
                        ),
                    })?;
            for lane in 0..chunk.len() {
                let miss_entry_index =
                    chunk_start
                        .checked_add(lane)
                        .ok_or_else(|| BackendError::InvalidProgram {
                            fix: format!(
                                "Fix: CUDA graph replay chunk {chunk_index} lane {lane} overflowed miss-entry indexing; split the replay batch."
                            ),
                        })?;
                let miss = miss_entries.get(miss_entry_index).copied().ok_or_else(|| {
                    BackendError::InvalidProgram {
                        fix: format!(
                            "Fix: CUDA graph replay chunk {chunk_index} lane {lane} resolved outside the miss-entry table; rebuild the compiled pipeline."
                        ),
                    }
                })?;
                let batch_index = miss.batch_index;
                let inputs = batches[batch_index];
                let input_state = match self.backend.prepare_cuda_graph_replay_input_state_with_key(
                    &lanes[lane],
                    inputs,
                    miss.input_key,
                ) {
                    Ok(input_state) => input_state,
                    Err(error) => {
                        self.finish_cuda_graph_indexed_lane_replays(
                            &mut lanes, &launched, outputs,
                        )?;
                        let _ = self.return_cached_graph_lanes(lanes);
                        return Err(error);
                    }
                };
                match self
                    .backend
                    .try_cuda_graph_materialized_cache_with_input_state_into(
                        &mut lanes[lane],
                        inputs,
                        &input_state,
                        &mut outputs[batch_index],
                    ) {
                    Ok(true) => {
                        self.remember_materialized_output_cache_with_key(
                            inputs,
                            miss.input_key,
                            &outputs[batch_index],
                        )?;
                        continue;
                    }
                    Ok(false) => {}
                    Err(error) => {
                        self.finish_cuda_graph_indexed_lane_replays(
                            &mut lanes, &launched, outputs,
                        )?;
                        let _ = self.return_cached_graph_lanes(lanes);
                        return Err(error);
                    }
                }
                match self.backend.enqueue_cuda_graph_replay_with_input_state(
                    &mut lanes[lane],
                    inputs,
                    &input_state,
                ) {
                    Ok(replay_stats) => launched.push(LaunchedMaterializedBatch {
                        lane,
                        batch_index,
                        input_key: miss.input_key,
                        replay_stats,
                    }),
                    Err(error) => {
                        self.finish_cuda_graph_indexed_lane_replays(
                            &mut lanes, &launched, outputs,
                        )?;
                        let _ = self.return_cached_graph_lanes(lanes);
                        return Err(error);
                    }
                }
            }
            if !launched.is_empty() {
                self.backend.record_cuda_graph_batched_replay_chunk(
                    CUDA_NUMERIC.usize_to_u64(launched.len(), "cuda graph replay lane count")?,
                );
            }
            if let Err(error) =
                self.finish_cuda_graph_indexed_lane_replays(&mut lanes, &launched, outputs)
            {
                let _ = self.return_cached_graph_lanes(lanes);
                return Err(error);
            }
            for launched_batch in launched.iter().copied() {
                self.remember_materialized_output_cache_with_key(
                    batches[launched_batch.batch_index],
                    launched_batch.input_key,
                    &outputs[launched_batch.batch_index],
                )?;
            }
        }

        self.return_cached_graph_lanes(lanes)
    }

    fn materialized_output_batch_cache_partition_into(
        &self,
        batches: &[&[&[u8]]],
        outputs: &mut Vec<OutputBuffers>,
    ) -> Result<SmallVec<[MaterializedBatchMiss; MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE]>, BackendError>
    {
        resize_vec_slots(
            outputs,
            batches.len(),
            "cuda graph materialized batch output",
        )?;
        let mut input_keys = SmallVec::<
            [(usize, MaterializedInputKey); MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE],
        >::new();
        reserve_smallvec(
            &mut input_keys,
            batches.len(),
            "cuda graph materialized batch input key",
        )?;
        for (batch_index, inputs) in batches.iter().enumerate() {
            input_keys.push((batch_index, materialized_input_key(inputs)?));
        }
        let mut miss_entries =
            SmallVec::<[MaterializedBatchMiss; MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE]>::new();
        reserve_smallvec(
            &mut miss_entries,
            batches.len(),
            "cuda graph materialized batch miss index",
        )?;
        let mut hit_snapshots = SmallVec::<[_; MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE]>::new();
        reserve_smallvec(
            &mut hit_snapshots,
            batches.len(),
            "cuda graph materialized batch hit snapshot",
        )?;
        {
            let cache = self.lock_materialized_output_cache("during batch cache replay")?;
            for (batch_index, input_key) in input_keys.iter().copied() {
                let inputs = batches[batch_index];
                if let Some(snapshot) = cache.snapshot_with_key(inputs, &input_key) {
                    hit_snapshots.push((batch_index, snapshot));
                } else {
                    miss_entries.push(MaterializedBatchMiss {
                        batch_index,
                        input_key,
                    });
                }
            }
        }
        for (batch_index, snapshot) in hit_snapshots {
            snapshot.copy_into(&mut outputs[batch_index])?;
            self.backend
                .telemetry
                .record_cuda_graph_materialized_cache_hit();
        }
        Ok(miss_entries)
    }

    fn materialized_output_cache_hit_into(
        &self,
        inputs: &[&[u8]],
        outputs: &mut OutputBuffers,
    ) -> Result<bool, BackendError> {
        let snapshot = {
            let cache = self.lock_materialized_output_cache("during single-dispatch replay")?;
            cache.snapshot(inputs)?
        };
        let Some(snapshot) = snapshot else {
            return Ok(false);
        };
        snapshot.copy_into(outputs)?;
        self.backend
            .telemetry
            .record_cuda_graph_materialized_cache_hit();
        Ok(true)
    }

    fn remember_materialized_output_cache(
        &self,
        inputs: &[&[u8]],
        outputs: &OutputBuffers,
    ) -> Result<(), BackendError> {
        let Some(entry) = MaterializedPipelineOutputCacheEntry::new_if_cacheable(inputs, outputs)?
        else {
            return Ok(());
        };
        let mut cache = self.lock_materialized_output_cache("while storing replay output")?;
        cache.remember_entry(entry)
    }

    fn remember_materialized_output_cache_with_key(
        &self,
        inputs: &[&[u8]],
        input_key: MaterializedInputKey,
        outputs: &OutputBuffers,
    ) -> Result<(), BackendError> {
        let Some(entry) = MaterializedPipelineOutputCacheEntry::new_with_key_if_cacheable(
            inputs, &input_key, outputs,
        )?
        else {
            return Ok(());
        };
        let mut cache = self.lock_materialized_output_cache("while storing keyed replay output")?;
        cache.remember_entry(entry)
    }

    fn lock_materialized_output_cache(
        &self,
        action: &'static str,
    ) -> Result<MutexGuard<'_, MaterializedPipelineOutputCache>, BackendError> {
        self.materialized_output_cache.lock().map_err(|_| {
            BackendError::DispatchFailed {
                code: None,
                message: format!(
                    "CUDA compiled-pipeline materialized output cache lock poisoned {action}. Fix: rebuild the compiled pipeline after a panic during materialized cache access."
                ),
            }
        })
    }

    fn finish_cuda_graph_indexed_lane_replays(
        &self,
        lanes: &mut [CachedCudaGraph],
        launched: &[LaunchedMaterializedBatch],
        outputs: &mut [OutputBuffers],
    ) -> Result<(), BackendError> {
        let mut finish_error = None;
        for launched_batch in launched.iter().copied() {
            if let Err(error) = self.backend.finish_cuda_graph_replay_into(
                &mut lanes[launched_batch.lane],
                launched_batch.replay_stats,
                &mut outputs[launched_batch.batch_index],
            ) {
                if finish_error.is_none() {
                    finish_error = Some(error);
                }
            }
        }
        if let Some(error) = finish_error {
            return Err(error);
        }
        Ok(())
    }

    fn take_cached_graph(&self, inputs: &[&[u8]]) -> Result<Option<CachedCudaGraph>, BackendError> {
        let mut graphs = self.graph_cache.lock().map_err(|_| {
            BackendError::DispatchFailed {
                code: None,
                message: "CUDA compiled-pipeline graph cache lock poisoned. Fix: rebuild the compiled pipeline after a panic during graph replay.".to_string(),
            }
        })?;
        let mut first_shape_match = None;
        for (index, cached) in graphs.iter().enumerate() {
            if !cached.input_shape_matches(inputs) {
                continue;
            }
            if first_shape_match.is_none() {
                first_shape_match = Some(index);
            }
            if cached.materialized_output_cache_matches(inputs)? {
                return Ok(Some(graphs.swap_remove(index)));
            }
        }
        Ok(first_shape_match.map(|index| graphs.swap_remove(index)))
    }

    fn return_cached_graph(&self, cached: CachedCudaGraph) -> Result<(), BackendError> {
        let mut graphs = self.graph_cache.lock().map_err(|_| {
            BackendError::DispatchFailed {
                code: None,
                message: "CUDA compiled-pipeline graph cache lock poisoned while returning a graph. Fix: rebuild the compiled pipeline after a panic during graph replay.".to_string(),
            }
        })?;
        if graphs.len() < MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE {
            graphs.push(cached);
        }
        Ok(())
    }

    fn return_cached_graph_lanes(
        &self,
        lanes: SmallVec<[CachedCudaGraph; MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE]>,
    ) -> Result<(), BackendError> {
        let mut graphs = self.graph_cache.lock().map_err(|_| {
            BackendError::DispatchFailed {
                code: None,
                message: "CUDA compiled-pipeline graph cache lock poisoned while returning graph lanes. Fix: rebuild the compiled pipeline after a panic during batched graph replay.".to_string(),
            }
        })?;
        for lane in lanes {
            if graphs.len() >= MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE {
                break;
            }
            graphs.push(lane);
        }
        Ok(())
    }
}


//! `CompiledPipeline` implementation for precompiled CUDA pipelines.
//!
//! The parent `pipeline` module owns construction and static launch state. This
//! module owns dispatch entrypoints, CUDA graph replay selection, dynamic GPU
//! dispatch when runtime policy changes, and persistent-resource output routing.

use smallvec::SmallVec;
use vyre_driver::{
    BackendError, BindingRole, CompiledPipeline, DispatchConfig, OutputBuffers, Resource,
};

use crate::backend::cuda_graph_replay::CudaGraphReplayStats;
use crate::backend::resident_dispatch::CudaResidentDispatch;
use crate::backend::staging_reserve::{reserve_smallvec, reserved_vec, resize_vec_slots};
use crate::backend::CachedCudaGraph;
use crate::numeric::{elapsed_nanos_u64, usize_to_u64};
use crate::pipeline::{
    borrowed_input_shape_matches, cuda_graph_lane_count_for_batch, cuda_graph_replay_enabled,
    same_launch_shape, CudaCompiledPipeline, MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE,
};

impl CompiledPipeline for CudaCompiledPipeline {
    fn id(&self) -> &str {
        &self.id
    }

    fn dispatch(
        &self,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        let mut borrowed = SmallVec::<[&[u8]; 8]>::new();
        reserve_smallvec(&mut borrowed, inputs.len(), "borrowed input")?;
        for input in inputs {
            borrowed.push(input.as_slice());
        }
        self.dispatch_borrowed(&borrowed, config)
    }

    fn dispatch_borrowed(
        &self,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        if !same_launch_shape(&self.compiled_config, config) {
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
        if !same_launch_shape(&self.compiled_config, config) {
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
        }
        let device_ns = replay_result?;
        Ok(vyre_driver::TimedDispatchResult {
            outputs,
            wall_ns: elapsed_nanos_u64(started, "cuda graph replay wall latency")?,
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
        if !same_launch_shape(&self.compiled_config, config) {
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
        if batches.is_empty() {
            outputs.clear();
            return Ok(());
        }
        if cuda_graph_replay_enabled()
            && !self.prepared.cooperative
            && same_launch_shape(&self.compiled_config, config)
            && batches
                .iter()
                .all(|batch| borrowed_input_shape_matches(batches[0], batch))
        {
            return self.dispatch_borrowed_batched_via_cuda_graph_lanes(batches, config, outputs);
        }
        let mut pending = SmallVec::<[_; 8]>::new();
        reserve_smallvec(&mut pending, batches.len(), "pending dispatch")?;
        if same_launch_shape(&self.compiled_config, config) {
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
        let handles = self.backend.resident_handles_from_resources(inputs)?;
        if same_launch_shape(&self.compiled_config, config) {
            let _ = (
                &self.program,
                &handles,
                config,
                &self.ptx_src,
                self.module_key,
            );
            return self.backend.dispatch_resident_via_borrowed_into(
                &self.program,
                &handles,
                config,
                outputs,
            );
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

        if !same_launch_shape(&self.compiled_config, config) {
            return self.dispatch_dynamic_persistent_batches_concurrently(
                &resident_batches,
                config,
                outputs,
            );
        }

        let resident_dispatch = self
            .backend
            .dispatch_resident_batch_async_concrete_with_ptx_key(
                &self.program,
                &resident_batches,
                config,
                &self.ptx_src,
                self.module_key,
                (self.static_params.ptr != 0).then_some(self.static_params.ptr),
                &self.prepared,
            )?;
        let output_handles = resident_dispatch.output_handles;
        let output_readbacks = resident_dispatch.output_readbacks;
        resident_dispatch.pending.await_timed_result()?;
        self.backend.download_resident_readback_batches_many_into(
            &output_handles,
            &output_readbacks,
            outputs,
        )
    }

    fn dispatch_persistent_handle_rows_into(
        &self,
        rows: &[[Resource; 4]],
        config: &DispatchConfig,
        outputs: &mut Vec<OutputBuffers>,
    ) -> Result<(), BackendError> {
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

        if !same_launch_shape(&self.compiled_config, config) {
            return self.dispatch_dynamic_persistent_batches_concurrently(
                &resident_batches,
                config,
                outputs,
            );
        }

        let resident_dispatch = self
            .backend
            .dispatch_resident_batch_async_concrete_with_ptx_key(
                &self.program,
                &resident_batches,
                config,
                &self.ptx_src,
                self.module_key,
                (self.static_params.ptr != 0).then_some(self.static_params.ptr),
                &self.prepared,
            )?;
        let output_handles = resident_dispatch.output_handles;
        let output_readbacks = resident_dispatch.output_readbacks;
        resident_dispatch.pending.await_timed_result()?;
        self.backend.download_resident_readback_batches_many_into(
            &output_handles,
            &output_readbacks,
            outputs,
        )
    }

    fn dispatch_persistent_resource_outputs(
        &self,
        inputs: &[Resource],
        config: &DispatchConfig,
    ) -> Result<Vec<Resource>, BackendError> {
        let handles = self.backend.resident_handles_from_resources(inputs)?;
        let prepared = if same_launch_shape(&self.compiled_config, config) {
            &self.prepared
        } else {
            &self
                .backend
                .prepare_resident_dispatch(&self.program, &handles, config)?
        };
        let mut output_handles = SmallVec::<[crate::backend::CudaResidentBuffer; 8]>::new();
        reserve_smallvec(
            &mut output_handles,
            prepared.output_binding_indices.len(),
            "compiled resident fallback output handle",
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
        self.backend
            .dispatch_resident_via_borrowed(&self.program, &handles, config)?;
        let mut resources = reserved_vec(output_handles.len(), "resource output")?;
        for handle in output_handles {
            resources.push(Resource::Resident(handle.id));
        }
        Ok(resources)
    }
}

impl CudaCompiledPipeline {
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
        let lane_count =
            cuda_graph_lane_count_for_batch(&self.backend.caps, &self.prepared, batches)?;
        let mut lanes = SmallVec::<[CachedCudaGraph; MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE]>::new();
        reserve_smallvec(&mut lanes, lane_count, "cuda graph lane")?;
        for _ in 0..lane_count {
            lanes.push(match self.take_cached_graph(batches[0])? {
                Some(cached) => cached,
                None => {
                    self.backend
                        .record_cuda_graph_borrowed(&self.program, batches[0], config)?
                }
            });
        }

        resize_vec_slots(outputs, batches.len(), "cuda graph batched output")?;

        for (chunk_index, chunk) in batches.chunks(lane_count).enumerate() {
            let base_index =
                chunk_index
                    .checked_mul(lane_count)
                    .ok_or_else(|| BackendError::InvalidProgram {
                        fix: format!(
                            "Fix: CUDA graph replay batch index overflowed usize for chunk {chunk_index} with {lane_count} lane(s); split the batched dispatch."
                        ),
                    })?;
            let mut stats =
                SmallVec::<[CudaGraphReplayStats; MAX_GRAPH_CACHE_ENTRIES_PER_PIPELINE]>::new();
            for (lane, inputs) in chunk.iter().enumerate() {
                match self
                    .backend
                    .enqueue_cuda_graph_replay(&mut lanes[lane], inputs)
                {
                    Ok(replay_stats) => stats.push(replay_stats),
                    Err(error) => {
                        for (launched_lane, replay_stats) in stats.iter().copied().enumerate() {
                            self.backend.finish_cuda_graph_replay_into(
                                &lanes[launched_lane],
                                replay_stats,
                                &mut outputs[base_index + launched_lane],
                            )?;
                        }
                        let _ = self.return_cached_graph_lanes(lanes);
                        return Err(error);
                    }
                }
            }
            self.backend
                .record_cuda_graph_batched_replay_chunk(usize_to_u64(
                    stats.len(),
                    "cuda graph replay lane count",
                )?);
            let mut finish_error = None;
            for (lane, replay_stats) in stats.iter().copied().enumerate() {
                if let Err(error) = self.backend.finish_cuda_graph_replay_into(
                    &lanes[lane],
                    replay_stats,
                    &mut outputs[base_index + lane],
                ) {
                    if finish_error.is_none() {
                        finish_error = Some(error);
                    }
                }
            }
            if let Some(error) = finish_error {
                let _ = self.return_cached_graph_lanes(lanes);
                return Err(error);
            }
        }

        self.return_cached_graph_lanes(lanes)
    }

    fn take_cached_graph(&self, inputs: &[&[u8]]) -> Result<Option<CachedCudaGraph>, BackendError> {
        let mut graphs = self.graph_cache.lock().map_err(|_| {
            BackendError::DispatchFailed {
                code: None,
                message: "CUDA compiled-pipeline graph cache lock poisoned. Fix: rebuild the compiled pipeline after a panic during graph replay.".to_string(),
            }
        })?;
        Ok(graphs
            .iter()
            .position(|cached| cached.input_shape_matches(inputs))
            .map(|index| graphs.swap_remove(index)))
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

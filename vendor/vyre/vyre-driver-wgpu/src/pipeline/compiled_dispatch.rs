//! `CompiledPipeline` implementation for WGPU pipeline dispatch.
//!
//! The parent `pipeline` module owns compilation and metadata assembly. This
//! module owns the trait entrypoints that turn caller inputs into persistent
//! GPU handles, execute the compiled compute pipeline, and read back outputs.

use std::time::Instant;

use smallvec::SmallVec;
use vyre_driver::program_walks::enforce_actual_output_budget;
use vyre_driver::{BackendError, CompiledPipeline, DispatchConfig, OutputBuffers};

use crate::pipeline::WgpuPipeline;

fn fixpoint_iteration_count(config: &DispatchConfig) -> Result<usize, BackendError> {
    let iterations = config.fixpoint_iterations.unwrap_or(1).max(1);
    usize::try_from(iterations).map_err(|source| {
        BackendError::new(format!(
            "WGPU fixpoint iteration count {iterations} cannot fit usize: {source}. Fix: lower fixpoint_iterations or split the dispatch into bounded phases."
        ))
    })
}

impl CompiledPipeline for WgpuPipeline {
    fn dispatch_persistent_handles(
        &self,
        inputs: &[vyre_driver::Resource],
        config: &DispatchConfig,
    ) -> Result<OutputBuffers, BackendError> {
        let mut outputs = Vec::with_capacity(self.output_bindings.len());
        self.dispatch_persistent_handles_into(inputs, config, &mut outputs)?;
        enforce_actual_output_budget(config, outputs.as_slice())?;
        Ok(outputs)
    }

    fn dispatch_persistent_handles_into(
        &self,
        inputs: &[vyre_driver::Resource],
        config: &DispatchConfig,
        outputs: &mut OutputBuffers,
    ) -> Result<(), BackendError> {
        self.enforce_static_output_budget(config)?;
        let (device, queue) = &*self.device_queue;
        let workgroup_count = self.workgroups_for_dispatch(config)?;
        let deadline = config
            .timeout
            .and_then(|timeout| Instant::now().checked_add(timeout));
        let resolved = self.resolve_persistent_resources(inputs, queue)?;
        let item = crate::pipeline::persistent::BorrowedDispatchItem {
            inputs: crate::pipeline::persistent::borrowed_handle_refs(&resolved.inputs),
            outputs: crate::pipeline::persistent::borrowed_handle_refs(&resolved.outputs),
            params: None,
            workgroups: workgroup_count,
        };
        self.dispatch_borrowed_persistent_batched(&[item])?;
        self.raise_if_trapped(&resolved.inputs, device, queue, deadline)?;
        self.readback_persistent_outputs(&resolved.outputs, deadline, outputs)?;
        enforce_actual_output_budget(config, outputs.as_slice())
    }

    fn dispatch_persistent_resource_outputs(
        &self,
        inputs: &[vyre_driver::Resource],
        config: &DispatchConfig,
    ) -> Result<Vec<vyre_driver::Resource>, BackendError> {
        self.enforce_static_output_budget(config)?;
        let (device, queue) = &*self.device_queue;
        let output_resources = resident_output_resources(self, inputs)?;
        let resolved = self.resolve_persistent_resources(inputs, queue)?;
        let item = crate::pipeline::persistent::BorrowedDispatchItem {
            inputs: crate::pipeline::persistent::borrowed_handle_refs(&resolved.inputs),
            outputs: crate::pipeline::persistent::borrowed_handle_refs(&resolved.outputs),
            params: None,
            workgroups: self.workgroups_for_dispatch(config)?,
        };
        self.dispatch_borrowed_persistent_batched(&[item])?;
        let deadline = config
            .timeout
            .and_then(|timeout| Instant::now().checked_add(timeout));
        self.raise_if_trapped(&resolved.inputs, device, queue, deadline)?;
        Ok(output_resources)
    }

    fn dispatch_persistent_handles_batched(
        &self,
        batches: &[&[vyre_driver::Resource]],
        config: &DispatchConfig,
    ) -> Result<Vec<OutputBuffers>, BackendError> {
        let mut outputs = Vec::with_capacity(batches.len());
        self.dispatch_persistent_handles_batched_into(batches, config, &mut outputs)?;
        Ok(outputs)
    }

    fn dispatch_persistent_handles_batched_into(
        &self,
        batches: &[&[vyre_driver::Resource]],
        config: &DispatchConfig,
        batch_outputs: &mut Vec<OutputBuffers>,
    ) -> Result<(), BackendError> {
        if batches.is_empty() {
            batch_outputs.clear();
            return Ok(());
        }
        self.enforce_static_output_budget(config)?;
        let (device, queue) = &*self.device_queue;
        let workgroup_count = self.workgroups_for_dispatch(config)?;
        let deadline = config
            .timeout
            .and_then(|timeout| Instant::now().checked_add(timeout));

        let mut resolved = SmallVec::<[_; 8]>::with_capacity(batches.len());
        for batch in batches {
            resolved.push(self.resolve_persistent_resources(batch, queue)?);
        }

        let mut items =
            SmallVec::<[crate::pipeline::persistent::BorrowedDispatchItem<'_>; 8]>::with_capacity(
                resolved.len(),
            );
        for item in resolved.iter() {
            items.push(crate::pipeline::persistent::BorrowedDispatchItem {
                inputs: crate::pipeline::persistent::borrowed_handle_refs(&item.inputs),
                outputs: crate::pipeline::persistent::borrowed_handle_refs(&item.outputs),
                params: None,
                workgroups: workgroup_count,
            });
        }

        self.dispatch_borrowed_persistent_batched(&items)?;

        if batch_outputs.len() < resolved.len() {
            if batch_outputs.capacity() < resolved.len() {
                batch_outputs.reserve_exact(resolved.len() - batch_outputs.capacity());
            }
            batch_outputs.resize_with(resolved.len(), Vec::new);
        } else {
            batch_outputs.truncate(resolved.len());
        }
        for (item, outputs) in resolved.iter().zip(batch_outputs.iter_mut()) {
            self.raise_if_trapped(&item.inputs, device, queue, deadline)?;
            self.readback_persistent_outputs(&item.outputs, deadline, outputs)?;
            enforce_actual_output_budget(config, outputs.as_slice())?;
        }

        Ok(())
    }

    fn id(&self) -> &str {
        &self.id
    }

    fn dispatch(
        &self,
        inputs: &[Vec<u8>],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        let mut borrowed = SmallVec::<[&[u8]; 8]>::with_capacity(inputs.len());
        borrowed.extend(inputs.iter().map(Vec::as_slice));
        self.dispatch_borrowed(&borrowed, config)
    }

    fn dispatch_borrowed(
        &self,
        inputs: &[&[u8]],
        config: &DispatchConfig,
    ) -> Result<Vec<Vec<u8>>, BackendError> {
        let mut outputs = Vec::with_capacity(self.output_bindings.len());
        self.dispatch_borrowed_into(inputs, config, &mut outputs)?;
        Ok(outputs)
    }

    fn dispatch_borrowed_batched(
        &self,
        batches: &[&[&[u8]]],
        config: &DispatchConfig,
    ) -> Result<Vec<OutputBuffers>, BackendError> {
        let mut outputs = Vec::with_capacity(batches.len());
        self.dispatch_borrowed_batched_into(batches, config, &mut outputs)?;
        Ok(outputs)
    }

    fn dispatch_borrowed_batched_into(
        &self,
        batches: &[&[&[u8]]],
        config: &DispatchConfig,
        batch_outputs: &mut Vec<OutputBuffers>,
    ) -> Result<(), BackendError> {
        if batches.is_empty() {
            batch_outputs.clear();
            return Ok(());
        }
        self.enforce_static_output_budget(config)?;
        let deadline = config
            .timeout
            .and_then(|timeout| Instant::now().checked_add(timeout));
        let workgroup_count = self.workgroups_for_dispatch(config)?;

        let mut resolved = SmallVec::<[_; 8]>::with_capacity(batches.len());
        for inputs in batches {
            resolved.push(self.legacy_handles_from_inputs(inputs)?);
        }

        let mut items =
            SmallVec::<[crate::pipeline::persistent::BorrowedDispatchItem<'_>; 8]>::with_capacity(
                resolved.len(),
            );
        for (inputs, outputs) in resolved.iter() {
            items.push(crate::pipeline::persistent::BorrowedDispatchItem {
                inputs: crate::pipeline::persistent::borrowed_handle_refs(inputs),
                outputs: crate::pipeline::persistent::borrowed_handle_refs(outputs),
                params: None,
                workgroups: workgroup_count,
            });
        }

        let max_iters = fixpoint_iteration_count(config)?;
        for _ in 0..max_iters {
            self.dispatch_borrowed_persistent_batched(&items)?;
        }

        let (device, queue) = &*self.device_queue;
        if batch_outputs.len() < resolved.len() {
            if batch_outputs.capacity() < resolved.len() {
                batch_outputs.reserve_exact(resolved.len() - batch_outputs.capacity());
            }
            batch_outputs.resize_with(resolved.len(), Vec::new);
        } else {
            batch_outputs.truncate(resolved.len());
        }
        for ((inputs, outputs), item_outputs) in resolved.iter().zip(batch_outputs.iter_mut()) {
            self.raise_if_trapped(inputs, device, queue, deadline)?;
            self.readback_persistent_outputs(outputs, deadline, item_outputs)?;
            enforce_actual_output_budget(config, item_outputs.as_slice())?;
        }
        Ok(())
    }

    fn dispatch_borrowed_into(
        &self,
        inputs: &[&[u8]],
        config: &DispatchConfig,
        outputs: &mut OutputBuffers,
    ) -> Result<(), BackendError> {
        self.enforce_static_output_budget(config)?;
        let deadline = config
            .timeout
            .and_then(|timeout| Instant::now().checked_add(timeout));
        let workgroup_count = self.workgroups_for_dispatch(config)?;

        let (input_handles, mut output_handles) = self.legacy_handles_from_inputs(inputs)?;
        let max_iters = fixpoint_iteration_count(config)?;
        for _iter in 0..max_iters {
            self.dispatch_persistent(&input_handles, &mut output_handles, None, workgroup_count)?;
        }
        if max_iters > 1 {
            tracing::trace!(
                target: "vyre.dispatch.fixpoint",
                iters = max_iters,
                substrate_path = "persistent_pipeline_fixpoint_loop",
                "persistent pipeline fixpoint loop ran",
            );
        }
        let (device, queue) = &*self.device_queue;
        self.raise_if_trapped(&input_handles, device, queue, deadline)?;
        if outputs.len() < output_handles.len() {
            if outputs.capacity() < output_handles.len() {
                outputs.reserve_exact(output_handles.len() - outputs.capacity());
            }
            outputs.resize_with(output_handles.len(), Vec::new);
        } else {
            outputs.truncate(output_handles.len());
        }
        for ((handle, output), bytes) in output_handles
            .iter()
            .zip(self.output_bindings.iter())
            .zip(outputs.iter_mut())
        {
            crate::pipeline::output_readback::read_trimmed_output(
                handle,
                output,
                device,
                &self.staging_pool,
                queue,
                "persistent pipeline output",
                deadline,
                bytes,
            )?;
        }
        enforce_actual_output_budget(config, outputs.as_slice())?;
        Ok(())
    }
}

fn resident_output_resources(
    pipeline: &WgpuPipeline,
    resources: &[vyre_driver::Resource],
) -> Result<Vec<vyre_driver::Resource>, BackendError> {
    let mut resource_index = 0usize;
    let mut output_resources = Vec::with_capacity(pipeline.output_bindings.len());
    for info in pipeline.buffer_bindings.iter() {
        if info.kind == vyre_foundation::ir::MemoryKind::Shared || info.internal_trap {
            continue;
        }
        let resource = resources.get(resource_index).ok_or_else(|| {
            BackendError::new(format!(
                "persistent resident-output dispatch missing resource for binding {} (`{}`). Fix: pass one resource per public non-shared binding in BufferDecl order.",
                info.binding, info.name
            ))
        })?;
        resource_index += 1;
        if info.is_output {
            match resource {
                vyre_driver::Resource::Resident(id) => {
                    output_resources.push(vyre_driver::Resource::Resident(*id));
                }
                vyre_driver::Resource::Borrowed(_) => {
                    return Err(BackendError::new(format!(
                        "persistent resident-output dispatch cannot return borrowed output binding {} (`{}`). Fix: allocate a resident output buffer and pass Resource::Resident so the backend can skip host readback.",
                        info.binding, info.name
                    )));
                }
            }
        }
    }
    if resource_index != resources.len() {
        return Err(BackendError::new(format!(
            "persistent resident-output dispatch received {} resources but consumed {resource_index}. Fix: pass resources in public non-shared BufferDecl order without extra handles.",
            resources.len()
        )));
    }
    Ok(output_resources)
}

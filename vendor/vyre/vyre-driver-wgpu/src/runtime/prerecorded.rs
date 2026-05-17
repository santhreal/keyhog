//! Pre-recorded persistent dispatch command buffers.

use std::sync::{Arc, Mutex};

use smallvec::SmallVec;
use vyre_driver::BackendError;

use crate::buffer::GpuBufferHandle;
use crate::pipeline::binding::{clear_outputs_for_bound, validate_handle};
use crate::pipeline::{BufferBindingInfo, WgpuPipeline};

/// GPU work recorded ahead of submission for encoder-free dispatch handoff.
///
/// `wgpu::CommandBuffer` is single-submit. This type prevents the raw wgpu
/// panic by consuming the stored command buffer on the first replay and
/// returning a structured error on repeated replay attempts.
pub struct PrerecordedDispatch {
    /// Pre-recorded command buffer.
    pub cb: Mutex<Option<wgpu::CommandBuffer>>,
    /// Bind groups captured by the command buffer.
    pub bind_groups: Vec<Arc<wgpu::BindGroup>>,
    /// Buffer handles kept alive for the lifetime of the recorded commands.
    pub handles: Vec<GpuBufferHandle>,
    /// Output handles recorded for terminal readback by tests and callers.
    pub output_handles: Vec<GpuBufferHandle>,
    /// Device used to record this dispatch.
    pub device: wgpu::Device,
    /// Queue paired with `device`.
    pub queue: wgpu::Queue,
}

impl PrerecordedDispatch {
    /// Submit the pre-recorded command buffer to `queue`.
    ///
    /// # Errors
    ///
    /// Returns a backend error when this command buffer was already submitted.
    pub fn replay(&self, queue: &wgpu::Queue) -> Result<wgpu::SubmissionIndex, BackendError> {
        let command_buffer = self
            .cb
            .lock()
            .map_err(|source| {
                BackendError::new(format!(
                    "pre-recorded dispatch mutex poisoned: {source}. Fix: drop this dispatch and record a fresh command buffer."
                ))
            })?
            .take()
            .ok_or_else(|| {
                BackendError::new(
                    "pre-recorded wgpu command buffer was already submitted. Fix: record a new PrerecordedDispatch for each replay slot; wgpu command buffers are single-submit.",
                )
            })?;
        Ok(queue.submit(std::iter::once(command_buffer)))
    }

    /// Read one recorded output buffer into a byte vector.
    ///
    /// # Errors
    ///
    /// Returns a backend error when the output index is invalid or mapping
    /// fails.
    pub fn read_output(&self, index: usize) -> Result<Vec<u8>, BackendError> {
        let output = self.output_handles.get(index).ok_or_else(|| {
            BackendError::new(format!(
                "pre-recorded output index {index} is out of bounds for {} outputs. Fix: request an output produced by this dispatch.",
                self.output_handles.len()
            ))
        })?;
        let mut bytes = Vec::with_capacity(usize::try_from(output.byte_len()).unwrap_or(0));
        output.readback(&self.device, &self.queue, &mut bytes)?;
        Ok(bytes)
    }

    /// Read one recorded output buffer into caller-owned storage.
    ///
    /// Clears `out`, then reuses its allocation.
    ///
    /// # Errors
    ///
    /// Returns a backend error when the output index is invalid or mapping
    /// fails.
    pub fn read_output_into(&self, index: usize, out: &mut Vec<u8>) -> Result<(), BackendError> {
        let output = self.output_handles.get(index).ok_or_else(|| {
            BackendError::new(format!(
                "pre-recorded output index {index} is out of bounds for {} outputs. Fix: request an output produced by this dispatch.",
                self.output_handles.len()
            ))
        })?;
        output.readback(&self.device, &self.queue, out)
    }
}

impl WgpuPipeline {
    /// Record a persistent dispatch once so later submission bypasses encoder
    /// construction, output clears, bind-group lookup, and compute-pass setup.
    ///
    /// # Errors
    ///
    /// Returns a backend error when the handles do not match the compiled
    /// program's binding contract or command recording fails.
    pub fn prerecord_persistent_dispatch(
        &self,
        inputs: &[GpuBufferHandle],
        outputs: &[GpuBufferHandle],
        params: Option<&GpuBufferHandle>,
        workgroups: [u32; 3],
    ) -> Result<PrerecordedDispatch, BackendError> {
        let (device, queue) = &*self.device_queue;
        let bound = bind_handles(&self.buffer_bindings, inputs, outputs, params)?;
        let mut bind_groups = Vec::with_capacity(self.bind_group_layouts.len());
        for (group_index, layout) in self.bind_group_layouts.iter().enumerate() {
            let mut handle_ids: SmallVec<[u64; 16]> = SmallVec::new();
            for (_, handle) in bound
                .iter()
                .filter(|(info, _)| info.group == group_index as u32)
            {
                handle_ids.push(handle.allocation_identity());
                handle_ids.push(handle.byte_len().max(4).next_multiple_of(4));
            }
            let layout_id = Arc::as_ptr(layout).addr();
            let bg = self
                .bind_group_cache
                .get_or_create_by_ids(layout_id, handle_ids, || {
                    let entries: SmallVec<[wgpu::BindGroupEntry<'_>; 16]> = bound
                        .iter()
                        .filter(|(info, _)| info.group == group_index as u32)
                        .map(|(info, handle)| wgpu::BindGroupEntry {
                            binding: info.binding,
                            resource: wgpu::BindingResource::Buffer(wgpu::BufferBinding {
                                buffer: handle.buffer(),
                                offset: 0,
                                size: wgpu::BufferSize::new(
                                    handle.byte_len().max(4).next_multiple_of(4),
                                ),
                            }),
                        })
                        .collect();
                    device.create_bind_group(&wgpu::BindGroupDescriptor {
                        label: Some("vyre pre-recorded persistent bind group"),
                        layout,
                        entries: &entries,
                    })
                });
            bind_groups.push(bg);
        }

        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("vyre pre-recorded persistent dispatch"),
        });
        clear_outputs_for_bound("pre-recorded", &mut encoder, &bound, |binding| {
            self.output_binding(binding).cloned()
        })?;
        {
            let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
                label: Some("vyre pre-recorded persistent compute"),
                timestamp_writes: None,
            });
            pass.set_pipeline(&self.pipeline);
            for (i, bg) in bind_groups.iter().enumerate() {
                pass.set_bind_group(i as u32, bg.as_ref(), &[]);
            }
            if let Some(indirect) = &self.indirect {
                let indirect_handle = bound
                    .iter()
                    .find(|(info, _)| info.name.as_ref() == indirect.count_buffer.as_str())
                    .map(|(_, handle)| *handle)
                    .ok_or_else(|| {
                        BackendError::new(format!(
                            "indirect dispatch count buffer `{}` not bound in pre-recorded dispatch. Fix: supply the declared buffer handle.",
                            indirect.count_buffer
                        ))
                    })?;
                pass.dispatch_workgroups_indirect(indirect_handle.buffer(), indirect.count_offset);
            } else {
                pass.dispatch_workgroups(workgroups[0], workgroups[1], workgroups[2]);
            }
        }

        let handles = bound
            .iter()
            .map(|(_, handle)| (*handle).clone())
            .collect::<Vec<_>>();
        Ok(PrerecordedDispatch {
            cb: Mutex::new(Some(encoder.finish())),
            bind_groups,
            handles,
            output_handles: outputs.to_vec(),
            device: device.clone(),
            queue: queue.clone(),
        })
    }

    /// Upload borrowed host inputs, allocate output handles, and pre-record
    /// one persistent dispatch using this pipeline's device.
    ///
    /// # Errors
    ///
    /// Returns a backend error when upload, output allocation, or command
    /// recording fails.
    pub fn prerecord_borrowed_dispatch(
        &self,
        inputs: &[&[u8]],
        workgroups: [u32; 3],
    ) -> Result<PrerecordedDispatch, BackendError> {
        let (input_handles, output_handles) = self.legacy_handles_from_inputs(inputs)?;
        self.prerecord_persistent_dispatch(&input_handles, &output_handles, None, workgroups)
    }
}

fn bind_handles<'a>(
    bindings: &'a [BufferBindingInfo],
    inputs: &'a [GpuBufferHandle],
    outputs: &'a [GpuBufferHandle],
    params: Option<&'a GpuBufferHandle>,
) -> Result<SmallVec<[(&'a BufferBindingInfo, &'a GpuBufferHandle); 8]>, BackendError> {
    let mut input_index = 0usize;
    let mut output_index = 0usize;
    let mut params_used = false;
    let mut bound = SmallVec::with_capacity(bindings.len());
    for info in bindings {
        if info.kind == vyre_foundation::ir::MemoryKind::Shared {
            continue;
        }
        let handle = if info.is_output {
            let handle = outputs.get(output_index).ok_or_else(|| {
                BackendError::new(format!(
                    "pre-recorded dispatch missing output handle for binding {} (`{}`). Fix: pass one output handle per output BufferDecl.",
                    info.binding, info.name
                ))
            })?;
            output_index += 1;
            handle
        } else if matches!(
            info.kind,
            vyre_foundation::ir::MemoryKind::Uniform | vyre_foundation::ir::MemoryKind::Push
        ) && params.is_some()
            && !params_used
        {
            params_used = true;
            if let Some(handle) = params {
                handle
            } else {
                return Err(BackendError::new(
                    "pre-recorded dispatch parameter handle disappeared after validation. Fix: retry recording with a stable params handle.",
                ));
            }
        } else {
            let handle = inputs.get(input_index).ok_or_else(|| {
                BackendError::new(format!(
                    "pre-recorded dispatch missing input handle for binding {} (`{}`). Fix: pass non-output handles in BufferDecl order.",
                    info.binding, info.name
                ))
            })?;
            input_index += 1;
            handle
        };
        validate_handle("pre-recorded", info, handle)?;
        bound.push((info, handle));
    }
    if input_index != inputs.len() {
        return Err(BackendError::new(format!(
            "pre-recorded dispatch received {} input handles but consumed {input_index}. Fix: pass handles matching non-output BufferDecl order.",
            inputs.len()
        )));
    }
    if output_index != outputs.len() {
        return Err(BackendError::new(format!(
            "pre-recorded dispatch received {} output handles but consumed {output_index}. Fix: pass handles matching output BufferDecl order.",
            outputs.len()
        )));
    }
    Ok(bound)
}

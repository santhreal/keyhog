//! Pre-recorded persistent dispatch command buffers.

use std::sync::{Arc, Mutex};

use vyre_driver::BackendError;

use crate::buffer::GpuBufferHandle;
use crate::pipeline::{element_size_bytes, BufferBindingInfo, WgpuPipeline};

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
        let mut bytes = Vec::new();
        output.readback(&self.device, &self.queue, &mut bytes)?;
        Ok(bytes)
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
            let handles: Vec<GpuBufferHandle> = bound
                .iter()
                .filter(|(info, _)| info.group == group_index as u32)
                .map(|(_, handle)| (*handle).clone())
                .collect();
            let layout_id = Arc::as_ptr(layout).addr();
            let bg = self
                .bind_group_cache
                .get_or_create(layout_id, &handles, || {
                    let entries: Vec<_> = bound
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
        clear_outputs(&mut encoder, &bound, self.output_word_count)?;
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
                    .find(|(info, _)| info.name.as_ref() == indirect.count_buffer)
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
) -> Result<Vec<(&'a BufferBindingInfo, &'a GpuBufferHandle)>, BackendError> {
    let mut input_index = 0usize;
    let mut output_index = 0usize;
    let mut params_used = false;
    let mut bound = Vec::with_capacity(bindings.len());
    for info in bindings {
        if info.kind == vyre::ir::MemoryKind::Shared {
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
            vyre::ir::MemoryKind::Uniform | vyre::ir::MemoryKind::Push
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
        validate_handle(info, handle)?;
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

fn clear_outputs(
    encoder: &mut wgpu::CommandEncoder,
    bound: &[(&BufferBindingInfo, &GpuBufferHandle)],
    output_word_count: usize,
) -> Result<(), BackendError> {
    let clear_size = output_word_count.checked_mul(4).ok_or_else(|| {
        BackendError::new(
            "pre-recorded output clear size overflows usize. Fix: reduce output_word_count.",
        )
    })?;
    for (info, handle) in bound {
        if !info.is_output {
            continue;
        }
        if handle.allocation_len() < clear_size as u64 {
            return Err(BackendError::new(format!(
                "pre-recorded output buffer `{}` has {} bytes but dispatch requires {clear_size}. Fix: allocate the output handle with at least the compiled output size.",
                info.name,
                handle.allocation_len()
            )));
        }
        encoder.clear_buffer(handle.buffer(), 0, Some(clear_size as u64));
    }
    Ok(())
}

fn validate_handle(info: &BufferBindingInfo, handle: &GpuBufferHandle) -> Result<(), BackendError> {
    let required = usage_for_binding(info)?;
    if !handle.usage().contains(required) {
        return Err(BackendError::new(format!(
            "pre-recorded handle for binding {} (`{}`) has usage {:?} but requires {:?}. Fix: allocate the handle with the binding's required usage bits.",
            info.binding,
            info.name,
            handle.usage(),
            required
        )));
    }
    if info.count > 0 {
        let required_bytes = (info.count as usize)
            .checked_mul(element_size_bytes(info.element.clone())?)
            .ok_or_else(|| {
                BackendError::new(format!(
                    "buffer `{}` declared size overflows usize. Fix: reduce buffer count.",
                    info.name
                ))
            })?;
        if handle.allocation_len() < required_bytes as u64 {
            return Err(BackendError::new(format!(
                "pre-recorded handle for binding {} (`{}`) has {} bytes but requires {required_bytes}. Fix: allocate a larger GPU buffer.",
                info.binding,
                info.name,
                handle.allocation_len()
            )));
        }
    }
    Ok(())
}

fn usage_for_binding(info: &BufferBindingInfo) -> Result<wgpu::BufferUsages, BackendError> {
    let _binding_contract = (&info.access, &info.hints);
    if info.is_output {
        return Ok(wgpu::BufferUsages::STORAGE
            | wgpu::BufferUsages::COPY_SRC
            | wgpu::BufferUsages::COPY_DST
            | wgpu::BufferUsages::INDIRECT);
    }
    match info.kind {
        vyre::ir::MemoryKind::Readonly | vyre::ir::MemoryKind::Global => {
            Ok(wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_DST
                | wgpu::BufferUsages::INDIRECT)
        }
        vyre::ir::MemoryKind::Uniform | vyre::ir::MemoryKind::Push => {
            Ok(wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST)
        }
        vyre::ir::MemoryKind::Shared => Err(BackendError::new(
            "shared memory reached pre-recorded binding validation. Fix: lower Shared memory into workgroup variables before dispatch.",
        )),
        vyre::ir::MemoryKind::Local => Err(BackendError::new(format!(
            "buffer `{}` reached pre-recorded allocation with MemoryKind::Local. Fix: lower Local regions into shader function variables before dispatch.",
            info.name
        ))),
        _ => Err(BackendError::new(format!(
            "buffer `{}` uses an unknown future MemoryKind in pre-recorded wgpu allocation. Fix: update vyre-wgpu before dispatching this Program.",
            info.name
        ))),
    }
}

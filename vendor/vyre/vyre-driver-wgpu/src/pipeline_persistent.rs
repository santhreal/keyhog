//! Persistent-buffer dispatch for compiled wgpu pipelines.

use std::sync::Arc;

use vyre_driver::BackendError;

use crate::buffer::{BindGroupCacheStats, GpuBufferHandle};
use crate::pipeline::{element_size_bytes, BufferBindingInfo, WgpuPipeline};

/// One persistent dispatch record for batched queue submission.
pub struct DispatchItem<'a> {
    /// Input storage/uniform handles in declaration order.
    pub inputs: &'a [GpuBufferHandle],
    /// Output storage handles in declaration order.
    pub outputs: &'a [GpuBufferHandle],
    /// Optional params handle used for the first uniform/push binding.
    pub params: Option<&'a GpuBufferHandle>,
    /// Direct dispatch workgroup counts.
    pub workgroups: [u32; 3],
}

impl WgpuPipeline {
    /// Dispatch using caller-owned GPU-resident buffers.
    ///
    /// This path performs no input, output, or bind-group allocation on cache
    /// hits. The caller owns terminal readback through
    /// [`GpuBufferHandle::readback`].
    ///
    /// # Errors
    ///
    /// Returns a backend error when the supplied handles do not satisfy the
    /// program's binding contract or command recording fails.
    pub fn dispatch_persistent(
        &self,
        inputs: &[GpuBufferHandle],
        outputs: &mut [GpuBufferHandle],
        params: Option<&GpuBufferHandle>,
        workgroups: [u32; 3],
    ) -> Result<(), BackendError> {
        let item = DispatchItem {
            inputs,
            outputs,
            params,
            workgroups,
        };
        self.dispatch_persistent_batched(&[item])
    }

    /// Dispatch multiple persistent items in one queue submission.
    ///
    /// # Errors
    ///
    /// Returns a backend error when any item violates the binding contract or
    /// command recording fails.
    pub fn dispatch_persistent_batched(
        &self,
        items: &[DispatchItem<'_>],
    ) -> Result<(), BackendError> {
        if items.is_empty() {
            return Ok(());
        }
        let (device, queue) = &*self.device_queue;
        let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
            label: Some("vyre persistent dispatch batch"),
        });
        for item in items {
            self.record_persistent_item(device, &mut encoder, item)?;
        }
        queue.submit(std::iter::once(encoder.finish()));
        Ok(())
    }

    /// Return bind-group cache statistics for diagnostics and tests.
    #[must_use]
    pub fn bind_group_cache_stats(&self) -> BindGroupCacheStats {
        self.bind_group_cache.stats()
    }

    pub(crate) fn record_persistent_item(
        &self,
        device: &wgpu::Device,
        encoder: &mut wgpu::CommandEncoder,
        item: &DispatchItem<'_>,
    ) -> Result<(), BackendError> {
        let bound = self.bound_handles(item)?;
        let bind_groups = self.cached_bind_groups(device, &bound)?;
        self.clear_outputs(encoder, &bound)?;
        let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label: Some("vyre persistent compute"),
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
                .map(|(_, handle)| handle)
                .ok_or_else(|| {
                    BackendError::new(format!(
                        "indirect dispatch count buffer `{}` not bound in persistent dispatch. Fix: supply the declared buffer handle.",
                        indirect.count_buffer
                    ))
                })?;
            pass.dispatch_workgroups_indirect(indirect_handle.buffer(), indirect.count_offset);
        } else {
            pass.dispatch_workgroups(item.workgroups[0], item.workgroups[1], item.workgroups[2]);
        }
        Ok(())
    }

    pub(crate) fn legacy_handles_from_inputs(
        &self,
        inputs: &[&[u8]],
    ) -> Result<(Vec<GpuBufferHandle>, Vec<GpuBufferHandle>), BackendError> {
        let (_device, queue) = &*self.device_queue;
        let mut input_handles = Vec::new();
        let mut output_handles = Vec::new();
        // `inputs` is ordered like non-Shared `buffer_bindings`. Avoid building a
        // temporary `input_bindings` vec each call: advance a slot only for used entries.
        let mut input_slot: usize = 0;
        for info in self.buffer_bindings.iter() {
            if info.kind == vyre::ir::MemoryKind::Shared {
                continue;
            }
            let data = if info.internal_trap {
                None
            } else {
                let data = inputs.get(input_slot).copied();
                input_slot += 1;
                data
            };
            if info.is_output {
                let output = self.output_binding(info.binding)?;
                let output_bytes = output.word_count.checked_mul(4).ok_or_else(|| {
                    BackendError::new(format!(
                        "legacy persistent output `{}` size overflows usize. Fix: reduce its element count.",
                        output.name
                    ))
                })?;
                let handle = self
                    .persistent_pool
                    .acquire(output_bytes as u64, usage_for_binding(info)?)?;
                if info.preserve_input_contents {
                    crate::buffer::write_padded(
                        queue,
                        handle.buffer(),
                        data.unwrap_or(&[]),
                        output_bytes as u64,
                    )?;
                }
                output_handles.push(handle);
                continue;
            }
            let padded_size = binding_padded_size(info, data)? as u64;
            let handle = self
                .persistent_pool
                .acquire(padded_size, usage_for_binding(info)?)?;
            crate::buffer::write_padded(queue, handle.buffer(), data.unwrap_or(&[]), padded_size)?;
            input_handles.push(handle);
        }
        Ok((input_handles, output_handles))
    }

    fn clear_outputs(
        &self,
        encoder: &mut wgpu::CommandEncoder,
        bound: &[(&BufferBindingInfo, &GpuBufferHandle)],
    ) -> Result<(), BackendError> {
        for (info, handle) in bound {
            if !info.is_output {
                continue;
            }
            if info.preserve_input_contents {
                continue;
            }
            let output = self.output_binding(info.binding)?;
            let clear_size = output.word_count.checked_mul(4).ok_or_else(|| {
                BackendError::new(format!(
                    "persistent output clear size overflows usize for `{}`. Fix: reduce its element count.",
                    output.name
                ))
            })?;
            if handle.allocation_len() < clear_size as u64 {
                return Err(BackendError::new(format!(
                    "persistent output buffer `{}` has {} bytes but dispatch requires {clear_size}. Fix: allocate the output handle with at least the compiled output size.",
                    info.name,
                    handle.allocation_len()
                )));
            }
            encoder.clear_buffer(handle.buffer(), 0, Some(clear_size as u64));
        }
        Ok(())
    }

    fn bound_handles<'a>(
        &'a self,
        item: &'a DispatchItem<'a>,
    ) -> Result<smallvec::SmallVec<[(&'a BufferBindingInfo, &'a GpuBufferHandle); 8]>, BackendError>
    {
        let mut input_index = 0usize;
        let mut output_index = 0usize;
        let mut params_used = false;
        let mut bound: smallvec::SmallVec<[(&'a BufferBindingInfo, &'a GpuBufferHandle); 8]> =
            smallvec::SmallVec::new();
        for info in self.buffer_bindings.iter() {
            if info.kind == vyre::ir::MemoryKind::Shared {
                continue;
            }
            let handle = if info.is_output {
                let handle = item.outputs.get(output_index).ok_or_else(|| {
                    BackendError::new(format!(
                        "persistent dispatch missing output handle for binding {} (`{}`). Fix: pass one output handle per output BufferDecl.",
                        info.binding, info.name
                    ))
                })?;
                output_index += 1;
                handle
            } else if matches!(
                info.kind,
                vyre::ir::MemoryKind::Uniform | vyre::ir::MemoryKind::Push
            ) && item.params.is_some()
                && !params_used
            {
                params_used = true;
                item.params.expect("Fix: checked is_some")
            } else {
                let handle = item.inputs.get(input_index).ok_or_else(|| {
                    BackendError::new(format!(
                        "persistent dispatch missing input handle for binding {} (`{}`). Fix: pass non-output handles in BufferDecl order.",
                        info.binding, info.name
                    ))
                })?;
                input_index += 1;
                handle
            };
            validate_handle(info, handle)?;
            bound.push((info, handle));
        }
        validate_consumed_counts(item, input_index, output_index)?;
        Ok(bound)
    }

    fn cached_bind_groups(
        &self,
        device: &wgpu::Device,
        bound: &[(&BufferBindingInfo, &GpuBufferHandle)],
    ) -> Result<Arc<[Arc<wgpu::BindGroup>]>, BackendError> {
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
                        label: Some("vyre persistent bind group"),
                        layout,
                        entries: &entries,
                    })
                });
            bind_groups.push(bg);
        }
        Ok(bind_groups.into())
    }
}

fn binding_padded_size(
    info: &BufferBindingInfo,
    data: Option<&[u8]>,
) -> Result<usize, BackendError> {
    let declared_size = if info.count > 0 {
        (info.count as usize)
            .checked_mul(element_size_bytes(info.element.clone())?)
            .ok_or_else(|| {
                BackendError::new(format!(
                    "buffer `{}` declared size overflows usize. Fix: reduce buffer count.",
                    info.name
                ))
            })?
    } else {
        0
    };
    if let (declared, Some(bytes)) = (declared_size, data) {
        if declared > 0 && bytes.len() > declared {
            return Err(BackendError::new(format!(
                "buffer `{}` received {} input bytes but declares only {declared} bytes. Fix: either increase BufferDecl::count or pass bytes matching the static buffer contract.",
                info.name,
                bytes.len()
            )));
        }
    }
    let len = match (declared_size, data) {
        (d, Some(_)) if d > 0 => d,
        (d, None) if d > 0 => d,
        (0, Some(bytes)) => bytes.len(),
        (0, None) => 4,
        _ => return Err(BackendError::new(
            "binding_padded_size: unexpected (declared_size, data) combination. Fix: ensure buffer has either a declared count or input data.",
        )),
    }
    .max(4)
    .next_multiple_of(4);
    Ok(len)
}

fn validate_consumed_counts(
    item: &DispatchItem<'_>,
    input_index: usize,
    output_index: usize,
) -> Result<(), BackendError> {
    if input_index != item.inputs.len() {
        return Err(BackendError::new(format!(
            "persistent dispatch received {} input handles but consumed {input_index}. Fix: pass handles matching non-output BufferDecl order.",
            item.inputs.len()
        )));
    }
    if output_index != item.outputs.len() {
        return Err(BackendError::new(format!(
            "persistent dispatch received {} output handles but consumed {output_index}. Fix: pass handles matching output BufferDecl order.",
            item.outputs.len()
        )));
    }
    Ok(())
}

fn validate_handle(info: &BufferBindingInfo, handle: &GpuBufferHandle) -> Result<(), BackendError> {
    let required = usage_for_binding(info)?;
    if !handle.usage().contains(required) {
        return Err(BackendError::new(format!(
            "persistent handle for binding {} (`{}`) has usage {:?} but requires {:?}. Fix: allocate the handle with the binding's required usage bits.",
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
                "persistent handle for binding {} (`{}`) has {} bytes but requires {required_bytes}. Fix: allocate a larger GPU buffer.",
                info.binding,
                info.name,
                handle.allocation_len()
            )));
        }
    }
    Ok(())
}

pub(crate) fn usage_for_binding(
    info: &BufferBindingInfo,
) -> Result<wgpu::BufferUsages, BackendError> {
    let _binding_contract = (&info.access, &info.hints);
    if info.internal_trap {
        return Ok(wgpu::BufferUsages::STORAGE
            | wgpu::BufferUsages::COPY_SRC
            | wgpu::BufferUsages::COPY_DST);
    }
    if info.is_output {
        return Ok(wgpu::BufferUsages::STORAGE
            | wgpu::BufferUsages::COPY_SRC
            | wgpu::BufferUsages::COPY_DST);
    }
    match info.kind {
        vyre::ir::MemoryKind::Readonly | vyre::ir::MemoryKind::Global => {
            Ok(wgpu::BufferUsages::STORAGE | wgpu::BufferUsages::COPY_DST)
        }
        vyre::ir::MemoryKind::Uniform | vyre::ir::MemoryKind::Push => {
            Ok(wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST)
        }
        vyre::ir::MemoryKind::Shared => Err(BackendError::new(
            "shared memory reached persistent binding validation. Fix: lower Shared memory into workgroup variables before dispatch.",
        )),
        vyre::ir::MemoryKind::Local => Err(BackendError::new(format!(
            "buffer `{}` reached persistent allocation with MemoryKind::Local. Fix: lower Local regions into shader function variables before dispatch.",
            info.name
        ))),
        _ => Err(BackendError::new(format!(
            "buffer `{}` uses an unknown future MemoryKind in persistent wgpu allocation. Fix: update vyre-wgpu before dispatching this Program.",
            info.name
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn binding_info(count: u32) -> BufferBindingInfo {
        BufferBindingInfo {
            group: 0,
            binding: 0,
            name: Arc::from("input"),
            access: vyre::ir::BufferAccess::ReadOnly,
            kind: vyre::ir::MemoryKind::Readonly,
            hints: vyre::ir::MemoryHints::default(),
            element: vyre::ir::DataType::U32,
            count,
            is_output: false,
            preserve_input_contents: false,
            internal_trap: false,
        }
    }

    #[test]
    fn binding_padded_size_rejects_oversized_static_input() {
        let info = binding_info(4);
        let error = binding_padded_size(&info, Some(&[0u8; 20]))
            .expect_err("static buffer input larger than BufferDecl::count must fail");
        assert!(
            error
                .to_string()
                .contains("received 20 input bytes but declares only 16 bytes"),
            "{error}"
        );
    }

    #[test]
    fn binding_padded_size_accepts_runtime_sized_input() {
        let info = binding_info(0);
        let size = binding_padded_size(&info, Some(&[7u8; 20])).expect("runtime input sizes");
        assert_eq!(size, 20);
    }
}

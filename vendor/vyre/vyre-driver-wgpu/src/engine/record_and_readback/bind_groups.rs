use super::binding_lookup::BindingLookup;
use super::{GpuBuffers, RecordAndReadback};
use smallvec::SmallVec;
use std::sync::Arc;
use vyre_driver::BackendError;

pub(super) fn build_bind_groups(
    device: &wgpu::Device,
    request: &RecordAndReadback<'_>,
    gpu_buffers: &GpuBuffers,
    gpu_idx_by_binding: &BindingLookup,
    buffer_ids: &mut Vec<u64>,
    bound_indices: &mut Vec<usize>,
) -> Result<SmallVec<[Arc<wgpu::BindGroup>; 4]>, BackendError> {
    let mut bind_groups: SmallVec<[Arc<wgpu::BindGroup>; 4]> =
        SmallVec::with_capacity(request.bind_group_layouts.len());
    for (group_index, layout) in request.bind_group_layouts.iter().enumerate() {
        buffer_ids.clear();
        bound_indices.clear();
        for info in request
            .buffer_bindings
            .iter()
            .filter(|b| b.group == group_index as u32)
        {
            if info.kind == vyre_foundation::ir::MemoryKind::Shared {
                continue;
            }
            let idx = gpu_idx_by_binding.get(info.binding).ok_or_else(|| {
                BackendError::new(format!(
                    "GPU buffer for binding {} (`{}`) missing. Fix: ensure all declared buffers are allocated.",
                    info.binding, info.name
                ))
            })?;
            let (buffer, logical_size_bytes) =
                gpu_buffers
                    .get(idx)
                    .map(|(_, buf, size)| (buf, size))
                    .ok_or_else(|| {
                        BackendError::new(format!(
                            "GPU buffer for binding {} (`{}`) missing. Fix: ensure all declared buffers are allocated.",
                            info.binding, info.name
                        ))
                    })?;
            buffer_ids.push(buffer.id());
            buffer_ids.push((*logical_size_bytes).max(4).next_multiple_of(4));
            bound_indices.push(idx);
        }
        let layout_id = Arc::as_ptr(layout).addr();
        if let Some(cached) = request
            .bind_group_cache
            .and_then(|cache| cache.get_by_ids(layout_id, buffer_ids.as_slice()))
        {
            bind_groups.push(cached);
            continue;
        }

        let mut entries: SmallVec<[wgpu::BindGroupEntry<'_>; 16]> =
            SmallVec::with_capacity(bound_indices.len());
        for &idx in bound_indices.iter() {
            let (binding, buffer, logical_size_bytes) = gpu_buffers.get(idx).ok_or_else(|| {
                BackendError::new(format!(
                    "GPU buffer index {idx} missing while building bind group {group_index}. Fix: keep bind-group scratch indices synchronized with allocated buffers."
                ))
            })?;
            let buffer_arc = buffer.buffer();
            let bind_size = wgpu::BufferSize::new((*logical_size_bytes).max(4).next_multiple_of(4));
            entries.push(wgpu::BindGroupEntry {
                binding: *binding,
                resource: wgpu::BindingResource::Buffer(wgpu::BufferBinding {
                    buffer: buffer_arc,
                    offset: 0,
                    size: bind_size,
                }),
            });
        }
        let bind_group = if let Some(cache) = request.bind_group_cache {
            cache.insert_by_ids(
                layout_id,
                buffer_ids.as_slice(),
                device.create_bind_group(&wgpu::BindGroupDescriptor {
                    label: Some(request.labels.bind_group),
                    layout,
                    entries: &entries,
                }),
            )
        } else {
            Arc::new(device.create_bind_group(&wgpu::BindGroupDescriptor {
                label: Some(request.labels.bind_group),
                layout,
                entries: &entries,
            }))
        };
        bind_groups.push(bind_group);
    }
    Ok(bind_groups)
}

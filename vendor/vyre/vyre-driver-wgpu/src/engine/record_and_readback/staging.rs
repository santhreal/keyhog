use super::binding_lookup::BindingLookup;
use super::readback::{SubmittedMap, SubmittedReadback};
use super::{pool_backend_error, GpuBuffers, RecordAndReadback};
use smallvec::SmallVec;
use vyre_driver::BackendError;
use vyre_emit_naga::program::TRAP_SIDECAR_WORDS;

pub(super) fn record_readback_copies(
    device: &wgpu::Device,
    pool: &crate::buffer::BufferPool,
    encoder: &mut wgpu::CommandEncoder,
    request: &RecordAndReadback<'_>,
    gpu_buffers: &GpuBuffers,
    gpu_idx_by_binding: &BindingLookup,
) -> Result<SmallVec<[SubmittedMap; 4]>, BackendError> {
    let output_count = request.output_bindings.len();
    let trap_readback_count = usize::from(
        request
            .buffer_bindings
            .iter()
            .any(|info| info.internal_trap),
    );
    let mut readback_buffers: SmallVec<[SubmittedMap; 4]> =
        SmallVec::with_capacity(output_count + trap_readback_count);
    for (output_idx, output) in request.output_bindings.iter().enumerate() {
        let readback_size = output.layout.copy_size as u64;
        let output_buffer = gpu_idx_by_binding
            .get(output.binding)
            .and_then(|idx| gpu_buffers.get(idx))
            .map(|(_, buf, _)| buf)
            .ok_or_else(|| {
                BackendError::new(format!(
                    "GPU output buffer `{}` was not allocated. Fix: keep writable bindings synchronized during dispatch setup.",
                    output.name
                ))
            })?;
        if let Some(ring_set) = request.readback_rings {
            let ring = ring_set.ring_for(device, readback_size)?;
            let ticket = ring.record_copy(
                device,
                encoder,
                output_buffer.buffer(),
                output.layout.copy_offset as u64,
                readback_size,
            )?;
            readback_buffers.push((Some(output_idx), SubmittedReadback::Ring { ring, ticket }));
        } else {
            let readback_buffer = pool
                .acquire(readback_size,
                    wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
                )
                .map_err(pool_backend_error)?;
            encoder.copy_buffer_to_buffer(
                output_buffer.buffer(),
                output.layout.copy_offset as u64,
                readback_buffer.buffer(),
                0,
                readback_size,
            );
            readback_buffers.push((
                Some(output_idx),
                SubmittedReadback::Pooled {
                    buffer: readback_buffer,
                    mapped_range: 0..readback_size,
                },
            ));
        }
    }
    if let Some(trap_info) = request
        .buffer_bindings
        .iter()
        .find(|info| info.internal_trap)
    {
        let readback_size = u64::from(TRAP_SIDECAR_WORDS) * 4;
        let readback_buffer = pool
            .acquire(readback_size,
                wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            )
            .map_err(pool_backend_error)?;
        let trap_buffer = gpu_idx_by_binding
            .get(trap_info.binding)
            .and_then(|idx| gpu_buffers.get(idx))
            .map(|(_, buf, _)| buf)
            .ok_or_else(|| {
                BackendError::new(
                    "GPU trap sidecar was not allocated. Fix: keep internal trap binding metadata synchronized during dispatch setup.",
                )
            })?;
        encoder.copy_buffer_to_buffer(
            trap_buffer.buffer(),
            0,
            readback_buffer.buffer(),
            0,
            readback_size,
        );
        readback_buffers.push((
            None,
            SubmittedReadback::Pooled {
                buffer: readback_buffer,
                mapped_range: 0..4,
            },
        ));
    }
    Ok(readback_buffers)
}

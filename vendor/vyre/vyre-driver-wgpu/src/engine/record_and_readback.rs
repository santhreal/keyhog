//! Shared command recording, dispatch, and readback for vyre IR pipelines.

use crate::lowering::naga_emit::{TrapTag, TRAP_SIDECAR_WORDS};
use crate::pipeline::element_size_bytes;
use crate::pipeline::{BufferBindingInfo, OutputBindingLayout};
use crate::runtime::cache::{BufferPool, PooledBuffer};
use rustc_hash::FxHashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use vyre_driver::BackendError;

/// Static labels used for wgpu resource creation.
#[derive(Clone, Copy)]
pub(crate) struct DispatchLabels {
    /// Readback buffer label.
    pub readback: &'static str,
    /// Bind group label.
    pub bind_group: &'static str,
    /// Command encoder label.
    pub encoder: &'static str,
    /// Compute pass label.
    pub compute: &'static str,
}

/// Command recording inputs shared by direct and compiled dispatch.
pub(crate) struct RecordAndReadback<'a> {
    /// Device and queue owned by the backend or compiled pipeline.
    pub device_queue: &'a Arc<(wgpu::Device, wgpu::Queue)>,
    /// Dispatch-local buffer arena.
    pub pool: &'a BufferPool,
    /// Compiled compute pipeline to execute.
    pub pipeline: &'a wgpu::ComputePipeline,
    /// Bind-group layouts for `pipeline`.
    pub bind_group_layouts: &'a [Arc<wgpu::BindGroupLayout>],
    /// Buffer binding metadata derived from the Program at compile time.
    pub buffer_bindings: &'a [BufferBindingInfo],
    /// Caller-provided bytes for each non-shared, non-output buffer in declaration order.
    pub inputs: &'a [&'a [u8]],
    /// Per-output copy and trimming layouts.
    pub output_bindings: &'a [OutputBindingLayout],
    /// Trap tag table for backend-owned trap sidecar decoding.
    pub trap_tags: &'a [TrapTag],
    /// Workgroup count for direct dispatch.
    pub workgroup_count: [u32; 3],
    /// Optional indirect dispatch source.
    pub indirect: Option<&'a crate::pipeline::IndirectDispatch>,
    /// wgpu labels for trace readability.
    pub labels: DispatchLabels,
    /// Number of back-to-back compute dispatches to record before readback.
    pub iterations: u32,
}

type MapSlot = Arc<Mutex<Option<Result<(), wgpu::BufferAsyncError>>>>;
type PendingMap = (Option<OutputBindingLayout>, PooledBuffer, MapSlot);

/// Handle for submitted wgpu work whose readback maps are still in flight.
pub(crate) struct WgpuPendingReadback {
    device_queue: Arc<(wgpu::Device, wgpu::Queue)>,
    submission: wgpu::SubmissionIndex,
    pending: smallvec::SmallVec<[PendingMap; 4]>,
    trap_tags: Arc<[TrapTag]>,
}

impl WgpuPendingReadback {
    /// Non-blocking readiness probe.
    pub(crate) fn is_ready(&self) -> bool {
        let (device, _) = &*self.device_queue;
        match device.poll(wgpu::Maintain::Poll) {
            wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => {}
        }
        self.pending
            .iter()
            .all(|(_, _, result_slot)| map_slot_is_complete(result_slot))
    }

    /// Wait for the GPU submission and collect trimmed output buffers.
    pub(crate) fn await_result(self) -> Result<Vec<Vec<u8>>, BackendError> {
        let (device, _) = &*self.device_queue;
        match device.poll(wgpu::Maintain::wait_for(self.submission.clone())) {
            wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => {}
        }
        let deadline = Instant::now() + Duration::from_secs(30);
        while !self
            .pending
            .iter()
            .all(|(_, _, result_slot)| map_slot_is_complete(result_slot))
        {
            if Instant::now() >= deadline {
                let pending_count = self
                    .pending
                    .iter()
                    .filter(|(_, _, result_slot)| !map_slot_is_complete(result_slot))
                    .count();
                return Err(BackendError::new(format!(
                    "{pending_count} GPU readback map callback(s) did not complete within 30s after submission wait. Fix: inspect wgpu device polling, driver health, and readback buffer lifetimes."
                )));
            }
            match device.poll(wgpu::Maintain::Wait) {
                wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => {}
            }
        }

        let trap_tags = self.trap_tags;
        let mut outputs = Vec::with_capacity(self.pending.len());
        for (output, readback_buffer, result_slot) in self.pending {
            let map_result = result_slot.lock().map_err(vyre_driver::BackendError::poisoned_lock)?.take().ok_or_else(|| {
                BackendError::new(
                    "GPU readback callback was not invoked. Fix: ensure the device is polled before reading back mapped buffers.",
                )
            })?;
            map_result.map_err(|e| {
                BackendError::new(format!(
                    "GPU readback mapping failed: {e:?}. Fix: use MAP_READ and COPY_DST readback buffers."
                ))
            })?;

            let buf = readback_buffer.buffer().map_err(pool_backend_error)?;
            let slice = buf.slice(..);
            let mapped = slice.get_mapped_range();
            if let Some(output) = output {
                let trim = output.layout.trim_start;
                let end = trim.saturating_add(output.layout.read_size);
                if end > mapped.len() {
                    return Err(BackendError::new(format!(
                        "readback slice for output `{}` is out of bounds. Fix: verify OutputLayout against actual GPU readback size.",
                        output.name
                    )));
                }
                let read_len = end - trim;
                let mut out = Vec::with_capacity(read_len);
                out.extend_from_slice(&mapped[trim..end]);
                outputs.push(out);
            } else if let Some(error) =
                crate::pipeline::trap_error_from_sidecar(&mapped, &trap_tags)
            {
                drop(mapped);
                buf.unmap();
                return Err(error);
            }
            drop(mapped);
            buf.unmap();
        }

        Ok(outputs)
    }
}

fn map_slot_is_complete(result_slot: &MapSlot) -> bool {
    match result_slot.lock() {
        Ok(slot) => slot.is_some(),
        Err(error) => error.into_inner().is_some(),
    }
}

/// Record compute work, submit it, and return a pending readback handle.
///
/// # Errors
///
/// Returns a backend error when buffer sizing, bind-group construction, GPU
/// submission, or readback map request fails.
pub(crate) fn record_and_submit_async(
    request: RecordAndReadback<'_>,
) -> Result<WgpuPendingReadback, BackendError> {
    let (device, queue) = &**request.device_queue;
    let pool = request.pool;

    // Map buffer binding → index into `request.inputs`. Plain outputs are
    // allocated empty, but read-write state buffers with
    // `preserve_input_contents` are both inputs and outputs: their host bytes
    // must be uploaded before dispatch and read back after dispatch.
    let input_slot_count = request.inputs.len();
    let full_input_order_count = request
        .buffer_bindings
        .iter()
        .filter(|info| info.kind != vyre::ir::MemoryKind::Shared && !info.internal_trap)
        .count();
    let full_input_order = input_slot_count == full_input_order_count;
    let mut input_idx_by_binding: FxHashMap<u32, usize> = FxHashMap::default();
    input_idx_by_binding.reserve(request.buffer_bindings.len());
    let mut next_input = 0usize;
    for info in request.buffer_bindings.iter() {
        if info.kind == vyre::ir::MemoryKind::Shared || info.internal_trap {
            continue;
        }
        if info.is_output && !info.preserve_input_contents {
            if full_input_order {
                next_input = next_input.saturating_add(1);
            }
            continue;
        }
        input_idx_by_binding.insert(info.binding, next_input);
        next_input = next_input.saturating_add(1);
    }

    // Create a GPU buffer for every binding that needs one.
    let mut gpu_buffers: smallvec::SmallVec<[(u32, PooledBuffer); 8]> = smallvec::SmallVec::new();
    let mut gpu_idx_by_binding: FxHashMap<u32, usize> = FxHashMap::default();
    gpu_idx_by_binding.reserve(request.buffer_bindings.len());
    let mut clear_requests: smallvec::SmallVec<[(u32, u64); 8]> = smallvec::SmallVec::new();

    for info in request.buffer_bindings.iter() {
        if info.kind == vyre::ir::MemoryKind::Shared {
            continue;
        }
        let input_idx = input_idx_by_binding
            .get(&info.binding)
            .copied()
            .unwrap_or(input_slot_count);
        let data = request.inputs.get(input_idx).copied();

        let buf = if info.internal_trap {
            let size = u64::from(TRAP_SIDECAR_WORDS) * 4;
            let b = pool
                .acquire(
                    device,
                    "vyre trap sidecar",
                    size,
                    wgpu::BufferUsages::STORAGE
                        | wgpu::BufferUsages::COPY_SRC
                        | wgpu::BufferUsages::COPY_DST,
                )
                .map_err(pool_backend_error)?;
            clear_requests.push((info.binding, size));
            b
        } else if info.is_output {
            let output = output_binding(request.output_bindings, info.binding)?;
            let output_bytes = output.word_count.checked_mul(4).ok_or_else(|| {
                BackendError::new(format!(
                    "output buffer `{}` size overflows usize. Fix: reduce its element count.",
                    output.name
                ))
            })?;
            let usage = wgpu::BufferUsages::STORAGE
                | wgpu::BufferUsages::COPY_SRC
                | wgpu::BufferUsages::COPY_DST
                | wgpu::BufferUsages::INDIRECT;
            let b = pool
                .acquire(device, "vyre output", output_bytes as u64, usage)
                .map_err(pool_backend_error)?;
            if info.preserve_input_contents {
                if let Some(bytes) = data {
                    write_padded_input(
                        queue,
                        b.buffer().map_err(pool_backend_error)?,
                        bytes,
                        output_bytes,
                    );
                } else {
                    write_padded_input(
                        queue,
                        b.buffer().map_err(pool_backend_error)?,
                        &[],
                        output_bytes,
                    );
                }
            }
            b
        } else {
            let element_size = element_size_bytes(info.element.clone())?;
            let declared_size = if info.count > 0 {
                (info.count as usize)
                    .checked_mul(element_size)
                    .ok_or_else(|| {
                        BackendError::new(format!(
                            "buffer `{}` declared size overflows usize. Fix: reduce buffer count.",
                            info.name
                        ))
                    })?
            } else {
                0
            };

            let (size, contents): (usize, Option<&[u8]>) = match (declared_size, data) {
                (d, Some(bytes)) if d > 0 => (d.max(bytes.len()), Some(bytes)),
                (d, None) if d > 0 => (d, None),
                (0, Some(bytes)) => (bytes.len(), Some(bytes)),
                (0, None) => (4, None),
                _ => {
                    return Err(BackendError::new(
                        "unexpected (declared_size, data) combination. Fix: ensure buffer has either a declared count or input data.",
                    ));
                }
            };

            // wgpu requires buffer sizes to be a multiple of 4 for some usages.
            let size = size.max(4).next_multiple_of(4);

            let usage = match info.kind {
                vyre::ir::MemoryKind::Readonly | vyre::ir::MemoryKind::Global => {
                    wgpu::BufferUsages::STORAGE
                        | wgpu::BufferUsages::COPY_DST
                        | wgpu::BufferUsages::INDIRECT
                }
                vyre::ir::MemoryKind::Uniform | vyre::ir::MemoryKind::Push => {
                    wgpu::BufferUsages::UNIFORM | wgpu::BufferUsages::COPY_DST
                }
                vyre::ir::MemoryKind::Shared => {
                    return Err(BackendError::new(format!(
                        "buffer `{}` reached wgpu allocation with MemoryKind::Shared after filtering. Fix: this is an internal invariant violation; report as a bug.",
                        info.name
                    )));
                }
                vyre::ir::MemoryKind::Local => {
                    return Err(BackendError::new(format!(
                        "buffer `{}` reached wgpu allocation with MemoryKind::Local. Fix: lower Local regions into shader function variables before dispatch.",
                        info.name
                    )));
                }
                _ => {
                    return Err(BackendError::new(format!(
                        "buffer `{}` uses an unknown future MemoryKind in wgpu allocation. Fix: update vyre-wgpu before dispatching this Program.",
                        info.name
                    )));
                }
            };

            let b = pool
                .acquire(device, "vyre buffer", size as u64, usage)
                .map_err(pool_backend_error)?;
            if let Some(c) = contents {
                write_padded_input(queue, b.buffer().map_err(pool_backend_error)?, c, size);
            } else {
                clear_requests.push((info.binding, size as u64));
            }
            b
        };

        let idx = gpu_buffers.len();
        gpu_buffers.push((info.binding, buf));
        gpu_idx_by_binding.insert(info.binding, idx);
    }

    // Build bind groups
    let mut bind_groups = Vec::with_capacity(request.bind_group_layouts.len());
    for (group_index, layout) in request.bind_group_layouts.iter().enumerate() {
        let mut entries = Vec::new();
        for info in request
            .buffer_bindings
            .iter()
            .filter(|b| b.group == group_index as u32)
        {
            if info.kind == vyre::ir::MemoryKind::Shared {
                continue;
            }
            let buffer = gpu_idx_by_binding
                .get(&info.binding)
                .copied()
                .and_then(|idx| gpu_buffers.get(idx))
                .map(|(_, buf)| buf)
                .ok_or_else(|| {
                    BackendError::new(format!(
                        "GPU buffer for binding {} (`{}`) missing. Fix: ensure all declared buffers are allocated.",
                        info.binding, info.name
                    ))
                })?;
            entries.push(wgpu::BindGroupEntry {
                binding: info.binding,
                resource: buffer
                    .buffer()
                    .map_err(pool_backend_error)?
                    .as_entire_binding(),
            });
        }
        bind_groups.push(device.create_bind_group(&wgpu::BindGroupDescriptor {
            label: Some(request.labels.bind_group),
            layout,
            entries: &entries,
        }));
    }

    device.push_error_scope(wgpu::ErrorFilter::Validation);
    let mut encoder = device.create_command_encoder(&wgpu::CommandEncoderDescriptor {
        label: Some(request.labels.encoder),
    });

    // PERF-HOT-02: GPU-side zero-init for buffers that arrived without
    // input data. No CPU vec allocation, no host→device bus transfer.
    for (binding, size) in clear_requests {
        let (_, buf) = gpu_idx_by_binding
            .get(&binding)
            .copied()
            .and_then(|idx| gpu_buffers.get(idx))
            .ok_or_else(|| {
            BackendError::new(format!(
                "GPU buffer for binding {} missing during clear. Fix: internal invariant violation.",
                binding
            ))
        })?;
        encoder.clear_buffer(buf.buffer().map_err(pool_backend_error)?, 0, Some(size));
    }

    // Clear every writable output buffer before dispatch.
    for output in request.output_bindings {
        let info = request
            .buffer_bindings
            .iter()
            .find(|info| info.binding == output.binding)
            .ok_or_else(|| {
                BackendError::new(format!(
                    "missing binding metadata for output `{}`. Fix: keep buffer_bindings synchronized with output_bindings.",
                    output.name
                ))
            })?;
        if info.preserve_input_contents {
            continue;
        }
        if let Some((_, buf)) = gpu_idx_by_binding
            .get(&output.binding)
            .copied()
            .and_then(|idx| gpu_buffers.get(idx))
        {
            let clear_size = (output.word_count as u64).checked_mul(4).ok_or_else(|| {
                BackendError::new(format!(
                    "clear_buffer size overflows u64 for output `{}`. Fix: reduce its element count.",
                    output.name
                ))
            })?;
            encoder.clear_buffer(
                buf.buffer().map_err(pool_backend_error)?,
                0,
                Some(clear_size),
            );
        }
    }

    {
        let mut pass = encoder.begin_compute_pass(&wgpu::ComputePassDescriptor {
            label: Some(request.labels.compute),
            timestamp_writes: None,
        });
        pass.set_pipeline(request.pipeline);
        for (i, bg) in bind_groups.iter().enumerate() {
            pass.set_bind_group(i as u32, bg, &[]);
        }

        let indirect_dispatch_buffer = if let Some(indirect) = request.indirect {
            let indirect_binding = request
                    .buffer_bindings
                    .iter()
                    .find(|b| b.name.as_ref() == indirect.count_buffer)
                    .map(|b| b.binding)
                    .ok_or_else(|| {
                        BackendError::new(format!(
                            "indirect dispatch count buffer `{}` not found in program bindings. Fix: declare the buffer in the Program.",
                            indirect.count_buffer
                        ))
                    })?;
            Some(
                gpu_idx_by_binding
                    .get(&indirect_binding)
                    .copied()
                    .and_then(|idx| gpu_buffers.get(idx))
                    .map(|(_, buf)| buf)
                    .ok_or_else(|| {
                        BackendError::new(format!(
                            "indirect dispatch count buffer `{}` was not allocated. Fix: ensure the buffer has a declared count or input data.",
                            indirect.count_buffer
                        ))
                    })?
                    .buffer()
                    .map_err(pool_backend_error)?,
            )
        } else {
            None
        };

        for _ in 0..request.iterations.max(1) {
            if let (Some(indirect), Some(indirect_buffer)) =
                (request.indirect, indirect_dispatch_buffer)
            {
                pass.dispatch_workgroups_indirect(indirect_buffer, indirect.count_offset);
            } else {
                pass.dispatch_workgroups(
                    request.workgroup_count[0],
                    request.workgroup_count[1],
                    request.workgroup_count[2],
                );
            }
        }
    }

    let mut readback_buffers: smallvec::SmallVec<
        [(Option<&OutputBindingLayout>, PooledBuffer); 4],
    > = smallvec::SmallVec::new();
    for output in request.output_bindings {
        let readback_size = output.layout.copy_size as u64;
        let readback_buffer = pool
            .acquire(
                device,
                request.labels.readback,
                readback_size,
                wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            )
            .map_err(pool_backend_error)?;
        let output_buffer = gpu_idx_by_binding
            .get(&output.binding)
            .copied()
            .and_then(|idx| gpu_buffers.get(idx))
            .map(|(_, buf)| buf)
            .ok_or_else(|| {
                BackendError::new(format!(
                    "GPU output buffer `{}` was not allocated. Fix: keep writable bindings synchronized during dispatch setup.",
                    output.name
                ))
            })?;
        encoder.copy_buffer_to_buffer(
            output_buffer.buffer().map_err(pool_backend_error)?,
            output.layout.copy_offset as u64,
            readback_buffer.buffer().map_err(pool_backend_error)?,
            0,
            readback_size,
        );
        readback_buffers.push((Some(output), readback_buffer));
    }
    if let Some(trap_info) = request
        .buffer_bindings
        .iter()
        .find(|info| info.internal_trap)
    {
        let readback_size = u64::from(TRAP_SIDECAR_WORDS) * 4;
        let readback_buffer = pool
            .acquire(
                device,
                request.labels.readback,
                readback_size,
                wgpu::BufferUsages::COPY_DST | wgpu::BufferUsages::MAP_READ,
            )
            .map_err(pool_backend_error)?;
        let trap_buffer = gpu_idx_by_binding
            .get(&trap_info.binding)
            .copied()
            .and_then(|idx| gpu_buffers.get(idx))
            .map(|(_, buf)| buf)
            .ok_or_else(|| {
                BackendError::new(
                    "GPU trap sidecar was not allocated. Fix: keep internal trap binding metadata synchronized during dispatch setup.",
                )
            })?;
        encoder.copy_buffer_to_buffer(
            trap_buffer.buffer().map_err(pool_backend_error)?,
            0,
            readback_buffer.buffer().map_err(pool_backend_error)?,
            0,
            readback_size,
        );
        readback_buffers.push((None, readback_buffer));
    }

    let command_buffer = encoder.finish();
    let submission = queue.submit(std::iter::once(command_buffer));
    match device.poll(wgpu::Maintain::Poll) {
        wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => {}
    }
    if let Some(error) = pollster::block_on(device.pop_error_scope()) {
        return Err(BackendError::DispatchFailed {
            code: None,
            message: format!(
                "wgpu rejected command recording or queue submission: {error}. Fix: verify bind groups, adapter limits, dispatch dimensions, and copy ranges before submitting."
            ),
        });
    }

    // V7-PERF-006: batch all map_async requests BEFORE the single
    // poll so every readback's mapping completes in one device
    // wait, then collect mapped ranges. The previous per-buffer
    // poll serialized N round-trips to the driver.
    let mut pending: smallvec::SmallVec<[PendingMap; 4]> = smallvec::SmallVec::new();
    for (output, readback_buffer) in readback_buffers {
        let buf = readback_buffer.buffer().map_err(pool_backend_error)?;
        let slice = buf.slice(..);
        let result_slot = Arc::new(Mutex::new(None));
        let result_slot_cb = Arc::clone(&result_slot);
        slice.map_async(wgpu::MapMode::Read, move |result| {
            let mut lock = result_slot_cb.lock().unwrap_or_else(|e| e.into_inner());
            *lock = Some(result);
        });
        pending.push((output.cloned(), readback_buffer, result_slot));
    }

    Ok(WgpuPendingReadback {
        device_queue: Arc::clone(request.device_queue),
        submission,
        pending,
        trap_tags: Arc::from(request.trap_tags),
    })
}

/// Record compute work, submit it, and return trimmed readback bytes.
///
/// # Errors
///
/// Returns a backend error when buffer sizing, bind-group construction, GPU
/// submission, or readback mapping fails.
pub(crate) fn record_and_readback(
    request: RecordAndReadback<'_>,
) -> Result<Vec<Vec<u8>>, BackendError> {
    record_and_submit_async(request)?.await_result()
}

fn output_binding(
    outputs: &[OutputBindingLayout],
    binding: u32,
) -> Result<&OutputBindingLayout, BackendError> {
    outputs.iter().find(|output| output.binding == binding).ok_or_else(|| {
        BackendError::new(format!(
            "missing output layout metadata for binding {binding}. Fix: keep writable BufferDecl metadata synchronized during dispatch setup."
        ))
    })
}

fn pool_backend_error(error: impl std::fmt::Display) -> BackendError {
    BackendError::new(format!(
        "GPU buffer pool acquisition failed: {error}. Fix: restart the process if the pool lock was poisoned, or reduce concurrent dispatch pressure."
    ))
}

fn write_padded_input(queue: &wgpu::Queue, buffer: &wgpu::Buffer, bytes: &[u8], size: usize) {
    let aligned_len = bytes.len() & !3;
    if aligned_len > 0 {
        queue.write_buffer(buffer, 0, &bytes[..aligned_len]);
    }

    let mut zero_start = aligned_len;
    let tail_len = bytes.len() - aligned_len;
    if tail_len > 0 {
        let mut tail = [0u8; 4];
        tail[..tail_len].copy_from_slice(&bytes[aligned_len..]);
        queue.write_buffer(buffer, aligned_len as u64, &tail);
        zero_start += 4;
    }

    if size > zero_start {
        static SCRATCH_ZEROS: [u8; 4096] = [0u8; 4096];
        let mut offset = zero_start;
        while offset < size {
            let chunk = (size - offset).min(SCRATCH_ZEROS.len());
            queue.write_buffer(buffer, offset as u64, &SCRATCH_ZEROS[..chunk]);
            offset += chunk;
        }
    }
}

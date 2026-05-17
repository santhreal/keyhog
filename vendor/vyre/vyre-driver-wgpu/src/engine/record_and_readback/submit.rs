use super::readback::{PendingMap, WgpuPendingReadback};
use super::RecordedDispatch;
use smallvec::SmallVec;
use std::sync::Arc;
use vyre_driver::BackendError;

pub(crate) fn submit_recorded_dispatch(
    mut recorded: RecordedDispatch,
) -> Result<WgpuPendingReadback, BackendError> {
    let (device, queue) = &*recorded.device_queue;
    device.push_error_scope(wgpu::ErrorFilter::Validation);
    let command_buffer = recorded.command_buffer.take().ok_or_else(|| {
        BackendError::new(
            "recorded dispatch was submitted twice. Fix: keep RecordedDispatch ownership linear.",
        )
    })?;
    let _submission = queue.submit(std::iter::once(command_buffer));
    match device.poll(wgpu::Maintain::Poll) {
        wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => {}
    }
    if let Some(error) = crate::runtime::device::pop_error_scope_now(device).map_err(|message| {
        BackendError::DispatchFailed {
            code: None,
            message: format!(
                "wgpu queue-submit validation did not complete without a host wait: {message}"
            ),
        }
    })? {
        return Err(BackendError::DispatchFailed {
            code: None,
            message: format!(
                "wgpu rejected queue submission: {error}. Fix: verify command-buffer resource lifetimes, dispatch dimensions, and copy ranges before submitting."
            ),
        });
    }
    pending_after_submission(recorded)
}

pub(crate) fn submit_recorded_batch(
    mut recorded: Vec<RecordedDispatch>,
) -> Result<Vec<WgpuPendingReadback>, BackendError> {
    let Some(first) = recorded.first() else {
        return Ok(Vec::new());
    };
    let device_queue = Arc::clone(&first.device_queue);
    for item in &recorded {
        if !Arc::ptr_eq(&device_queue, &item.device_queue) {
            return Err(BackendError::new(
                "batched wgpu submit received command buffers from multiple device queues. Fix: group batch jobs by backend/device before submission.",
            ));
        }
    }
    let (device, queue) = &*device_queue;
    device.push_error_scope(wgpu::ErrorFilter::Validation);
    let mut command_buffers: SmallVec<[wgpu::CommandBuffer; 8]> =
        SmallVec::with_capacity(recorded.len());
    for item in &mut recorded {
        command_buffers.push(item.command_buffer.take().ok_or_else(|| {
            BackendError::new(
                "recorded dispatch batch contained a previously submitted command buffer. Fix: keep RecordedDispatch ownership linear.",
            )
        })?);
    }
    let _submission = queue.submit(command_buffers);
    match device.poll(wgpu::Maintain::Poll) {
        wgpu::MaintainResult::Ok | wgpu::MaintainResult::SubmissionQueueEmpty => {}
    }
    if let Some(error) = crate::runtime::device::pop_error_scope_now(device).map_err(|message| {
        BackendError::DispatchFailed {
            code: None,
            message: format!("wgpu batched queue-submit validation did not complete without a host wait: {message}"),
        }
    })? {
        return Err(BackendError::DispatchFailed {
            code: None,
            message: format!(
                "wgpu rejected batched queue submission: {error}. Fix: verify every command buffer in the batch uses the same live device and valid copy ranges."
            ),
        });
    }
    let mut pending = Vec::with_capacity(recorded.len());
    for item in recorded {
        pending.push(pending_after_submission(item)?);
    }
    Ok(pending)
}

fn pending_after_submission(
    recorded: RecordedDispatch,
) -> Result<WgpuPendingReadback, BackendError> {
    let mut pending: smallvec::SmallVec<[PendingMap; 4]> =
        smallvec::SmallVec::with_capacity(recorded.readback_buffers.len());
    for (output, readback) in recorded.readback_buffers {
        pending.push((output, readback.map_async()?));
    }
    let timestamp_profile = if let Some(recorder) = recorded.timestamp_recorder {
        Some(recorder.map_async()?)
    } else {
        None
    };

    Ok(WgpuPendingReadback {
        device_queue: recorded.device_queue,
        pending,
        outputs: Vec::with_capacity(recorded.output_count),
        output_count: recorded.output_count,
        output_bindings: recorded.output_bindings,
        trap_tags: recorded.trap_tags,
        timestamp_profile,
    })
}

//! Runtime-owned wgpu megakernel dispatch wrapper.

use std::time::Instant;
use vyre_driver::{BackendError, DispatchConfig, VyreBackend};
use vyre_driver_megakernel::{MegakernelConfig, MegakernelReport, WorkItem};

use super::io::{try_encode_empty_io_queue, validate_io_queue_bytes, IO_SLOT_COUNT};
use super::protocol::{self, slot, SLOT_WORDS, STATUS_WORD};
use super::{build_program_sharded_once_slots, Megakernel};

/// Runtime wrapper for persistent megakernel dispatch.
pub struct WgpuMegakernelDispatcher<'a> {
    backend: &'a dyn VyreBackend,
}

impl<'a> WgpuMegakernelDispatcher<'a> {
    /// Create a new dispatcher.
    #[must_use]
    pub fn new(backend: &'a dyn VyreBackend) -> Self {
        Self { backend }
    }

    /// Decode a raw little-endian `WorkItem` queue and launch the megakernel.
    ///
    /// # Errors
    ///
    /// Returns a backend error when `work_queue_bytes` is not exactly aligned to
    /// [`WorkItem`] records or when backend dispatch fails.
    pub fn dispatch_megakernel_bytes(
        &self,
        work_queue_bytes: &[u8],
        config: &MegakernelConfig,
    ) -> Result<MegakernelReport, BackendError> {
        if work_queue_bytes.len() % std::mem::size_of::<WorkItem>() != 0 {
            return Err(BackendError::new(format!(
                "megakernel work queue has {} bytes, which is not a multiple of sizeof(WorkItem)={}. Fix: encode whole WorkItem records before dispatch.",
                work_queue_bytes.len(),
                std::mem::size_of::<WorkItem>()
            )));
        }
        let work_items = bytemuck::try_cast_slice::<u8, WorkItem>(work_queue_bytes).map_err(|err| {
            BackendError::new(format!(
                "megakernel work queue bytes are not aligned as WorkItem records: {err}. Fix: allocate or copy the queue into aligned WorkItem storage before dispatch."
            ))
        })?;
        self.dispatch_megakernel(work_items, config)
    }

    /// Launch the megakernel.
    pub fn dispatch_megakernel(
        &self,
        work_items: &[WorkItem],
        config: &MegakernelConfig,
    ) -> Result<MegakernelReport, BackendError> {
        config.validate()?;

        if work_items.is_empty() {
            return Ok(MegakernelReport::default());
        }

        let io_queue_bytes = try_encode_empty_io_queue(IO_SLOT_COUNT)
            .map_err(|e| BackendError::new(e.to_string()))?;
        self.dispatch_megakernel_with_io_queue(work_items, config, io_queue_bytes)
    }

    /// Launch the megakernel with a caller-supplied IO queue.
    ///
    /// The queue is validated against the megakernel ABI before any backend
    /// work starts, so malformed queue views fail before compilation or GPU
    /// submission.
    pub fn dispatch_megakernel_with_io_queue(
        &self,
        work_items: &[WorkItem],
        config: &MegakernelConfig,
        io_queue_bytes: Vec<u8>,
    ) -> Result<MegakernelReport, BackendError> {
        config.validate()?;
        validate_io_queue_bytes(&io_queue_bytes).map_err(|e| BackendError::new(e.to_string()))?;

        let item_count = work_items.len();
        if item_count == 0 {
            return Ok(MegakernelReport::default());
        }

        let queue_len = u32::try_from(item_count).map_err(|_| {
            BackendError::new(
                "megakernel work queue length exceeds u32::MAX. Fix: shard the queue before dispatch.",
            )
        })?;
        let max_workgroup_size_x = self.backend.max_workgroup_size()[0];
        if max_workgroup_size_x == 0 {
            return Err(BackendError::new(format!(
                "backend `{}` reported max_workgroup_size.x=0. Fix: use a backend that exposes real adapter limits before megakernel dispatch.",
                self.backend.id()
            )));
        }
        let launch = config.launch_recommendation(
            queue_len,
            max_workgroup_size_x,
            self.backend.max_compute_workgroups_per_dimension(),
            self.backend.max_compute_invocations_per_workgroup(),
        )?;
        let geometry = launch.geometry;

        let program =
            build_program_sharded_once_slots(geometry.workgroup_size_x, geometry.slot_count, &[]);
        let mut ring_bytes = Megakernel::try_encode_empty_ring(geometry.slot_count)
            .map_err(|e| BackendError::new(e.to_string()))?;
        for (slot_idx, item) in work_items.iter().enumerate() {
            Megakernel::publish_slot(
                &mut ring_bytes,
                slot_idx as u32,
                0,
                item.op_handle,
                &[item.input_handle, item.output_handle, item.param],
            )
            .map_err(|e| BackendError::new(e.to_string()))?;
        }
        let control_bytes = Megakernel::try_encode_control(false, 1, 0)
            .map_err(|e| BackendError::new(e.to_string()))?;
        let debug_log_bytes =
            Megakernel::try_encode_empty_debug_log(protocol::debug::RECORD_CAPACITY)
                .map_err(|e| BackendError::new(e.to_string()))?;

        let start = Instant::now();
        let mut dispatch_config = DispatchConfig::default();
        dispatch_config.timeout = Some(config.max_wall_time);

        dispatch_config.grid_override = Some(geometry.dispatch_grid);
        dispatch_config.workgroup_override = Some([geometry.workgroup_size_x, 1, 1]);

        let outputs = self.backend.dispatch_borrowed(
            &program,
            &[
                control_bytes.as_slice(),
                ring_bytes.as_slice(),
                debug_log_bytes.as_slice(),
                io_queue_bytes.as_slice(),
            ],
            &dispatch_config,
        )?;
        let wall_time = start.elapsed();

        let control_done_count = outputs
            .first()
            .map(|b| Megakernel::read_done_count(b))
            .unwrap_or(0) as u64;
        let slot_done_count = outputs
            .iter()
            .filter_map(|bytes| count_done_slots(bytes, item_count))
            .max()
            .unwrap_or(0);
        let done_count = control_done_count.max(slot_done_count);
        Ok(MegakernelReport {
            items_processed: done_count,
            items_remaining: (item_count as u64).saturating_sub(done_count),
            wall_time,
        })
    }
}

fn count_done_slots(bytes: &[u8], item_count: usize) -> Option<u64> {
    let slot_bytes = usize::try_from(SLOT_WORDS).ok()?.checked_mul(4)?;
    if item_count == 0 || bytes.len() < item_count.checked_mul(slot_bytes)? {
        return None;
    }
    let status_offset = usize::try_from(STATUS_WORD).ok()?.checked_mul(4)?;
    let mut done = 0u64;
    for slot_idx in 0..item_count {
        let offset = slot_idx
            .checked_mul(slot_bytes)?
            .checked_add(status_offset)?;
        let word = u32::from_le_bytes(bytes.get(offset..offset + 4)?.try_into().ok()?);
        if word == slot::DONE {
            done += 1;
        }
    }
    Some(done)
}

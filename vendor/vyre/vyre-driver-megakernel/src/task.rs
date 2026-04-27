use vyre_driver::backend::BackendError;

use crate::core::WorkItem;
use crate::policy::MegakernelLaunchRequest;

/// Number of `u32` words in one continuation task slot.
pub const TASK_SLOT_WORDS: usize = 16;

/// Number of bytes in one continuation task slot.
pub const TASK_SLOT_BYTES: usize = TASK_SLOT_WORDS * core::mem::size_of::<u32>();

/// Lowest flag bit set when a task voluntarily paused at a continuation point.
pub const TASK_FLAG_PAUSED: u32 = 1 << 0;

/// Flag bit set when a task yielded so another task can run on the same worker.
pub const TASK_FLAG_YIELDED: u32 = 1 << 1;

/// Flag bit set when a task asked the scheduler to publish it again.
pub const TASK_FLAG_REQUEUE_REQUESTED: u32 = 1 << 2;

/// Flag bit set when a paused task is eligible to resume.
pub const TASK_FLAG_RESUME_READY: u32 = 1 << 3;

/// GPU-visible lifecycle state for one continuation task slot.
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskState {
    /// Slot is empty and may be reused.
    Empty = 0,
    /// Slot is published and may be claimed by a GPU worker.
    Ready = 1,
    /// Slot is currently owned by a GPU worker.
    Running = 2,
    /// Slot finished successfully.
    Done = 3,
    /// Slot is paused until an external device-visible condition is met.
    Paused = 4,
    /// Slot yielded voluntarily and should remain schedulable.
    Yielded = 5,
    /// Slot should be placed back into its priority partition.
    Requeued = 6,
    /// Slot faulted and must not be executed again without repair.
    Faulted = 7,
}

impl TaskState {
    /// Decode a raw ABI word into a task state.
    #[must_use]
    pub const fn from_word(word: u32) -> Option<Self> {
        match word {
            0 => Some(Self::Empty),
            1 => Some(Self::Ready),
            2 => Some(Self::Running),
            3 => Some(Self::Done),
            4 => Some(Self::Paused),
            5 => Some(Self::Yielded),
            6 => Some(Self::Requeued),
            7 => Some(Self::Faulted),
            _ => None,
        }
    }

    /// Encode this state as the raw ABI word written by the GPU scheduler.
    #[must_use]
    pub const fn word(self) -> u32 {
        self as u32
    }

    /// Return true when this state is eligible for GPU scheduling.
    #[must_use]
    pub const fn is_schedulable(self) -> bool {
        matches!(self, Self::Ready | Self::Yielded | Self::Requeued)
    }
}

/// Priority partition for a continuation task slot.
#[repr(u32)]
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum TaskPriority {
    /// Highest priority partition for latency-critical work.
    Critical = 0,
    /// High priority partition for urgent work.
    High = 1,
    /// Default priority partition.
    #[default]
    Normal = 2,
    /// Low priority partition for background work.
    Low = 3,
    /// Idle partition processed only when higher priorities are empty.
    Idle = 4,
}

impl TaskPriority {
    /// Decode a raw ABI word into a task priority.
    #[must_use]
    pub const fn from_word(word: u32) -> Option<Self> {
        match word {
            0 => Some(Self::Critical),
            1 => Some(Self::High),
            2 => Some(Self::Normal),
            3 => Some(Self::Low),
            4 => Some(Self::Idle),
            _ => None,
        }
    }

    /// Encode this priority as the raw ABI word used by the priority scheduler.
    #[must_use]
    pub const fn word(self) -> u32 {
        self as u32
    }
}

/// One device-visible continuation task slot.
///
/// The first four words match the persistent ring header:
/// status, opcode, tenant, priority. The remaining twelve words are the slot
/// payload. Words 4..6 preserve the legacy [`WorkItem`] payload; words 7..15
/// carry continuation and scheduler state.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct TaskWorkItem {
    /// Raw [`TaskState`] word.
    pub state: u32,
    /// Stable op id index into the dialect registry.
    pub op_handle: u32,
    /// Tenant id checked by the runtime scheduler.
    pub tenant_id: u32,
    /// Raw [`TaskPriority`] word.
    pub priority: u32,
    /// Input-buffer handle.
    pub input_handle: u32,
    /// Output-buffer handle.
    pub output_handle: u32,
    /// Per-item parameter word.
    pub param: u32,
    /// Program counter or block id where the worker should resume.
    pub continuation_pc: u32,
    /// Opaque continuation-local scratch word.
    pub continuation_data: u32,
    /// Device-visible epoch at which the task may resume.
    pub resume_epoch: u32,
    /// Stable task id used to join yielded/requeued continuations.
    pub task_id: u32,
    /// Parent task id for split or fan-out work; zero when absent.
    pub parent_task_id: u32,
    /// Scheduler age ticks accumulated while waiting.
    pub age_ticks: u32,
    /// Number of times this task has been requeued.
    pub requeue_count: u32,
    /// Number of times this task has yielded.
    pub yield_count: u32,
    /// Bitset of `TASK_FLAG_*` continuation flags.
    pub flags: u32,
}

impl TaskWorkItem {
    /// Construct a ready continuation task from the compact legacy work item.
    #[must_use]
    pub const fn from_work_item(
        task_id: u32,
        tenant_id: u32,
        priority: TaskPriority,
        item: WorkItem,
    ) -> Self {
        Self {
            state: TaskState::Ready.word(),
            op_handle: item.op_handle,
            tenant_id,
            priority: priority.word(),
            input_handle: item.input_handle,
            output_handle: item.output_handle,
            param: item.param,
            continuation_pc: 0,
            continuation_data: 0,
            resume_epoch: 0,
            task_id,
            parent_task_id: 0,
            age_ticks: 0,
            requeue_count: 0,
            yield_count: 0,
            flags: 0,
        }
    }

    /// Return the compact legacy work item payload carried by this task.
    #[must_use]
    pub const fn work_item(&self) -> WorkItem {
        WorkItem {
            op_handle: self.op_handle,
            input_handle: self.input_handle,
            output_handle: self.output_handle,
            param: self.param,
        }
    }

    /// Decode the task state word.
    #[must_use]
    pub const fn task_state(&self) -> Option<TaskState> {
        TaskState::from_word(self.state)
    }

    /// Decode the task priority word.
    #[must_use]
    pub const fn task_priority(&self) -> Option<TaskPriority> {
        TaskPriority::from_word(self.priority)
    }

    /// Return true when the task is eligible to be claimed by a worker.
    #[must_use]
    pub const fn is_schedulable(&self) -> bool {
        match self.task_state() {
            Some(state) => state.is_schedulable(),
            None => false,
        }
    }

    /// Encode a pause at `continuation_pc` until `resume_epoch`.
    #[must_use]
    pub const fn paused(
        mut self,
        continuation_pc: u32,
        continuation_data: u32,
        resume_epoch: u32,
    ) -> Self {
        self.state = TaskState::Paused.word();
        self.continuation_pc = continuation_pc;
        self.continuation_data = continuation_data;
        self.resume_epoch = resume_epoch;
        self.flags = (self.flags | TASK_FLAG_PAUSED) & !TASK_FLAG_RESUME_READY;
        self
    }

    /// Mark a paused task ready for GPU-side resume.
    #[must_use]
    pub const fn resumed(mut self) -> Self {
        self.state = TaskState::Ready.word();
        self.flags =
            (self.flags | TASK_FLAG_RESUME_READY) & !(TASK_FLAG_PAUSED | TASK_FLAG_YIELDED);
        self
    }

    /// Yield this task back to the scheduler at `continuation_pc`.
    #[must_use]
    pub const fn yielded(mut self, continuation_pc: u32, continuation_data: u32) -> Self {
        self.state = TaskState::Yielded.word();
        self.continuation_pc = continuation_pc;
        self.continuation_data = continuation_data;
        self.yield_count = self.yield_count.saturating_add(1);
        self.flags |= TASK_FLAG_YIELDED;
        self
    }

    /// Requeue this task, optionally changing its priority partition.
    #[must_use]
    pub const fn requeued(
        mut self,
        continuation_pc: u32,
        continuation_data: u32,
        priority: TaskPriority,
    ) -> Self {
        self.state = TaskState::Requeued.word();
        self.priority = priority.word();
        self.continuation_pc = continuation_pc;
        self.continuation_data = continuation_data;
        self.requeue_count = self.requeue_count.saturating_add(1);
        self.age_ticks = self.age_ticks.saturating_add(1);
        self.flags |= TASK_FLAG_REQUEUE_REQUESTED;
        self
    }

    /// Mark this task completed.
    #[must_use]
    pub const fn completed(mut self) -> Self {
        self.state = TaskState::Done.word();
        self.flags = 0;
        self
    }

    /// Mark this task faulted with a compact fault code.
    #[must_use]
    pub const fn faulted(mut self, fault_code: u32) -> Self {
        self.state = TaskState::Faulted.word();
        self.continuation_data = fault_code;
        self
    }
}

/// Queue telemetry derived from device-visible continuation task slots.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct TaskQueueSnapshot {
    /// Count of ready slots.
    pub ready_count: u32,
    /// Count of paused slots.
    pub paused_count: u32,
    /// Count of yielded slots.
    pub yielded_count: u32,
    /// Count of requeued slots.
    pub requeued_count: u32,
    /// Count of running slots.
    pub running_count: u32,
    /// Count of faulted slots.
    pub faulted_count: u32,
    /// Sum of per-slot requeue counters.
    pub total_requeues: u64,
    /// Maximum priority-aging tick observed in the queue.
    pub max_priority_age: u32,
}

impl TaskQueueSnapshot {
    /// Build a queue snapshot from continuation task slots.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the slice contains an unknown task state or
    /// a count cannot fit the u32 ABI.
    pub fn from_tasks(tasks: &[TaskWorkItem]) -> Result<Self, BackendError> {
        let mut snapshot = Self::default();
        for task in tasks {
            snapshot.max_priority_age = snapshot.max_priority_age.max(task.age_ticks);
            snapshot.total_requeues = snapshot
                .total_requeues
                .saturating_add(u64::from(task.requeue_count));
            match task.task_state() {
                Some(TaskState::Empty | TaskState::Done) => {}
                Some(TaskState::Ready) => checked_increment(&mut snapshot.ready_count)?,
                Some(TaskState::Paused) => checked_increment(&mut snapshot.paused_count)?,
                Some(TaskState::Yielded) => checked_increment(&mut snapshot.yielded_count)?,
                Some(TaskState::Requeued) => checked_increment(&mut snapshot.requeued_count)?,
                Some(TaskState::Running) => checked_increment(&mut snapshot.running_count)?,
                Some(TaskState::Faulted) => checked_increment(&mut snapshot.faulted_count)?,
                None => {
                    return Err(BackendError::new(format!(
                        "megakernel task slot has unknown state word {}. Fix: write a valid TaskState ABI word before publishing the slot.",
                        task.state
                    )));
                }
            }
        }
        Ok(snapshot)
    }

    /// Number of slots immediately eligible for GPU scheduling.
    #[must_use]
    pub fn schedulable_count(&self) -> u32 {
        self.ready_count
            .saturating_add(self.yielded_count)
            .saturating_add(self.requeued_count)
    }

    /// Number of slots carrying continuation pressure.
    #[must_use]
    pub fn continuation_pressure_count(&self) -> u64 {
        u64::from(self.yielded_count)
            .saturating_add(u64::from(self.requeued_count))
            .saturating_add(self.total_requeues)
    }

    /// Merge this queue telemetry into a launch request.
    #[must_use]
    pub fn apply_to_launch_request(
        &self,
        mut request: MegakernelLaunchRequest,
    ) -> MegakernelLaunchRequest {
        request.queue_len = self.schedulable_count();
        request.requeue_count = request
            .requeue_count
            .saturating_add(self.continuation_pressure_count());
        request.max_priority_age = request.max_priority_age.max(self.max_priority_age);
        request
    }
}

fn checked_increment(counter: &mut u32) -> Result<(), BackendError> {
    *counter = counter.checked_add(1).ok_or_else(|| {
        BackendError::new(
            "megakernel task queue count exceeds u32::MAX. Fix: shard the task ring before launch.",
        )
    })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn legacy_item(op_handle: u32) -> WorkItem {
        WorkItem {
            op_handle,
            input_handle: 11,
            output_handle: 12,
            param: 13,
        }
    }

    #[test]
    fn task_work_item_is_one_ring_slot_and_preserves_legacy_payload() {
        assert_eq!(core::mem::size_of::<TaskWorkItem>(), TASK_SLOT_BYTES);
        assert_eq!(
            core::mem::align_of::<TaskWorkItem>(),
            core::mem::align_of::<u32>()
        );

        let task = TaskWorkItem::from_work_item(7, 3, TaskPriority::High, legacy_item(99));
        assert_eq!(task.state, TaskState::Ready.word());
        assert_eq!(task.priority, TaskPriority::High.word());
        assert_eq!(task.task_id, 7);
        assert_eq!(task.tenant_id, 3);
        assert_eq!(task.work_item(), legacy_item(99));
    }

    #[test]
    fn transitions_encode_pause_resume_yield_requeue_without_host_side_state() {
        let task = TaskWorkItem::from_work_item(1, 0, TaskPriority::Normal, legacy_item(10))
            .paused(44, 55, 66);
        assert_eq!(task.task_state(), Some(TaskState::Paused));
        assert_eq!(task.continuation_pc, 44);
        assert_eq!(task.continuation_data, 55);
        assert_eq!(task.resume_epoch, 66);
        assert_eq!(task.flags & TASK_FLAG_PAUSED, TASK_FLAG_PAUSED);
        assert!(!task.is_schedulable());

        let task = task.resumed().yielded(77, 88);
        assert_eq!(task.task_state(), Some(TaskState::Yielded));
        assert_eq!(task.yield_count, 1);
        assert_eq!(task.flags & TASK_FLAG_YIELDED, TASK_FLAG_YIELDED);
        assert!(task.is_schedulable());

        let task = task.requeued(99, 100, TaskPriority::Critical);
        assert_eq!(task.task_state(), Some(TaskState::Requeued));
        assert_eq!(task.task_priority(), Some(TaskPriority::Critical));
        assert_eq!(task.requeue_count, 1);
        assert_eq!(task.age_ticks, 1);
        assert_eq!(
            task.flags & TASK_FLAG_REQUEUE_REQUESTED,
            TASK_FLAG_REQUEUE_REQUESTED
        );
        assert!(task.is_schedulable());
    }

    #[test]
    fn snapshot_feeds_launch_request_from_schedulable_continuations() {
        let ready = TaskWorkItem::from_work_item(1, 0, TaskPriority::Normal, legacy_item(1));
        let paused = ready.paused(10, 20, 30);
        let yielded = ready.yielded(11, 21);
        let requeued =
            ready
                .requeued(12, 22, TaskPriority::High)
                .requeued(13, 23, TaskPriority::Critical);
        let done = ready.completed();

        let snapshot = TaskQueueSnapshot::from_tasks(&[ready, paused, yielded, requeued, done])
            .expect("Fix: valid task states must snapshot");
        assert_eq!(snapshot.ready_count, 1);
        assert_eq!(snapshot.paused_count, 1);
        assert_eq!(snapshot.yielded_count, 1);
        assert_eq!(snapshot.requeued_count, 1);
        assert_eq!(snapshot.schedulable_count(), 3);
        assert_eq!(snapshot.total_requeues, 2);
        assert_eq!(snapshot.max_priority_age, 2);

        let request =
            snapshot.apply_to_launch_request(MegakernelLaunchRequest::direct(99, 64, 256));
        assert_eq!(request.queue_len, 3);
        assert_eq!(request.requeue_count, 4);
        assert_eq!(request.max_priority_age, 2);
    }

    #[test]
    fn snapshot_rejects_unknown_state_word() {
        let mut task = TaskWorkItem::from_work_item(1, 0, TaskPriority::Normal, legacy_item(1));
        task.state = 99;

        let err =
            TaskQueueSnapshot::from_tasks(&[task]).expect_err("unknown ABI state word must reject");
        assert!(
            format!("{err}").contains("unknown state word 99"),
            "error must name the invalid state; got: {err}"
        );
    }
}

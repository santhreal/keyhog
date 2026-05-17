#![forbid(unsafe_code)]
#![deny(missing_docs)]

//! Shared megakernel dispatch contracts.

mod core;
mod policy;
mod task;
pub use crate::core::{
    default_worker_groups_from_limits, dispatch_grid_for, padded_slot_count, worker_workgroup_size,
    MegakernelCaps, MegakernelConfig, MegakernelGridLimits, MegakernelGridPlan,
    MegakernelGridRequest, MegakernelLaunchGeometry, MegakernelReport, MegakernelSizingPolicy,
    WorkItem,
};
pub use crate::policy::{
    MegakernelExecutionMode, MegakernelLaunchPolicy, MegakernelLaunchRecommendation,
    MegakernelLaunchRequest, MegakernelQueuePressure, PriorityRequeueAccounting,
};
pub use crate::task::{
    TaskPriority, TaskQueueSnapshot, TaskState, TaskWorkItem, TASK_FLAG_PAUSED,
    TASK_FLAG_REQUEUE_REQUESTED, TASK_FLAG_RESUME_READY, TASK_FLAG_YIELDED, TASK_SLOT_BYTES,
    TASK_SLOT_WORDS,
};
use vyre_driver::BackendError;

/// High-throughput persistent dispatch capability.
pub trait MegakernelDispatch {
    /// Executes a batch of work items on a persistent GPU kernel.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend cannot validate, compile, launch, or
    /// drain the requested megakernel dispatch.
    fn dispatch_megakernel(
        &self,
        work_queue: &[WorkItem],
        config: &MegakernelConfig,
    ) -> Result<MegakernelReport, BackendError>;
}

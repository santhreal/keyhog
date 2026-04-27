//! Occupancy-aware grid scaling for megakernels.
//!
//! Runtime code re-exports the driver-megakernel scheduling policy instead
//! of carrying a second partial copy.

pub use vyre_driver_megakernel::{
    default_worker_groups_from_limits, dispatch_grid_for, padded_slot_count, worker_workgroup_size,
    MegakernelExecutionMode, MegakernelGridLimits, MegakernelGridPlan, MegakernelGridRequest,
    MegakernelLaunchGeometry, MegakernelLaunchPolicy, MegakernelLaunchRecommendation,
    MegakernelLaunchRequest, MegakernelQueuePressure, MegakernelSizingPolicy,
    PriorityRequeueAccounting,
};

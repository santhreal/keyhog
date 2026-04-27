use std::time::Duration;
use vyre_driver::backend::BackendError;

use crate::policy::{
    MegakernelLaunchPolicy, MegakernelLaunchRecommendation, MegakernelLaunchRequest,
};
use crate::task::{TaskQueueSnapshot, TaskWorkItem};

mod sizing;

pub use sizing::MegakernelSizingPolicy;

/// Configuration for one megakernel dispatch invocation.
#[derive(Debug, Clone)]
pub struct MegakernelConfig {
    /// Number of persistent worker workgroups.
    pub worker_count: u32,
    /// Maximum wall-clock time the megakernel runs before draining
    /// queued work and exiting.
    pub max_wall_time: Duration,
    /// Hint to the scheduler about expected items per worker.
    pub expected_items_per_worker: u32,
}

impl Default for MegakernelConfig {
    fn default() -> Self {
        Self {
            worker_count: MegakernelSizingPolicy::standard().default_worker_count(),
            max_wall_time: Duration::from_secs(60),
            expected_items_per_worker: 0,
        }
    }
}

impl MegakernelConfig {
    /// Validate the config and surface actionable errors.
    ///
    /// # Errors
    ///
    /// Returns an error when the worker count is zero or the wall-clock budget
    /// is empty, because either condition would make persistent dispatch
    /// unschedulable.
    pub fn validate(&self) -> Result<(), BackendError> {
        if self.worker_count == 0 {
            return Err(BackendError::new(
                "megakernel worker_count must be non-zero. Fix: provide at least one worker workgroup.",
            ));
        }
        if self.max_wall_time.is_zero() {
            return Err(BackendError::new(
                "megakernel max_wall_time must be non-zero. Fix: supply a positive Duration budget.",
            ));
        }
        Ok(())
    }

    /// Compute the direct-dispatch grid for `queue_len` logical work slots.
    ///
    /// `worker_count` is the caller's persistent worker-workgroup ceiling; the
    /// returned grid never launches more workgroups than that ceiling or the
    /// backend occupancy cap.
    #[must_use]
    pub fn dispatch_grid(&self, queue_len: u32, max_workgroup_size_x: u32) -> [u32; 3] {
        dispatch_grid_for(self.worker_count, queue_len, max_workgroup_size_x)
    }

    /// Build a policy request from this config and adapter limits.
    #[must_use]
    pub const fn launch_request(
        &self,
        queue_len: u32,
        max_workgroup_size_x: u32,
        max_compute_workgroups_per_dimension: u32,
        max_compute_invocations_per_workgroup: u32,
    ) -> MegakernelLaunchRequest {
        MegakernelLaunchRequest {
            queue_len,
            requested_worker_groups: self.worker_count,
            max_workgroup_size_x,
            max_compute_workgroups_per_dimension,
            max_compute_invocations_per_workgroup,
            requested_hit_capacity: 0,
            expected_hits_per_item: if self.expected_items_per_worker > 1 {
                self.expected_items_per_worker
            } else {
                1
            },
            hot_opcode_count: 0,
            hot_window_count: 0,
            requeue_count: 0,
            max_priority_age: 0,
        }
    }

    /// Build a policy request from device-visible continuation task slots.
    ///
    /// Paused, completed, empty, running, and faulted tasks do not add launch
    /// lanes. Yielded and requeued tasks stay schedulable so the GPU can resume
    /// them without a CPU-side republish loop.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when a task slot contains an invalid state word.
    pub fn launch_request_for_tasks(
        &self,
        tasks: &[TaskWorkItem],
        max_workgroup_size_x: u32,
        max_compute_workgroups_per_dimension: u32,
        max_compute_invocations_per_workgroup: u32,
    ) -> Result<MegakernelLaunchRequest, BackendError> {
        let snapshot = TaskQueueSnapshot::from_tasks(tasks)?;
        Ok(snapshot.apply_to_launch_request(self.launch_request(
            snapshot.schedulable_count(),
            max_workgroup_size_x,
            max_compute_workgroups_per_dimension,
            max_compute_invocations_per_workgroup,
        )))
    }

    /// Recommend one launch shape through the shared megakernel policy.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when adapter limits are malformed.
    pub fn launch_recommendation(
        &self,
        queue_len: u32,
        max_workgroup_size_x: u32,
        max_compute_workgroups_per_dimension: u32,
        max_compute_invocations_per_workgroup: u32,
    ) -> Result<MegakernelLaunchRecommendation, BackendError> {
        MegakernelLaunchPolicy::standard().recommend(self.launch_request(
            queue_len,
            max_workgroup_size_x,
            max_compute_workgroups_per_dimension,
            max_compute_invocations_per_workgroup,
        ))
    }

    /// Recommend one launch shape for a continuation task queue.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when adapter limits are malformed or any task
    /// slot contains an invalid state word.
    pub fn launch_recommendation_for_tasks(
        &self,
        tasks: &[TaskWorkItem],
        max_workgroup_size_x: u32,
        max_compute_workgroups_per_dimension: u32,
        max_compute_invocations_per_workgroup: u32,
    ) -> Result<MegakernelLaunchRecommendation, BackendError> {
        MegakernelLaunchPolicy::standard().recommend(self.launch_request_for_tasks(
            tasks,
            max_workgroup_size_x,
            max_compute_workgroups_per_dimension,
            max_compute_invocations_per_workgroup,
        )?)
    }
}

/// Adapter limits that bound a megakernel worker-grid recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MegakernelGridLimits {
    /// Adapter maximum workgroup size in the x dimension.
    pub max_workgroup_size_x: u32,
    /// Adapter maximum compute workgroups per dimension.
    pub max_compute_workgroups_per_dimension: u32,
    /// Adapter maximum invocations per compute workgroup.
    pub max_compute_invocations_per_workgroup: u32,
}

impl MegakernelGridLimits {
    /// Construct megakernel grid limits from backend adapter limits.
    #[must_use]
    pub const fn new(
        max_workgroup_size_x: u32,
        max_compute_workgroups_per_dimension: u32,
        max_compute_invocations_per_workgroup: u32,
    ) -> Self {
        Self {
            max_workgroup_size_x,
            max_compute_workgroups_per_dimension,
            max_compute_invocations_per_workgroup,
        }
    }

    fn validate(self) -> Result<(), BackendError> {
        if self.max_workgroup_size_x == 0 {
            return Err(BackendError::new(
                "megakernel max_workgroup_size_x must be non-zero. Fix: pass live adapter limits instead of a zero limit.",
            ));
        }
        if self.max_compute_workgroups_per_dimension == 0 {
            return Err(BackendError::new(
                "megakernel max_compute_workgroups_per_dimension must be non-zero. Fix: pass live adapter limits instead of a zero limit.",
            ));
        }
        if self.max_compute_invocations_per_workgroup == 0 {
            return Err(BackendError::new(
                "megakernel max_compute_invocations_per_workgroup must be non-zero. Fix: pass live adapter limits instead of a zero limit.",
            ));
        }
        Ok(())
    }
}

/// Logical work shape requested for a megakernel worker-grid recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MegakernelGridRequest {
    /// Logical ring slots or work items queued for this launch.
    pub queue_len: u32,
    /// Caller-requested worker workgroup ceiling. Zero means derive from occupancy.
    pub requested_worker_groups: u32,
}

impl MegakernelGridRequest {
    /// Construct a worker-grid request.
    #[must_use]
    pub const fn new(queue_len: u32, requested_worker_groups: u32) -> Self {
        Self {
            queue_len,
            requested_worker_groups,
        }
    }
}

/// Resolved worker-grid plan shared by direct and policy-driven megakernel paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MegakernelGridPlan {
    /// Padded launch geometry for the ring protocol.
    pub geometry: MegakernelLaunchGeometry,
    /// Worker workgroups selected for the dispatch.
    pub worker_groups: u32,
}

impl MegakernelGridPlan {
    /// Resolve worker groups, workgroup width, slot padding, and dispatch grid.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when adapter limits are malformed.
    pub fn recommend(
        request: MegakernelGridRequest,
        limits: MegakernelGridLimits,
    ) -> Result<Self, BackendError> {
        MegakernelSizingPolicy::standard().calculate_optimal_grid(request, limits)
    }
}

/// Host-side launch geometry for a finite megakernel dispatch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MegakernelLaunchGeometry {
    /// Lanes per worker workgroup used to compile the program.
    pub workgroup_size_x: u32,
    /// Ring slots allocated for the dispatch, padded to a full workgroup.
    pub slot_count: u32,
    /// Grid submitted to the backend.
    pub dispatch_grid: [u32; 3],
}

impl MegakernelLaunchGeometry {
    /// Build geometry for `item_count` host work items.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when the host queue cannot be represented by
    /// the u32 ring protocol.
    pub fn from_item_count(
        item_count: usize,
        worker_count: u32,
        max_workgroup_size_x: u32,
    ) -> Result<Self, BackendError> {
        let item_count = u32::try_from(item_count).map_err(|_| {
            BackendError::new(
                "megakernel work queue length exceeds u32::MAX. Fix: shard the queue before dispatch.",
            )
        })?;
        let geometry = Self::from_slots(item_count, worker_count, max_workgroup_size_x);
        if geometry.slot_count < item_count {
            return Err(BackendError::new(
                "megakernel work queue cannot be padded inside the u32 ring protocol. Fix: shard the queue before dispatch.",
            ));
        }
        Ok(geometry)
    }

    /// Build geometry for an already-sized ring.
    #[must_use]
    pub fn from_slots(slot_count: u32, worker_count: u32, max_workgroup_size_x: u32) -> Self {
        MegakernelSizingPolicy::standard().geometry_from_slots(
            slot_count,
            worker_count,
            max_workgroup_size_x,
        )
    }

    /// Number of worker workgroups needed to cover every ring slot exactly once.
    #[must_use]
    pub const fn covering_worker_groups(&self) -> u32 {
        self.slot_count / self.workgroup_size_x
    }
}

/// Clamp the caller's worker setting into the legal x dimension used by the
/// current megakernel ABI.
#[must_use]
pub fn worker_workgroup_size(worker_count: u32, max_workgroup_size_x: u32) -> u32 {
    MegakernelSizingPolicy::standard().worker_workgroup_size(worker_count, max_workgroup_size_x)
}

/// Round a logical slot count up to a whole workgroup.
#[must_use]
pub fn padded_slot_count(slot_count: u32, workgroup_size_x: u32) -> u32 {
    MegakernelSizingPolicy::standard().padded_slot_count(slot_count, workgroup_size_x)
}

/// Compute the backend dispatch grid for a logical queue length.
#[must_use]
pub fn dispatch_grid_for(worker_count: u32, queue_len: u32, max_workgroup_size_x: u32) -> [u32; 3] {
    MegakernelSizingPolicy::standard().dispatch_grid_for(
        worker_count,
        queue_len,
        max_workgroup_size_x,
    )
}

/// Compute a persistent-worker ceiling from adapter limits.
///
/// This is the single host-side policy used by runtime batch dispatchers and
/// direct megakernel dispatch. Callers can still clamp further through
/// [`MegakernelConfig::worker_count`], but occupancy heuristics live here.
#[must_use]
pub fn default_worker_groups_from_limits(
    max_compute_workgroups_per_dimension: u32,
    max_compute_invocations_per_workgroup: u32,
) -> u32 {
    MegakernelSizingPolicy::standard().default_worker_groups_from_limits(
        max_compute_workgroups_per_dimension,
        max_compute_invocations_per_workgroup,
    )
}

/// Capabilities surfaced by megakernel-aware backends.
#[derive(Debug, Clone, Copy)]
pub struct MegakernelCaps {
    /// Whether the backend implements a megakernel path.
    pub supported: bool,
    /// Maximum worker-count ceiling the backend accepts.
    pub max_worker_count: u32,
}

impl MegakernelCaps {
    /// Unsupported — every method returns an explicit error.
    #[must_use]
    pub const fn unsupported() -> Self {
        Self {
            supported: false,
            max_worker_count: 0,
        }
    }

    /// Declare supported with the given worker ceiling.
    #[must_use]
    pub const fn supported(max_worker_count: u32) -> Self {
        Self {
            supported: true,
            max_worker_count,
        }
    }
}

/// One work-queue item the megakernel worker consumes.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, bytemuck::Pod, bytemuck::Zeroable)]
pub struct WorkItem {
    /// Stable op id index into the dialect registry.
    pub op_handle: u32,
    /// Input-buffer handle.
    pub input_handle: u32,
    /// Output-buffer handle.
    pub output_handle: u32,
    /// Optional per-item parameter word.
    pub param: u32,
}

/// Summary stats from one megakernel run.
#[derive(Debug, Clone, Default)]
pub struct MegakernelReport {
    /// Items the workers processed before exiting.
    pub items_processed: u64,
    /// Items still queued when `max_wall_time` fired.
    pub items_remaining: u64,
    /// Wall-clock time spent.
    pub wall_time: Duration,
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_foundation::execution_plan::SchedulingPolicy;

    #[test]
    fn launch_geometry_pads_slots_and_caps_grid_by_workers() {
        let geometry = MegakernelLaunchGeometry::from_slots(300, 64, 256);
        assert_eq!(geometry.workgroup_size_x, 64);
        assert_eq!(geometry.slot_count, 320);
        assert_eq!(geometry.covering_worker_groups(), 5);
        assert_eq!(geometry.dispatch_grid, [5, 1, 1]);
    }

    #[test]
    fn launch_geometry_preserves_legacy_worker_clamp() {
        let geometry = MegakernelLaunchGeometry::from_slots(1, 1_000, 256);
        assert_eq!(geometry.workgroup_size_x, 256);
        assert_eq!(geometry.slot_count, 256);
        assert_eq!(geometry.dispatch_grid, [1, 1, 1]);
    }

    #[test]
    fn dispatch_grid_keeps_worker_count_as_ceiling() {
        let config = MegakernelConfig {
            worker_count: 2,
            ..MegakernelConfig::default()
        };
        assert_eq!(config.dispatch_grid(4096, 64), [2, 1, 1]);
    }

    #[test]
    fn dispatch_grid_preserves_logical_queue_width_policy() {
        let config = MegakernelConfig {
            worker_count: 64,
            ..MegakernelConfig::default()
        };
        assert_eq!(config.dispatch_grid(300, 256), [2, 1, 1]);
    }

    #[test]
    fn megakernel_helpers_delegate_to_shared_scheduling_policy() {
        let policy = SchedulingPolicy::standard();
        assert_eq!(
            MegakernelConfig::default().worker_count,
            policy.default_worker_count()
        );
        assert_eq!(
            worker_workgroup_size(1_000, 256),
            policy.worker_workgroup_size(1_000, 256)
        );
        assert_eq!(
            padded_slot_count(300, 64),
            policy.padded_slot_count(300, 64)
        );
        assert_eq!(
            dispatch_grid_for(64, 300, 256),
            policy.dispatch_grid_for(64, 300, 256)
        );
        assert_eq!(
            default_worker_groups_from_limits(65_536, 4_096),
            policy.default_worker_groups_from_limits(65_536, 4_096)
        );
    }

    #[test]
    fn config_builds_launch_policy_from_continuation_task_queue() {
        let config = MegakernelConfig {
            worker_count: 64,
            expected_items_per_worker: 2,
            ..MegakernelConfig::default()
        };
        let item = WorkItem {
            op_handle: 10,
            input_handle: 11,
            output_handle: 12,
            param: 13,
        };
        let ready = TaskWorkItem::from_work_item(1, 0, crate::task::TaskPriority::Normal, item);
        let paused = ready.paused(20, 30, 40);
        let requeued = ready.requeued(50, 60, crate::task::TaskPriority::High);

        let request = config
            .launch_request_for_tasks(&[ready, paused, requeued], 256, 65_536, 1_024)
            .expect("Fix: valid continuation tasks must produce a launch request");
        assert_eq!(request.queue_len, 2);
        assert_eq!(request.expected_hits_per_item, 2);
        assert_eq!(request.requeue_count, 2);
        assert_eq!(request.max_priority_age, 1);

        let rec = config
            .launch_recommendation_for_tasks(&[ready, paused, requeued], 256, 65_536, 1_024)
            .expect("Fix: valid continuation tasks must produce a launch recommendation");
        assert_eq!(rec.geometry.workgroup_size_x, 64);
        assert!(rec.age_priority_work);
    }
}

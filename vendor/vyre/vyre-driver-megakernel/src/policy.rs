use vyre_driver::backend::BackendError;

use crate::core::{MegakernelGridLimits, MegakernelGridRequest, MegakernelLaunchGeometry};

/// Host-side pressure classification for one megakernel launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MegakernelQueuePressure {
    /// No logical slots are queued.
    Empty,
    /// The queue is below the available worker lanes.
    Light,
    /// The queue is large enough to keep the submitted workers occupied.
    Balanced,
    /// The queue is several waves deep or already showing requeue pressure.
    Saturated,
}

/// Interpreter/JIT route selected by the launch policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MegakernelExecutionMode {
    /// Use the generic opcode interpreter.
    Interpreter,
    /// Use a fused payload processor for hot windows or opcodes.
    Jit,
}

/// Inputs for one launch-policy recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MegakernelLaunchRequest {
    /// Logical ring slots or work items queued for this launch.
    pub queue_len: u32,
    /// Caller-requested worker workgroup ceiling. Zero means derive from occupancy.
    pub requested_worker_groups: u32,
    /// Adapter maximum workgroup size in the x dimension.
    pub max_workgroup_size_x: u32,
    /// Adapter maximum compute workgroups per dimension.
    pub max_compute_workgroups_per_dimension: u32,
    /// Adapter maximum invocations per compute workgroup.
    pub max_compute_invocations_per_workgroup: u32,
    /// Caller-requested sparse-hit capacity. Zero means derive from queue shape.
    pub requested_hit_capacity: u32,
    /// Expected sparse hits per queued item when deriving hit capacity.
    pub expected_hits_per_item: u32,
    /// Count of opcodes observed hot enough for promotion.
    pub hot_opcode_count: u32,
    /// Count of ticketed route windows observed hot enough for promotion.
    pub hot_window_count: u32,
    /// Slots requeued by priority scheduling since the last recommendation.
    pub requeue_count: u64,
    /// Maximum priority age observed since the last recommendation.
    pub max_priority_age: u32,
}

impl MegakernelLaunchRequest {
    /// Construct a direct-dispatch request with conservative defaults.
    #[must_use]
    pub const fn direct(
        queue_len: u32,
        requested_worker_groups: u32,
        max_workgroup_size_x: u32,
    ) -> Self {
        Self {
            queue_len,
            requested_worker_groups,
            max_workgroup_size_x,
            max_compute_workgroups_per_dimension: requested_worker_groups,
            max_compute_invocations_per_workgroup: max_workgroup_size_x,
            requested_hit_capacity: 0,
            expected_hits_per_item: 1,
            hot_opcode_count: 0,
            hot_window_count: 0,
            requeue_count: 0,
            max_priority_age: 0,
        }
    }
}

/// Policy output consumed by runtime dispatchers and batch builders.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MegakernelLaunchRecommendation {
    /// Padded launch geometry for the ring protocol.
    pub geometry: MegakernelLaunchGeometry,
    /// Worker workgroups selected for the dispatch.
    pub worker_groups: u32,
    /// Sparse-hit capacity selected for the dispatch.
    pub hit_capacity: u32,
    /// Queue pressure classification.
    pub pressure: MegakernelQueuePressure,
    /// Interpreter or JIT route selected from telemetry.
    pub execution_mode: MegakernelExecutionMode,
    /// True when hot opcode counters justify fused opcode promotion.
    pub promote_hot_opcodes: bool,
    /// True when ticketed route windows justify fused window promotion.
    pub promote_hot_windows: bool,
    /// True when aged/requeued priority work should be lifted on the next publish.
    pub age_priority_work: bool,
}

/// Requeue and aging counters produced by priority-aware schedulers.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PriorityRequeueAccounting {
    /// Number of slots requeued due to contention or quota pressure.
    pub requeue_count: u64,
    /// Number of slots promoted because their priority age crossed policy.
    pub aged_promotions: u64,
    /// Largest age observed for any queued priority slot.
    pub max_priority_age: u32,
}

impl PriorityRequeueAccounting {
    /// Record one requeue event.
    pub fn record_requeue(&mut self, age_ticks: u32) {
        self.requeue_count = self.requeue_count.saturating_add(1);
        self.max_priority_age = self.max_priority_age.max(age_ticks);
    }

    /// Record one priority-aging promotion.
    pub fn record_aged_promotion(&mut self, age_ticks: u32) {
        self.aged_promotions = self.aged_promotions.saturating_add(1);
        self.max_priority_age = self.max_priority_age.max(age_ticks);
    }
}

/// Single policy surface for megakernel launch sizing and telemetry-driven routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MegakernelLaunchPolicy {
    /// Sizing policy for worker counts and grid geometry.
    pub sizing: crate::core::MegakernelSizingPolicy,
    /// Minimum capacity for sparse-hit results.
    pub min_hit_capacity: u32,
    /// Multiplier for expected hits to determine capacity.
    pub hit_capacity_multiplier: u32,
    /// Number of waves that define a saturated queue.
    pub saturated_waves: u32,
    /// Threshold for promoting hot opcodes to JIT.
    pub hot_opcode_threshold: u32,
    /// Threshold for promoting hot windows to JIT.
    pub hot_window_threshold: u32,
    /// Queue length threshold to prefer JIT over interpreter.
    pub jit_queue_len_threshold: u32,
    /// Priority age threshold to trigger aging promotions.
    pub priority_age_threshold: u32,
}

impl Default for MegakernelLaunchPolicy {
    fn default() -> Self {
        Self::standard()
    }
}

impl MegakernelLaunchPolicy {
    /// Standard launch policy used by VYRE megakernel dispatchers.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            sizing: crate::core::MegakernelSizingPolicy::standard(),
            min_hit_capacity: 1024,
            hit_capacity_multiplier: 2,
            saturated_waves: 4,
            hot_opcode_threshold: 8,
            hot_window_threshold: 4,
            jit_queue_len_threshold: 4096,
            priority_age_threshold: 32,
        }
    }

    /// Recommend geometry, hit capacity, and interpreter/JIT route.
    ///
    /// # Errors
    ///
    /// Returns [`BackendError`] when required adapter limits are zero or derived
    /// launch values cannot fit the u32 ring protocol.
    pub fn recommend(
        &self,
        request: MegakernelLaunchRequest,
    ) -> Result<MegakernelLaunchRecommendation, BackendError> {
        let grid = self.sizing.calculate_optimal_grid(
            MegakernelGridRequest::new(request.queue_len, request.requested_worker_groups),
            MegakernelGridLimits::new(
                request.max_workgroup_size_x,
                request.max_compute_workgroups_per_dimension,
                request.max_compute_invocations_per_workgroup,
            ),
        )?;
        let geometry = grid.geometry;
        let worker_groups = grid.worker_groups;
        let lanes = u64::from(geometry.dispatch_grid[0])
            .saturating_mul(u64::from(geometry.workgroup_size_x));
        let pressure = classify_pressure(request.queue_len, lanes, request.requeue_count, self);
        let hit_capacity = self.hit_capacity_for(request);
        let promote_hot_opcodes = request.hot_opcode_count >= self.hot_opcode_threshold;
        let promote_hot_windows = request.hot_window_count >= self.hot_window_threshold;
        let execution_mode = if request.queue_len >= self.jit_queue_len_threshold
            || promote_hot_opcodes
            || promote_hot_windows
        {
            MegakernelExecutionMode::Jit
        } else {
            MegakernelExecutionMode::Interpreter
        };
        let age_priority_work =
            request.requeue_count > 0 || request.max_priority_age >= self.priority_age_threshold;

        Ok(MegakernelLaunchRecommendation {
            geometry,
            worker_groups,
            hit_capacity,
            pressure,
            execution_mode,
            promote_hot_opcodes,
            promote_hot_windows,
            age_priority_work,
        })
    }

    fn hit_capacity_for(&self, request: MegakernelLaunchRequest) -> u32 {
        if request.requested_hit_capacity != 0 {
            return request.requested_hit_capacity;
        }
        let expected_hits = request.expected_hits_per_item.max(1);
        request
            .queue_len
            .saturating_mul(expected_hits)
            .saturating_mul(self.hit_capacity_multiplier)
            .max(self.min_hit_capacity)
    }
}

fn classify_pressure(
    queue_len: u32,
    lanes: u64,
    requeue_count: u64,
    policy: &MegakernelLaunchPolicy,
) -> MegakernelQueuePressure {
    if queue_len == 0 {
        return MegakernelQueuePressure::Empty;
    }
    let lanes = lanes.max(1);
    let queue_len = u64::from(queue_len);
    if requeue_count > 0 || queue_len >= lanes.saturating_mul(u64::from(policy.saturated_waves)) {
        MegakernelQueuePressure::Saturated
    } else if queue_len >= lanes {
        MegakernelQueuePressure::Balanced
    } else {
        MegakernelQueuePressure::Light
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn policy_recommends_padded_geometry_and_hit_capacity() {
        let policy = MegakernelLaunchPolicy::standard();
        let rec = policy
            .recommend(MegakernelLaunchRequest {
                queue_len: 300,
                requested_worker_groups: 64,
                max_workgroup_size_x: 256,
                requested_hit_capacity: 0,
                expected_hits_per_item: 3,
                ..MegakernelLaunchRequest::direct(300, 64, 256)
            })
            .expect("Fix: policy should accept non-zero adapter limits");
        assert_eq!(rec.geometry.workgroup_size_x, 64);
        assert_eq!(rec.geometry.slot_count, 320);
        assert_eq!(rec.geometry.dispatch_grid, [5, 1, 1]);
        assert_eq!(rec.hit_capacity, 1800);
    }

    #[test]
    fn telemetry_pressure_selects_jit_and_priority_aging() {
        let policy = MegakernelLaunchPolicy::standard();
        let rec = policy
            .recommend(MegakernelLaunchRequest {
                queue_len: 8192,
                requested_worker_groups: 64,
                max_workgroup_size_x: 256,
                hot_opcode_count: 8,
                requeue_count: 1,
                max_priority_age: 64,
                ..MegakernelLaunchRequest::direct(8192, 64, 256)
            })
            .expect("Fix: policy should accept non-zero adapter limits");
        assert_eq!(rec.pressure, MegakernelQueuePressure::Saturated);
        assert_eq!(rec.execution_mode, MegakernelExecutionMode::Jit);
        assert!(rec.promote_hot_opcodes);
        assert!(rec.age_priority_work);
    }
}

//! Megakernel grid request, limits, plan cache, and recommendation surface.

use std::cell::RefCell;
use std::collections::VecDeque;

use rustc_hash::FxHashMap;
use vyre_driver::backend::BackendError;

use super::geometry::MegakernelLaunchGeometry;
use super::sizing::MegakernelSizingPolicy;

/// Adapter limits that bound a megakernel worker-grid recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MegakernelGridLimits {
    /// Adapter maximum workgroup size in the x dimension.
    pub max_workgroup_size_x: u32,
    /// Adapter maximum compute workgroups per dimension.
    pub max_compute_workgroups_per_dimension: u32,
    /// Adapter maximum invocations per compute workgroup.
    pub max_compute_invocations_per_workgroup: u32,
}

const GRID_PLAN_CACHE_CAP: usize = 128;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct GeometryCacheKey {
    slot_count: u32,
    worker_count: u32,
    max_workgroup_size_x: u32,
}

#[derive(Default)]
struct MegakernelPlannerCache {
    grid_plans: FxHashMap<(MegakernelGridRequest, MegakernelGridLimits), MegakernelGridPlan>,
    grid_order: VecDeque<(MegakernelGridRequest, MegakernelGridLimits)>,
    geometries: FxHashMap<GeometryCacheKey, MegakernelLaunchGeometry>,
    geometry_order: VecDeque<GeometryCacheKey>,
}

impl MegakernelPlannerCache {
    fn insert_grid_plan(
        &mut self,
        key: (MegakernelGridRequest, MegakernelGridLimits),
        value: MegakernelGridPlan,
    ) {
        if self.grid_plans.insert(key, value).is_none() {
            self.grid_order.push_back(key);
        }
        while self.grid_order.len() > GRID_PLAN_CACHE_CAP {
            if let Some(evicted) = self.grid_order.pop_front() {
                self.grid_plans.remove(&evicted);
            }
        }
    }

    fn insert_geometry(&mut self, key: GeometryCacheKey, value: MegakernelLaunchGeometry) {
        if self.geometries.insert(key, value).is_none() {
            self.geometry_order.push_back(key);
        }
        while self.geometry_order.len() > GRID_PLAN_CACHE_CAP {
            if let Some(evicted) = self.geometry_order.pop_front() {
                self.geometries.remove(&evicted);
            }
        }
    }
}

thread_local! {
    static PLANNER_CACHE: RefCell<MegakernelPlannerCache> = RefCell::new(MegakernelPlannerCache::default());
}

fn cached_grid_plan(
    request: MegakernelGridRequest,
    limits: MegakernelGridLimits,
) -> Result<MegakernelGridPlan, BackendError> {
    if let Some(plan) =
        PLANNER_CACHE.with(|cache| cache.borrow().grid_plans.get(&(request, limits)).copied())
    {
        return Ok(plan);
    }

    let plan = MegakernelSizingPolicy::standard().calculate_optimal_grid(request, limits)?;
    PLANNER_CACHE.with(|cache| {
        cache.borrow_mut().insert_grid_plan((request, limits), plan);
    });
    Ok(plan)
}

pub(super) fn cached_geometry_from_slots(
    slot_count: u32,
    worker_count: u32,
    max_workgroup_size_x: u32,
) -> MegakernelLaunchGeometry {
    let key = GeometryCacheKey {
        slot_count,
        worker_count,
        max_workgroup_size_x,
    };
    if let Some(geometry) = PLANNER_CACHE.with(|cache| cache.borrow().geometries.get(&key).copied())
    {
        return geometry;
    }

    let geometry = MegakernelSizingPolicy::standard().geometry_from_slots(
        slot_count,
        worker_count,
        max_workgroup_size_x,
    );
    PLANNER_CACHE.with(|cache| {
        cache.borrow_mut().insert_geometry(key, geometry);
    });
    geometry
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

    pub(super) fn validate(self) -> Result<(), BackendError> {
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
        cached_grid_plan(request, limits)
    }
}

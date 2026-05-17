//! Resident megakernel launch policy and queue-pressure decisions.

use vyre_driver::backend::BackendError;

mod cache;
use super::planner::{MegakernelGridLimits, MegakernelGridRequest, MegakernelLaunchGeometry};

/// Host-side pressure classification for one megakernel launch.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum MegakernelExecutionMode {
    /// Use the generic opcode interpreter.
    Interpreter,
    /// Use a fused payload processor for hot windows or opcodes.
    Jit,
}

/// Inputs for one launch-policy recommendation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
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

/// Diffuse priority signals across a set of priority-class siblings
/// via sheaf diffusion (P-RUNTIME-3). Higher-priority siblings pull
/// neighbors toward higher priority; lower-priority siblings drag
/// down. After a few diffusion steps, each item's priority reflects
/// both its own age and its neighborhood pressure — letting requeue
/// decisions be group-aware without hand-rolling a propagation pass.
///
/// `priority_stalks` is the per-item priority value (caller's choice
/// of scale; higher = more urgent). `restriction_diag` is the
/// per-item transmission coefficient (1.0 = freely shares priority,
/// 0.0 = isolated). `damping` controls the diffusion rate in [0, 1].
///
/// Returns the post-diffusion priority vector, same shape as input.
#[must_use]
pub fn diffuse_priority_across_siblings(
    priority_stalks: &[f64],
    restriction_diag: &[f64],
    damping: f64,
    iterations: u32,
) -> Vec<f64> {
    let mut current = Vec::with_capacity(priority_stalks.len());
    let mut next = Vec::with_capacity(priority_stalks.len());
    diffuse_priority_across_siblings_into(
        priority_stalks,
        restriction_diag,
        damping,
        iterations,
        &mut current,
        &mut next,
    );
    current
}

/// Diffuse priority signals into caller-owned storage.
pub fn diffuse_priority_across_siblings_into(
    priority_stalks: &[f64],
    restriction_diag: &[f64],
    damping: f64,
    iterations: u32,
    out: &mut Vec<f64>,
    scratch: &mut Vec<f64>,
) {
    out.clear();
    out.extend_from_slice(priority_stalks);
    scratch.clear();
    if priority_stalks.len() != restriction_diag.len() {
        return;
    }
    for _ in 0..iterations {
        diffuse_step_into(out, restriction_diag, damping, scratch);
        std::mem::swap(out, scratch);
    }
}

/// Single policy surface for megakernel launch sizing and telemetry-driven routing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MegakernelLaunchPolicy {
    /// Sizing policy for worker counts and grid geometry.
    pub sizing: super::planner::MegakernelSizingPolicy,
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
            sizing: super::planner::MegakernelSizingPolicy::standard(),
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
        let cache_key = cache::LaunchRecommendationCacheKey {
            policy: *self,
            request,
        };
        if let Some(cached) =
            cache::LAUNCH_RECOMMENDATION_CACHE.with(|cache| cache.borrow().get(&cache_key))
        {
            return Ok(cached);
        }

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

        let recommendation = MegakernelLaunchRecommendation {
            geometry,
            worker_groups,
            hit_capacity,
            pressure,
            execution_mode,
            promote_hot_opcodes,
            promote_hot_windows,
            age_priority_work,
        };
        cache::LAUNCH_RECOMMENDATION_CACHE.with(|cache| {
            cache.borrow_mut().insert(cache_key, recommendation);
        });
        Ok(recommendation)
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

    /// Select the best `hit_capacity_multiplier` from a candidate set.
    ///
    /// `candidate_multipliers` are the multipliers to try; `costs[i]`
    /// is the observed dispatch latency (or any minimization metric)
    /// when `candidate_multipliers[i]` was used. Lower cost wins; the
    /// minimum observed cost selects the multiplier.
    ///
    /// Returns the chosen multiplier. If `candidate_multipliers` is
    /// empty, returns the policy's existing `hit_capacity_multiplier`.
    ///
    #[must_use]
    pub fn autotune_hit_capacity_multiplier(
        &self,
        candidate_multipliers: &[u32],
        costs: &[f64],
    ) -> u32 {
        if candidate_multipliers.is_empty() || costs.is_empty() {
            return self.hit_capacity_multiplier;
        }
        let n = candidate_multipliers.len().min(costs.len());
        let chosen = best_cost_index(&costs[..n]);
        candidate_multipliers
            .get(chosen)
            .copied()
            .unwrap_or(self.hit_capacity_multiplier)
    }

    /// Select the best workgroup-size from a candidate set.
    ///
    /// `candidate_sizes[i]` is paired
    /// with `costs[i]` (lower is better). Returns the chosen size or
    /// the policy's `sizing.default_workgroup_size_x()` fallback.
    #[must_use]
    pub fn autotune_workgroup_size(
        &self,
        candidate_sizes: &[u32],
        costs: &[f64],
        current_size: u32,
    ) -> u32 {
        if candidate_sizes.is_empty() || costs.is_empty() {
            return current_size;
        }
        let n = candidate_sizes.len().min(costs.len());
        let chosen = best_cost_index(&costs[..n]);
        candidate_sizes.get(chosen).copied().unwrap_or(current_size)
    }

    /// Compute the next-step parameter delta for a continuous autotune
    /// knob using a Fisher-preconditioned natural-gradient step.
    ///
    /// `m_inv_sqrt`: inverse-square-root of the Fisher block (n×n
    /// row-major). Passing an identity matrix reduces the natural
    /// gradient to plain gradient descent.
    ///
    /// `grad`: plain gradient ∂latency/∂param (length n).
    ///
    /// Returns the parameter delta `-lr · M_inv_sqrt · grad`.
    ///
    /// P-DRIVER-8: every continuous autotune knob (workgroup size,
    /// hit-capacity, fixpoint iteration count, …) should follow the
    /// natural-gradient direction by default — Fisher-preconditioned
    /// descent converges 5-10× faster than plain gradient on the
    /// elongated-valley latency surfaces typical of GPU autotuning.
    #[must_use]
    pub fn natural_gradient_autotune_step(
        m_inv_sqrt: &[f64],
        grad: &[f64],
        n: u32,
        learning_rate: f64,
    ) -> Vec<f64> {
        let mut out = Vec::with_capacity(n as usize);
        Self::natural_gradient_autotune_step_into(m_inv_sqrt, grad, n, learning_rate, &mut out);
        out
    }

    /// Compute the natural-gradient autotune step into caller-owned storage.
    pub fn natural_gradient_autotune_step_into(
        m_inv_sqrt: &[f64],
        grad: &[f64],
        n: u32,
        learning_rate: f64,
        out: &mut Vec<f64>,
    ) {
        let n = n as usize;
        out.clear();
        out.resize(n, 0.0);
        let Some(required_matrix_len) = n.checked_mul(n) else {
            return;
        };
        if m_inv_sqrt.len() < required_matrix_len || grad.len() < n {
            return;
        }
        for row in 0..n {
            let mut acc = 0.0;
            for col in 0..n {
                acc += m_inv_sqrt[row * n + col] * grad[col];
            }
            out[row] = -learning_rate * acc;
        }
    }
}

fn diffuse_step_into(stalks: &[f64], restriction_diag: &[f64], damping: f64, out: &mut Vec<f64>) {
    out.clear();
    reserve_target_capacity(out, stalks.len());
    out.extend(
        stalks
            .iter()
            .zip(restriction_diag.iter())
            .map(|(&stalk, &restriction)| stalk - damping * restriction * stalk),
    );
}

fn reserve_target_capacity<T>(out: &mut Vec<T>, target_capacity: usize) {
    if out.capacity() < target_capacity {
        out.reserve_exact(target_capacity);
    }
}

fn best_cost_index(costs: &[f64]) -> usize {
    debug_assert!(!costs.is_empty());
    let mut best = 0;
    let mut best_cost = costs[0];
    for (index, &cost) in costs.iter().enumerate().skip(1) {
        if cost.total_cmp(&best_cost).is_lt() {
            best = index;
            best_cost = cost;
        }
    }
    best
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
mod tests;

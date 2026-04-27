//! Shared scheduling and launch-shape policy for execution backends.

/// Backend route category emitted by the shared scheduling policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum PolicyRoute {
    /// CPU SIMD path for tiny programs where GPU launch overhead dominates.
    CpuSimd,
    /// Standard compiled GPU pipeline.
    GpuPipeline,
    /// Persistent megakernel runtime for large sustained workloads.
    PersistentMegakernel,
}

/// Central contract for scheduling, routing, and launch-grid thresholds.
///
/// The values are private on purpose: callers ask policy questions instead of
/// copying numeric thresholds into each crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchedulingPolicy {
    persistent_runtime_node_max: usize,
    cpu_fast_path_node_max: usize,
    cpu_fast_path_static_bytes_below: u64,
    megakernel_node_count_above: usize,
    fused_over_dispatch_multiplier: u64,
    default_worker_count: u32,
    occupancy_worker_divisor: u32,
    max_dispatch_workgroups: u32,
    powerful_invocation_threshold: u32,
    powerful_min_worker_groups: u32,
}

impl Default for SchedulingPolicy {
    fn default() -> Self {
        Self::standard()
    }
}

impl SchedulingPolicy {
    /// Return the standard balanced policy used by vyre's built-in planners.
    #[must_use]
    pub const fn standard() -> Self {
        Self {
            persistent_runtime_node_max: 64,
            cpu_fast_path_node_max: 64,
            cpu_fast_path_static_bytes_below: 1 << 16,
            megakernel_node_count_above: 1024,
            fused_over_dispatch_multiplier: 4,
            default_worker_count: 64,
            occupancy_worker_divisor: 256,
            max_dispatch_workgroups: 1024,
            powerful_invocation_threshold: 4096,
            powerful_min_worker_groups: 64,
        }
    }

    /// Return true when a program should use persistent runtime dispatch.
    #[must_use]
    pub const fn use_persistent_runtime(&self, node_count: usize) -> bool {
        node_count <= self.persistent_runtime_node_max
    }

    /// Return true when dispatch-shape autotuning should measure variants.
    #[must_use]
    pub const fn recommend_autotune(&self, node_count: usize) -> bool {
        node_count > self.persistent_runtime_node_max
    }

    /// Route a plan represented by node count and static bytes.
    #[must_use]
    pub const fn route(&self, node_count: usize, static_bytes: u64) -> PolicyRoute {
        if self.use_cpu_fast_path(node_count, static_bytes) {
            PolicyRoute::CpuSimd
        } else if self.use_persistent_megakernel(node_count) {
            PolicyRoute::PersistentMegakernel
        } else {
            PolicyRoute::GpuPipeline
        }
    }

    /// Return true when a tiny static workload should stay on CPU SIMD.
    #[must_use]
    pub const fn use_cpu_fast_path(&self, node_count: usize, static_bytes: u64) -> bool {
        node_count <= self.cpu_fast_path_node_max
            && static_bytes < self.cpu_fast_path_static_bytes_below
    }

    /// Return true when the persistent megakernel is the preferred route.
    #[must_use]
    pub const fn use_persistent_megakernel(&self, node_count: usize) -> bool {
        node_count > self.megakernel_node_count_above
    }

    /// Return true when an axis-wise fused launch stays within policy.
    #[must_use]
    pub const fn allow_fused_threads(&self, fused_threads: u64, max_arm_threads: u64) -> bool {
        fused_threads <= max_arm_threads.saturating_mul(self.fused_over_dispatch_multiplier)
    }

    /// Multiplier used to reject pathological axis-wise fused launch shapes.
    #[must_use]
    pub const fn fused_over_dispatch_multiplier(&self) -> u64 {
        self.fused_over_dispatch_multiplier
    }

    /// Default persistent worker workgroup count.
    #[must_use]
    pub const fn default_worker_count(&self) -> u32 {
        self.default_worker_count
    }

    /// Clamp a requested worker count into the legal workgroup x dimension.
    #[must_use]
    pub const fn worker_workgroup_size(&self, worker_count: u32, max_workgroup_size_x: u32) -> u32 {
        let max_workgroup_size_x = if max_workgroup_size_x > 1 {
            max_workgroup_size_x
        } else {
            1
        };
        if worker_count == 0 {
            1
        } else if worker_count > max_workgroup_size_x {
            max_workgroup_size_x
        } else {
            worker_count
        }
    }

    /// Round a logical slot count up to a whole worker workgroup.
    #[must_use]
    pub const fn padded_slot_count(&self, slot_count: u32, workgroup_size_x: u32) -> u32 {
        let workgroup_size_x = if workgroup_size_x > 1 {
            workgroup_size_x
        } else {
            1
        };
        let groups = slot_count
            .saturating_add(workgroup_size_x - 1)
            .saturating_div(workgroup_size_x);
        let groups = if groups > 1 { groups } else { 1 };
        groups.saturating_mul(workgroup_size_x)
    }

    /// Compute the backend dispatch grid for a logical queue length.
    #[must_use]
    pub const fn dispatch_grid_for(
        &self,
        worker_count: u32,
        queue_len: u32,
        max_workgroup_size_x: u32,
    ) -> [u32; 3] {
        let workgroup_width = if max_workgroup_size_x > 1 {
            max_workgroup_size_x
        } else {
            1
        };
        let requested_workers = if worker_count > 1 { worker_count } else { 1 };
        let workgroups = queue_len
            .saturating_add(workgroup_width - 1)
            .saturating_div(workgroup_width);
        let workgroups = if workgroups > 1 { workgroups } else { 1 };
        let final_workgroups = min3(workgroups, requested_workers, self.max_dispatch_workgroups);
        [final_workgroups, 1, 1]
    }

    /// Compute a persistent-worker ceiling from adapter limits.
    #[must_use]
    pub const fn default_worker_groups_from_limits(
        &self,
        max_compute_workgroups_per_dimension: u32,
        max_compute_invocations_per_workgroup: u32,
    ) -> u32 {
        let occupancy_based = clamp_between(
            max_compute_workgroups_per_dimension / self.occupancy_worker_divisor,
            1,
            self.max_dispatch_workgroups,
        );
        let min_for_powerful =
            if max_compute_invocations_per_workgroup >= self.powerful_invocation_threshold {
                self.powerful_min_worker_groups
            } else {
                1
            };
        if occupancy_based > min_for_powerful {
            occupancy_based
        } else {
            min_for_powerful
        }
    }
}

const fn clamp_between(value: u32, min: u32, max: u32) -> u32 {
    if value < min {
        min
    } else if value > max {
        max
    } else {
        value
    }
}

const fn min3(a: u32, b: u32, c: u32) -> u32 {
    let ab = if a < b { a } else { b };
    if ab < c {
        ab
    } else {
        c
    }
}

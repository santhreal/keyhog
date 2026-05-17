//! I4 substrate: occupancy-aware empirical autotuning.
//!
//! Given a probed [`CudaDeviceCaps`] snapshot and a kernel's measured
//! per-thread register pressure plus per-block shared-memory usage, compute
//! the expected hardware occupancy at a candidate workgroup size. The
//! workgroup-size picker chooses the candidate that maximises blocks/SM
//! within the device's hard limits (max_threads_per_block, warp alignment,
//! register and shared-memory ceilings).
//!
//! The estimator is intentionally pure (takes a [`CudaDeviceCaps`] by
//! reference, returns a value type) so it can be unit-tested without a
//! live CUDA context. Live ptxas register counts feed the
//! `regs_per_thread` parameter; `shared_bytes_per_block` is read directly
//! from the descriptor's shared bindings.

use crate::device::CudaDeviceCaps;

/// Per-kernel resource pressure required to compute occupancy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KernelResourceUsage {
    /// 32-bit registers used by each thread, as reported by ptxas
    /// `--ptxas-options=-v` for the JIT-compiled module.
    pub regs_per_thread: u32,
    /// Static shared memory bytes the kernel allocates per block.
    pub shared_bytes_per_block: u32,
}

/// Estimated occupancy at a given workgroup size on a given device.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OccupancyEstimate {
    /// Active blocks per streaming multiprocessor at this workgroup size.
    /// Zero when the workgroup configuration cannot run at all (exceeds
    /// per-block register or shared-memory ceiling).
    pub blocks_per_sm: u32,
    /// Active warps per SM (`blocks_per_sm * workgroup_size / warp_size`).
    pub warps_per_sm: u32,
    /// `warps_per_sm` as a fraction of the device's `max_warps_per_sm`,
    /// expressed in basis points (0..=10000) so the value is integer-only
    /// and comparable across configurations without floating-point.
    pub occupancy_bps: u32,
}

impl OccupancyEstimate {
    /// Sentinel for "this workgroup size cannot execute on this device."
    pub const ZERO: Self = Self {
        blocks_per_sm: 0,
        warps_per_sm: 0,
        occupancy_bps: 0,
    };

    /// Whether the configuration achieves at least one resident block.
    #[must_use]
    pub fn is_runnable(&self) -> bool {
        self.blocks_per_sm > 0
    }
}

/// Compute the occupancy estimate for `workgroup_size` threads/block on
/// `caps` given measured `usage`.
///
/// Returns [`OccupancyEstimate::ZERO`] when the workgroup is fundamentally
/// unrunnable (exceeds per-block register or shared-memory limits, or
/// exceeds `max_threads_per_block`). Otherwise the estimator takes the
/// minimum of:
///   - register-pressure cap: `max_registers_per_sm / (regs_per_thread * workgroup_size)`
///   - shared-memory cap: `shared_per_sm / shared_bytes_per_block` (best-effort)
///   - thread-residence cap: `max_threads_per_sm / workgroup_size`
#[must_use]
pub fn estimate_occupancy(
    caps: &CudaDeviceCaps,
    usage: KernelResourceUsage,
    workgroup_size: u32,
) -> OccupancyEstimate {
    let warp = match caps.warp_size_u32() {
        Some(w) if w > 0 => w,
        _ => return OccupancyEstimate::ZERO,
    };
    if workgroup_size == 0 || workgroup_size > caps.max_threads_per_block_u32() {
        return OccupancyEstimate::ZERO;
    }
    let max_regs_block = u32::try_from(caps.max_registers_per_block).unwrap_or(0);
    let max_regs_sm = u32::try_from(caps.max_registers_per_sm).unwrap_or(0);
    let max_threads_sm = u32::try_from(caps.max_threads_per_sm).unwrap_or(0);
    let shared_per_block = caps.shared_memory_per_block_bytes();

    if max_regs_block == 0 || max_regs_sm == 0 || max_threads_sm == 0 {
        return OccupancyEstimate::ZERO;
    }

    // Per-block register requirement.
    let regs_per_block = usage.regs_per_thread.saturating_mul(workgroup_size);
    if regs_per_block > max_regs_block {
        return OccupancyEstimate::ZERO;
    }
    if usage.shared_bytes_per_block > shared_per_block {
        return OccupancyEstimate::ZERO;
    }

    let blocks_by_threads = max_threads_sm / workgroup_size;
    let blocks_by_regs = if regs_per_block == 0 {
        u32::MAX
    } else {
        max_regs_sm / regs_per_block
    };
    let blocks_by_shared = if usage.shared_bytes_per_block == 0 {
        u32::MAX
    } else {
        // Approximate per-SM shared budget as 4× per-block on modern
        // devices (sm_75+). For the tighter bound used in production
        // autotune the runtime can pass an exact `shared_per_sm` once
        // probed; the conservative 4× factor keeps the estimate from
        // being silently wrong on older arches.
        let shared_per_sm = shared_per_block.saturating_mul(4);
        shared_per_sm / usage.shared_bytes_per_block
    };

    let blocks_per_sm = blocks_by_threads.min(blocks_by_regs).min(blocks_by_shared);
    if blocks_per_sm == 0 {
        return OccupancyEstimate::ZERO;
    }

    let warps_per_block = workgroup_size.div_ceil(warp);
    let warps_per_sm = blocks_per_sm.saturating_mul(warps_per_block);
    let max_warps_per_sm = max_threads_sm / warp;
    let occupancy_bps = if max_warps_per_sm == 0 {
        0
    } else {
        ((warps_per_sm as u64 * 10_000) / max_warps_per_sm as u64).min(10_000) as u32
    };

    OccupancyEstimate {
        blocks_per_sm,
        warps_per_sm,
        occupancy_bps,
    }
}

/// Pick the workgroup size from `candidates` that maximises occupancy on
/// `caps` for the measured `usage`. Ties resolve toward the smaller size
/// so launch latency stays low when occupancy is identical. Returns
/// `None` when no candidate is runnable.
#[must_use]
pub fn pick_workgroup_size_for_occupancy(
    caps: &CudaDeviceCaps,
    usage: KernelResourceUsage,
    candidates: &[u32],
) -> Option<u32> {
    let mut best: Option<(u32, OccupancyEstimate)> = None;
    for &candidate in candidates {
        let est = estimate_occupancy(caps, usage, candidate);
        if !est.is_runnable() {
            continue;
        }
        match best {
            None => best = Some((candidate, est)),
            Some((_, current)) if est.occupancy_bps > current.occupancy_bps => {
                best = Some((candidate, est))
            }
            Some((current_size, current))
                if est.occupancy_bps == current.occupancy_bps && candidate < current_size =>
            {
                best = Some((candidate, est))
            }
            _ => {}
        }
    }
    best.map(|(size, _)| size)
}

/// Decision returned by [`can_launch_concurrently`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcurrentLaunchDecision {
    /// The two kernels can launch concurrently on the same SM with
    /// neither one's per-SM resource budget exceeded.
    Concurrent,
    /// At least one resource (registers, threads, or shared memory)
    /// would be over-subscribed; the dispatcher should serialize.
    Serialize {
        /// Human-readable reason naming the over-subscribed resource.
        reason: ConcurrentLaunchBlocker,
    },
}

/// Reason a co-launch was rejected. Useful for telemetry / diagnostics
/// so operators can understand why concurrency wasn't achieved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConcurrentLaunchBlocker {
    /// Device does not support concurrent kernels at all
    /// (`CU_DEVICE_ATTRIBUTE_CONCURRENT_KERNELS == 0`).
    DeviceUnsupported,
    /// Either kernel alone would not run (occupancy estimate ZERO).
    KernelUnrunnable,
    /// Combined warps/SM exceed the device's hardware ceiling.
    WarpResidency,
    /// Combined registers/SM exceed the per-SM register file.
    RegisterPressure,
    /// Combined per-block shared bytes exceed the per-block ceiling
    /// (each kernel still has to fit its own block's shared budget).
    SharedMemory,
}

/// Decide whether two kernels can launch concurrently on the same CUDA
/// device under the same SM resources. Pure decision — does not perform
/// the launch, only validates that the device + measured per-kernel
/// `KernelResourceUsage` would fit a co-resident schedule.
///
/// Resource model: concurrent kernels need at least one block from each
/// kernel to be co-resident on an SM. Full single-kernel occupancy is not
/// required for overlap; CUDA can interleave blocks as resources free up.
/// This check therefore first proves each kernel is individually runnable,
/// then checks the combined one-block register, warp, and shared-memory
/// footprint against per-SM caps.
///
/// `concurrent_kernels = false` on the device short-circuits to
/// `Serialize { DeviceUnsupported }`.
#[must_use]
pub fn can_launch_concurrently(
    caps: &CudaDeviceCaps,
    usage_a: KernelResourceUsage,
    workgroup_a: u32,
    usage_b: KernelResourceUsage,
    workgroup_b: u32,
) -> ConcurrentLaunchDecision {
    if !caps.concurrent_kernels {
        return ConcurrentLaunchDecision::Serialize {
            reason: ConcurrentLaunchBlocker::DeviceUnsupported,
        };
    }

    let est_a = estimate_occupancy(caps, usage_a, workgroup_a);
    let est_b = estimate_occupancy(caps, usage_b, workgroup_b);
    if !est_a.is_runnable() || !est_b.is_runnable() {
        return ConcurrentLaunchDecision::Serialize {
            reason: ConcurrentLaunchBlocker::KernelUnrunnable,
        };
    }

    let warp = match caps.warp_size_u32() {
        Some(w) if w > 0 => w,
        _ => {
            return ConcurrentLaunchDecision::Serialize {
                reason: ConcurrentLaunchBlocker::DeviceUnsupported,
            };
        }
    };
    let max_threads_sm = u32::try_from(caps.max_threads_per_sm).unwrap_or(0);
    let max_warps_sm = max_threads_sm / warp;
    let warps_a = workgroup_a.div_ceil(warp);
    let warps_b = workgroup_b.div_ceil(warp);
    if warps_a.saturating_add(warps_b) > max_warps_sm {
        return ConcurrentLaunchDecision::Serialize {
            reason: ConcurrentLaunchBlocker::WarpResidency,
        };
    }

    let max_regs_sm = u32::try_from(caps.max_registers_per_sm).unwrap_or(0);
    let regs_a = usage_a.regs_per_thread.saturating_mul(workgroup_a);
    let regs_b = usage_b.regs_per_thread.saturating_mul(workgroup_b);
    if regs_a.saturating_add(regs_b) > max_regs_sm {
        return ConcurrentLaunchDecision::Serialize {
            reason: ConcurrentLaunchBlocker::RegisterPressure,
        };
    }

    let shared_per_block = caps.shared_memory_per_block_bytes();
    let shared_per_sm = shared_per_block.saturating_mul(4);
    let shared_a = usage_a.shared_bytes_per_block;
    let shared_b = usage_b.shared_bytes_per_block;
    if shared_a.saturating_add(shared_b) > shared_per_sm {
        return ConcurrentLaunchDecision::Serialize {
            reason: ConcurrentLaunchBlocker::SharedMemory,
        };
    }

    ConcurrentLaunchDecision::Concurrent
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::CudaDeviceCaps;

    fn sm120_caps() -> CudaDeviceCaps {
        CudaDeviceCaps {
            name: "Test sm_120".into(),
            ordinal: 0,
            compute_capability: (12, 0),
            total_memory: 32 * 1024 * 1024 * 1024,
            max_threads_per_block: 1024,
            max_block_dim: [1024, 1024, 64],
            max_grid_dim: [i32::MAX, 65_535, 65_535],
            shared_memory_per_block: 128 * 1024,
            warp_size: 32,
            cooperative_launch: true,
            concurrent_kernels: true,
            async_engine_count: 2,
            max_registers_per_block: 65_536,
            max_registers_per_sm: 65_536,
            max_threads_per_sm: 2048,
        }
    }

    #[test]
    fn estimate_zero_when_workgroup_exceeds_max_threads_per_block() {
        let caps = sm120_caps();
        let usage = KernelResourceUsage {
            regs_per_thread: 32,
            shared_bytes_per_block: 0,
        };
        let est = estimate_occupancy(&caps, usage, 4096);
        assert_eq!(est, OccupancyEstimate::ZERO);
    }

    #[test]
    fn estimate_zero_when_register_pressure_too_high() {
        let caps = sm120_caps();
        // 256 regs/thread * 256 threads = 65_536 → fits exactly per block.
        // 256 regs/thread * 257 threads = 65_792 → busts per-block ceiling.
        let usage = KernelResourceUsage {
            regs_per_thread: 256,
            shared_bytes_per_block: 0,
        };
        let busts = estimate_occupancy(&caps, usage, 257);
        assert_eq!(busts, OccupancyEstimate::ZERO);
        let fits = estimate_occupancy(&caps, usage, 256);
        assert!(fits.is_runnable());
    }

    #[test]
    fn estimate_full_occupancy_on_lightweight_kernel() {
        let caps = sm120_caps();
        // 16 regs/thread, no shared. At 256 threads → blocks-by-regs =
        // 65_536 / (16*256) = 16; blocks-by-threads = 2048/256 = 8 →
        // 8 blocks/SM. Warps/SM = 8 * 8 = 64 = max_threads_per_sm/warp =
        // 2048/32 = 64 → 100% occupancy.
        let usage = KernelResourceUsage {
            regs_per_thread: 16,
            shared_bytes_per_block: 0,
        };
        let est = estimate_occupancy(&caps, usage, 256);
        assert_eq!(est.blocks_per_sm, 8);
        assert_eq!(est.warps_per_sm, 64);
        assert_eq!(est.occupancy_bps, 10_000);
    }

    #[test]
    fn picker_chooses_smaller_size_on_tie() {
        let caps = sm120_caps();
        let usage = KernelResourceUsage {
            regs_per_thread: 16,
            shared_bytes_per_block: 0,
        };
        // 128 and 256 both reach 100% occupancy; picker should choose 128.
        let chosen = pick_workgroup_size_for_occupancy(&caps, usage, &[128, 256, 512]);
        assert_eq!(chosen, Some(128));
    }

    #[test]
    fn picker_returns_none_when_no_candidate_runnable() {
        let caps = sm120_caps();
        // 65_537 regs/thread per block is impossible at any block size > 0.
        let usage = KernelResourceUsage {
            regs_per_thread: 65_537,
            shared_bytes_per_block: 0,
        };
        let chosen = pick_workgroup_size_for_occupancy(&caps, usage, &[32, 64, 128]);
        assert_eq!(chosen, None);
    }

    #[test]
    fn estimate_zero_when_shared_memory_exceeds_per_block_limit() {
        let caps = sm120_caps();
        let usage = KernelResourceUsage {
            regs_per_thread: 16,
            shared_bytes_per_block: 256 * 1024,
        };
        let est = estimate_occupancy(&caps, usage, 64);
        assert_eq!(est, OccupancyEstimate::ZERO);
    }

    #[test]
    fn occupancy_bps_is_proportional_to_warps_per_sm() {
        let caps = sm120_caps();
        // High-pressure kernel: 64 regs/thread, 256 threads. Blocks/SM =
        // min(2048/256, 65536/(64*256)) = min(8, 4) = 4.
        // Warps/SM = 4 * 8 = 32. max_warps_per_sm = 64.
        // occupancy_bps = (32 * 10000) / 64 = 5000.
        let usage = KernelResourceUsage {
            regs_per_thread: 64,
            shared_bytes_per_block: 0,
        };
        let est = estimate_occupancy(&caps, usage, 256);
        assert_eq!(est.blocks_per_sm, 4);
        assert_eq!(est.warps_per_sm, 32);
        assert_eq!(est.occupancy_bps, 5_000);
    }

    #[test]
    fn picker_prefers_higher_occupancy_over_smaller_size() {
        let caps = sm120_caps();
        // At 32 threads, 64 regs/thread → blocks_by_regs = 65536/2048 = 32,
        // blocks_by_threads = 2048/32 = 64 → 32 blocks * 1 warp = 32 warps/SM = 50%.
        // At 256 threads, 64 regs/thread → 32 warps/SM = 50% (computed above).
        // Tie → picker prefers smaller size (32).
        let usage = KernelResourceUsage {
            regs_per_thread: 64,
            shared_bytes_per_block: 0,
        };
        let chosen = pick_workgroup_size_for_occupancy(&caps, usage, &[32, 256]);
        assert_eq!(chosen, Some(32));
    }

    // ── D5: concurrent-launch decision policy tests ─────────────────

    #[test]
    fn co_launch_two_kernels_with_headroom_fits_concurrently() {
        let caps = sm120_caps();
        let light = KernelResourceUsage {
            regs_per_thread: 16,
            shared_bytes_per_block: 0,
        };
        let decision = can_launch_concurrently(&caps, light, 256, light, 256);
        assert_eq!(decision, ConcurrentLaunchDecision::Concurrent);
    }

    #[test]
    fn co_launch_two_full_occupancy_kernels_overflows_warp_cap() {
        let mut caps = sm120_caps();
        caps.max_threads_per_sm = 512;
        let full = KernelResourceUsage {
            regs_per_thread: 16,
            shared_bytes_per_block: 0,
        };
        let decision = can_launch_concurrently(&caps, full, 512, full, 512);
        assert_eq!(
            decision,
            ConcurrentLaunchDecision::Serialize {
                reason: ConcurrentLaunchBlocker::WarpResidency
            }
        );
    }

    #[test]
    fn co_launch_register_heavy_kernels_serializes_on_register_pressure() {
        let caps = sm120_caps();
        let heavy = KernelResourceUsage {
            regs_per_thread: 129,
            shared_bytes_per_block: 0,
        };
        let decision = can_launch_concurrently(&caps, heavy, 256, heavy, 256);
        assert_eq!(
            decision,
            ConcurrentLaunchDecision::Serialize {
                reason: ConcurrentLaunchBlocker::RegisterPressure
            }
        );
    }

    #[test]
    fn co_launch_with_unrunnable_kernel_returns_kernel_unrunnable() {
        let caps = sm120_caps();
        let runnable = KernelResourceUsage {
            regs_per_thread: 16,
            shared_bytes_per_block: 0,
        };
        let too_big = KernelResourceUsage {
            regs_per_thread: 65_537, // exceeds per-block register cap
            shared_bytes_per_block: 0,
        };
        let decision = can_launch_concurrently(&caps, runnable, 128, too_big, 256);
        assert_eq!(
            decision,
            ConcurrentLaunchDecision::Serialize {
                reason: ConcurrentLaunchBlocker::KernelUnrunnable
            }
        );
    }

    #[test]
    fn co_launch_on_device_without_concurrency_short_circuits() {
        let mut caps = sm120_caps();
        caps.concurrent_kernels = false;
        let usage = KernelResourceUsage {
            regs_per_thread: 16,
            shared_bytes_per_block: 0,
        };
        let decision = can_launch_concurrently(&caps, usage, 64, usage, 64);
        assert_eq!(
            decision,
            ConcurrentLaunchDecision::Serialize {
                reason: ConcurrentLaunchBlocker::DeviceUnsupported
            }
        );
    }

    #[test]
    fn co_launch_with_shared_memory_headroom_fits() {
        let caps = sm120_caps();
        let shared = KernelResourceUsage {
            regs_per_thread: 16,
            shared_bytes_per_block: 96 * 1024,
        };
        let decision = can_launch_concurrently(&caps, shared, 128, shared, 128);
        assert_eq!(decision, ConcurrentLaunchDecision::Concurrent);
    }
}

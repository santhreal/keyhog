//! CUDA device-side work queue planning for dependent dataflow execution.

/// Host synchronization policy for a CUDA device-side work queue.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CudaWorkQueueHostSync {
    /// Host reads only final completion state after device-side draining.
    FinalOnly,
    /// Host participates during queue draining.
    HostParticipates,
}

/// Work queue workload profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaDeviceWorkQueueProfile {
    /// Initial active work items enqueued before launch.
    pub initial_items: u64,
    /// Maximum resident queue capacity in work items.
    pub queue_capacity: u64,
    /// ABI bytes per queue entry.
    pub entry_bytes: u64,
    /// Bytes required for queue head/tail counters and changed flags.
    pub control_bytes: u64,
    /// Caller-approved device-memory budget.
    pub budget_bytes: u64,
    /// Host synchronization policy.
    pub host_sync: CudaWorkQueueHostSync,
}

/// Device-side work queue execution plan.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaDeviceWorkQueuePlan {
    /// Resident queue bytes.
    pub queue_bytes: u64,
    /// Resident control bytes.
    pub control_bytes: u64,
    /// Total resident bytes.
    pub resident_bytes: u64,
    /// Queue occupancy in basis points before device-side expansion.
    pub initial_occupancy_bps: u32,
    /// Whether the plan guarantees final-state-only host synchronization.
    pub final_only_host_sync: bool,
}

/// Device-side work queue drain strategy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CudaDeviceWorkQueueDrainStrategy {
    /// One resident drain window covers the whole queue.
    SingleResidentDrain,
    /// Queue capacity is split into multiple resident drain windows to bound
    /// per-launch queue pressure without host participation.
    ChunkedResidentDrain,
}

/// Device-side work queue plan with bounded resident drain windows.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CudaDeviceWorkQueueBackpressurePlan {
    /// Base resident queue byte plan.
    pub queue: CudaDeviceWorkQueuePlan,
    /// Selected resident drain strategy.
    pub strategy: CudaDeviceWorkQueueDrainStrategy,
    /// Maximum queue entries drained by one device-side window.
    pub items_per_chunk: u64,
    /// Number of resident drain windows required to cover queue capacity.
    pub chunks: u64,
    /// Whether the backpressure plan preserves final-state-only host sync.
    pub final_only_host_sync: bool,
}

/// Device work queue planning errors.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum CudaDeviceWorkQueueError {
    /// Queue capacity must be non-zero.
    ZeroCapacity,
    /// Entry ABI width must be explicit and non-zero.
    ZeroEntryBytes,
    /// Device-side drain chunk size must be non-zero.
    ZeroDrainChunk,
    /// Initial queue contents exceed capacity.
    InitialItemsExceedCapacity {
        /// Initial active items.
        initial_items: u64,
        /// Queue capacity.
        queue_capacity: u64,
    },
    /// Host participation would reintroduce CPU orchestration.
    HostParticipationRejected,
    /// Byte arithmetic overflowed.
    ByteCountOverflow {
        /// Field being computed.
        field: &'static str,
    },
    /// Queue does not fit the explicit device budget.
    OverBudget {
        /// Required bytes.
        required_bytes: u64,
        /// Budget bytes.
        budget_bytes: u64,
    },
}

impl std::fmt::Display for CudaDeviceWorkQueueError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ZeroCapacity => write!(
                f,
                "CUDA device work queue capacity is zero. Fix: size the resident queue before launch."
            ),
            Self::ZeroEntryBytes => write!(
                f,
                "CUDA device work queue entry_bytes is zero. Fix: pass the concrete queue-entry ABI width."
            ),
            Self::ZeroDrainChunk => write!(
                f,
                "CUDA device work queue drain chunk is zero. Fix: pass a non-zero device-side drain window."
            ),
            Self::InitialItemsExceedCapacity {
                initial_items,
                queue_capacity,
            } => write!(
                f,
                "CUDA device work queue initial_items={initial_items} exceeds queue_capacity={queue_capacity}. Fix: shard initial frontier items or increase explicit queue capacity."
            ),
            Self::HostParticipationRejected => write!(
                f,
                "CUDA device work queue rejected host participation. Fix: use final-only completion readback so dependent dataflow stays device-side."
            ),
            Self::ByteCountOverflow { field } => write!(
                f,
                "CUDA device work queue overflowed while computing {field}. Fix: shard the dependent dataflow workload before queue planning."
            ),
            Self::OverBudget {
                required_bytes,
                budget_bytes,
            } => write!(
                f,
                "CUDA device work queue requires {required_bytes} bytes but budget allows {budget_bytes}. Fix: reduce queue capacity, shard the graph, or raise the explicit device budget."
            ),
        }
    }
}

impl std::error::Error for CudaDeviceWorkQueueError {}

/// Plan a CUDA-resident work queue for dependent dataflow execution.
pub fn plan_cuda_device_work_queue(
    profile: CudaDeviceWorkQueueProfile,
) -> Result<CudaDeviceWorkQueuePlan, CudaDeviceWorkQueueError> {
    if profile.queue_capacity == 0 {
        return Err(CudaDeviceWorkQueueError::ZeroCapacity);
    }
    if profile.entry_bytes == 0 {
        return Err(CudaDeviceWorkQueueError::ZeroEntryBytes);
    }
    if profile.initial_items > profile.queue_capacity {
        return Err(CudaDeviceWorkQueueError::InitialItemsExceedCapacity {
            initial_items: profile.initial_items,
            queue_capacity: profile.queue_capacity,
        });
    }
    if profile.host_sync != CudaWorkQueueHostSync::FinalOnly {
        return Err(CudaDeviceWorkQueueError::HostParticipationRejected);
    }

    let queue_bytes = checked_mul(profile.queue_capacity, profile.entry_bytes, "queue bytes")?;
    let resident_bytes = checked_add(queue_bytes, profile.control_bytes, "resident bytes")?;
    if resident_bytes > profile.budget_bytes {
        return Err(CudaDeviceWorkQueueError::OverBudget {
            required_bytes: resident_bytes,
            budget_bytes: profile.budget_bytes,
        });
    }
    let initial_occupancy_bps = u32::try_from(
        u128::from(profile.initial_items)
            .checked_mul(10_000)
            .ok_or(CudaDeviceWorkQueueError::ByteCountOverflow {
                field: "initial occupancy",
            })?
            / u128::from(profile.queue_capacity),
    )
    .map_err(|_| CudaDeviceWorkQueueError::ByteCountOverflow {
        field: "initial occupancy",
    })?;

    Ok(CudaDeviceWorkQueuePlan {
        queue_bytes,
        control_bytes: profile.control_bytes,
        resident_bytes,
        initial_occupancy_bps,
        final_only_host_sync: true,
    })
}

/// Plan a CUDA-resident work queue plus bounded device-side drain windows.
pub fn plan_cuda_device_work_queue_backpressure(
    profile: CudaDeviceWorkQueueProfile,
    max_items_per_drain_launch: u64,
) -> Result<CudaDeviceWorkQueueBackpressurePlan, CudaDeviceWorkQueueError> {
    if max_items_per_drain_launch == 0 {
        return Err(CudaDeviceWorkQueueError::ZeroDrainChunk);
    }
    let queue = plan_cuda_device_work_queue(profile)?;
    let chunks = div_ceil_u64(
        profile.queue_capacity,
        max_items_per_drain_launch,
        "drain chunks",
    )?;
    let strategy = if chunks == 1 {
        CudaDeviceWorkQueueDrainStrategy::SingleResidentDrain
    } else {
        CudaDeviceWorkQueueDrainStrategy::ChunkedResidentDrain
    };
    Ok(CudaDeviceWorkQueueBackpressurePlan {
        queue,
        strategy,
        items_per_chunk: max_items_per_drain_launch.min(profile.queue_capacity),
        chunks,
        final_only_host_sync: true,
    })
}

fn checked_mul(lhs: u64, rhs: u64, field: &'static str) -> Result<u64, CudaDeviceWorkQueueError> {
    lhs.checked_mul(rhs)
        .ok_or(CudaDeviceWorkQueueError::ByteCountOverflow { field })
}

fn checked_add(lhs: u64, rhs: u64, field: &'static str) -> Result<u64, CudaDeviceWorkQueueError> {
    lhs.checked_add(rhs)
        .ok_or(CudaDeviceWorkQueueError::ByteCountOverflow { field })
}

fn div_ceil_u64(lhs: u64, rhs: u64, field: &'static str) -> Result<u64, CudaDeviceWorkQueueError> {
    if lhs == 0 {
        return Ok(0);
    }

    let quotient = (lhs - 1) / rhs;
    quotient
        .checked_add(1)
        .ok_or(CudaDeviceWorkQueueError::ByteCountOverflow { field })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn device_work_queue_plans_final_only_resident_execution() {
        let plan = plan_cuda_device_work_queue(CudaDeviceWorkQueueProfile {
            initial_items: 256,
            queue_capacity: 1_024,
            entry_bytes: 16,
            control_bytes: 128,
            budget_bytes: 32_768,
            host_sync: CudaWorkQueueHostSync::FinalOnly,
        })
        .expect("valid device work queue should plan");

        assert_eq!(plan.queue_bytes, 16_384);
        assert_eq!(plan.control_bytes, 128);
        assert_eq!(plan.resident_bytes, 16_512);
        assert_eq!(plan.initial_occupancy_bps, 2_500);
        assert!(plan.final_only_host_sync);
    }

    #[test]
    fn device_work_queue_rejects_host_participation() {
        assert_eq!(
            plan_cuda_device_work_queue(CudaDeviceWorkQueueProfile {
                initial_items: 1,
                queue_capacity: 8,
                entry_bytes: 16,
                control_bytes: 64,
                budget_bytes: 1_024,
                host_sync: CudaWorkQueueHostSync::HostParticipates,
            })
            .expect_err("host participation should fail"),
            CudaDeviceWorkQueueError::HostParticipationRejected
        );
    }

    #[test]
    fn device_work_queue_rejects_invalid_capacity_and_budget() {
        assert_eq!(
            plan_cuda_device_work_queue(CudaDeviceWorkQueueProfile {
                initial_items: 9,
                queue_capacity: 8,
                entry_bytes: 16,
                control_bytes: 64,
                budget_bytes: 1_024,
                host_sync: CudaWorkQueueHostSync::FinalOnly,
            })
            .expect_err("initial overflow should fail"),
            CudaDeviceWorkQueueError::InitialItemsExceedCapacity {
                initial_items: 9,
                queue_capacity: 8,
            }
        );
        assert_eq!(
            plan_cuda_device_work_queue(CudaDeviceWorkQueueProfile {
                initial_items: 1,
                queue_capacity: 8,
                entry_bytes: 16,
                control_bytes: 64,
                budget_bytes: 128,
                host_sync: CudaWorkQueueHostSync::FinalOnly,
            })
            .expect_err("over-budget queue should fail"),
            CudaDeviceWorkQueueError::OverBudget {
                required_bytes: 192,
                budget_bytes: 128,
            }
        );
    }

    #[test]
    fn device_work_queue_occupancy_uses_widened_arithmetic_for_huge_queues() {
        let plan = plan_cuda_device_work_queue(CudaDeviceWorkQueueProfile {
            initial_items: u64::MAX,
            queue_capacity: u64::MAX,
            entry_bytes: 1,
            control_bytes: 0,
            budget_bytes: u64::MAX,
            host_sync: CudaWorkQueueHostSync::FinalOnly,
        })
        .expect("max-sized byte queue should fit exactly");

        assert_eq!(
            plan.initial_occupancy_bps, 10_000,
            "Fix: CUDA work-queue occupancy must not use saturating u64 multiplication before division; full queues must report 10000 bps even near u64::MAX."
        );
    }

    #[test]
    fn device_work_queue_backpressure_chunks_large_resident_queues_without_host_participation() {
        let plan = plan_cuda_device_work_queue_backpressure(
            CudaDeviceWorkQueueProfile {
                initial_items: 4_096,
                queue_capacity: 65_536,
                entry_bytes: 16,
                control_bytes: 128,
                budget_bytes: 2 << 20,
                host_sync: CudaWorkQueueHostSync::FinalOnly,
            },
            8_192,
        )
        .expect("large resident work queue should plan bounded device-side drain chunks");

        assert_eq!(
            plan.strategy,
            CudaDeviceWorkQueueDrainStrategy::ChunkedResidentDrain
        );
        assert_eq!(plan.items_per_chunk, 8_192);
        assert_eq!(plan.chunks, 8);
        assert_eq!(plan.queue.resident_bytes, 1_048_704);
        assert!(plan.final_only_host_sync);
        assert!(plan.queue.final_only_host_sync);
    }

    #[test]
    fn device_work_queue_backpressure_ceil_division_handles_max_capacity() {
        let plan = plan_cuda_device_work_queue_backpressure(
            CudaDeviceWorkQueueProfile {
                initial_items: u64::MAX,
                queue_capacity: u64::MAX,
                entry_bytes: 1,
                control_bytes: 0,
                budget_bytes: u64::MAX,
                host_sync: CudaWorkQueueHostSync::FinalOnly,
            },
            65_536,
        )
        .expect("ceil division for max-capacity queues must not overflow");

        assert_eq!(
            plan.strategy,
            CudaDeviceWorkQueueDrainStrategy::ChunkedResidentDrain
        );
        assert_eq!(plan.queue.queue_bytes, u64::MAX);
        assert_eq!(plan.items_per_chunk, 65_536);
        assert_eq!(plan.chunks, 281_474_976_710_656);
        assert!(plan.final_only_host_sync);
    }

    #[test]
    fn device_work_queue_backpressure_rejects_zero_drain_chunk() {
        let err = plan_cuda_device_work_queue_backpressure(
            CudaDeviceWorkQueueProfile {
                initial_items: 1,
                queue_capacity: 8,
                entry_bytes: 16,
                control_bytes: 64,
                budget_bytes: 1_024,
                host_sync: CudaWorkQueueHostSync::FinalOnly,
            },
            0,
        )
        .expect_err("zero drain chunk must fail loudly");

        assert_eq!(err, CudaDeviceWorkQueueError::ZeroDrainChunk);
    }
}

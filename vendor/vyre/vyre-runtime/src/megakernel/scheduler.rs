//! Work scheduler — priority-aware slot scanning for the persistent megakernel.
//!
//! Extends the base slot-claim logic with priority partitioning:
//! each priority level occupies a contiguous partition of the ring buffer.
//! Workers scan from highest priority (0=CRITICAL) to lowest (4=IDLE),
//! claiming the first PUBLISHED slot found. This ensures latency-sensitive
//! work is processed before background tasks without true preemption.
//!
//! ## Slot Layout Extension
//!
//! The priority is encoded in `ring_buffer[slot_base + PRIORITY_WORD]`.
//! The host sets this when publishing; the scheduler reads it to
//! sort work into the right scan order.
//!
//! ## Starvation Guard
//!
//! After `STARVATION_THRESHOLD` consecutive high-priority claims, the
//! scheduler forcibly scans lower-priority partitions for one iteration.
//! This prevents priority inversion where a flood of CRITICAL slots
//! starves NORMAL/"background" work indefinitely.

use super::protocol::*;
use crate::PipelineError;
use vyre_foundation::ir::{Expr, Node};

fn atomic_load_relaxed(buffer: &str, index: Expr) -> Expr {
    Expr::atomic_add(buffer, index, Expr::u32(0))
}

fn atomic_store_relaxed(name: &str, buffer: &str, index: Expr, value: Expr) -> Node {
    Node::let_bind(name, Expr::atomic_exchange(buffer, index, value))
}

/// Number of priority levels the scheduler supports.
pub const PRIORITY_LEVELS: u32 = 5;

/// Priority discriminants.
pub mod priority {
    /// Highest priority — interactive/latency-critical work.
    pub const CRITICAL: u32 = 0;
    /// High priority — important but not latency-critical.
    pub const HIGH: u32 = 1;
    /// Normal priority — the default for all work.
    pub const NORMAL: u32 = 2;
    /// Low priority — background, non-urgent work.
    pub const LOW: u32 = 3;
    /// Idle priority — processed only when no other work exists.
    pub const IDLE: u32 = 4;
}

/// After this many consecutive claims at the same (or higher) priority,
/// the scheduler forcibly scans lower-priority partitions for one iteration.
pub const STARVATION_THRESHOLD: u32 = 16;

/// After this many claims by a single tenant in a single worker's "epoch",
/// the tenant is considered "greedy" and may be throttled.
pub const TENANT_FAIRNESS_THRESHOLD: u32 = 64;

/// Control word storing the priority partition offsets.
/// `control[PRIORITY_OFFSETS_BASE + pri]` = first slot index for priority `pri`.
/// `control[PRIORITY_OFFSETS_BASE + PRIORITY_LEVELS]` = total slot count (sentinel).
pub const PRIORITY_OFFSETS_BASE: u32 = control::PRIORITY_OFFSETS_BASE;

/// Control word storing consecutive high-priority claims.
pub const PRIORITY_STARVATION_COUNTER: u32 = control::PRIORITY_STARVATION_COUNTER;

/// Policy helper: select the next slot to probe within a partition.
///
/// Offsetting the start by `lane_id` reduces CAS contention on the first
/// few slots of a partition when many workers wake up simultaneously.
#[must_use]
pub fn policy_offset_start(partition_start: Expr, partition_end: Expr, lane_id: Expr) -> Expr {
    let range = Expr::sub(partition_end.clone(), partition_start.clone());
    Expr::add(partition_start, Expr::rem(lane_id, range))
}

/// Policy helper: check if a tenant has exceeded its fairness quota.
#[must_use]
pub fn check_tenant_fairness(tenant_id: Expr) -> Expr {
    let tenant_counter = Expr::rem(tenant_id, Expr::u32(control::TENANT_FAIRNESS_SLOTS));
    let count = atomic_load_relaxed(
        "control",
        Expr::add(Expr::u32(control::TENANT_FAIRNESS_BASE), tenant_counter),
    );
    Expr::lt(count, Expr::u32(TENANT_FAIRNESS_THRESHOLD))
}

/// Policy helper: check if a priority level has exceeded its fairness quota.
#[must_use]
pub fn check_priority_fairness(priority: Expr) -> Expr {
    let count = atomic_load_relaxed(
        "control",
        Expr::add(Expr::u32(control::PRIORITY_FAIRNESS_BASE), priority),
    );
    Expr::lt(count, Expr::u32(STARVATION_THRESHOLD))
}

/// Build the priority-aware scan loop as `Vec<Node>` for composition.
///
/// The scan checks priorities from `start_priority` to `PRIORITY_LEVELS - 1`.
/// For each priority level, it scans the corresponding ring partition
/// for a PUBLISHED slot. If found, claims it via CAS and yields
/// the slot base to the caller.
///
/// Variables set on success:
/// - `claimed_slot_base`: the slot_base of the claimed slot (u32::MAX if none found)
/// - `claimed_priority`: the priority level of the claimed slot
/// - `claimed_tenant`: the tenant id of the claimed slot
///
/// Requires `lane_id` and `workgroup_size_x` in scope.
#[must_use]
pub fn priority_scan_body(total_slots: u32) -> Vec<Node> {
    vec![
        // Initialize output: no slot claimed
        Node::let_bind("claimed_slot_base", Expr::u32(u32::MAX)),
        Node::let_bind("claimed_priority", Expr::u32(u32::MAX)),
        Node::let_bind("claimed_tenant", Expr::u32(u32::MAX)),
        Node::let_bind(
            "priority_starvation_count",
            atomic_load_relaxed("control", Expr::u32(PRIORITY_STARVATION_COUNTER)),
        ),
        Node::let_bind(
            "priority_force_lower",
            Expr::ge(
                Expr::var("priority_starvation_count"),
                Expr::u32(STARVATION_THRESHOLD),
            ),
        ),
        // Scan each priority level in order
        Node::loop_for(
            "scan_pri",
            Expr::u32(0),
            Expr::u32(PRIORITY_LEVELS),
            vec![
                // Skip if we already claimed a slot
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("claimed_slot_base"), Expr::u32(u32::MAX)),
                        Expr::or(
                            Expr::not(Expr::var("priority_force_lower")),
                            Expr::gt(Expr::var("scan_pri"), Expr::u32(priority::HIGH)),
                        ),
                    ),
                    vec![
                        // Load partition boundaries from control buffer
                        Node::let_bind(
                            "part_start",
                            atomic_load_relaxed(
                                "control",
                                Expr::add(Expr::u32(PRIORITY_OFFSETS_BASE), Expr::var("scan_pri")),
                            ),
                        ),
                        Node::let_bind(
                            "part_end",
                            atomic_load_relaxed(
                                "control",
                                Expr::add(
                                    Expr::u32(PRIORITY_OFFSETS_BASE),
                                    Expr::add(Expr::var("scan_pri"), Expr::u32(1)),
                                ),
                            ),
                        ),
                        // Scan slots within this priority partition
                        Node::loop_for(
                            "scan_idx",
                            Expr::u32(0),
                            Expr::sub(Expr::var("part_end"), Expr::var("part_start")),
                            vec![Node::if_then(
                                Expr::and(
                                    Expr::eq(Expr::var("claimed_slot_base"), Expr::u32(u32::MAX)),
                                    Expr::lt(
                                        Expr::add(Expr::var("part_start"), Expr::var("scan_idx")),
                                        Expr::u32(total_slots),
                                    ),
                                ),
                                vec![
                                    // Use policy to select slot: start at lane-dependent offset
                                    Node::let_bind(
                                        "scan_slot",
                                        Expr::add(
                                            Expr::var("part_start"),
                                            Expr::rem(
                                                Expr::add(
                                                    Expr::var("scan_idx"),
                                                    Expr::var("lane_id"),
                                                ),
                                                Expr::sub(
                                                    Expr::var("part_end"),
                                                    Expr::var("part_start"),
                                                ),
                                            ),
                                        ),
                                    ),
                                    Node::let_bind(
                                        "probe_base",
                                        Expr::mul(Expr::var("scan_slot"), Expr::u32(SLOT_WORDS)),
                                    ),
                                    // CAS status: PUBLISHED → CLAIMED
                                    Node::let_bind(
                                        "probe_status",
                                        atomic_load_relaxed("ring_buffer", Expr::var("probe_base")),
                                    ),
                                    Node::let_bind(
                                        "probe_schedulable",
                                        Expr::or(
                                            Expr::eq(
                                                Expr::var("probe_status"),
                                                Expr::u32(slot::PUBLISHED),
                                            ),
                                            Expr::or(
                                                Expr::eq(
                                                    Expr::var("probe_status"),
                                                    Expr::u32(slot::YIELD),
                                                ),
                                                Expr::eq(
                                                    Expr::var("probe_status"),
                                                    Expr::u32(slot::REQUEUE),
                                                ),
                                            ),
                                        ),
                                    ),
                                    Node::if_then(
                                        Expr::var("probe_schedulable"),
                                        vec![
                                            // Hierarchy Phase 2: Tenant Fairness Accounting
                                            Node::let_bind(
                                                "probe_tenant",
                                                Expr::load(
                                                    "ring_buffer",
                                                    Expr::add(
                                                        Expr::var("probe_base"),
                                                        Expr::u32(TENANT_WORD),
                                                    ),
                                                ),
                                            ),
                                            Node::let_bind(
                                                "tenant_fair",
                                                check_tenant_fairness(Expr::var("probe_tenant")),
                                            ),
                                            Node::if_then(
                                                Expr::var("tenant_fair"),
                                                vec![
                                                    Node::let_bind(
                                                        "probe_expected",
                                                        Expr::var("probe_status"),
                                                    ),
                                                    Node::let_bind(
                                                        "probe_prev",
                                                        Expr::atomic_compare_exchange(
                                                            "ring_buffer",
                                                            Expr::var("probe_base"),
                                                            Expr::var("probe_expected"),
                                                            Expr::u32(slot::CLAIMED),
                                                        ),
                                                    ),
                                                    Node::if_then(
                                                        Expr::eq(
                                                            Expr::var("probe_prev"),
                                                            Expr::var("probe_expected"),
                                                        ),
                                                        vec![
                                                            Node::assign(
                                                                "claimed_slot_base",
                                                                Expr::var("probe_base"),
                                                            ),
                                                            Node::assign(
                                                                "claimed_priority",
                                                                Expr::var("scan_pri"),
                                                            ),
                                                            Node::assign(
                                                                "claimed_tenant",
                                                                Expr::var("probe_tenant"),
                                                            ),
                                                        ],
                                                    ),
                                                ],
                                            ),
                                        ],
                                    ),
                                ],
                            )],
                        ),
                    ],
                ),
            ],
        ),
        // Post-claim: Update fairness accounting
        Node::if_then(
            Expr::ne(Expr::var("claimed_priority"), Expr::u32(u32::MAX)),
            vec![
                // Update priority starvation counter
                atomic_store_relaxed(
                    "priority_starvation_prev",
                    "control",
                    Expr::u32(PRIORITY_STARVATION_COUNTER),
                    Expr::select(
                        Expr::le(Expr::var("claimed_priority"), Expr::u32(priority::HIGH)),
                        Expr::add(Expr::var("priority_starvation_count"), Expr::u32(1)),
                        Expr::u32(0),
                    ),
                ),
                // Update per-tenant fairness counter
                Node::let_bind(
                    "tenant_fairness_prev",
                    Expr::atomic_add(
                        "control",
                        Expr::add(
                            Expr::u32(control::TENANT_FAIRNESS_BASE),
                            Expr::rem(
                                Expr::var("claimed_tenant"),
                                Expr::u32(control::TENANT_FAIRNESS_SLOTS),
                            ),
                        ),
                        Expr::u32(1),
                    ),
                ),
                // Update per-priority fairness counter (telemetry)
                Node::let_bind(
                    "priority_fairness_prev",
                    Expr::atomic_add(
                        "control",
                        Expr::add(
                            Expr::u32(control::PRIORITY_FAIRNESS_BASE),
                            Expr::var("claimed_priority"),
                        ),
                        Expr::u32(1),
                    ),
                ),
            ],
        ),
    ]
}

/// Encode default priority partition offsets for uniform distribution.
///
/// Each priority level gets `total_slots / PRIORITY_LEVELS` slots.
/// Any remainder goes to the NORMAL partition.
#[must_use]
pub fn default_priority_offsets(total_slots: u32) -> Vec<u32> {
    let base_per_pri = total_slots / PRIORITY_LEVELS;
    let remainder = total_slots % PRIORITY_LEVELS;
    let mut offsets = Vec::with_capacity(PRIORITY_LEVELS as usize + 1);
    let mut cursor = 0u32;
    for pri in 0..PRIORITY_LEVELS {
        offsets.push(cursor);
        let size = base_per_pri
            + if pri == priority::NORMAL {
                remainder
            } else {
                0
            };
        cursor += size;
    }
    offsets.push(cursor); // sentinel
    offsets
}

/// Write default priority partition offsets into an encoded control buffer.
///
/// # Errors
///
/// Returns [`PipelineError::QueueFull`] when the provided control buffer is too
/// short or not aligned to u32 words.
pub fn write_default_priority_offsets(
    control_bytes: &mut [u8],
    total_slots: u32,
) -> Result<(), PipelineError> {
    if control_bytes.len() % 4 != 0 {
        return Err(PipelineError::QueueFull {
            queue: "submission",
            fix: "control buffer byte length is not 4-byte aligned; rebuild it with Megakernel::encode_control",
        });
    }
    let offsets = default_priority_offsets(total_slots);
    for (i, value) in offsets.iter().enumerate() {
        let word_idx = PRIORITY_OFFSETS_BASE as usize + i;
        let start = word_idx.checked_mul(4).ok_or(PipelineError::QueueFull {
            queue: "submission",
            fix: "priority-offset byte index overflowed usize; keep control ABI constants bounded",
        })?;
        let end = start.checked_add(4).ok_or(PipelineError::QueueFull {
            queue: "submission",
            fix: "priority-offset byte index overflowed usize; keep control ABI constants bounded",
        })?;
        let dst = control_bytes.get_mut(start..end).ok_or(PipelineError::QueueFull {
            queue: "submission",
            fix: "control buffer is too small for priority partition offsets; rebuild it with Megakernel::encode_control",
        })?;
        dst.copy_from_slice(&value.to_le_bytes());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_offsets_cover_all_slots() {
        let offsets = default_priority_offsets(256);
        assert_eq!(offsets.len(), PRIORITY_LEVELS as usize + 1);
        assert_eq!(*offsets.last().unwrap(), 256);
        // Every partition has at least base_per_pri slots
        for i in 0..PRIORITY_LEVELS as usize {
            assert!(
                offsets[i + 1] > offsets[i],
                "empty partition at priority {i}"
            );
        }
    }

    #[test]
    fn offsets_with_small_count() {
        let offsets = default_priority_offsets(5);
        // 5 / 5 = 1 per partition
        assert_eq!(offsets, vec![0, 1, 2, 3, 4, 5]);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn priority_offsets_do_not_overlap_epoch() {
        assert!(
            PRIORITY_OFFSETS_BASE > control::EPOCH,
            "priority offsets must not overwrite the batch-fence epoch word"
        );
    }

    #[test]
    fn write_default_offsets_populates_control_buffer() {
        let mut control = crate::megakernel::Megakernel::try_encode_control(false, 1, 0).unwrap();
        write_default_priority_offsets(&mut control, 10).unwrap();
        let read = |word: u32| {
            let start = word as usize * 4;
            u32::from_le_bytes(control[start..start + 4].try_into().unwrap())
        };
        assert_eq!(read(PRIORITY_OFFSETS_BASE), 0);
        assert_eq!(read(PRIORITY_OFFSETS_BASE + PRIORITY_LEVELS), 10);
        assert_eq!(read(control::EPOCH), 0);
    }

    #[test]
    fn priority_scan_produces_valid_ir() {
        let nodes = priority_scan_body(256);
        assert!(
            nodes.len() >= 6,
            "priority scan must include claim outputs, starvation accounting, scan loop, and accounting writeback"
        );
    }
}

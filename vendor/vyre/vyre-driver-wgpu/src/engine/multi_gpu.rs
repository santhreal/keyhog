//! Mockable multi-GPU work partitioning and work-stealing decisions.
//!
//! This module intentionally owns host-side scheduling only. It does not probe
//! adapters or submit GPU work; tests can exercise the partitioner without
//! requiring hardware.
//!
//! ## Two allocation modes
//!
//! 1. **Batch + cost-aware** (`partition_work_stealing`): caller
//!    knows every work item + its cost up front; LPT greedy assigns
//!    the heaviest item to the least-loaded device.
//! 2. **Stream + content-addressed**
//!    (`shard_by_blake3` + `StreamShardAllocator`): caller yields
//!    `(key, cost)` pairs one at a time from a walker. The initial
//!    device is `blake3(key)[0] % n_gpus` for deterministic
//!    affinity — files with the same path always land on the same
//!    GPU across runs, which enables cache-warm re-scans. Overflow
//!    (queue on the target GPU is already loaded above threshold)
//!    spills to the least-loaded neighbor to keep tail latency
//!    bounded.

/// One pending unit of GPU work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkItem {
    /// Stable work identifier used by callers to map results back.
    pub id: usize,
    /// Relative cost estimate. Zero-cost work is rejected because it cannot
    /// contribute to a meaningful load balance.
    pub cost: u64,
}

/// Current mocked device load.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DeviceLoad {
    /// Device ordinal in the caller's adapter list.
    pub device_index: usize,
    /// Cost already queued on the device before this partitioning pass.
    pub queued_cost: u64,
}

/// Work assigned to one device.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Partition {
    /// Device ordinal receiving this partition.
    pub device_index: usize,
    /// Work item identifiers assigned to the device.
    pub item_ids: Vec<usize>,
    /// Total assigned cost including pre-existing queued cost.
    pub total_cost: u64,
}

/// Partition work by repeatedly assigning the largest remaining item to the
/// least-loaded device.
///
/// # Errors
///
/// Returns an actionable error when no devices are available, duplicate device
/// ordinals are supplied, or a work item has zero cost.
pub fn partition_work_stealing(
    devices: &[DeviceLoad],
    items: &[WorkItem],
) -> Result<Vec<Partition>, String> {
    validate_inputs(devices, items)?;
    let mut partitions = devices
        .iter()
        .map(|device| Partition {
            device_index: device.device_index,
            item_ids: Vec::new(),
            total_cost: device.queued_cost,
        })
        .collect::<Vec<_>>();

    let mut ordered = items.to_vec();
    ordered.sort_by(|left, right| {
        right
            .cost
            .cmp(&left.cost)
            .then_with(|| left.id.cmp(&right.id))
    });

    for item in ordered {
        let target = partitions
            .iter_mut()
            .min_by_key(|partition| (partition.total_cost, partition.device_index))
            .ok_or_else(|| {
                "partition target not found. Fix: validate non-empty device list before partitioning."
                    .to_string()
            })?;
        target.item_ids.push(item.id);
        target.total_cost = target.total_cost.checked_add(item.cost).ok_or_else(|| {
            "partition cost overflow. Fix: split the batch before multi-GPU scheduling.".to_string()
        })?;
    }
    Ok(partitions)
}

fn validate_inputs(devices: &[DeviceLoad], items: &[WorkItem]) -> Result<(), String> {
    if devices.is_empty() {
        return Err(
            "no GPU devices supplied. Fix: probe adapters before partitioning.".to_string(),
        );
    }
    let mut seen = rustc_hash::FxHashSet::default();
    for device in devices {
        if !seen.insert(device.device_index) {
            return Err(format!(
                "duplicate GPU device index {}. Fix: pass each adapter exactly once.",
                device.device_index
            ));
        }
    }
    for item in items {
        if item.cost == 0 {
            return Err(format!(
                "work item {} has zero cost. Fix: assign at least one cost unit or remove it.",
                item.id
            ));
        }
    }
    Ok(())
}

/// Deterministic content-addressed device pick.
///
/// Computes `blake3(key)` and maps the first 4 bytes (little-endian)
/// onto `[0, n_gpus)`. Callers use this as the initial landing
/// device; overflow handling lives in `StreamShardAllocator`.
///
/// `n_gpus == 0` returns `0` — callers that call with no devices
/// have a precondition bug, but we prefer to never panic on this
/// hot path.
#[must_use]
pub fn shard_by_blake3(key: &[u8], n_gpus: u32) -> u32 {
    if n_gpus == 0 {
        return 0;
    }
    let hash = blake3::hash(key);
    let bytes: [u8; 4] = hash.as_bytes()[..4]
        .try_into()
        .unwrap_or_else(|_| unreachable!("blake3 output is 32 bytes"));
    u32::from_le_bytes(bytes) % n_gpus
}

/// Streaming shard allocator. Callers feed `(key, cost)` pairs; the
/// allocator returns the target device plus a running snapshot of
/// per-device load.
///
/// Initial landing is `shard_by_blake3`. If the target device's
/// running cost exceeds the least-loaded device's cost by more than
/// `spill_threshold`, the item spills to the least-loaded device.
/// Spilling keeps tail latency bounded on adversarial streams where
/// hash-collision bias concentrates work on one GPU.
pub struct StreamShardAllocator {
    per_device_cost: Vec<u64>,
    n_gpus: u32,
    spill_threshold: u64,
}

impl StreamShardAllocator {
    /// Create an allocator for `n_gpus` devices with an initial
    /// zero-cost load vector.
    #[must_use]
    pub fn new(n_gpus: u32, spill_threshold: u64) -> Self {
        let gpus = n_gpus.max(1);
        Self {
            per_device_cost: vec![0u64; gpus as usize],
            n_gpus: gpus,
            spill_threshold,
        }
    }

    /// Inject pre-existing load (e.g., already-queued work).
    pub fn seed_load(&mut self, device: u32, cost: u64) {
        if let Some(slot) = self.per_device_cost.get_mut(device as usize) {
            *slot = slot.saturating_add(cost);
        }
    }

    /// Assign one item. Returns the chosen device index, or `None`
    /// if `cost` is zero (zero-cost items are rejected, matching
    /// the batch partitioner).
    pub fn assign(&mut self, key: &[u8], cost: u64) -> Option<u32> {
        if cost == 0 {
            return None;
        }
        let initial = shard_by_blake3(key, self.n_gpus) as usize;
        let initial_cost = self.per_device_cost[initial];

        // Identify the least-loaded device; ties break on the lower
        // index so the allocation is deterministic.
        let (least_idx, least_cost) = self
            .per_device_cost
            .iter()
            .copied()
            .enumerate()
            .min_by_key(|&(idx, cost)| (cost, idx))
            .unwrap_or_else(|| unreachable!("per_device_cost is non-empty"));

        let target =
            if initial_cost > least_cost && initial_cost - least_cost > self.spill_threshold {
                least_idx
            } else {
                initial
            };

        self.per_device_cost[target] = self.per_device_cost[target].saturating_add(cost);
        Some(target as u32)
    }

    /// Snapshot of per-device cost. Index = device id.
    #[must_use]
    pub fn load(&self) -> &[u64] {
        &self.per_device_cost
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn multi_gpu_partition_unit() {
        let devices = [
            DeviceLoad {
                device_index: 0,
                queued_cost: 0,
            },
            DeviceLoad {
                device_index: 1,
                queued_cost: 4,
            },
        ];
        let items = [
            WorkItem { id: 10, cost: 9 },
            WorkItem { id: 11, cost: 4 },
            WorkItem { id: 12, cost: 4 },
            WorkItem { id: 13, cost: 1 },
        ];

        let partitions = partition_work_stealing(&devices, &items)
            .expect("Fix: valid mocked devices must partition");
        let mut assigned = partitions
            .iter()
            .flat_map(|partition| partition.item_ids.iter().copied())
            .collect::<Vec<_>>();
        assigned.sort_unstable();

        assert_eq!(assigned, vec![10, 11, 12, 13]);
        let spread = partitions
            .iter()
            .map(|partition| partition.total_cost)
            .max()
            .zip(
                partitions
                    .iter()
                    .map(|partition| partition.total_cost)
                    .min(),
            )
            .map(|(max, min)| max - min)
            .expect("Fix: partitions must be non-empty");
        assert!(
            spread <= 5,
            "mocked work stealing left an avoidable load spread: {partitions:?}"
        );
    }

    #[test]
    fn rejects_duplicate_device_ordinals() {
        let devices = [
            DeviceLoad {
                device_index: 0,
                queued_cost: 0,
            },
            DeviceLoad {
                device_index: 0,
                queued_cost: 1,
            },
        ];

        let error = partition_work_stealing(&devices, &[WorkItem { id: 1, cost: 1 }])
            .expect_err("Fix: duplicate mocked devices must be rejected");
        assert!(error.contains("duplicate GPU device index"));
    }

    // ── Phase 11 — blake3 sharding + stream allocator ─────────────

    #[test]
    fn shard_by_blake3_is_deterministic() {
        let key = b"src/foo.rs";
        let a = shard_by_blake3(key, 4);
        let b = shard_by_blake3(key, 4);
        assert_eq!(a, b);
        assert!(a < 4);
    }

    #[test]
    fn shard_by_blake3_spreads_across_devices() {
        // Over a diverse input set, the distribution should cover
        // every device at least once.
        let keys: Vec<Vec<u8>> = (0..128)
            .map(|i| format!("src/file_{i}.rs").into_bytes())
            .collect();
        let mut hits = [0u32; 4];
        for k in &keys {
            hits[shard_by_blake3(k, 4) as usize] += 1;
        }
        for h in &hits {
            assert!(*h > 0, "blake3 sharding must hit every device: {hits:?}");
        }
    }

    #[test]
    fn shard_by_blake3_n_zero_defaults_to_zero() {
        assert_eq!(shard_by_blake3(b"anything", 0), 0);
    }

    #[test]
    fn stream_allocator_initial_placement_matches_hash() {
        let mut a = StreamShardAllocator::new(4, /* spill_threshold = */ 100);
        let key = b"cold/file.bin";
        let initial = shard_by_blake3(key, 4);
        let assigned = a.assign(key, 10).expect("non-zero cost accepted");
        assert_eq!(assigned, initial);
        assert_eq!(a.load()[initial as usize], 10);
    }

    #[test]
    fn stream_allocator_rejects_zero_cost() {
        let mut a = StreamShardAllocator::new(2, 0);
        assert!(a.assign(b"x", 0).is_none());
    }

    #[test]
    fn stream_allocator_spills_when_imbalance_exceeds_threshold() {
        // Craft a load imbalance and a key whose blake3 hashes to
        // the overloaded device — the allocator must spill.
        let mut a = StreamShardAllocator::new(2, /* spill_threshold = */ 5);
        // Find a key that hashes to device 0.
        let mut key = vec![0u8; 4];
        while shard_by_blake3(&key, 2) != 0 {
            key[0] = key[0].wrapping_add(1);
        }
        // Pre-load device 0 above threshold.
        a.seed_load(0, 100);

        // Without spilling, this would land on device 0. With the
        // spill_threshold=5 policy we must land on device 1.
        let target = a.assign(&key, 1).expect("assigned");
        assert_eq!(target, 1, "heavy initial must spill to least-loaded");
    }

    #[test]
    fn stream_allocator_stays_affine_under_threshold() {
        // If the imbalance is below the threshold, the allocator
        // must honor blake3 affinity — cache-warm paths don't spill.
        let mut a = StreamShardAllocator::new(2, /* spill_threshold = */ 100);
        let mut key = vec![0u8; 4];
        while shard_by_blake3(&key, 2) != 0 {
            key[0] = key[0].wrapping_add(1);
        }
        a.seed_load(0, 50); // imbalance 50 < threshold 100
        let target = a.assign(&key, 1).expect("assigned");
        assert_eq!(target, 0, "affinity wins when imbalance ≤ spill_threshold");
    }

    #[test]
    fn stream_allocator_load_monotone() {
        let mut a = StreamShardAllocator::new(3, 0);
        for i in 0..30 {
            let key = format!("path{i}").into_bytes();
            a.assign(&key, 1).expect("assigned");
        }
        let total: u64 = a.load().iter().sum();
        assert_eq!(total, 30, "every assignment must bump total load by cost");
    }
}

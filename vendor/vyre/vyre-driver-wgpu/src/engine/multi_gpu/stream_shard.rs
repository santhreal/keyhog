/// Deterministic content-addressed device pick.
///
/// Computes `blake3(key)` and maps the first 4 bytes (little-endian) onto
/// `[0, n_gpus)`. Callers use this as the initial landing device; overflow
/// handling lives in [`StreamShardAllocator`].
///
/// `n_gpus == 0` returns `0`. Callers that call with no devices have a
/// precondition bug, but this hot path does not panic.
#[must_use]
pub fn shard_by_blake3(key: &[u8], n_gpus: u32) -> u32 {
    if n_gpus == 0 {
        return 0;
    }
    let hash = blake3::hash(key);
    let bytes = hash.as_bytes();
    let bytes = [bytes[0], bytes[1], bytes[2], bytes[3]];
    u32::from_le_bytes(bytes) % n_gpus
}

/// Streaming shard allocator.
///
/// Callers feed `(key, cost)` pairs; the allocator returns the target device
/// plus a running snapshot of per-device load. Initial landing is
/// [`shard_by_blake3`]. If the target device's running cost exceeds the
/// least-loaded device's cost by more than `spill_threshold`, the item spills
/// to the least-loaded device.
pub struct StreamShardAllocator {
    per_device_cost: Vec<u64>,
    n_gpus: u32,
    spill_threshold: u64,
}

impl StreamShardAllocator {
    /// Create an allocator for `n_gpus` devices with an initial zero-cost load
    /// vector.
    #[must_use]
    pub fn new(n_gpus: u32, spill_threshold: u64) -> Self {
        let gpus = n_gpus.max(1);
        Self {
            per_device_cost: vec![0u64; gpus as usize],
            n_gpus: gpus,
            spill_threshold,
        }
    }

    /// Inject pre-existing load, such as already-queued work.
    pub fn seed_load(&mut self, device: u32, cost: u64) {
        if let Some(slot) = self.per_device_cost.get_mut(device as usize) {
            *slot = slot.saturating_add(cost);
        }
    }

    /// Assign one item.
    ///
    /// Returns the chosen device index, or `None` when `cost` is zero.
    pub fn assign(&mut self, key: &[u8], cost: u64) -> Option<u32> {
        if cost == 0 {
            return None;
        }
        let initial = shard_by_blake3(key, self.n_gpus) as usize;
        let initial_cost = self.per_device_cost[initial];

        let (least_idx, least_cost) = self
            .per_device_cost
            .iter()
            .copied()
            .enumerate()
            .min_by_key(|&(idx, cost)| (cost, idx))?;

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
    fn shard_by_blake3_is_deterministic() {
        let key = b"src/foo.rs";
        let a = shard_by_blake3(key, 4);
        let b = shard_by_blake3(key, 4);
        assert_eq!(a, b);
        assert!(a < 4);
    }

    #[test]
    fn shard_by_blake3_spreads_across_devices() {
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
        let mut allocator = StreamShardAllocator::new(4, 100);
        let key = b"cold/file.bin";
        let initial = shard_by_blake3(key, 4);
        let assigned = allocator
            .assign(key, 10)
            .expect("Fix: non-zero cost accepted; restore this invariant before continuing.");
        assert_eq!(assigned, initial);
        assert_eq!(allocator.load()[initial as usize], 10);
    }

    #[test]
    fn stream_allocator_rejects_zero_cost() {
        let mut allocator = StreamShardAllocator::new(2, 0);
        assert!(allocator.assign(b"x", 0).is_none());
    }

    #[test]
    fn stream_allocator_spills_when_imbalance_exceeds_threshold() {
        let mut allocator = StreamShardAllocator::new(2, 5);
        let mut key = vec![0u8; 4];
        while shard_by_blake3(&key, 2) != 0 {
            key[0] = key[0].wrapping_add(1);
        }
        allocator.seed_load(0, 100);

        let target = allocator
            .assign(&key, 1)
            .expect("Fix: assigned; restore this invariant before continuing.");
        assert_eq!(target, 1, "heavy initial must spill to least-loaded");
    }

    #[test]
    fn stream_allocator_stays_affine_under_threshold() {
        let mut allocator = StreamShardAllocator::new(2, 100);
        let mut key = vec![0u8; 4];
        while shard_by_blake3(&key, 2) != 0 {
            key[0] = key[0].wrapping_add(1);
        }
        allocator.seed_load(0, 50);
        let target = allocator
            .assign(&key, 1)
            .expect("Fix: assigned; restore this invariant before continuing.");
        assert_eq!(target, 0, "affinity wins when imbalance <= spill_threshold");
    }

    #[test]
    fn stream_allocator_load_monotone() {
        let mut allocator = StreamShardAllocator::new(3, 0);
        for i in 0..30 {
            let key = format!("path{i}").into_bytes();
            allocator
                .assign(&key, 1)
                .expect("Fix: assigned; restore this invariant before continuing.");
        }
        let total: u64 = allocator.load().iter().sum();
        assert_eq!(total, 30, "every assignment must bump total load by cost");
    }
}

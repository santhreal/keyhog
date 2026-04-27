//! Multi-GPU work stealing scheduler (Innovation I.7).
//!
//! Partitions a large Program or batch of Programs across all
//! registered physical devices.

use std::sync::Arc;
use vyre_driver::{VyreBackend, BackendError};

/// A unit of work assigned to one GPU.
pub struct Shard {
    pub backend_id: String,
    pub work_range: std::ops::Range<usize>,
}

/// Dynamic work-stealing scheduler.
pub struct WorkStealingScheduler {
    backends: Vec<Arc<dyn VyreBackend>>,
}

impl WorkStealingScheduler {
    pub fn new(backends: Vec<Arc<dyn VyreBackend>>) -> Self {
        Self { backends }
    }

    /// Partition a large haystack across available GPUs.
    pub fn partition(&self, total_len: usize) -> Vec<Shard> {
        let n = self.backends.len();
        if n == 0 { return Vec::new(); }

        let chunk_size = total_len / n;
        let mut shards = Vec::with_capacity(n);

        for i in 0..n {
            let start = i * chunk_size;
            let end = if i == n - 1 { total_len } else { (i + 1) * chunk_size };
            shards.push(Shard {
                backend_id: self.backends[i].id().to_string(),
                work_range: start..end,
            });
        }

        shards
    }
}

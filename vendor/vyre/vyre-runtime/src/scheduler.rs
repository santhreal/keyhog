//! Multi-GPU work stealing scheduler (Innovation I.7).
//!
//! Partitions a large Program or batch of Programs across all
//! registered physical devices.

use std::ops::Range;
use std::sync::atomic::AtomicUsize;
use std::sync::Arc;
use vyre_driver::VyreBackend;

/// A unit of work assigned to one GPU.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shard {
    /// Stable backend identifier for the GPU backend receiving this shard.
    pub backend_id: &'static str,
    /// Half-open byte/item range assigned to the backend.
    pub work_range: Range<usize>,
}

/// Dynamic work-stealing scheduler.
pub struct WorkStealingScheduler {
    backends: Vec<Arc<dyn VyreBackend>>,
    /// Atomic work index used by dispatch loops to let fast backends
    /// steal more fine-grained work units.
    #[allow(dead_code)]
    work_index: AtomicUsize,
}

impl WorkStealingScheduler {
    /// Create a scheduler over the live runtime backends available to the process.
    pub fn new(backends: Vec<Arc<dyn VyreBackend>>) -> Self {
        Self {
            backends,
            work_index: AtomicUsize::new(0),
        }
    }

    /// Partition a large haystack across available GPUs.
    pub fn partition(&self, total_len: usize) -> Vec<Shard> {
        let mut shards = Vec::new();
        self.partition_into(total_len, &mut shards);
        shards
    }

    /// Partition a large haystack into many fine-grained work units
    /// assigned round-robin to backends. A caller-side dispatch loop
    /// can use `work_index` to let worker threads atomically claim
    /// units so fast backends steal more work.
    pub fn partition_into(&self, total_len: usize, out: &mut Vec<Shard>) {
        let n = self.backends.len();
        out.clear();
        if n == 0 || total_len == 0 {
            return;
        }
        let work_unit_size = (total_len / (n * 4)).max(1);
        let num_units = (total_len + work_unit_size - 1) / work_unit_size;
        out.reserve(num_units);
        let mut start = 0;
        for i in 0..num_units {
            let end = (start + work_unit_size).min(total_len);
            out.push(Shard {
                backend_id: self.backends[i % n].id(),
                work_range: start..end,
            });
            start = end;
        }
    }
}

#[cfg(test)]
fn partition_ranges(total_len: usize, backend_count: usize) -> Vec<Range<usize>> {
    if backend_count == 0 || total_len == 0 {
        return Vec::new();
    }
    let work_unit_size = (total_len / (backend_count * 4)).max(1);
    let num_units = (total_len + work_unit_size - 1) / work_unit_size;
    let mut ranges = Vec::with_capacity(num_units);
    let mut start = 0;
    for _ in 0..num_units {
        let end = (start + work_unit_size).min(total_len);
        ranges.push(start..end);
        start = end;
    }
    ranges
}

#[cfg(test)]
mod tests {
    use super::{partition_ranges, WorkStealingScheduler};
    use std::sync::Arc;
    use vyre_driver::backend::{DispatchConfig, VyreBackend};
    use vyre_foundation::ir::Program;

    struct TestBackend(&'static str);

    impl vyre_driver::backend::private::Sealed for TestBackend {}

    impl VyreBackend for TestBackend {
        fn id(&self) -> &'static str {
            self.0
        }

        fn dispatch(
            &self,
            _program: &Program,
            _inputs: &[Vec<u8>],
            _config: &DispatchConfig,
        ) -> Result<Vec<Vec<u8>>, vyre_driver::BackendError> {
            Ok(Vec::new())
        }
    }

    #[test]
    fn partition_ranges_produces_fine_grained_units() {
        let ranges = partition_ranges(10, 3);
        assert_eq!(ranges.len(), 10);
        assert_eq!(ranges, vec![0..1, 1..2, 2..3, 3..4, 4..5, 5..6, 6..7, 7..8, 8..9, 9..10]);
    }

    #[test]
    fn partition_ranges_never_emits_empty_shards() {
        let ranges = partition_ranges(2, 8);
        assert_eq!(ranges, vec![0..1, 1..2]);
    }

    #[test]
    fn scheduler_partition_into_reuses_output_storage() {
        let scheduler = WorkStealingScheduler::new(vec![
            Arc::new(TestBackend("a")),
            Arc::new(TestBackend("b")),
            Arc::new(TestBackend("c")),
        ]);
        let mut shards = Vec::with_capacity(10);

        scheduler.partition_into(10, &mut shards);
        let ptr = shards.as_ptr();
        scheduler.partition_into(10, &mut shards);

        assert_eq!(shards.as_ptr(), ptr);
        assert_eq!(shards.len(), 10);
        assert_eq!(shards[0].backend_id, "a");
        assert_eq!(shards[0].work_range, 0..1);
        assert_eq!(shards[1].backend_id, "b");
        assert_eq!(shards[1].work_range, 1..2);
        assert_eq!(shards[9].backend_id, "a");
        assert_eq!(shards[9].work_range, 9..10);
        assert_eq!(scheduler.work_index.load(std::sync::atomic::Ordering::Relaxed), 0);
    }
}

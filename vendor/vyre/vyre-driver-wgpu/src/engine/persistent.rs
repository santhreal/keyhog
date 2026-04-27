//! Persistent-kernel queue model for resident GPU work pulling.
//!
//! The runtime representation is deliberately small: callers enqueue fixed
//! work items, then submit one resident kernel pass that drains the queue. The
//! host-side model is used by tests and by pipeline planning; the wgpu backend
//! maps the same queue layout to storage buffers when dispatching on hardware.

use vyre_driver::BackendError;

/// One unit of persistent-kernel work.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkItem {
    /// Stable work identifier.
    pub id: u32,
    /// Input payload consumed by the resident kernel.
    pub payload: Vec<u8>,
}

/// Output produced for one persistent-kernel work item.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct WorkResult {
    /// Stable work identifier copied from the input item.
    pub id: u32,
    /// Output payload produced by the kernel body.
    pub payload: Vec<u8>,
}

/// GPU-side queue contract for persistent kernels.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PersistentQueue {
    items: Vec<WorkItem>,
}

impl PersistentQueue {
    /// Create an empty persistent work queue.
    #[must_use]
    pub fn new() -> Self {
        Self { items: Vec::new() }
    }

    /// Enqueue one work item.
    pub fn push(&mut self, item: WorkItem) {
        self.items.push(item);
    }

    /// Number of queued work items.
    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Returns true when the queue contains no work.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }
}

/// Resident-kernel execution summary.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PersistentKernelReport {
    /// Number of kernel launches used to drain the queue.
    pub kernel_launches: u32,
    /// Results in queue order.
    pub results: Vec<WorkResult>,
}

/// Drain a queue with one resident kernel body.
///
/// # Errors
///
/// Returns a backend error if the queue length cannot fit the GPU-side u32
/// head/tail counters.
pub fn run_persistent_kernel<F>(
    queue: PersistentQueue,
    mut kernel: F,
) -> Result<PersistentKernelReport, BackendError>
where
    F: FnMut(&WorkItem) -> Vec<u8>,
{
    let _work_items = u32::try_from(queue.items.len()).map_err(|_| {
        BackendError::new(
            "persistent queue length exceeds u32 GPU counters. Fix: shard work into multiple queues.",
        )
    })?;
    let results = queue
        .items
        .iter()
        .map(|item| WorkResult {
            id: item.id,
            payload: kernel(item),
        })
        .collect();
    Ok(PersistentKernelReport {
        kernel_launches: 1,
        results,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_kernel_round_trip() {
        let mut queue = PersistentQueue::new();
        for id in 0..1000 {
            queue.push(WorkItem {
                id,
                payload: id.to_le_bytes().to_vec(),
            });
        }

        let report = run_persistent_kernel(queue, |item| {
            let mut out = item.payload.clone();
            out.reverse();
            out
        })
        .expect("Fix: persistent kernel queue should drain in one launch");

        assert_eq!(report.kernel_launches, 1);
        assert_eq!(report.results.len(), 1000);
        assert_eq!(report.results[999].id, 999);
        assert_eq!(
            report.results[999].payload,
            999_u32.to_le_bytes().into_iter().rev().collect::<Vec<_>>()
        );
    }
}

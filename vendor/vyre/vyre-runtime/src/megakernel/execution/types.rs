use vyre_driver::backend::Resource;

/// Per-dispatch host-side runtime instrumentation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MegakernelDispatchStats {
    /// Bytes supplied to the backend across control, ring, debug, and IO buffers.
    pub input_bytes: u64,
    /// Bytes returned by the backend across all output buffers.
    pub output_bytes: u64,
    /// Host-observed dispatch latency in nanoseconds.
    pub latency_ns: u64,
    /// Number of output buffers returned by the backend.
    pub output_buffers: u32,
    /// True when the first dispatch failed with device-loss symptoms and the
    /// runtime rebuilt the compiled pipeline before retrying.
    pub recovered_after_device_loss: bool,
}

impl MegakernelDispatchStats {
    /// Throughput over returned output bytes in bytes per second.
    #[must_use]
    pub fn output_bytes_per_second(&self) -> u64 {
        if self.latency_ns == 0 {
            return 0;
        }
        self.output_bytes
            .saturating_mul(1_000_000_000)
            .saturating_div(self.latency_ns)
    }
}

/// Backend outputs paired with host-side dispatch instrumentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MegakernelDispatchOutput {
    /// Backend output buffers.
    pub buffers: Vec<Vec<u8>>,
    /// Host-side dispatch instrumentation.
    pub stats: MegakernelDispatchStats,
}

/// Backend outputs for a resident-handle batch plus aggregate host-side
/// instrumentation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MegakernelBatchDispatchOutput {
    /// One output-buffer set per submitted resident handle tuple.
    pub batches: Vec<Vec<Vec<u8>>>,
    /// Aggregate host-side dispatch instrumentation for the whole batch.
    pub stats: MegakernelDispatchStats,
}

/// GPU-resident buffer handles for the four-buffer megakernel ABI.
///
/// Backends that implement persistent handles can keep control, ring, debug,
/// and IO queue buffers resident across launches. Runtime callers use this
/// type when a host byte mirror would force avoidable copies on the hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MegakernelResidentHandles {
    /// Resident control-buffer handle.
    pub control: u64,
    /// Resident ring-buffer handle.
    pub ring: u64,
    /// Resident debug-log buffer handle.
    pub debug_log: u64,
    /// Resident IO-queue buffer handle.
    pub io_queue: u64,
}

impl MegakernelResidentHandles {
    /// Construct resident handles in megakernel ABI binding order.
    #[must_use]
    pub const fn new(control: u64, ring: u64, debug_log: u64, io_queue: u64) -> Self {
        Self {
            control,
            ring,
            debug_log,
            io_queue,
        }
    }

    pub(super) fn resources(self) -> [Resource; 4] {
        [
            Resource::Resident(self.control),
            Resource::Resident(self.ring),
            Resource::Resident(self.debug_log),
            Resource::Resident(self.io_queue),
        ]
    }
}

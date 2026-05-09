//! # vyre-runtime — persistent megakernel + io_uring zero-copy
//!
//! This crate provides the execution runtime for vyre — the layer
//! between "I have a compiled Program" and "bytes flow through the
//! GPU continuously."
//!
//! ## Architecture
//!
//! 1. **`megakernel`** — the persistent GPU process. A vyre `Program`
//!    wrapping `Node::forever` that loops a ring-buffer interpreter
//!    or a JIT-fused payload processor.
//!    - `protocol` — slot layout, control words, opcodes
//!    - `opcode` — built-in opcode handlers + extension mechanism
//!    - `builder` — IR `Program` construction (interpreted + JIT)
//! 2. **`cache`** — content-addressed compilation cache.
//! 3. **`stream`** — `GpuStream` glue bridging io_uring completions
//!    to the megakernel tail pointer.
//! 4. **`uring`** (Linux only) — raw `io_uring` syscall wrappers.
//!
//! ## Design laws
//!
//! - **No CPU executor on the hot path.** Compatibility ingest may submit
//!   registered mapped reads, but the native path is NVMe passthrough into
//!   BAR1 GPU memory; after launch the megakernel owns execution and the CPU
//!   only touches queue metadata.
//! - **Megakernel is IR, not WGSL.** The persistent kernel is a
//!   `Program` any `VyreBackend` can compile + dispatch.
//! - **Structured errors, never silent swallowing.** Every failure
//!   mode returns `PipelineError` with a `Fix: ` hint.

#![deny(missing_docs)]
#![warn(unreachable_pub)]

/// Errors surfaced by the runtime layer. Every variant carries a
/// `Fix:`-bearing message so a reviewer can act on the failure.
#[derive(Debug, Clone, thiserror::Error)]
#[non_exhaustive]
pub enum PipelineError {
    /// Raw io_uring / libc syscall failed with an errno.
    #[error("io_uring {syscall} failed: errno={errno}. Fix: {fix}")]
    IoUringSyscall {
        /// Which syscall failed (`io_uring_setup`, `mmap`, `io_uring_enter`).
        syscall: &'static str,
        /// Underlying errno value.
        errno: i32,
        /// Actionable remediation.
        fix: &'static str,
    },
    /// io_uring submission or completion queue was full / overflowed.
    #[error("io_uring {queue} queue at capacity. Fix: {fix}")]
    QueueFull {
        /// "submission" or "completion".
        queue: &'static str,
        /// Actionable remediation.
        fix: &'static str,
    },
    /// Attempted to use io_uring on a non-Linux platform.
    #[error(
        "io_uring is Linux-only. Fix: run on Linux 5.1+ or use Megakernel::dispatch without a GpuStream"
    )]
    NotLinux,
    /// Feature required for NVMe passthrough is not enabled.
    #[error(
        "NVMe passthrough requires the `uring-cmd-nvme` feature + Linux kernel 6.0+. Fix: add `features = [\"uring-cmd-nvme\"]` to your Cargo.toml"
    )]
    NvmePassthroughDisabled,
    /// Backend error bubbled up from compile or dispatch.
    #[error("backend error: {0}")]
    Backend(String),
}

impl From<vyre_driver::backend::BackendError> for PipelineError {
    fn from(err: vyre_driver::backend::BackendError) -> Self {
        PipelineError::Backend(err.to_string())
    }
}

/// Persistent megakernel — the vyre Program that runs forever on
/// the GPU, decoding host-fed ring opcodes from a host-fed ring buffer.
pub mod megakernel;

/// Content-addressed pipeline cache: `blake3(canonicalize(p).to_wire())`
/// is the cache key.
pub mod pipeline_cache;

/// Differential megakernel replay log — captures every published
/// ring slot so a later cert run can diff epoch-by-epoch execution
/// against a live backend.
pub mod replay;

/// Backend routing policy for execution plans.
pub mod routing;

/// Multi-tenant megakernel multiplexing — one persistent kernel per
/// GPU, shared across warpscan / keyhog / soleno / vein etc via the
/// `tenant_id` field already in the ring protocol.
pub mod tenant;

pub use replay::{RecordedSlot, ReplayLogError, RingLog};
pub use tenant::{
    TenantError, TenantHandle, TenantRegistry, OPCODE_RANGE_PER_TENANT, TENANT_ID_MAX,
    TENANT_OPCODE_BASE,
};

#[cfg(feature = "remote")]
pub use pipeline_cache::RemoteCache;
pub use pipeline_cache::{
    InMemoryPipelineCache, LayeredPipelineCache, PipelineCacheStore, PipelineFingerprint,
};

pub use megakernel::{Megakernel, WgpuMegakernelDispatcher};

/// Linux io_uring integration. Compiled out on macOS / Windows.
#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub mod uring;

/// Handle to an orchestrated pipeline. Couples a compiled megakernel
/// to its submission + completion infrastructure.
pub struct GpuStream<'a> {
    #[cfg(target_os = "linux")]
    uring: Option<uring::AsyncUringStream<'a>>,
    /// Phantom binding so the `'a` lifetime is always used even on
    /// non-Linux platforms where the `uring` field is cfg'd out.
    /// Without this the lib fails to compile on Windows / macOS with
    /// `unused lifetime parameter`. (vyre-side fix candidate; until
    /// upstream lands a cross-platform structural change we keep this
    /// PhantomData here in the vendored copy.)
    #[cfg(not(target_os = "linux"))]
    _marker: std::marker::PhantomData<&'a ()>,
    shutdown_requested: bool,
}

impl Default for GpuStream<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> GpuStream<'a> {
    /// Create a pipeline handle with no io_uring stream attached.
    ///
    /// # Examples
    ///
    /// ```
    /// use vyre_runtime::GpuStream;
    ///
    /// let stream = GpuStream::new();
    ///
    /// assert!(!stream.is_shutdown_requested());
    /// ```
    #[must_use]
    pub fn new() -> Self {
        Self {
            #[cfg(target_os = "linux")]
            uring: None,
            #[cfg(not(target_os = "linux"))]
            _marker: std::marker::PhantomData,
            shutdown_requested: false,
        }
    }

    /// Attach an io_uring stream for GPU-visible reads. Linux-only.
    ///
    /// Use `uring::NvmeGpuIngestDriver::new_gpudirect` when the caller
    /// requires the native NVMe → BAR1 path instead of registered mapped reads.
    #[cfg(target_os = "linux")]
    #[must_use]
    pub fn with_uring(mut self, stream: uring::AsyncUringStream<'a>) -> Self {
        self.uring = Some(stream);
        self
    }

    /// Reap completions and bump the megakernel tail pointer.
    ///
    /// # Errors
    ///
    /// Propagates any uring syscall error from the underlying ring.
    pub fn poll(&mut self) -> Result<u32, PipelineError> {
        #[cfg(target_os = "linux")]
        {
            if let Some(ref mut stream) = self.uring {
                return stream.poll();
            }
        }
        Ok(0)
    }

    /// Request graceful shutdown of the pipeline.
    pub fn request_shutdown(&mut self) {
        self.shutdown_requested = true;
    }

    /// Whether shutdown has been requested.
    #[must_use]
    pub fn is_shutdown_requested(&self) -> bool {
        self.shutdown_requested
    }

    /// Block until the megakernel writes a new value into the
    /// observable word. Uses `futex_waitv` on Linux 5.16+.
    ///
    /// # Errors
    ///
    /// - [`PipelineError::NotLinux`] on non-Linux hosts.
    /// - [`PipelineError::IoUringSyscall`] on futex errors.
    ///
    /// # Safety
    ///
    /// `host_visible_addr` must be host-mapped and outlive this call.
    #[cfg(target_os = "linux")]
    #[allow(unsafe_code)]
    pub unsafe fn wait_for_observable(
        host_visible_addr: *const u32,
        current: u32,
        timeout_ns: u64,
    ) -> Result<(), PipelineError> {
        #[repr(C)]
        struct futex_waitv {
            val: u64,
            uaddr: u64,
            flags: u32,
            __reserved: u32,
        }
        const FUTEX2_SIZE_U32: u32 = 0x02;
        const SYS_FUTEX_WAITV: libc::c_long = 449;

        let waitv = [futex_waitv {
            val: current as u64,
            uaddr: host_visible_addr as u64,
            flags: FUTEX2_SIZE_U32,
            __reserved: 0,
        }];

        #[repr(C)]
        struct Timespec {
            tv_sec: i64,
            tv_nsec: i64,
        }
        let ts = Timespec {
            tv_sec: (timeout_ns / 1_000_000_000) as i64,
            tv_nsec: (timeout_ns % 1_000_000_000) as i64,
        };

        let res = libc::syscall(
            SYS_FUTEX_WAITV,
            waitv.as_ptr() as *const libc::c_void,
            1u32,
            0u32,
            &ts as *const Timespec,
            0u64,
        );

        if res < 0 {
            let errno = *libc::__errno_location();
            if errno == libc::EAGAIN {
                return Ok(());
            }
            return Err(PipelineError::IoUringSyscall {
                syscall: "futex_waitv",
                errno,
                fix: "kernel 5.16+ required; ETIMEDOUT means the value didn't change within timeout_ns",
            });
        }
        Ok(())
    }

    /// Non-Linux implementation returning the structured platform error.
    #[cfg(not(target_os = "linux"))]
    #[allow(unsafe_code, clippy::missing_safety_doc)]
    pub unsafe fn wait_for_observable(
        _host_visible_addr: *const u32,
        _current: u32,
        _timeout_ns: u64,
    ) -> Result<(), PipelineError> {
        Err(PipelineError::NotLinux)
    }
}

/// Linux-only: host-visible GPU buffer that io_uring can DMA into.
#[cfg(target_os = "linux")]
pub use uring::GpuMappedBuffer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn construct_stream_has_no_shutdown() {
        let stream = GpuStream::new();
        assert!(!stream.is_shutdown_requested());
    }

    #[test]
    fn shutdown_is_idempotent() {
        let mut stream = GpuStream::new();
        stream.request_shutdown();
        stream.request_shutdown();
        assert!(stream.is_shutdown_requested());
    }

    #[test]
    fn poll_without_uring_returns_zero() {
        let mut stream = GpuStream::new();
        assert_eq!(stream.poll().unwrap(), 0);
    }
}

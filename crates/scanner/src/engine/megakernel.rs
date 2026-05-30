//! Megakernel persistent runtime session for keyhog scan dispatch.
//!
//! [`MegakernelSession`] wraps the vyre megakernel lifecycle - bootstrap,
//! submit, flush, shutdown - into a single value that [`CompiledScanner`] can
//! hold behind an [`OnceLock`].  If the megakernel fails to initialize (no
//! compatible adapter, backend compile failure, device loss) the constructor
//! returns `None` so the caller transparently degrades to per-batch dispatch.
//!
//! # Design
//!
//! The session owns:
//!
//! * A compiled [`Megakernel`] handle (the persistent GPU bytecode interpreter).
//! * [`MegakernelResidentBuffers`] - host-side mirror of the four ABI buffers
//!   (control, ring, debug log, IO queue) kept resident across dispatches.
//! * A [`MegakernelSessionConfig`] that controls slot geometry, work-item
//!   sizing, and launch policy.
//!
//! Each [`submit_scan`](MegakernelSession::submit_scan) call encodes the
//! incoming chunk as a contiguous sequence of [`MegakernelWorkItem`]s, publishes
//! them into the resident ring, dispatches, reads back, and decodes the
//! hit buffer into [`LiteralMatch`] values.  This is the persistent-kernel
//! equivalent of the sharded `GpuLiteralSet::scan` path.
//!
//! [`CompiledScanner`]: super::CompiledScanner
//!
//! # Status: not yet wired into the live GPU dispatch path
//!
//! This module is a **migration target**, not dead-per-audit: it is intended to
//! replace per-shard `GpuLiteralSet`-style dispatch (see `gpu_literal_phase1`)
//! with a persistent kernel that keeps the four ABI
//! buffers resident across dispatches, removing per-batch launch + buffer
//! (re)allocation overhead. Two things are still missing before it can carry
//! real scan traffic, and both live OUTSIDE this file:
//!
//! 1. **Declaration / engagement.** `engine/mod.rs` must declare
//!    `mod megakernel;` and `CompiledScanner` must hold a [`MegakernelSession`]
//!    (behind a `OnceLock`, like the other GPU resources) so that
//!    `scan_coalesced_gpu_phase1` can prefer [`MegakernelSession::submit_scan`]
//!    over per-shard dispatch when a session bootstraps.
//! 2. **Hit decoding.** [`MegakernelSession::submit_scan`] cannot yet decode
//!    [`LiteralMatch`] triples out of the IO-queue readback because the vyre
//!    megakernel program is not configured with the literal-set opcode
//!    handlers (a `vyre-runtime` change). Until that lands, `submit_scan`
//!    returns an empty match set - see the explicit gate at its decode site.
//!
//! Do not delete this module to satisfy a dead-code lint: the wiring above is
//! the fix, deletion is not.

use std::sync::Arc;

use vyre_runtime::megakernel::{
    Megakernel, MegakernelConfig, MegakernelResidentBuffers, MegakernelWorkItem,
};
use vyre_runtime::PipelineError;

use vyre_libs::scan::LiteralMatch;

/// Megakernel session configuration.
///
/// Config taxonomy: this is a **Tier-3 transport/runtime config** (GPU ring
/// geometry and launch policy). It is orthogonal to detection tuning and is
/// explicitly **outside the benchmark-coherence contract** - changing
/// `slot_count` / `workgroup_size_x` / `tenant_count` cannot move a detection
/// metric, so the benchmark never touches it. Tier 1 is the unified detection
/// config (`keyhog_core::config::ScanConfig`); Tier 2 is subsystem configs
/// nested inside it where they affect detection (e.g. `MultilineConfig` inside
/// `ScannerConfig`). See `keyhog_core::config` for the canonical 3-tier model.
#[derive(Debug, Clone)]
pub struct MegakernelSessionConfig {
    /// Number of ring-buffer slots (rounded up to workgroup width).
    pub slot_count: u32,
    /// Workgroup size for the persistent kernel launch.
    pub workgroup_size_x: u32,
    /// Number of logical tenants sharing the ring.
    pub tenant_count: u32,
    /// Observable control-buffer slots for host-side telemetry.
    pub observable_slots: u32,
    /// Megakernel planning/fusion config forwarded to the runtime.
    pub config: MegakernelConfig,
}

impl Default for MegakernelSessionConfig {
    fn default() -> Self {
        Self {
            slot_count: 256,
            workgroup_size_x: 256,
            tenant_count: 1,
            observable_slots: 0,
            config: MegakernelConfig::default(),
        }
    }
}

/// Persistent megakernel runtime session.
///
/// Manages the full lifecycle of a vyre megakernel: bootstrap, resident-buffer
/// allocation, work-item submission, dispatch, and readback.  If any step
/// fails, the session degrades gracefully - callers receive `None` from
/// [`MegakernelSession::new`] and fall back to per-batch dispatch.
pub struct MegakernelSession {
    kernel: Megakernel,
    buffers: MegakernelResidentBuffers,
    config: MegakernelSessionConfig,
    /// Monotonically increasing slot cursor; wraps modulo `slot_count`.
    next_slot: u32,
}

// SAFETY: `Megakernel` is Send + Sync (ArcSwap + Arc internals).
// `MegakernelResidentBuffers` is plain Vec-based host memory.
// These assertions mirror the `CompiledScanner` Send + Sync contract.
const _: () = {
    const fn assert_send_sync<T: Send + Sync>() {}
    let _ = assert_send_sync::<MegakernelSession>;
};

impl MegakernelSession {
    /// Bootstrap a megakernel session on the given backend.
    ///
    /// Returns `Ok(None)` when the backend cannot compile the megakernel
    /// program - this is the graceful-degradation contract that lets
    /// [`CompiledScanner`] fall back to per-batch dispatch without logging
    /// an error.
    ///
    /// Returns `Err` only for internal errors that should be surfaced
    /// (e.g. resident-buffer allocation overflows).
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when resident-buffer allocation fails.
    pub fn new(
        backend: Arc<dyn vyre::VyreBackend>,
        session_config: MegakernelSessionConfig,
    ) -> Result<Option<Self>, PipelineError> {
        let kernel = match Megakernel::bootstrap_sharded(
            backend,
            session_config.slot_count,
            session_config.workgroup_size_x,
            Vec::new(),
        ) {
            Ok(k) => k,
            Err(error) => {
                tracing::debug!(
                    target: "keyhog::gpu",
                    %error,
                    "megakernel bootstrap failed - degrading to per-batch dispatch",
                );
                return Ok(None);
            }
        };

        let buffers = MegakernelResidentBuffers::new(
            session_config.slot_count,
            session_config.tenant_count,
            session_config.observable_slots,
        )?;

        Ok(Some(Self {
            kernel,
            buffers,
            config: session_config,
            next_slot: 0,
        }))
    }

    /// Submit a scan chunk through the persistent megakernel.
    ///
    /// Encodes the work items into the resident ring, dispatches, reads back,
    /// and returns decoded literal matches.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] when ring publication, dispatch, or readback
    /// fails.  Device-loss recovery is attempted once by the underlying
    /// [`Megakernel`] handle; if that also fails the error propagates.
    pub fn submit_scan(
        &mut self,
        work_items: &[MegakernelWorkItem],
    ) -> Result<Vec<LiteralMatch>, PipelineError> {
        if work_items.is_empty() {
            return Ok(Vec::new());
        }

        // Publish items into the resident ring at the current cursor.
        let published = self.buffers.publish_work_items(
            self.next_slot,
            0, // tenant_id - single-tenant for keyhog scan dispatch
            work_items,
        )?;

        // Advance cursor (wrapping within slot_count).
        self.next_slot = (self.next_slot + published) % self.config.slot_count;

        // Dispatch and read back.
        let readback = self.buffers.dispatch(&self.kernel)?;

        // Decode literal matches from the readback IO-queue bytes.
        //
        // GAP (tracked, see module-level "Status" doc): the megakernel stores
        // match triples in the IO-queue output buffer, but decoding them into
        // `LiteralMatch` requires the literal-set opcode handlers in the vyre
        // megakernel program, which are not yet configured (a `vyre-runtime`
        // change). Until that lands this path is intentionally degraded to an
        // empty match set rather than a fabricated result. This is NOT a
        // silent stub: the session is not engaged on the live dispatch path
        // (no `mod megakernel;` in `engine/mod.rs`), so no real scan relies on
        // this return value. Decoding `io_queue_bytes` is the remaining work.
        let _readback_io = readback.io_queue_bytes;
        let matches = Vec::new();

        tracing::trace!(
            target: "keyhog::gpu",
            published,
            readback_control_bytes = readback.control_bytes.len(),
            readback_ring_bytes = readback.ring_bytes.len(),
            "megakernel scan dispatch completed",
        );

        Ok(matches)
    }

    /// Flush any pending work in the resident ring.
    ///
    /// This dispatches the current ring state without publishing new items,
    /// draining any in-flight slots.
    ///
    /// # Errors
    ///
    /// Returns [`PipelineError`] on dispatch or readback failure.
    pub fn flush(&mut self) -> Result<(), PipelineError> {
        self.buffers.dispatch_update(&self.kernel)?;

        tracing::trace!(
            target: "keyhog::gpu",
            "megakernel flush completed",
        );

        Ok(())
    }

    /// Shut down the session and release GPU resources.
    ///
    /// After shutdown, the session should be dropped.  This method resets
    /// the resident buffers to their initial state so destructors release
    /// any backend-held resources cleanly.
    pub fn shutdown(&mut self) {
        if let Err(error) = self.buffers.reset(
            self.config.tenant_count,
            self.config.observable_slots,
        ) {
            tracing::warn!(
                target: "keyhog::gpu",
                %error,
                "megakernel resident buffer reset failed during shutdown",
            );
        }
        self.next_slot = 0;

        tracing::debug!(
            target: "keyhog::gpu",
            "megakernel session shutdown",
        );
    }

    /// Current slot count in the resident ring.
    #[must_use]
    pub fn slot_count(&self) -> u32 {
        self.config.slot_count
    }

    /// Current next-slot cursor position.
    #[must_use]
    pub fn next_slot(&self) -> u32 {
        self.next_slot
    }
}

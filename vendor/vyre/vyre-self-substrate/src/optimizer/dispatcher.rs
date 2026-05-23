//! Dispatcher trait — the seam between the self-hosted optimizer and
//! a backend that can actually run vyre Programs.
//!
//! The optimizer encodes the user's Program into ProgramGraph buffers,
//! builds a vyre Program that does the analysis (e.g. `persistent_bfs`),
//! and asks an `OptimizerDispatcher` to run that analysis Program. The
//! returned bytes drive the rewrite.
//!
//! `vyre-self-substrate` cannot depend on a concrete backend — it sits
//! below the driver layer. The trait inverts that dependency: the
//! orchestrator code stays in self-substrate, and a backend crate
//! (e.g. `vyre-driver-wgpu` or a runtime wrapper) provides the impl.
//!
//! Test code in this crate uses `oracle::CpuOracleDispatcher` so the
//! encoder can be proven sound against the existing primitive oracles
//! before any GPU backend is wired. The CPU oracle is gated to tests
//! only — it is never on a production code path.

use vyre_foundation::ir::Program;

/// One resident-buffer kernel launch in an ordered optimizer sequence.
pub struct ResidentDispatchStep<'a> {
    /// Program to launch.
    pub program: &'a Program,
    /// Resident handle ids in canonical buffer binding order.
    pub handle_ids: &'a [u64],
    /// Optional launch grid override.
    pub grid_override: Option<[u32; 3]>,
}

/// One byte range to read from a resident buffer after an ordered sequence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ResidentReadRange {
    /// Resident handle id.
    pub handle_id: u64,
    /// First byte to read from the device buffer.
    pub byte_offset: usize,
    /// Number of meaningful bytes to transfer.
    pub byte_len: usize,
}

/// Errors a dispatcher may surface. Concrete backends compose their
/// own error types into this; the orchestrator only needs the
/// boundary message.
#[derive(Debug)]
pub enum DispatchError {
    /// The dispatcher rejected the Program. The string carries the
    /// backend's actionable message (must contain `Fix:`).
    Rejected(String),
    /// Input arity or shape did not match the Program's declared
    /// buffer set. Hard error — not retryable.
    BadInputs(String),
    /// Backend raised an internal error. Same shape as `Rejected` but
    /// the cause is in the backend, not the Program.
    BackendError(String),
}

impl std::fmt::Display for DispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Rejected(msg) => write!(f, "dispatcher rejected program: {msg}"),
            Self::BadInputs(msg) => write!(f, "dispatcher input mismatch: {msg}"),
            Self::BackendError(msg) => write!(f, "dispatcher backend error: {msg}"),
        }
    }
}

impl std::error::Error for DispatchError {}

/// Run a vyre Program with byte inputs, return byte outputs in the
/// Program's declared output order.
///
/// This is the canonical dispatch boundary. Production impls go
/// through `vyre-driver-wgpu` or `vyre-driver-cuda`; test impls use
/// CPU oracles (gated to test-only builds).
pub trait OptimizerDispatcher {
    /// Dispatch `program` with the given byte inputs (one `Vec<u8>`
    /// per declared input buffer in canonical buffer order). Returns
    /// the declared outputs in the same canonical order.
    ///
    /// `grid_override` lets parallel kernels dispatch enough
    /// workgroups to cover their input. `None` means "use the
    /// backend's default grid" (typically `[1, 1, 1]`), which is what
    /// sequential single-thread Programs want. Parallel passes
    /// compute `Some([ceil(work/wg_x), 1, 1])` based on the input
    /// size and their declared workgroup_size.
    fn dispatch(
        &self,
        program: &Program,
        inputs: &[Vec<u8>],
        grid_override: Option<[u32; 3]>,
    ) -> Result<Vec<Vec<u8>>, DispatchError>;

    /// Whether this dispatcher supports the persistent-resident path.
    /// Default: false. CUDA backend overrides to true. The orchestrator
    /// uses this to decide whether to take the persistent fast-path
    /// (encode arena once → upload once → dispatch many → readback once)
    /// or use the non-resident per-call GPU dispatch path.
    fn supports_persistent(&self) -> bool {
        false
    }

    /// Device/lowering feature bits that affect reusable plan identity.
    ///
    /// Backends with feature-dependent lowering must override this so
    /// self-substrate plan caches cannot replay a Program shape prepared for a
    /// different hardware/lowering capability set. Test-only and reference
    /// dispatchers keep the zero default because they do not specialize plans by
    /// device.
    fn device_feature_cache_key(&self) -> u64 {
        0
    }

    /// Allocate a backend-resident buffer. Returns an opaque u64
    /// handle. Callers must `free_resident` to release.
    fn alloc_resident(&self, _byte_len: usize) -> Result<u64, DispatchError> {
        Err(DispatchError::Rejected(
            "Fix: this dispatcher does not implement the persistent path; \
             use `dispatch` instead, or wire the resident-buffer methods."
                .to_string(),
        ))
    }

    /// Upload host bytes into a resident buffer.
    fn upload_resident(&self, _handle: u64, _bytes: &[u8]) -> Result<(), DispatchError> {
        Err(DispatchError::Rejected(
            "Fix: dispatcher does not implement upload_resident.".to_string(),
        ))
    }

    /// Upload several resident buffers with one backend fence when supported.
    fn upload_resident_many(&self, uploads: &[(u64, &[u8])]) -> Result<(), DispatchError> {
        for &(handle, bytes) in uploads {
            self.upload_resident(handle, bytes)?;
        }
        Ok(())
    }

    /// Download a resident buffer's current contents to host bytes.
    fn read_resident(&self, _handle: u64) -> Result<Vec<u8>, DispatchError> {
        Err(DispatchError::Rejected(
            "Fix: dispatcher does not implement read_resident.".to_string(),
        ))
    }

    /// Download several resident buffers with one backend fence when supported.
    fn read_resident_many(&self, handles: &[u64]) -> Result<Vec<Vec<u8>>, DispatchError> {
        handles
            .iter()
            .map(|&handle| self.read_resident(handle))
            .collect()
    }

    /// Download selected byte ranges from resident buffers.
    fn read_resident_ranges(
        &self,
        ranges: &[ResidentReadRange],
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        let mut outputs = Vec::with_capacity(ranges.len());
        for range in ranges {
            let full = self.read_resident(range.handle_id)?;
            let end = range
                .byte_offset
                .checked_add(range.byte_len)
                .ok_or_else(|| {
                    DispatchError::BadInputs(format!(
                    "Fix: resident read range for handle {} overflows usize at offset {} len {}.",
                    range.handle_id, range.byte_offset, range.byte_len
                ))
                })?;
            if end > full.len() {
                return Err(DispatchError::BadInputs(format!(
                    "Fix: resident read range for handle {} requested bytes [{}..{}) but buffer readback has {} bytes.",
                    range.handle_id,
                    range.byte_offset,
                    end,
                    full.len()
                )));
            }
            outputs.push(full[range.byte_offset..end].to_vec());
        }
        Ok(outputs)
    }

    /// Free a resident buffer previously returned by `alloc_resident`.
    fn free_resident(&self, _handle: u64) -> Result<(), DispatchError> {
        Err(DispatchError::Rejected(
            "Fix: dispatcher does not implement free_resident.".to_string(),
        ))
    }

    /// Dispatch a Program against resident-buffer handles. Each
    /// handle is referenced from the Program's declared buffer in the
    /// same canonical buffer order. RW buffers are not read back —
    /// caller invokes `read_resident` once at end of pipeline.
    fn dispatch_resident(
        &self,
        _program: &Program,
        _handles: &[u64],
        _grid_override: Option<[u32; 3]>,
    ) -> Result<(), DispatchError> {
        Err(DispatchError::Rejected(
            "Fix: dispatcher does not implement dispatch_resident.".to_string(),
        ))
    }

    /// Dispatch an ordered sequence of resident-buffer Programs.
    ///
    /// Default implementation preserves correctness by fencing each step
    /// through `dispatch_resident`. CUDA overrides this to enqueue the whole
    /// dependent chain on one stream and synchronize once.
    fn dispatch_resident_sequence(
        &self,
        steps: &[ResidentDispatchStep<'_>],
    ) -> Result<(), DispatchError> {
        for step in steps {
            self.dispatch_resident(step.program, step.handle_ids, step.grid_override)?;
        }
        Ok(())
    }

    /// Dispatch an ordered resident sequence and read selected resident buffers.
    ///
    /// Default implementation keeps the portable contract: execute the ordered
    /// sequence, then read buffers through `read_resident_many`. CUDA overrides
    /// this to enqueue the D2H readbacks behind the kernels on the same stream
    /// and pay one host fence.
    fn dispatch_resident_sequence_read_many(
        &self,
        steps: &[ResidentDispatchStep<'_>],
        read_handles: &[u64],
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        self.dispatch_resident_sequence(steps)?;
        self.read_resident_many(read_handles)
    }

    /// Dispatch an ordered resident sequence and read selected byte ranges.
    fn dispatch_resident_sequence_read_ranges(
        &self,
        steps: &[ResidentDispatchStep<'_>],
        read_ranges: &[ResidentReadRange],
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        self.dispatch_resident_sequence(steps)?;
        self.read_resident_ranges(read_ranges)
    }

    /// Upload resident buffers, dispatch an ordered resident sequence, then
    /// read selected resident buffers.
    ///
    /// Default implementation fences at each portable boundary. CUDA overrides
    /// this so H2D uploads, kernels, and D2H readbacks are ordered on one stream
    /// with one host synchronization point.
    fn upload_resident_many_sequence_read_many(
        &self,
        uploads: &[(u64, &[u8])],
        steps: &[ResidentDispatchStep<'_>],
        read_handles: &[u64],
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        self.upload_resident_many(uploads)?;
        self.dispatch_resident_sequence_read_many(steps, read_handles)
    }

    /// Upload resident buffers, dispatch an ordered resident sequence, then
    /// read selected byte ranges.
    fn upload_resident_many_sequence_read_ranges(
        &self,
        uploads: &[(u64, &[u8])],
        steps: &[ResidentDispatchStep<'_>],
        read_ranges: &[ResidentReadRange],
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        self.upload_resident_many(uploads)?;
        self.dispatch_resident_sequence_read_ranges(steps, read_ranges)
    }

    /// Same contract as [`Self::upload_resident_many_sequence_read_many`],
    /// but writes readbacks into caller-owned byte slots.
    fn upload_resident_many_sequence_read_many_into(
        &self,
        uploads: &[(u64, &[u8])],
        steps: &[ResidentDispatchStep<'_>],
        read_handles: &[u64],
        outputs: &mut Vec<Vec<u8>>,
    ) -> Result<(), DispatchError> {
        let readbacks =
            self.upload_resident_many_sequence_read_many(uploads, steps, read_handles)?;
        if outputs.len() < readbacks.len() {
            outputs.resize_with(readbacks.len(), Vec::new);
        } else {
            outputs.truncate(readbacks.len());
        }
        for (slot, readback) in outputs.iter_mut().zip(readbacks) {
            slot.clear();
            slot.extend_from_slice(&readback);
        }
        Ok(())
    }

    /// Same contract as [`Self::upload_resident_many_sequence_read_ranges`],
    /// but writes compact readbacks into caller-owned byte slots.
    fn upload_resident_many_sequence_read_ranges_into(
        &self,
        uploads: &[(u64, &[u8])],
        steps: &[ResidentDispatchStep<'_>],
        read_ranges: &[ResidentReadRange],
        outputs: &mut Vec<Vec<u8>>,
    ) -> Result<(), DispatchError> {
        let readbacks =
            self.upload_resident_many_sequence_read_ranges(uploads, steps, read_ranges)?;
        if outputs.len() < readbacks.len() {
            outputs.resize_with(readbacks.len(), Vec::new);
        } else {
            outputs.truncate(readbacks.len());
        }
        for (slot, readback) in outputs.iter_mut().zip(readbacks) {
            slot.clear();
            slot.extend_from_slice(&readback);
        }
        Ok(())
    }
}

#[cfg(test)]
pub mod oracle {
    //! CPU oracle dispatcher — test-only. Maps a small allowlist of
    //! self-hosted-optimizer Programs onto their `vyre_primitives`
    //! `cpu_ref` reference implementations and reproduces the
    //! dispatch byte contract.
    //!
    //! This module exists to prove the encoder/decoder are sound
    //! against the same numerical contract the production GPU path
    //! must honor. It is never reachable from a production build.
    //!
    //! Adding a Program here means the oracle hand-writes the byte
    //! marshalling that the WgpuBackend dispatcher infers from
    //! `BufferDecl`s. That duplication is acceptable for tests; a
    //! production dispatcher reflectively reads BufferDecls.
    //!
    //! For now we cover the Programs the orchestrator currently
    //! invokes (DCE → `persistent_bfs`). When CSE / const-fold land
    //! they each add a small case here.

    use super::{DispatchError, OptimizerDispatcher};
    use vyre_foundation::ir::Program;

    /// CPU oracle dispatcher. Recognizes only the optimizer's own
    /// canonical Programs by matching the wrapping Region's generator
    /// op-id and the declared buffer set.
    pub struct CpuOracleDispatcher;

    impl CpuOracleDispatcher {
        /// Construct the oracle dispatcher. Cheap; does no backend
        /// probing.
        #[must_use]
        pub fn new() -> Self {
            Self
        }
    }

    impl Default for CpuOracleDispatcher {
        fn default() -> Self {
            Self::new()
        }
    }

    impl OptimizerDispatcher for CpuOracleDispatcher {
        fn dispatch(
            &self,
            program: &Program,
            inputs: &[Vec<u8>],
            _grid_override: Option<[u32; 3]>,
        ) -> Result<Vec<Vec<u8>>, DispatchError> {
            // Identify the optimizer Program by its top-level Region
            // generator. Self-hosted Programs all wrap their bodies
            // in a Region with a known op-id (`vyre-primitives::graph::*`).
            let generator = top_level_region_generator(program).ok_or_else(|| {
                DispatchError::Rejected(
                    "Fix: oracle dispatcher only accepts canonical \
                     graph-primitive Programs whose entry is a single \
                     wrapping Region with a generator id."
                        .to_string(),
                )
            })?;

            match generator {
                vyre_primitives::graph::persistent_bfs::OP_ID => {
                    persistent_bfs_oracle(program, inputs)
                }
                other => Err(DispatchError::Rejected(format!(
                    "Fix: oracle dispatcher does not recognize generator \
                     `{other}`. Wire the oracle for this primitive or \
                     dispatch through the production backend."
                ))),
            }
        }
    }

    fn top_level_region_generator(program: &Program) -> Option<&str> {
        match program.entry() {
            [vyre_foundation::ir::Node::Region { generator, .. }] => Some(generator.as_str()),
            _ => None,
        }
    }

    fn persistent_bfs_oracle(
        program: &Program,
        inputs: &[Vec<u8>],
    ) -> Result<Vec<Vec<u8>>, DispatchError> {
        // Buffer order (per `persistent_bfs.rs::persistent_bfs`):
        //   0 pg_nodes (RO)
        //   1 pg_edge_offsets (RO)
        //   2 pg_edge_targets (RO)
        //   3 pg_edge_kind_mask (RO)
        //   4 pg_node_tags (RO)
        //   5 frontier_in (RO)
        //   6 frontier_out (RW)
        //   7 changed (RW)
        //   8 wg_scratch (workgroup)  — not an input
        if inputs.len() < 6 {
            return Err(DispatchError::BadInputs(format!(
                "Fix: persistent_bfs oracle expects ≥ 6 input buffers, got {}",
                inputs.len()
            )));
        }
        let nodes = read_u32_buffer(&inputs[0]);
        let edge_offsets = read_u32_buffer(&inputs[1]);
        let edge_targets_raw = read_u32_buffer(&inputs[2]);
        let edge_kind_mask_raw = read_u32_buffer(&inputs[3]);
        let _node_tags = read_u32_buffer(&inputs[4]);
        let frontier_in = read_u32_buffer(&inputs[5]);

        // The Region carries the shape and max_iters in its body
        // structure; rather than re-derive that from IR walks, the
        // oracle re-computes via cpu_ref using the buffers' lengths.
        let node_count = nodes.len() as u32;

        // Iteration cap: if the caller declared `frontier_in` of length L
        // (= bitset_words(node_count)) the oracle uses `node_count` as
        // the saturation budget — same default the Program builder uses
        // when callers want closure.
        let max_iters = node_count.max(1);

        let _ = program; // reserved for future cross-checks
        let allow_mask = u32::MAX;
        let edge_count = declared_edge_count(&edge_offsets)?;
        let edge_targets = trim_padded_edge_buffer("edge_targets", &edge_targets_raw, edge_count)?;
        let edge_kind_mask =
            trim_padded_edge_buffer("edge_kind_mask", &edge_kind_mask_raw, edge_count)?;

        let (frontier_out, changed) = vyre_primitives::graph::persistent_bfs::cpu_ref(
            node_count,
            &edge_offsets,
            edge_targets,
            edge_kind_mask,
            &frontier_in,
            allow_mask,
            max_iters,
        );

        // Outputs in declared order: frontier_out first, then changed.
        let frontier_bytes = u32_buffer_to_bytes(&frontier_out);
        let changed_bytes = u32_buffer_to_bytes(&[changed]);
        Ok(vec![frontier_bytes, changed_bytes])
    }

    fn declared_edge_count(edge_offsets: &[u32]) -> Result<usize, DispatchError> {
        edge_offsets
            .last()
            .copied()
            .map(|edge_count| edge_count as usize)
            .ok_or_else(|| {
                DispatchError::BadInputs(
                    "Fix: persistent_bfs oracle requires a CSR offset sentinel.".to_string(),
                )
            })
    }

    fn trim_padded_edge_buffer<'a>(
        name: &str,
        buffer: &'a [u32],
        edge_count: usize,
    ) -> Result<&'a [u32], DispatchError> {
        if buffer.len() < edge_count {
            return Err(DispatchError::BadInputs(format!(
                "Fix: persistent_bfs oracle {name} has {} words but CSR declares {edge_count} edges.",
                buffer.len()
            )));
        }
        Ok(&buffer[..edge_count])
    }

    fn read_u32_buffer(bytes: &[u8]) -> Vec<u32> {
        let mut out = Vec::with_capacity(bytes.len() / 4);
        for chunk in bytes.chunks_exact(4) {
            out.push(u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]));
        }
        out
    }

    fn u32_buffer_to_bytes(words: &[u32]) -> Vec<u8> {
        let mut out = Vec::with_capacity(words.len() * 4);
        for &w in words {
            out.extend_from_slice(&w.to_le_bytes());
        }
        out
    }
}

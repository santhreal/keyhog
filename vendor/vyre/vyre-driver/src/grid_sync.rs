//! Grid-sync kernel splitting.
//!
//! Op id: `vyre-driver::grid_sync`. Soundness: `Exact` over the
//! cross-grid barrier contract.
//!
//! ## Why this lives in vyre-driver, not the backend
//!
//! Every backend that lacks a native cooperative whole-grid launch
//! needs the same kernel-split semantics for
//! `Node::Barrier { ordering: GridSync }`: split the program at the
//! barrier, dispatch each segment as its own kernel launch, and
//! re-feed the prior segment's outputs as inputs to the next. The
//! kernel-launch boundary itself is the grid-level fence — every
//! prior write becomes globally visible before the next launch reads.
//!
//! Backends route through [`crate::grid_sync::dispatch_with_grid_sync_split`] when
//! [`VyreBackend::supports_grid_sync`] is `false` and the program
//! contains any `Node::Barrier { ordering: GridSync }`. Backends that
//! return `true` emit one kernel and satisfy the barrier device-side.
//!
//! ## Algorithm
//!
//! 1. Walk the program's top-level entry sequence.
//! 2. Each prefix-suffix split at a `Node::Barrier { GridSync }`
//!    becomes one segment.
//! 3. For each segment, build a `Program` with the SAME buffer table,
//!    workgroup size, and metadata as the original; only the entry
//!    nodes change.
//! 4. Dispatch segments in order, threading every output of segment N
//!    as the corresponding input to segment N+1. Backends with native
//!    GPU buffers preserve the bytes server-side via the Resident
//!    handle path; the borrowed-bytes API replicates host-side.
//!
//! ## Soundness
//!
//! - Atomicity preserved: every `atomic_or` that fired in segment N
//!   has flushed to global memory by the time segment N+1 launches —
//!   backend launch APIs issue an implicit grid-level fence at
//!   submission boundaries.
//! - Ordering preserved: the original program's host-visible output
//!   is byte-identical to the un-split version, modulo timing.
//! - No re-validation surprise: each split segment validates against
//!   the same backend supported-ops set as the original.

use std::sync::Arc;

use smallvec::SmallVec;
use vyre_foundation::ir::{Ident, Node, Program};
use vyre_foundation::memory_model::MemoryOrdering;

use crate::backend::{BackendError, DispatchConfig, OutputBuffers, TimedDispatchResult, VyreBackend};

/// Walk past `Program::wrapped`'s synthetic outer Region. Real
/// programs are constructed via `wrapped`, which inserts a single
/// outer Region around the user's entry sequence; the split logic
/// must operate on the inner sequence so a `GridSync` barrier inside
/// the wrapper actually splits the program. Programs constructed
/// via `Program::new` use the entry sequence directly — in that
/// case we just return it unchanged.
fn entry_sequence(program: &Program) -> &[Node] {
    let entry = program.entry();
    if entry.len() == 1 {
        if let Node::Region { body, .. } = &entry[0] {
            return body.as_slice();
        }
    }
    entry
}

/// Whether `program` contains any `Node::Barrier { ordering: GridSync }`
/// in its dispatch-level entry sequence (peeled past any synthetic
/// outer Region).
///
/// The check is intentionally shallow: nested grid-sync barriers
/// inside `Node::Loop` or inner `Node::Region` bodies are a contract
/// violation (`validate::barrier` rejects them) and never reach this
/// path. The split operates at the dispatch-level granularity.
#[must_use]
pub fn contains_grid_sync(program: &Program) -> bool {
    entry_sequence(program).iter().any(|node| {
        matches!(
            node,
            Node::Barrier {
                ordering: MemoryOrdering::GridSync,
                ..
            }
        )
    })
}

/// Split `program` at every top-level `Node::Barrier { GridSync }`.
///
/// Returns a vector of segments in execution order. The barrier nodes
/// themselves are dropped from the segments — the kernel-launch
/// boundary between segments takes their place.
///
/// Each returned segment is a complete `Program` that shares the
/// original's buffer table, workgroup size, and metadata; only the
/// entry sequence changes. Segments without any executable nodes are
/// preserved (an empty segment between two adjacent barriers becomes
/// a no-op kernel that completes with byte-identical inputs and
/// outputs).
#[must_use]
pub fn split_on_grid_sync(program: &Program) -> Vec<Program> {
    let inner = entry_sequence(program);
    let split_count = inner
        .iter()
        .filter(|node| {
            matches!(
                node,
                Node::Barrier {
                    ordering: MemoryOrdering::GridSync,
                    ..
                }
            )
        })
        .count();
    if split_count == 0 {
        return vec![program.clone()];
    }
    // Preserve the outer Region's generator name (if present) so each
    // segment carries the same provenance metadata as the original.
    let outer_generator: Option<Ident> = if let [Node::Region { generator, .. }] = program.entry() {
        Some(generator.clone())
    } else {
        None
    };

    let segment_count = split_count + 1;
    let executable_nodes = inner.len().saturating_sub(split_count);
    let segment_capacity = executable_nodes.div_ceil(segment_count);
    let mut segments = Vec::with_capacity(segment_count);
    let mut current = Vec::with_capacity(segment_capacity);
    for node in inner {
        match node {
            Node::Barrier {
                ordering: MemoryOrdering::GridSync,
                ..
            } => {
                let entry = std::mem::replace(&mut current, Vec::with_capacity(segment_capacity));
                segments.push(wrap_split_segment(program, outer_generator.as_ref(), entry));
            }
            other => {
                current.push(other.clone());
            }
        }
    }
    segments.push(wrap_split_segment(
        program,
        outer_generator.as_ref(),
        current,
    ));
    segments
}

fn wrap_split_segment(
    program: &Program,
    outer_generator: Option<&Ident>,
    entry: Vec<Node>,
) -> Program {
    // Re-wrap each segment in the same outer Region the source had, so
    // downstream callers see byte-identical Program shape
    // (region-wrapped or new-style) per segment.
    let wrapped_entry = match outer_generator {
        Some(generator) => vec![Node::Region {
            generator: generator.clone(),
            source_region: None,
            body: Arc::new(entry),
        }],
        None => entry,
    };
    program.with_rewritten_entry(wrapped_entry)
}

/// Universal dispatch helper that satisfies `Node::Barrier { ordering:
/// GridSync }` on any backend by splitting at the barrier and running
/// each segment as its own kernel launch.
///
/// Backends with native cooperative-launch grid sync (advertised via
/// [`VyreBackend::supports_grid_sync`]) bypass the split — the
/// program is dispatched once. Backends without it route here so the
/// kernel-launch boundary becomes the grid-level fence: every prior
/// write is globally visible to subsequent launches.
///
/// # Inputs
/// `inputs` matches the input slice the caller would have passed to
/// `dispatch_borrowed`. After each segment, the helper refreshes
/// every ReadWrite buffer's slot from the segment's readback so the
/// next segment sees the prior writes.
///
/// # Errors
/// Propagates any `BackendError` raised by `dispatch_borrowed` on a
/// segment, prefixed with the segment index for diagnosability.
pub fn dispatch_with_grid_sync_split(
    backend: &dyn VyreBackend,
    program: &Program,
    inputs: &[&[u8]],
    config: &DispatchConfig,
) -> Result<Vec<Vec<u8>>, BackendError> {
    let mut outputs = Vec::new();
    dispatch_with_grid_sync_split_into(backend, program, inputs, config, &mut outputs)?;
    Ok(outputs)
}

/// Timed variant of [`dispatch_with_grid_sync_split`].
///
/// # Errors
/// Propagates any [`BackendError`] raised by a segment dispatch.
pub fn dispatch_with_grid_sync_split_timed(
    backend: &dyn VyreBackend,
    program: &Program,
    inputs: &[&[u8]],
    config: &DispatchConfig,
) -> Result<TimedDispatchResult, BackendError> {
    let started = std::time::Instant::now();
    let outputs = dispatch_with_grid_sync_split(backend, program, inputs, config)?;
    Ok(TimedDispatchResult {
        outputs,
        wall_ns: started.elapsed().as_nanos() as u64,
        device_ns: None,
        enqueue_ns: None,
        wait_ns: None,
    })
}

/// Variant of [`dispatch_with_grid_sync_split`] that writes final outputs into
/// caller-owned storage.
///
/// # Errors
/// Propagates any `BackendError` raised by a segment dispatch.
pub fn dispatch_with_grid_sync_split_into(
    backend: &dyn VyreBackend,
    program: &Program,
    inputs: &[&[u8]],
    config: &DispatchConfig,
    outputs: &mut OutputBuffers,
) -> Result<(), BackendError> {
    if !contains_grid_sync(program) || backend.supports_grid_sync() {
        return backend.dispatch_borrowed_into(program, inputs, config, outputs);
    }
    let segments = split_on_grid_sync(program);
    if segments.is_empty() {
        return Err(BackendError::InvalidProgram {
            fix: "Fix: program contains GridSync barrier but split_on_grid_sync produced 0 \
                  segments. This is a grid_sync invariant bug — split_on_grid_sync must \
                  always return at least one segment."
                .to_string(),
        });
    }
    outputs.clear();

    // Build a mutable input set we rotate between segments. ReadOnly
    // inputs stay borrowed from the caller for the whole split; only
    // ReadWrite buffers become owned after a segment produces updated
    // bytes. The previous implementation cloned every input before
    // the first launch, which turned large read-only buffers into a
    // host-memory copy on the slow path.
    let mut current_inputs: Vec<GridSyncInput<'_>> = inputs
        .iter()
        .copied()
        .map(GridSyncInput::Borrowed)
        .collect();
    let mut segment_outputs = Vec::new();

    for (segment_idx, segment) in segments.iter().enumerate() {
        let borrowed: SmallVec<[&[u8]; 8]> =
            current_inputs.iter().map(GridSyncInput::as_slice).collect();
        if segment_idx + 1 == segments.len() {
            return backend
                .dispatch_borrowed_into(segment, borrowed.as_slice(), config, outputs)
                .map_err(|error| grid_sync_segment_error(error, segment_idx, segments.len()));
        }
        backend
            .dispatch_borrowed_into(segment, borrowed.as_slice(), config, &mut segment_outputs)
            .map_err(|error| grid_sync_segment_error(error, segment_idx, segments.len()))?;
        drop(borrowed);
        refresh_readwrite_inputs(segment, &mut segment_outputs, &mut current_inputs);
    }
    Ok(())
}

fn grid_sync_segment_error(
    error: BackendError,
    segment_idx: usize,
    segment_count: usize,
) -> BackendError {
    match error {
        BackendError::InvalidProgram { fix } => BackendError::InvalidProgram {
            fix: format!(
                "Fix: grid-sync split segment {segment_idx} of {segment_count} dispatch failed: {fix}"
            ),
        },
        other => other,
    }
}

enum GridSyncInput<'a> {
    Borrowed(&'a [u8]),
    Owned(Vec<u8>),
}

impl GridSyncInput<'_> {
    fn as_slice(&self) -> &[u8] {
        match self {
            Self::Borrowed(bytes) => bytes,
            Self::Owned(bytes) => bytes.as_slice(),
        }
    }
}

/// After each segment dispatch, overwrite every ReadWrite buffer's
/// slot in `inputs` with the freshly-read bytes from `outputs`. The
/// backend returns one Vec<u8> per ReadWrite buffer in declaration
/// order; this function locates each ReadWrite buffer's input-slot
/// index and overwrites it. ReadOnly buffers stay untouched between
/// segments.
fn refresh_readwrite_inputs(
    segment: &Program,
    outputs: &mut Vec<Vec<u8>>,
    inputs: &mut [GridSyncInput<'_>],
) {
    use vyre_foundation::ir::BufferAccess;
    // Walk the segment's buffer table twice in lockstep — once for the
    // input slice, once for the output readback. Both paths must
    // mirror the convention `dispatch_borrowed` uses: input position
    // skips Workgroup AND `is_output` buffers; output position emits
    // one slot per ReadWrite buffer (whether or not is_output).
    let mut input_idx = 0usize;
    let mut output_idx = 0usize;
    for buffer in segment.buffers() {
        if matches!(buffer.access(), BufferAccess::Workgroup) {
            continue;
        }
        let is_output_buffer = buffer.is_output();
        let is_readwrite = matches!(buffer.access(), BufferAccess::ReadWrite);

        // Refresh the input slot from the readback if this buffer
        // appears in BOTH input and output positions (i.e. ReadWrite
        // and NOT is_output — the rule scratch / `gets` case).
        if is_readwrite && !is_output_buffer {
            if let (Some(slot), Some(bytes)) =
                (inputs.get_mut(input_idx), outputs.get_mut(output_idx))
            {
                *slot = GridSyncInput::Owned(std::mem::take(bytes));
            }
        }

        // Advance the input cursor for every non-output buffer.
        if !is_output_buffer {
            input_idx += 1;
        }
        // Advance the output cursor for every ReadWrite buffer (output
        // or not — the backend includes them all in the readback).
        if is_readwrite {
            output_idx += 1;
        }
    }
    outputs.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr};

    fn buffer() -> BufferDecl {
        BufferDecl::storage("buf", 0, BufferAccess::ReadWrite, DataType::U32).with_count(4)
    }

    fn region(generator: &str, body: Vec<Node>) -> Node {
        Node::Region {
            generator: Ident::from(generator),
            source_region: None,
            body: Arc::new(body),
        }
    }

    /// Get the inner-segment node count for a wrapped or unwrapped Program.
    fn inner_len(program: &Program) -> usize {
        entry_sequence(program).len()
    }

    #[test]
    fn no_grid_sync_returns_single_segment() {
        let program = Program::wrapped(
            vec![buffer()],
            [1, 1, 1],
            vec![region(
                "a",
                vec![Node::store("buf", Expr::u32(0), Expr::u32(1))],
            )],
        );
        assert!(!contains_grid_sync(&program));
        let segments = split_on_grid_sync(&program);
        assert_eq!(segments.len(), 1);
        // Original entry was [Region("a", ...)] so the inner sequence is 1.
        assert_eq!(inner_len(&segments[0]), 1);
    }

    #[test]
    fn one_grid_sync_splits_into_two() {
        let program = Program::wrapped(
            vec![buffer()],
            [1, 1, 1],
            vec![
                region("a", vec![Node::store("buf", Expr::u32(0), Expr::u32(1))]),
                Node::barrier_with_ordering(MemoryOrdering::GridSync),
                region("b", vec![Node::store("buf", Expr::u32(1), Expr::u32(2))]),
            ],
        );
        assert!(contains_grid_sync(&program));
        let segments = split_on_grid_sync(&program);
        assert_eq!(segments.len(), 2);
        assert_eq!(inner_len(&segments[0]), 1);
        assert_eq!(inner_len(&segments[1]), 1);
    }

    #[test]
    fn three_grid_syncs_split_into_four() {
        let program = Program::wrapped(
            vec![buffer()],
            [1, 1, 1],
            vec![
                region("a", vec![Node::Return]),
                Node::barrier_with_ordering(MemoryOrdering::GridSync),
                region("b", vec![Node::Return]),
                Node::barrier_with_ordering(MemoryOrdering::GridSync),
                region("c", vec![Node::Return]),
                Node::barrier_with_ordering(MemoryOrdering::GridSync),
                region("d", vec![Node::Return]),
            ],
        );
        let segments = split_on_grid_sync(&program);
        assert_eq!(segments.len(), 4);
    }

    #[test]
    fn workgroup_barrier_does_not_split() {
        let program = Program::wrapped(
            vec![buffer()],
            [1, 1, 1],
            vec![
                region("a", vec![Node::Return]),
                Node::barrier_with_ordering(MemoryOrdering::SeqCst),
                region("b", vec![Node::Return]),
            ],
        );
        assert!(!contains_grid_sync(&program));
        let segments = split_on_grid_sync(&program);
        assert_eq!(segments.len(), 1);
        // Region("a"), Barrier(SeqCst), Region("b") = 3 inner nodes.
        assert_eq!(inner_len(&segments[0]), 3);
    }

    #[test]
    fn buffers_and_workgroup_size_propagate_to_each_segment() {
        let program = Program::wrapped(
            vec![buffer()],
            [256, 1, 1],
            vec![
                region("a", vec![Node::Return]),
                Node::barrier_with_ordering(MemoryOrdering::GridSync),
                region("b", vec![Node::Return]),
            ],
        );
        let segments = split_on_grid_sync(&program);
        for seg in &segments {
            assert_eq!(seg.workgroup_size(), [256, 1, 1]);
            assert_eq!(seg.buffers().len(), 1);
            assert_eq!(seg.buffers()[0].name(), "buf");
        }
    }
}

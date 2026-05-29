//! Region-graph dataflow fixpoint via #1 semiring_gemm (#26 substrate).
//!
//! Treats vyre's Region tree adjacency as a sparse boolean matrix
//! and computes reachability / liveness / dominance / constant-prop
//! via `semiring_gemm` iterations under different semirings:
//!
//! | Analysis | Semiring | Combine | Accumulate |
//! |---|---|---|---|
//! | Reachability | BoolOr | AND | OR |
//! | Liveness | BoolOr (reverse direction) | AND | OR |
//! | Reaching defs | Lineage | OR (zero-absorbing) | OR |
//! | Constant prop | Lineage | OR | OR |
//! | Min-cost path | MinPlus | + (sat) | min |
//!
//! Same primitive (#1), same Program, four different IR analyses.
//! Demonstrates the recursion thesis directly.

use vyre_foundation::pass_substrate::dataflow_fixpoint as foundation_dataflow;
pub use vyre_foundation::pass_substrate::dataflow_fixpoint::Semiring;

use crate::dispatch_buffers::{
    ceil_div_u32, decode_u32_output_exact, ensure_input_slots, write_u32_slice_le_bytes,
    write_zero_bytes,
};
use crate::hardware::scratch::reserve_vec_capacity;
#[cfg(any(test, feature = "cpu-parity"))]
use crate::hardware::scratch::reserve_vec_capacity_or_panic;
use crate::optimizer::dispatcher::{DispatchError, OptimizerDispatcher};

/// Caller-owned dispatch scratch for repeated semiring-GEMM GPU calls.
#[derive(Debug, Default)]
pub struct SemiringGemmGpuScratch {
    inputs: Vec<Vec<u8>>,
}

/// Caller-owned scratch for GPU-backed SCC composition over reachability closure.
#[derive(Debug, Default)]
pub struct SccComponentsGpuScratch {
    fwd_closure: Vec<u32>,
    bwd_closure: Vec<u32>,
    fwd_next: Vec<u32>,
    bwd_next: Vec<u32>,
    transpose: Vec<u32>,
    forward: Vec<u32>,
    backward: Vec<u32>,
    semiring: SemiringGemmGpuScratch,
    inputs: Vec<Vec<u8>>,
}

/// Multiply matrices over the selected semiring through the reference oracle.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn reference_semiring_gemm(
    a: &[u32],
    b: &[u32],
    m: u32,
    n: u32,
    k: u32,
    semiring: Semiring,
) -> Vec<u32> {
    let mut c = Vec::new();
    reference_semiring_gemm_into(a, b, m, n, k, semiring, &mut c);
    c
}

/// Multiply matrices over the selected semiring into caller-owned storage.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn reference_semiring_gemm_into(
    a: &[u32],
    b: &[u32],
    m: u32,
    n: u32,
    k: u32,
    semiring: Semiring,
    c: &mut Vec<u32>,
) {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    foundation_dataflow::semiring_gemm_cpu_into(a, b, m, n, k, semiring, c);
}

/// Compute boolean reachability closure on a Region adjacency matrix
/// via repeated `semiring_gemm` iterations under `Semiring::BoolOr`.
/// Iterates until fixpoint (max `max_iters` steps).
#[must_use]
pub fn reachability_closure(adj: &[u32], n: u32, max_iters: u32) -> Vec<u32> {
    let mut current = Vec::new();
    let mut next = Vec::new();
    reachability_closure_into(adj, n, max_iters, &mut current, &mut next);
    current
}

/// Compute boolean reachability closure into caller-owned buffers.
pub fn reachability_closure_into(
    adj: &[u32],
    n: u32,
    max_iters: u32,
    current: &mut Vec<u32>,
    next: &mut Vec<u32>,
) {
    foundation_dataflow::reachability_closure_into(adj, n, max_iters, current, next);
}

/// Compute lineage (which-clauses-used) closure under `Semiring::Lineage`.
/// Each entry of `adj` is a bitset of clause/source IDs.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn lineage_closure(adj: &[u32], n: u32, max_iters: u32) -> Vec<u32> {
    let mut current = Vec::new();
    let mut next = Vec::new();
    lineage_closure_into(adj, n, max_iters, &mut current, &mut next);
    current
}

/// Compute lineage closure into caller-owned buffers.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn lineage_closure_into(
    adj: &[u32],
    n: u32,
    max_iters: u32,
    current: &mut Vec<u32>,
    next: &mut Vec<u32>,
) {
    foundation_dataflow::lineage_closure_into(adj, n, max_iters, current, next);
}

/// Compute min-cost shortest-path distance matrix under `Semiring::MinPlus`.
/// Use `u32::MAX` for "no edge".
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn shortest_path_closure(adj: &[u32], n: u32, max_iters: u32) -> Vec<u32> {
    let mut current = Vec::new();
    let mut next = Vec::new();
    shortest_path_closure_into(adj, n, max_iters, &mut current, &mut next);
    current
}

/// Compute min-cost shortest-path closure into caller-owned buffers.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn shortest_path_closure_into(
    adj: &[u32],
    n: u32,
    max_iters: u32,
    current: &mut Vec<u32>,
    next: &mut Vec<u32>,
) {
    foundation_dataflow::shortest_path_closure_into(adj, n, max_iters, current, next);
}

/// Reusable buffers for SCC/dataflow closure queries.
#[derive(Debug, Default)]
#[cfg(any(test, feature = "cpu-parity"))]
pub struct DataflowFixpointScratch {
    fwd_closure: Vec<u32>,
    bwd_closure: Vec<u32>,
    transpose: Vec<u32>,
    forward: Vec<u32>,
    backward: Vec<u32>,
    next_components: Vec<u32>,
}

#[cfg(any(test, feature = "cpu-parity"))]
impl DataflowFixpointScratch {
    /// Forward-reach bitset produced by the last pivot query.
    #[must_use]
    pub fn forward_bitset(&self) -> &[u32] {
        &self.forward
    }

    /// Backward-reach bitset produced by the last pivot query.
    #[must_use]
    pub fn backward_bitset(&self) -> &[u32] {
        &self.backward
    }
}

/// Compute per-pivot forward + backward reach bitsets for the
/// strongly-connected-component decomposition primitive
/// (`vyre_primitives::graph::scc_decompose::cpu_ref`).
///
/// Returns `(forward, backward)` where `forward[w]` is the bitset
/// row indexed by `pivot` of the BoolOr reachability closure of
/// `adj`, and `backward[w]` is the same for the transposed
/// adjacency. The bitsets are packed 32-bits-per-u32, length
/// `bitset_words(n)`. Wires the dataflow-fixpoint primitive
/// (#26) into the SCC primitive (`scc_decompose`) so the
/// decomposition runs through vyre's substrate end-to-end.
///
/// # Panics
///
/// Panics if `pivot >= n` or `adj.len() != n*n`.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn forward_backward_bitsets_for_pivot(adj: &[u32], pivot: u32, n: u32) -> (Vec<u32>, Vec<u32>) {
    let mut scratch = DataflowFixpointScratch::default();
    forward_backward_bitsets_for_pivot_into(adj, pivot, n, &mut scratch);
    (scratch.forward, scratch.backward)
}

/// Compute per-pivot forward + backward reach bitsets into caller-owned scratch.
///
/// Results are written to `scratch.forward` and `scratch.backward`.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn forward_backward_bitsets_for_pivot_into(
    adj: &[u32],
    pivot: u32,
    n: u32,
    scratch: &mut DataflowFixpointScratch,
) {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    assert!(
        n > 0,
        "Fix: forward_backward_bitsets_for_pivot requires n > 0."
    );
    assert!(pivot < n, "Fix: pivot index must be < n.");
    let n_us = n as usize;
    assert_eq!(
        adj.len(),
        n_us * n_us,
        "Fix: adjacency must contain n*n entries."
    );

    let words = ((n + 31) / 32) as usize;

    reachability_closure_into(
        adj,
        n,
        n,
        &mut scratch.fwd_closure,
        &mut scratch.bwd_closure,
    );
    scratch.transpose.clear();
    scratch.transpose.resize(n_us * n_us, 0);
    for i in 0..n_us {
        for j in 0..n_us {
            scratch.transpose[j * n_us + i] = adj[i * n_us + j];
        }
    }
    reachability_closure_into(
        &scratch.transpose,
        n,
        n,
        &mut scratch.bwd_closure,
        &mut scratch.next_components,
    );

    scratch.forward.resize(words, 0);
    scratch.backward.resize(words, 0);
    write_pivot_bitsets(
        &scratch.fwd_closure,
        &scratch.bwd_closure,
        pivot,
        n_us,
        &mut scratch.forward,
        &mut scratch.backward,
    );
}

fn write_pivot_bitsets(
    fwd_closure: &[u32],
    bwd_closure: &[u32],
    pivot: u32,
    n_us: usize,
    forward: &mut [u32],
    backward: &mut [u32],
) {
    forward.fill(0);
    backward.fill(0);
    let pivot_us = pivot as usize;
    // Pivot reaches itself.
    let pivot_word = pivot_us / 32;
    let pivot_bit = 1u32 << (pivot_us % 32);
    forward[pivot_word] |= pivot_bit;
    backward[pivot_word] |= pivot_bit;
    for v in 0..n_us {
        if fwd_closure[pivot_us * n_us + v] != 0 {
            forward[v / 32] |= 1u32 << (v % 32);
        }
        if bwd_closure[pivot_us * n_us + v] != 0 {
            backward[v / 32] |= 1u32 << (v % 32);
        }
    }
}

/// Drive `vyre_primitives::graph::scc_decompose::cpu_ref` end-to-end
/// over an `n×n` adjacency: pick pivots in descending unassigned
/// order and stamp every node in `forward(p) ∩ backward(p)` with `p`.
/// Returns the per-node component-id vector. Unassigned nodes (not
/// inside any non-trivial SCC starting at the chosen pivots) carry
/// `u32::MAX`. Wires #26 (dataflow_fixpoint) and the
/// `scc_decompose` primitive together as one substrate path.
#[must_use]
#[cfg(any(test, feature = "cpu-parity"))]
pub fn scc_components_via_substrate(adj: &[u32], n: u32) -> Vec<u32> {
    let mut components = Vec::new();
    let mut scratch = DataflowFixpointScratch::default();
    reference_scc_components_via_substrate_into(adj, n, &mut components, &mut scratch);
    components
}

/// Drive SCC decomposition into caller-owned output and scratch buffers.
#[cfg(any(test, feature = "cpu-parity"))]
pub fn reference_scc_components_via_substrate_into(
    adj: &[u32],
    n: u32,
    components: &mut Vec<u32>,
    scratch: &mut DataflowFixpointScratch,
) {
    use crate::observability::{bump, dataflow_fixpoint_calls};
    bump(&dataflow_fixpoint_calls);
    components.clear();
    if n == 0 {
        return;
    }
    let n_us = n as usize;
    components.resize(n_us, u32::MAX);
    let words = ((n + 31) / 32) as usize;
    reachability_closure_into(
        adj,
        n,
        n,
        &mut scratch.fwd_closure,
        &mut scratch.bwd_closure,
    );
    scratch.transpose.clear();
    scratch.transpose.resize(n_us * n_us, 0);
    for i in 0..n_us {
        for j in 0..n_us {
            scratch.transpose[j * n_us + i] = adj[i * n_us + j];
        }
    }
    reachability_closure_into(
        &scratch.transpose,
        n,
        n,
        &mut scratch.bwd_closure,
        &mut scratch.next_components,
    );
    scratch.forward.resize(words, 0);
    scratch.backward.resize(words, 0);
    scratch.next_components.clear();
    reserve_vec_capacity_or_panic(
        &mut scratch.next_components,
        n_us,
        "SCC component staging scratch",
    );
    for pivot in 0..n {
        if components[pivot as usize] != u32::MAX {
            continue;
        }
        write_pivot_bitsets(
            &scratch.fwd_closure,
            &scratch.bwd_closure,
            pivot,
            n_us,
            &mut scratch.forward,
            &mut scratch.backward,
        );
        vyre_primitives::graph::scc_decompose::cpu_ref_into(
            n,
            &scratch.forward,
            &scratch.backward,
            components,
            pivot,
            &mut scratch.next_components,
        );
        std::mem::swap(components, &mut scratch.next_components);
    }
}

/// GPU dispatch wrapper around the primitive semiring GEMM program for an
/// arbitrary semiring.
///
/// # Errors
///
/// Returns [`crate::optimizer::dispatcher::DispatchError`] when dimensions
/// overflow, inputs do not match the declared matrix shape, dispatch fails,
/// or readback does not contain the `m * n` output matrix.
#[allow(clippy::too_many_arguments)]
pub fn semiring_gemm_via(
    dispatcher: &dyn OptimizerDispatcher,
    a: &[u32],
    b: &[u32],
    m: u32,
    n: u32,
    k: u32,
    semiring: Semiring,
) -> Result<Vec<u32>, DispatchError> {
    let c_words = m.checked_mul(n).ok_or_else(|| {
        DispatchError::BadInputs(format!(
            "Fix: semiring_gemm_via dimensions overflow m*n: m={m}, n={n}."
        ))
    })? as usize;
    let mut c = Vec::with_capacity(c_words);
    semiring_gemm_via_into(dispatcher, a, b, m, n, k, semiring, &mut c)?;
    Ok(c)
}

/// Multiply matrices over the selected semiring through a dispatcher into caller-owned storage.
#[allow(clippy::too_many_arguments)]
pub fn semiring_gemm_via_into(
    dispatcher: &dyn OptimizerDispatcher,
    a: &[u32],
    b: &[u32],
    m: u32,
    n: u32,
    k: u32,
    semiring: Semiring,
    c: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let mut scratch = SemiringGemmGpuScratch::default();
    semiring_gemm_via_with_scratch_into(dispatcher, a, b, m, n, k, semiring, &mut scratch, c)
}

/// Multiply matrices over the selected semiring using caller-owned dispatch scratch.
#[allow(clippy::too_many_arguments)]
pub fn semiring_gemm_via_with_scratch_into(
    dispatcher: &dyn OptimizerDispatcher,
    a: &[u32],
    b: &[u32],
    m: u32,
    n: u32,
    k: u32,
    semiring: Semiring,
    scratch: &mut SemiringGemmGpuScratch,
    c: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let a_words = m.checked_mul(k).ok_or_else(|| {
        DispatchError::BadInputs(format!(
            "Fix: semiring_gemm_via dimensions overflow m*k: m={m}, k={k}."
        ))
    })? as usize;
    let b_words = k.checked_mul(n).ok_or_else(|| {
        DispatchError::BadInputs(format!(
            "Fix: semiring_gemm_via dimensions overflow k*n: k={k}, n={n}."
        ))
    })? as usize;
    let c_words_u32 = m.checked_mul(n).ok_or_else(|| {
        DispatchError::BadInputs(format!(
            "Fix: semiring_gemm_via dimensions overflow m*n: m={m}, n={n}."
        ))
    })?;
    let c_words = c_words_u32 as usize;
    let c_bytes = c_words
        .checked_mul(std::mem::size_of::<u32>())
        .ok_or_else(|| {
            DispatchError::BadInputs(format!(
                "Fix: semiring_gemm_via output byte count overflows usize for {c_words} words."
            ))
        })?;

    if m == 0 || n == 0 || k == 0 {
        return Err(DispatchError::BadInputs(format!(
            "Fix: semiring_gemm_via requires nonzero dimensions; got m={m}, n={n}, k={k}."
        )));
    }
    if a.len() != a_words {
        return Err(DispatchError::BadInputs(format!(
            "Fix: semiring_gemm_via expected a.len() == m*k == {a_words}, got {}.",
            a.len()
        )));
    }
    if b.len() != b_words {
        return Err(DispatchError::BadInputs(format!(
            "Fix: semiring_gemm_via expected b.len() == k*n == {b_words}, got {}.",
            b.len()
        )));
    }

    let program =
        vyre_primitives::math::semiring_gemm::semiring_gemm("a", "b", "c", m, n, k, semiring);
    ensure_input_slots(&mut scratch.inputs, 3);
    write_u32_slice_le_bytes(&mut scratch.inputs[0], a);
    write_u32_slice_le_bytes(&mut scratch.inputs[1], b);
    write_zero_bytes(&mut scratch.inputs[2], c_bytes);
    let grid_x = ceil_div_u32(c_words_u32, 256);
    let outputs = dispatcher.dispatch(&program, &scratch.inputs, Some([grid_x, 1, 1]))?;
    if outputs.len() != 1 {
        return Err(DispatchError::BackendError(format!(
            "Fix: semiring_gemm_via expected exactly one c output buffer, got {}.",
            outputs.len()
        )));
    }
    decode_u32_output_exact(&outputs[0], c_words, "semiring_gemm_via c", c)
}

/// Boolean-OR semiring specialisation of [`semiring_gemm_via`].

pub fn semiring_gemm_via_bool_or(
    dispatcher: &dyn OptimizerDispatcher,
    a: &[u32],
    b: &[u32],
    m: u32,
    n: u32,
    k: u32,
) -> Result<Vec<u32>, DispatchError> {
    semiring_gemm_via(dispatcher, a, b, m, n, k, Semiring::BoolOr)
}

/// Min-plus semiring specialisation of [`semiring_gemm_via`].
pub fn semiring_gemm_via_min_plus(
    dispatcher: &dyn OptimizerDispatcher,
    a: &[u32],
    b: &[u32],
    m: u32,
    n: u32,
    k: u32,
) -> Result<Vec<u32>, DispatchError> {
    semiring_gemm_via(dispatcher, a, b, m, n, k, Semiring::MinPlus)
}

/// Lineage (provenance OR) semiring specialisation of [`semiring_gemm_via`].
pub fn semiring_gemm_via_lineage(
    dispatcher: &dyn OptimizerDispatcher,
    a: &[u32],
    b: &[u32],
    m: u32,
    n: u32,
    k: u32,
) -> Result<Vec<u32>, DispatchError> {
    semiring_gemm_via(dispatcher, a, b, m, n, k, Semiring::Lineage)
}

// ─────────────────────────────────────────────────────────────────────
// GPU dispatcher wrappers (`*_via`)
// ─────────────────────────────────────────────────────────────────────
//
// Each wrapper takes an `OptimizerDispatcher` and routes closure steps through
// vyre dispatch. The host currently owns the fixed-point loop and convergence
// check; each matrix-power step is backend-dispatched via semiring GEMM.

/// GPU dispatch wrapper around reachability closure.
///
/// # Errors
///
/// Propagates semiring-GEMM dispatch failures.
pub fn reachability_closure_via(
    dispatcher: &dyn OptimizerDispatcher,
    adj: &[u32],
    n: u32,
    max_iters: u32,
) -> Result<Vec<u32>, DispatchError> {
    let mut current = Vec::new();
    let mut next = Vec::new();
    reachability_closure_via_into(dispatcher, adj, n, max_iters, &mut current, &mut next)?;
    Ok(current)
}

/// GPU dispatch wrapper around reachability closure into caller-owned buffers.
///
/// # Errors
///
/// Propagates semiring-GEMM dispatch failures.
pub fn reachability_closure_via_into(
    dispatcher: &dyn OptimizerDispatcher,
    adj: &[u32],
    n: u32,
    _max_iters: u32,
    current: &mut Vec<u32>,
    next: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    let mut scratch = SemiringGemmGpuScratch::default();
    reachability_closure_via_with_scratch_into(
        dispatcher,
        adj,
        n,
        _max_iters,
        &mut scratch,
        current,
        next,
    )
}

/// GPU dispatch wrapper around reachability closure with caller-owned dispatch scratch.
///
/// # Errors
///
/// Propagates semiring-GEMM dispatch failures.
pub fn reachability_closure_via_with_scratch_into(
    dispatcher: &dyn OptimizerDispatcher,
    adj: &[u32],
    n: u32,
    _max_iters: u32,
    scratch: &mut SemiringGemmGpuScratch,
    current: &mut Vec<u32>,
    next: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    current.clear();
    current.extend_from_slice(adj);
    next.clear();
    reserve_vec_capacity(next, current.len(), "reachability closure next matrix")?;
    for _ in 0..n {
        semiring_gemm_via_with_scratch_into(
            dispatcher,
            current.as_slice(),
            current.as_slice(),
            n,
            n,
            n,
            Semiring::BoolOr,
            scratch,
            next,
        )?;
        if !foundation_dataflow::merge_or_changed(current, next) {
            return Ok(());
        }
    }
    Ok(())
}

/// GPU dispatch wrapper around lineage closure.
///
/// # Errors
///
/// Propagates semiring-GEMM dispatch failures.
pub fn lineage_closure_via(
    dispatcher: &dyn OptimizerDispatcher,
    adj: &[u32],
    n: u32,
    max_iters: u32,
) -> Result<Vec<u32>, DispatchError> {
    let mut current = adj.to_vec();
    let mut next = Vec::with_capacity(current.len());
    for _ in 0..max_iters {
        semiring_gemm_via_into(
            dispatcher,
            &current,
            &current,
            n,
            n,
            n,
            Semiring::Lineage,
            &mut next,
        )?;
        if !foundation_dataflow::merge_or_changed(&mut current, &next) {
            return Ok(current);
        }
    }
    Ok(current)
}

/// GPU dispatch wrapper around shortest-path closure.
///
/// # Errors
///
/// Propagates semiring-GEMM dispatch failures.
pub fn shortest_path_closure_via(
    dispatcher: &dyn OptimizerDispatcher,
    adj: &[u32],
    n: u32,
    max_iters: u32,
) -> Result<Vec<u32>, DispatchError> {
    let mut current = adj.to_vec();
    let mut next = Vec::with_capacity(current.len());
    for _ in 0..max_iters {
        semiring_gemm_via_into(
            dispatcher,
            &current,
            &current,
            n,
            n,
            n,
            Semiring::MinPlus,
            &mut next,
        )?;
        if !foundation_dataflow::merge_min_changed(&mut current, &next) {
            return Ok(current);
        }
    }
    Ok(current)
}

/// GPU-backed forward/backward reach bitset query for one pivot.
///
/// # Errors
///
/// Propagates reachability closure dispatch failures.
pub fn forward_backward_bitsets_for_pivot_via(
    dispatcher: &dyn OptimizerDispatcher,
    adj: &[u32],
    pivot: u32,
    n: u32,
) -> Result<(Vec<u32>, Vec<u32>), DispatchError> {
    if n == 0 || pivot >= n {
        return Err(DispatchError::BadInputs(format!(
            "Fix: forward_backward_bitsets_for_pivot_via requires n > 0 and pivot < n; got n={n}, pivot={pivot}."
        )));
    }
    let n_us = n as usize;
    let cells = n_us.checked_mul(n_us).ok_or_else(|| {
        DispatchError::BadInputs(format!(
            "Fix: forward_backward_bitsets_for_pivot_via n*n overflows usize for n={n}."
        ))
    })?;
    if adj.len() != cells {
        return Err(DispatchError::BadInputs(format!(
            "Fix: forward_backward_bitsets_for_pivot_via expected adj.len() == n*n == {cells}, got {}.",
            adj.len()
        )));
    }

    let fwd_closure = reachability_closure_via(dispatcher, adj, n, n)?;
    let mut transpose = vec![0u32; cells];
    for i in 0..n_us {
        for j in 0..n_us {
            transpose[j * n_us + i] = adj[i * n_us + j];
        }
    }
    let bwd_closure = reachability_closure_via(dispatcher, &transpose, n, n)?;
    let words = ((n + 31) / 32) as usize;
    let mut forward = vec![0u32; words];
    let mut backward = vec![0u32; words];
    write_pivot_bitsets(
        &fwd_closure,
        &bwd_closure,
        pivot,
        n_us,
        &mut forward,
        &mut backward,
    );
    Ok((forward, backward))
}

/// GPU-backed SCC composition over reachability and SCC-decompose primitives.
///
/// # Errors
///
/// Propagates closure or SCC-decompose dispatch failures.
pub fn scc_components_via_substrate_via(
    dispatcher: &dyn OptimizerDispatcher,
    adj: &[u32],
    n: u32,
) -> Result<Vec<u32>, DispatchError> {
    let mut scratch = SccComponentsGpuScratch::default();
    let mut components = Vec::new();
    scc_components_via_substrate_with_scratch_into(
        dispatcher,
        adj,
        n,
        &mut scratch,
        &mut components,
    )?;
    Ok(components)
}

/// GPU-backed SCC composition using caller-owned scratch across closure and pivot dispatches.
///
/// # Errors
///
/// Propagates closure or SCC-decompose dispatch failures.
pub fn scc_components_via_substrate_with_scratch_via(
    dispatcher: &dyn OptimizerDispatcher,
    adj: &[u32],
    n: u32,
    scratch: &mut SccComponentsGpuScratch,
) -> Result<Vec<u32>, DispatchError> {
    let mut components = Vec::new();
    scc_components_via_substrate_with_scratch_into(dispatcher, adj, n, scratch, &mut components)?;
    Ok(components)
}

/// GPU-backed SCC composition into caller-owned output storage.
///
/// # Errors
///
/// Propagates closure or SCC-decompose dispatch failures.
pub fn scc_components_via_substrate_with_scratch_into(
    dispatcher: &dyn OptimizerDispatcher,
    adj: &[u32],
    n: u32,
    scratch: &mut SccComponentsGpuScratch,
    components: &mut Vec<u32>,
) -> Result<(), DispatchError> {
    if n == 0 {
        components.clear();
        return Ok(());
    }
    let n_us = n as usize;
    let cells = n_us.checked_mul(n_us).ok_or_else(|| {
        DispatchError::BadInputs(format!(
            "Fix: scc_components_via_substrate_via n*n overflows usize for n={n}."
        ))
    })?;
    if adj.len() != cells {
        return Err(DispatchError::BadInputs(format!(
            "Fix: scc_components_via_substrate_via expected adj.len() == n*n == {cells}, got {}.",
            adj.len()
        )));
    }

    reachability_closure_via_with_scratch_into(
        dispatcher,
        adj,
        n,
        n,
        &mut scratch.semiring,
        &mut scratch.fwd_closure,
        &mut scratch.fwd_next,
    )?;
    scratch.transpose.clear();
    scratch.transpose.resize(cells, 0);
    for i in 0..n_us {
        for j in 0..n_us {
            scratch.transpose[j * n_us + i] = adj[i * n_us + j];
        }
    }
    reachability_closure_via_with_scratch_into(
        dispatcher,
        &scratch.transpose,
        n,
        n,
        &mut scratch.semiring,
        &mut scratch.bwd_closure,
        &mut scratch.bwd_next,
    )?;
    let words = ((n + 31) / 32) as usize;
    scratch.forward.clear();
    scratch.forward.resize(words, 0);
    scratch.backward.clear();
    scratch.backward.resize(words, 0);
    components.clear();
    components.resize(n_us, u32::MAX);
    ensure_input_slots(&mut scratch.inputs, 3);

    for pivot in 0..n {
        if components[pivot as usize] != u32::MAX {
            continue;
        }
        write_pivot_bitsets(
            &scratch.fwd_closure,
            &scratch.bwd_closure,
            pivot,
            n_us,
            &mut scratch.forward,
            &mut scratch.backward,
        );
        let program = vyre_primitives::graph::scc_decompose::scc_decompose(
            n,
            "forward",
            "backward",
            "components",
            pivot,
        );
        write_u32_slice_le_bytes(&mut scratch.inputs[0], &scratch.forward);
        write_u32_slice_le_bytes(&mut scratch.inputs[1], &scratch.backward);
        write_u32_slice_le_bytes(&mut scratch.inputs[2], components);
        let outputs = dispatcher.dispatch(&program, &scratch.inputs, Some([n, 1, 1]))?;
        if outputs.len() != 1 {
            return Err(DispatchError::BackendError(format!(
                "Fix: scc_components_via_substrate_via expected exactly one component output, got {}.",
                outputs.len()
            )));
        }
        decode_u32_output_exact(
            &outputs[0],
            n_us,
            "scc_components_via_substrate_via components",
            components,
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::erasing_op, clippy::identity_op)]
mod tests {
    use super::*;
    use crate::dispatch_buffers::u32_slice_to_le_bytes;
    use std::cell::Cell;
    use vyre_foundation::ir::Program;

    struct SemiringDispatcher {
        outputs: Vec<Vec<u8>>,
    }

    impl OptimizerDispatcher for SemiringDispatcher {
        fn dispatch(
            &self,
            _program: &Program,
            inputs: &[Vec<u8>],
            grid_override: Option<[u32; 3]>,
        ) -> Result<Vec<Vec<u8>>, DispatchError> {
            assert_eq!(grid_override, Some([1, 1, 1]));
            if inputs.len() != 3 {
                return Err(DispatchError::BadInputs(format!(
                    "Fix: semiring test dispatcher expected 3 inputs, got {}.",
                    inputs.len()
                )));
            }
            Ok(self.outputs.clone())
        }
    }

    struct SequenceDispatcher {
        outputs: Vec<Vec<Vec<u8>>>,
        cursor: Cell<usize>,
    }

    impl OptimizerDispatcher for SequenceDispatcher {
        fn dispatch(
            &self,
            _program: &Program,
            inputs: &[Vec<u8>],
            _grid_override: Option<[u32; 3]>,
        ) -> Result<Vec<Vec<u8>>, DispatchError> {
            if inputs.len() != 3 {
                return Err(DispatchError::BadInputs(format!(
                    "Fix: sequence test dispatcher expected 3 inputs, got {}.",
                    inputs.len()
                )));
            }
            let idx = self.cursor.get();
            self.cursor.set(idx + 1);
            self.outputs.get(idx).cloned().ok_or_else(|| {
                DispatchError::BackendError("Fix: sequence dispatcher exhausted outputs.".into())
            })
        }
    }

    #[test]
    fn reachability_chain_graph() {
        // 0 → 1 → 2 → 3
        let adj = vec![0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let closure = reachability_closure(&adj, 4, 5);
        // After closure: 0 reaches {1, 2, 3}; 1 reaches {2, 3}; 2 reaches {3}.
        assert_eq!(closure[0 * 4 + 1], 1);
        assert_eq!(closure[0 * 4 + 2], 1);
        assert_eq!(closure[0 * 4 + 3], 1);
        assert_eq!(closure[1 * 4 + 3], 1);
        // No reverse edges
        assert_eq!(closure[3 * 4 + 0], 0);
    }

    #[test]
    fn reference_semiring_gemm_into_delegates_to_foundation_authority() {
        let left = vec![1, 2, 3, 4, 5, 6];
        let right = vec![7, 8, 9, 10, 11, 12];
        let mut out = Vec::with_capacity(8);
        let ptr = out.as_ptr();
        reference_semiring_gemm_into(&left, &right, 2, 2, 3, Semiring::Real, &mut out);
        let mut expected = Vec::new();
        foundation_dataflow::semiring_gemm_cpu_into(
            &left,
            &right,
            2,
            2,
            3,
            Semiring::Real,
            &mut expected,
        );
        assert_eq!(out, expected);
        assert_eq!(out.as_ptr(), ptr);
    }

    #[test]
    fn reachability_invalid_shapes_clear_buffers_without_panicking() {
        let mut current = vec![99, 100];
        let mut next = vec![101];
        reachability_closure_into(&[0, 1, 0], 2, 4, &mut current, &mut next);
        assert!(current.is_empty());
        assert!(next.is_empty());
        reachability_closure_into(&[], 0, 4, &mut current, &mut next);
        assert!(current.is_empty());
        assert!(next.is_empty());
    }

    #[test]
    fn reachability_respects_primitive_max_iters_policy() {
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        assert_eq!(reachability_closure(&adj, 3, 0).len(), adj.len());
        assert_eq!(reachability_closure(&adj, 3, 0), adj);
    }

    #[test]
    fn generated_reachability_matches_foundation_authority() {
        for n in 1u32..=8 {
            let cells = (n * n) as usize;
            for seed in 0u32..64 {
                let mut state = seed ^ n.wrapping_mul(0x9E37);
                let mut adj = Vec::with_capacity(cells);
                for _ in 0..cells {
                    state = state.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
                    adj.push((state >> 31) & 1);
                }
                assert_eq!(
                    reachability_closure(&adj, n, n),
                    foundation_dataflow::reachability_closure(&adj, n, n),
                    "n={n} seed={seed}"
                );
            }
        }
    }

    #[test]
    fn semiring_via_into_decodes_exact_output_into_reused_buffer() {
        let dispatcher = SemiringDispatcher {
            outputs: vec![u32_slice_to_le_bytes(&[7])],
        };
        let mut c = Vec::with_capacity(4);
        let ptr = c.as_ptr();
        semiring_gemm_via_into(&dispatcher, &[2], &[3], 1, 1, 1, Semiring::Real, &mut c)
            .expect("Fix: dispatch succeeds");
        assert_eq!(c, vec![7]);
        assert_eq!(c.as_ptr(), ptr);
    }

    #[test]
    fn semiring_via_rejects_extra_outputs() {
        let dispatcher = SemiringDispatcher {
            outputs: vec![u32_slice_to_le_bytes(&[7]), u32_slice_to_le_bytes(&[0])],
        };
        let err = semiring_gemm_via(&dispatcher, &[2], &[3], 1, 1, 1, Semiring::Real)
            .expect_err("extra outputs must be rejected");
        assert!(
            matches!(err, DispatchError::BackendError(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn semiring_via_rejects_trailing_output_bytes() {
        let dispatcher = SemiringDispatcher {
            outputs: vec![vec![7, 0, 0, 0, 1]],
        };
        let err = semiring_gemm_via(&dispatcher, &[2], &[3], 1, 1, 1, Semiring::Real)
            .expect_err("trailing output bytes must be rejected");
        assert!(
            matches!(err, DispatchError::BackendError(_)),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn reachability_disjoint_components_stay_disjoint() {
        // 0 → 1, 2 → 3, no cross.
        let adj = vec![0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        let closure = reachability_closure(&adj, 4, 5);
        assert_eq!(closure[0 * 4 + 2], 0);
        assert_eq!(closure[2 * 4 + 0], 0);
    }

    #[test]
    fn lineage_closure_unions_clauses_along_paths() {
        // Edge 0→1 used clause f1 = 0b01; edge 1→2 used clause f2 = 0b10.
        // Path 0→2 uses both: 0b11.
        let f1 = 0b01;
        let f2 = 0b10;
        let adj = vec![0, f1, 0, 0, 0, f2, 0, 0, 0];
        let closure = lineage_closure(&adj, 3, 5);
        assert_eq!(closure[0 * 3 + 2], f1 | f2);
    }

    #[test]
    fn shortest_path_closure_finds_two_hop_minimum() {
        let inf = u32::MAX;
        // 0→1 cost 5, 1→2 cost 3, 0→2 cost 100 (slower direct).
        let adj = vec![inf, 5, 100, inf, inf, 3, inf, inf, inf];
        let closure = shortest_path_closure(&adj, 3, 5);
        // Best 0→2 = min(100, 5+3) = 8.
        assert_eq!(closure[0 * 3 + 2], 8);
    }

    #[test]
    fn reachability_self_loop_detected() {
        // 0 → 1, 1 → 0. Closure should mark both.
        let adj = vec![0, 1, 1, 0];
        let closure = reachability_closure(&adj, 2, 5);
        // After 1 iteration: 0 reaches 0 via 0→1→0; 1 reaches 1.
        assert_eq!(closure[0 * 2 + 0], 1);
        assert_eq!(closure[1 * 2 + 1], 1);
    }

    // ---- forward_backward_bitsets_for_pivot + scc_components_via_substrate ----

    #[test]
    fn fb_bitsets_chain_pivot_zero() {
        // 0 → 1 → 2. From pivot 0: forward = {0,1,2}, backward = {0}.
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        let (fwd, bwd) = forward_backward_bitsets_for_pivot(&adj, 0, 3);
        assert_eq!(fwd, vec![0b111]);
        assert_eq!(bwd, vec![0b001]);
    }

    #[test]
    fn fb_bitsets_chain_pivot_two() {
        // 0 → 1 → 2. From pivot 2: forward = {2}, backward = {0,1,2}.
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        let (fwd, bwd) = forward_backward_bitsets_for_pivot(&adj, 2, 3);
        assert_eq!(fwd, vec![0b100]);
        assert_eq!(bwd, vec![0b111]);
    }

    #[test]
    fn fb_bitsets_into_reuses_capacity_and_matches_owned() {
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        let mut scratch = DataflowFixpointScratch::default();
        forward_backward_bitsets_for_pivot_into(&adj, 2, 3, &mut scratch);
        let fwd_capacity = scratch.forward.capacity();
        let bwd_capacity = scratch.backward.capacity();
        assert_eq!(scratch.forward_bitset(), &[0b100]);
        assert_eq!(scratch.backward_bitset(), &[0b111]);

        forward_backward_bitsets_for_pivot_into(&adj, 0, 3, &mut scratch);
        assert_eq!(scratch.forward.capacity(), fwd_capacity);
        assert_eq!(scratch.backward.capacity(), bwd_capacity);
        assert_eq!(scratch.forward_bitset(), &[0b111]);
        assert_eq!(scratch.backward_bitset(), &[0b001]);
    }

    #[test]
    fn scc_components_chain_each_node_singleton() {
        // 0 → 1 → 2 (DAG). Every SCC is a singleton.
        let adj = vec![0, 1, 0, 0, 0, 1, 0, 0, 0];
        let comps = scc_components_via_substrate(&adj, 3);
        // Each node stamped by itself (first pivot wins).
        assert_eq!(comps, vec![0, 1, 2]);
    }

    #[test]
    fn scc_components_two_cycle_collapses_to_first_pivot() {
        // 0 → 1, 1 → 0. {0,1} is one SCC. First pivot 0 stamps both.
        let adj = vec![0, 1, 1, 0];
        let comps = scc_components_via_substrate(&adj, 2);
        assert_eq!(comps, vec![0, 0]);
    }

    #[test]
    fn scc_components_into_reuses_output_and_matches_owned() {
        let adj = vec![0, 1, 1, 0];
        let mut comps = Vec::new();
        let mut scratch = DataflowFixpointScratch::default();
        reference_scc_components_via_substrate_into(&adj, 2, &mut comps, &mut scratch);
        let comps_capacity = comps.capacity();
        let scratch_capacity = scratch.next_components.capacity();
        assert_eq!(comps, vec![0, 0]);

        reference_scc_components_via_substrate_into(&adj, 2, &mut comps, &mut scratch);
        assert_eq!(comps.capacity(), comps_capacity);
        assert_eq!(scratch.next_components.capacity(), scratch_capacity);
        assert_eq!(comps, scc_components_via_substrate(&adj, 2));
    }

    #[test]
    fn scc_components_gpu_into_reuses_output_storage() {
        let adj = vec![0, 1, 1, 0];
        let semiring_step_a = u32_slice_to_le_bytes(&[1, 0, 0, 1]);
        let semiring_step_b = u32_slice_to_le_bytes(&[1, 1, 1, 1]);
        let components_done = u32_slice_to_le_bytes(&[0, 0]);
        let dispatcher = SequenceDispatcher {
            outputs: vec![
                vec![semiring_step_a.clone()],
                vec![semiring_step_b.clone()],
                vec![semiring_step_a.clone()],
                vec![semiring_step_b.clone()],
                vec![components_done.clone()],
                vec![semiring_step_a.clone()],
                vec![semiring_step_b.clone()],
                vec![semiring_step_a],
                vec![semiring_step_b],
                vec![components_done],
            ],
            cursor: Cell::new(0),
        };
        let mut scratch = SccComponentsGpuScratch::default();
        let mut components = Vec::with_capacity(2);

        scc_components_via_substrate_with_scratch_into(
            &dispatcher,
            &adj,
            2,
            &mut scratch,
            &mut components,
        )
        .unwrap();
        let capacity = components.capacity();
        assert_eq!(components, vec![0, 0]);

        scc_components_via_substrate_with_scratch_into(
            &dispatcher,
            &adj,
            2,
            &mut scratch,
            &mut components,
        )
        .unwrap();
        assert_eq!(components.capacity(), capacity);
        assert_eq!(components, vec![0, 0]);
    }

    /// Closure-bar: the substrate-driven SCC must agree with running
    /// `scc_decompose::cpu_ref` directly with manually-prepared
    /// forward/backward bitsets. Asserts the wiring doesn't drift.
    #[test]
    fn scc_components_match_direct_primitive_call() {
        // 0 → 1 → 2 → 0 (one big cycle), 3 → 4 separate.
        let adj = vec![
            0, 1, 0, 0, 0, // 0 -> 1
            0, 0, 1, 0, 0, // 1 -> 2
            1, 0, 0, 0, 0, // 2 -> 0
            0, 0, 0, 0, 1, // 3 -> 4
            0, 0, 0, 0, 0, // 4
        ];
        let via_substrate = scc_components_via_substrate(&adj, 5);

        // Manual replay: pivot 0 stamps {0,1,2}; pivot 3 stamps {3};
        // pivot 4 stamps {4}.
        let mut manual = vec![u32::MAX; 5];
        for pivot in [0u32, 3, 4] {
            let (fwd, bwd) = forward_backward_bitsets_for_pivot(&adj, pivot, 5);
            manual = vyre_primitives::graph::scc_decompose::cpu_ref(5, &fwd, &bwd, &manual, pivot);
        }
        assert_eq!(via_substrate, manual);
        // The cycle members all carry pivot 0.
        assert_eq!(via_substrate[0..3], [0, 0, 0]);
        // Singletons keep their own pivot id.
        assert_eq!(via_substrate[3], 3);
        assert_eq!(via_substrate[4], 4);
    }

    /// Adversarial: a fully disconnected graph (no edges) must yield
    /// `[0, 1, 2, ..., n-1]` because every pivot stamps only itself.
    #[test]
    fn scc_components_no_edges_each_pivot_stamps_only_itself() {
        let n = 4;
        let adj = vec![0u32; (n * n) as usize];
        let comps = scc_components_via_substrate(&adj, n);
        assert_eq!(comps, vec![0, 1, 2, 3]);
    }

    /// Adversarial: a self-loop on a node must NOT pull other nodes
    /// into its SCC. A common bug is to over-eagerly mark every node
    /// reached via the closure's reflexive-transitive interpretation.
    #[test]
    fn scc_components_self_loop_does_not_merge_distinct_components() {
        // 0 -> 0 (self-loop), 1 isolated, 2 isolated.
        let adj = vec![1, 0, 0, 0, 0, 0, 0, 0, 0];
        let comps = scc_components_via_substrate(&adj, 3);
        assert_eq!(comps, vec![0, 1, 2]);
    }
}


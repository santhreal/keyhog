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
//! kernel-launch boundary itself is the grid-level fence  -  every
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
//!   has flushed to global memory by the time segment N+1 launches  -
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

use crate::backend::{
    BackendError, DispatchConfig, OutputBuffers, Resource, TimedDispatchResult, VyreBackend,
};

/// Walk past `Program::wrapped`'s synthetic outer Region. Real
/// programs are constructed via `wrapped`, which inserts a single
/// outer Region around the user's entry sequence; the split logic
/// must operate on the inner sequence so a `GridSync` barrier inside
/// the wrapper actually splits the program. Programs constructed
/// via `Program::new` use the entry sequence directly  -  in that
/// case we just return it unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
enum EntryWrapper {
    Region { generator: Ident },
    Block,
}

fn peel_entry_wrappers(program: &Program) -> (Vec<EntryWrapper>, &[Node]) {
    let mut wrappers = Vec::new();
    let mut entry = program.entry();
    loop {
        if entry.len() == 1 {
            match &entry[0] {
                Node::Region {
                    generator, body, ..
                } => {
                    wrappers.push(EntryWrapper::Region {
                        generator: generator.clone(),
                    });
                    entry = body.as_slice();
                    continue;
                }
                Node::Block(body) => {
                    wrappers.push(EntryWrapper::Block);
                    entry = body.as_slice();
                    continue;
                }
                _ => {}
            }
        }
        break;
    }
    (wrappers, entry)
}

fn entry_sequence(program: &Program) -> &[Node] {
    peel_entry_wrappers(program).1
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
    // O(1) negative gate: if the cached ProgramStats bitset records no
    // Barrier of any kind in the entire tree, there is definitely no
    // top-level GridSync barrier either. Skip the entry-sequence walk
    // (which itself is shallow but still pays a buffers/buffer_index
    // dispatch on every backend dispatch path).
    if !program.stats().has_node_barrier() {
        return false;
    }
    node_slice_contains_grid_sync(entry_sequence(program))
}

fn node_slice_contains_grid_sync(nodes: &[Node]) -> bool {
    nodes.iter().any(node_contains_grid_sync)
}

fn node_contains_grid_sync(node: &Node) -> bool {
    match node {
        Node::Barrier {
            ordering: MemoryOrdering::GridSync,
            ..
        } => true,
        Node::If {
            then, otherwise, ..
        } => node_slice_contains_grid_sync(then) || node_slice_contains_grid_sync(otherwise),
        Node::Loop { body, .. } | Node::Block(body) => node_slice_contains_grid_sync(body),
        Node::Region { body, .. } => node_slice_contains_grid_sync(body),
        _ => false,
    }
}

/// Split `program` at every top-level `Node::Barrier { GridSync }`.
///
/// Returns a vector of segments in execution order. The barrier nodes
/// themselves are dropped from the segments  -  the kernel-launch
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
    match try_split_on_grid_sync(program) {
        Ok(segments) => segments,
        Err(_error) => Vec::new(),
    }
}

/// Fallible variant of [`split_on_grid_sync`] for production dispatch paths.
///
/// # Errors
/// Returns an actionable [`BackendError`] if segment storage cannot be
/// reserved or if split accounting overflows.
fn hoist_grid_sync_barriers(nodes: &[Node]) -> Vec<Node> {
    let mut new_nodes = Vec::new();
    for node in nodes {
        match node {
            Node::Block(body) => {
                let new_body = hoist_grid_sync_barriers(body);
                let has_barrier = new_body.iter().any(|n| {
                    matches!(
                        n,
                        Node::Barrier {
                            ordering: MemoryOrdering::GridSync,
                            ..
                        }
                    )
                });
                if has_barrier {
                    let mut current_segment = Vec::new();
                    for b_node in new_body {
                        if matches!(
                            b_node,
                            Node::Barrier {
                                ordering: MemoryOrdering::GridSync,
                                ..
                            }
                        ) {
                            new_nodes.push(Node::Block(std::mem::take(&mut current_segment)));
                            new_nodes.push(b_node);
                        } else {
                            current_segment.push(b_node);
                        }
                    }
                    new_nodes.push(Node::Block(current_segment));
                } else {
                    new_nodes.push(Node::Block(new_body));
                }
            }
            Node::Region {
                generator,
                source_region,
                body,
            } => {
                let new_body = hoist_grid_sync_barriers(body);
                let has_barrier = new_body.iter().any(|n| {
                    matches!(
                        n,
                        Node::Barrier {
                            ordering: MemoryOrdering::GridSync,
                            ..
                        }
                    )
                });
                if has_barrier {
                    let mut current_segment = Vec::new();
                    for b_node in new_body {
                        if matches!(
                            b_node,
                            Node::Barrier {
                                ordering: MemoryOrdering::GridSync,
                                ..
                            }
                        ) {
                            new_nodes.push(Node::Region {
                                generator: generator.clone(),
                                source_region: source_region.clone(),
                                body: Arc::new(std::mem::take(&mut current_segment)),
                            });
                            new_nodes.push(b_node);
                        } else {
                            current_segment.push(b_node);
                        }
                    }
                    new_nodes.push(Node::Region {
                        generator: generator.clone(),
                        source_region: source_region.clone(),
                        body: Arc::new(current_segment),
                    });
                } else {
                    new_nodes.push(Node::Region {
                        generator: generator.clone(),
                        source_region: source_region.clone(),
                        body: Arc::new(new_body),
                    });
                }
            }
            other => {
                new_nodes.push(other.clone());
            }
        }
    }
    new_nodes
}

fn collect_global_let_bindings(nodes: &[Node], map: &mut std::collections::HashMap<String, Node>) {
    for node in nodes {
        match node {
            Node::Let { name, .. } => {
                map.insert(name.as_str().to_string(), node.clone());
            }
            Node::If {
                then, otherwise, ..
            } => {
                collect_global_let_bindings(then, map);
                collect_global_let_bindings(otherwise, map);
            }
            Node::Loop { body, .. } | Node::Block(body) => {
                collect_global_let_bindings(body, map);
            }
            Node::Region { body, .. } => {
                collect_global_let_bindings(&body[..], map);
            }
            _ => {}
        }
    }
}

fn collect_locally_defined_vars(nodes: &[Node], vars: &mut std::collections::HashSet<String>) {
    for node in nodes {
        match node {
            Node::Let { name, .. } => {
                vars.insert(name.as_str().to_string());
            }
            Node::Loop { var, body, .. } => {
                vars.insert(var.as_str().to_string());
                collect_locally_defined_vars(body, vars);
            }
            Node::If {
                then, otherwise, ..
            } => {
                collect_locally_defined_vars(then, vars);
                collect_locally_defined_vars(otherwise, vars);
            }
            Node::Block(body) => {
                collect_locally_defined_vars(body, vars);
            }
            Node::Region { body, .. } => {
                collect_locally_defined_vars(&body[..], vars);
            }
            _ => {}
        }
    }
}

use vyre_foundation::ir::Expr;

fn collect_referenced_vars(expr: &Expr, vars: &mut std::collections::HashSet<String>) {
    match expr {
        Expr::Var(name) => {
            vars.insert(name.as_str().to_string());
        }
        Expr::Load { index, .. } => {
            collect_referenced_vars(index, vars);
        }
        Expr::BinOp { left, right, .. } => {
            collect_referenced_vars(left, vars);
            collect_referenced_vars(right, vars);
        }
        Expr::UnOp { operand, .. } => {
            collect_referenced_vars(operand, vars);
        }
        Expr::Call { args, .. } => {
            for arg in args {
                collect_referenced_vars(arg, vars);
            }
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            collect_referenced_vars(cond, vars);
            collect_referenced_vars(true_val, vars);
            collect_referenced_vars(false_val, vars);
        }
        Expr::Cast { value, .. } => {
            collect_referenced_vars(value, vars);
        }
        Expr::Fma { a, b, c } => {
            collect_referenced_vars(a, vars);
            collect_referenced_vars(b, vars);
            collect_referenced_vars(c, vars);
        }
        Expr::Atomic {
            index,
            expected,
            value,
            ..
        } => {
            collect_referenced_vars(index, vars);
            if let Some(expected) = expected {
                collect_referenced_vars(expected, vars);
            }
            collect_referenced_vars(value, vars);
        }
        Expr::SubgroupBallot { cond } => {
            collect_referenced_vars(cond, vars);
        }
        Expr::SubgroupShuffle { value, lane } => {
            collect_referenced_vars(value, vars);
            collect_referenced_vars(lane, vars);
        }
        Expr::SubgroupAdd { value } => {
            collect_referenced_vars(value, vars);
        }
        _ => {}
    }
}

fn collect_node_referenced_vars(node: &Node, vars: &mut std::collections::HashSet<String>) {
    match node {
        Node::Let { value, .. } => {
            collect_referenced_vars(value, vars);
        }
        Node::Assign { value, .. } => {
            collect_referenced_vars(value, vars);
        }
        Node::Store { index, value, .. } => {
            collect_referenced_vars(index, vars);
            collect_referenced_vars(value, vars);
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            collect_referenced_vars(cond, vars);
            for n in then {
                collect_node_referenced_vars(n, vars);
            }
            for n in otherwise {
                collect_node_referenced_vars(n, vars);
            }
        }
        Node::Loop { from, to, body, .. } => {
            collect_referenced_vars(from, vars);
            collect_referenced_vars(to, vars);
            for n in body {
                collect_node_referenced_vars(n, vars);
            }
        }
        Node::Block(body) => {
            for n in body {
                collect_node_referenced_vars(n, vars);
            }
        }
        Node::Region { body, .. } => {
            for n in body.as_ref() {
                collect_node_referenced_vars(n, vars);
            }
        }
        Node::AsyncLoad { offset, size, .. } => {
            collect_referenced_vars(offset, vars);
            collect_referenced_vars(size, vars);
        }
        Node::AsyncStore { offset, size, .. } => {
            collect_referenced_vars(offset, vars);
            collect_referenced_vars(size, vars);
        }
        Node::Trap { address, .. } => {
            collect_referenced_vars(address, vars);
        }
        _ => {}
    }
}

fn resolve_dependencies(
    name: &str,
    global_lets: &std::collections::HashMap<String, Node>,
    resolved_names: &mut std::collections::HashSet<String>,
    resolved_lets: &mut Vec<Node>,
) {
    if resolved_names.contains(name) {
        return;
    }
    if let Some(let_node) = global_lets.get(name) {
        resolved_names.insert(name.to_string());
        let mut deps = std::collections::HashSet::new();
        collect_node_referenced_vars(let_node, &mut deps);
        for dep in deps {
            resolve_dependencies(&dep, global_lets, resolved_names, resolved_lets);
        }
        resolved_lets.push(let_node.clone());
    }
}

fn propagate_let_bindings(segments: &mut [Vec<Node>], hoisted_inner: &[Node]) {
    let mut global_lets = std::collections::HashMap::new();
    collect_global_let_bindings(hoisted_inner, &mut global_lets);

    for segment_nodes in segments {
        let mut locally_defined = std::collections::HashSet::new();
        collect_locally_defined_vars(segment_nodes, &mut locally_defined);

        let mut referenced = std::collections::HashSet::new();
        for node in segment_nodes.iter() {
            collect_node_referenced_vars(node, &mut referenced);
        }

        let mut free_vars = Vec::new();
        for name in referenced {
            if !locally_defined.contains(&name) {
                free_vars.push(name);
            }
        }

        let mut resolved_lets = Vec::new();
        let mut resolved_names = std::collections::HashSet::new();
        for name in free_vars {
            resolve_dependencies(&name, &global_lets, &mut resolved_names, &mut resolved_lets);
        }

        if !resolved_lets.is_empty() {
            resolved_lets.extend(std::mem::take(segment_nodes));
            *segment_nodes = resolved_lets;
        }
    }
}

/// Fallible variant of [`split_on_grid_sync`] for production dispatch paths.
///
/// # Errors
/// Returns an actionable [`BackendError`] if segment storage cannot be
/// reserved or if split accounting overflows.

pub fn try_split_on_grid_sync(program: &Program) -> Result<Vec<Program>, BackendError> {
    let (wrappers, inner) = peel_entry_wrappers(program);
    let hoisted_inner = hoist_grid_sync_barriers(inner);
    let split_count = hoisted_inner
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
        let mut segments = Vec::new();
        reserve_grid_sync_vec(&mut segments, 1, "grid-sync no-op segment")?;
        segments.push(program.clone());
        return Ok(segments);
    }

    let segment_count = split_count + 1;
    let executable_nodes = hoisted_inner.len().checked_sub(split_count).ok_or_else(|| {
        BackendError::InvalidProgram {
            fix: format!(
            "grid-sync split_count {split_count} exceeded entry node count {}. Fix: split_on_grid_sync must count barriers from the same entry sequence it segments.",
            hoisted_inner.len()
            ),
        }
    })?;
    let segment_capacity = executable_nodes.div_ceil(segment_count);

    let mut raw_segments = Vec::new();
    let mut current = Vec::new();
    reserve_grid_sync_vec(&mut current, segment_capacity, "grid-sync current segment")?;
    for node in &hoisted_inner {
        match node {
            Node::Barrier {
                ordering: MemoryOrdering::GridSync,
                ..
            } => {
                let mut next = Vec::new();
                reserve_grid_sync_vec(&mut next, segment_capacity, "grid-sync next segment")?;
                let entry = std::mem::replace(&mut current, next);
                raw_segments.push(entry);
            }
            other => {
                current.push(other.clone());
            }
        }
    }
    raw_segments.push(current);

    propagate_let_bindings(&mut raw_segments, &hoisted_inner);

    let mut segments = Vec::new();
    reserve_grid_sync_vec(
        &mut segments,
        raw_segments.len(),
        "grid-sync split segments",
    )?;
    for entry in raw_segments {
        segments.push(wrap_split_segment(program, &wrappers, entry));
    }
    Ok(segments)
}

fn wrap_split_segment(program: &Program, wrappers: &[EntryWrapper], entry: Vec<Node>) -> Program {
    // Re-wrap each segment in the same wrapper stack the source had,
    // so tagged/fused programs keep provenance and structure while the
    // executable body is split at launch boundaries.
    let mut wrapped_entry = entry;
    for wrapper in wrappers.iter().rev() {
        match wrapper {
            EntryWrapper::Region { generator } => {
                wrapped_entry = vec![Node::Region {
                    generator: generator.clone(),
                    source_region: None,
                    body: Arc::new(wrapped_entry),
                }];
            }
            EntryWrapper::Block => {
                wrapped_entry = vec![Node::Block(wrapped_entry)];
            }
        }
    }
    program.with_rewritten_entry(wrapped_entry)
}

/// Universal dispatch helper that satisfies `Node::Barrier { ordering:
/// GridSync }` on any backend by splitting at the barrier and running
/// each segment as its own kernel launch.
///
/// Backends with native cooperative-launch grid sync (advertised via
/// [`VyreBackend::supports_grid_sync`]) bypass the split  -  the
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
    reserve_grid_sync_vec(
        &mut outputs,
        program.output_buffer_indices().len().max(1),
        "grid-sync final outputs",
    )?;
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
        wall_ns: elapsed_wall_ns(started)?,
        device_ns: None,
        enqueue_ns: None,
        wait_ns: None,
    })
}

/// Resident-resource variant of [`dispatch_with_grid_sync_split_timed`].
///
/// This keeps the same resource handles bound for every segment. Read-write
/// buffers therefore refresh in place on the backend's device-resident storage
/// between segment launches instead of downloading bytes to the host and
/// re-uploading them as the next segment's inputs.
///
/// # Errors
/// Propagates any [`BackendError`] raised by a segment resident dispatch.
pub fn dispatch_resident_with_grid_sync_split_timed(
    backend: &dyn VyreBackend,
    program: &Program,
    resources: &[Resource],
    config: &DispatchConfig,
) -> Result<TimedDispatchResult, BackendError> {
    if !contains_grid_sync(program) || backend.supports_grid_sync() {
        return backend.dispatch_resident_timed(program, resources, config);
    }
    let segments = try_split_on_grid_sync(program)?;
    if segments.is_empty() {
        return Err(BackendError::InvalidProgram {
            fix: "Fix: program contains GridSync barrier but split_on_grid_sync produced 0 \
                  segments. This is a grid_sync invariant bug  -  split_on_grid_sync must \
                  always return at least one segment."
                .to_string(),
        });
    }
    let started = std::time::Instant::now();
    let mut final_outputs = Vec::new();
    let mut device_ns = Some(0_u64);
    let mut enqueue_ns = Some(0_u64);
    let mut wait_ns = Some(0_u64);
    for (segment_idx, segment) in segments.iter().enumerate() {
        let timed = backend
            .dispatch_resident_timed(segment, resources, config)
            .map_err(|error| grid_sync_segment_error(error, segment_idx, segments.len()))?;
        if segment_idx + 1 == segments.len() {
            final_outputs = timed.outputs;
        }
        device_ns = sum_optional_timing(device_ns, timed.device_ns, "device timing")?;
        enqueue_ns = sum_optional_timing(enqueue_ns, timed.enqueue_ns, "enqueue timing")?;
        wait_ns = sum_optional_timing(wait_ns, timed.wait_ns, "wait timing")?;
    }
    Ok(TimedDispatchResult {
        outputs: final_outputs,
        wall_ns: elapsed_wall_ns(started)?,
        device_ns,
        enqueue_ns,
        wait_ns,
    })
}

fn elapsed_wall_ns(started: std::time::Instant) -> Result<u64, BackendError> {
    u64::try_from(started.elapsed().as_nanos()).map_err(|error| BackendError::InvalidProgram {
        fix: format!(
            "Fix: grid-sync segmented wall timing cannot fit u64 nanoseconds: {error}. Split telemetry windows or report per-segment timing."
        ),
    })
}

fn sum_optional_timing(
    accumulator: Option<u64>,
    next: Option<u64>,
    field: &'static str,
) -> Result<Option<u64>, BackendError> {
    match (accumulator, next) {
        (Some(left), Some(right)) => Ok(Some(left.checked_add(right).ok_or_else(|| {
            BackendError::InvalidProgram {
                fix: format!(
                    "Fix: grid-sync segmented {field} overflowed u64 nanoseconds. Split telemetry windows or report per-segment timing instead of silently clamping."
                ),
            }
        })?)),
        _ => Ok(None),
    }
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
    let segments = try_split_on_grid_sync(program)?;
    if segments.is_empty() {
        return Err(BackendError::InvalidProgram {
            fix: "Fix: program contains GridSync barrier but split_on_grid_sync produced 0 \
                  segments. This is a grid_sync invariant bug  -  split_on_grid_sync must \
                  always return at least one segment."
                .to_string(),
        });
    }
    crate::observability::record_grid_sync_split(segments.len());
    // Build a mutable input set we rotate between segments. ReadOnly
    // inputs stay borrowed from the caller for the whole split; only
    // ReadWrite buffers become owned after a segment produces updated
    // bytes. The previous implementation cloned every input before
    // the first launch, which turned large read-only buffers into a
    // host-memory copy on the slow path.
    let mut current_inputs: Vec<GridSyncInput<'_>> = Vec::new();
    reserve_grid_sync_vec(
        &mut current_inputs,
        inputs.len(),
        "grid-sync rotating inputs",
    )?;
    current_inputs.extend(inputs.iter().copied().map(GridSyncInput::Borrowed));
    let mut segment_outputs = Vec::new();
    reserve_grid_sync_vec(
        &mut segment_outputs,
        outputs.capacity().max(1),
        "grid-sync intermediate outputs",
    )?;

    for (segment_idx, segment) in segments.iter().enumerate() {
        let borrowed = borrowed_grid_sync_inputs(&current_inputs)?;
        if segment_idx + 1 == segments.len() {
            return backend
                .dispatch_borrowed_into(segment, borrowed.as_slice(), config, outputs)
                .map_err(|error| grid_sync_segment_error(error, segment_idx, segments.len()));
        }
        backend
            .dispatch_borrowed_into(segment, borrowed.as_slice(), config, &mut segment_outputs)
            .map_err(|error| grid_sync_segment_error(error, segment_idx, segments.len()))?;
        drop(borrowed);
        refresh_readwrite_inputs(segment, &mut segment_outputs, &mut current_inputs)?;
    }
    Ok(())
}

fn reserve_grid_sync_vec<T>(
    vec: &mut Vec<T>,
    capacity: usize,
    field: &'static str,
) -> Result<(), BackendError> {
    crate::allocation::try_reserve_vec_to_capacity(vec, capacity).map_err(|error| {
        BackendError::InvalidProgram {
            fix: format!(
                "Fix: failed to reserve {field} for {capacity} entries during grid-sync dispatch splitting: {error}. Split the program into fewer grid-sync segments or run on a backend with native grid sync."
            ),
        }
    })
}

fn borrowed_grid_sync_inputs<'a>(
    inputs: &'a [GridSyncInput<'a>],
) -> Result<SmallVec<[&'a [u8]; 8]>, BackendError> {
    let mut borrowed = SmallVec::<[&[u8]; 8]>::new();
    borrowed.try_reserve(inputs.len()).map_err(|error| {
        BackendError::InvalidProgram {
            fix: format!(
                "Fix: failed to reserve grid-sync borrowed input slices for {} input(s): {error}. Split the program into fewer grid-sync live buffers or run on a backend with native grid sync.",
                inputs.len()
            ),
        }
    })?;
    borrowed.extend(inputs.iter().map(GridSyncInput::as_slice));
    Ok(borrowed)
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

    fn refresh_from_output(&mut self, bytes: &mut Vec<u8>) -> Result<(), BackendError> {
        match self {
            Self::Borrowed(_) => {
                let mut owned = Vec::new();
                reserve_grid_sync_vec(&mut owned, bytes.len(), "grid-sync readwrite input")?;
                owned.extend_from_slice(bytes);
                *self = Self::Owned(owned);
            }
            Self::Owned(owned) => {
                std::mem::swap(owned, bytes);
            }
        }
        Ok(())
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
) -> Result<(), BackendError> {
    use vyre_foundation::ir::BufferAccess;
    // Walk the segment's buffer table twice in lockstep  -  once for the
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
        // and NOT is_output  -  the rule scratch / `gets` case).
        if is_readwrite && !is_output_buffer {
            if let (Some(slot), Some(bytes)) =
                (inputs.get_mut(input_idx), outputs.get_mut(output_idx))
            {
                slot.refresh_from_output(bytes)?;
            }
        }

        // Advance the input cursor for every non-output buffer.
        if !is_output_buffer {
            input_idx += 1;
        }
        // Advance the output cursor for every ReadWrite buffer (output
        // or not  -  the backend includes them all in the readback).
        if is_readwrite {
            output_idx += 1;
        }
    }
    for output in outputs {
        output.clear();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
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

    #[test]
    fn grid_sync_release_paths_use_fallible_split_storage() {
        let source = include_str!("grid_sync.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("Fix: grid-sync production source must precede tests");

        assert!(
            production.contains("pub fn try_split_on_grid_sync")
                && production.contains("fn reserve_grid_sync_vec")
                && production.contains("try_reserve_vec_to_capacity"),
            "Fix: grid-sync splitting must expose fallible segment/input/output scratch reservation."
        );
        assert!(
            production.contains("let segments = try_split_on_grid_sync(program)?")
                && !production.contains("let segments = split_on_grid_sync(program);"),
            "Fix: production grid-sync dispatch paths must use fallible splitting, not the legacy infallible helper."
        );
        assert!(
            !production.contains("Vec::with_capacity"),
            "Fix: production grid-sync splitting must not allocate dispatch scratch infallibly."
        );
        assert!(
            !production.contains(".as_nanos() as u64")
                && !production.contains("segmented timing overflowed u64"),
            "Fix: production grid-sync timing telemetry must return typed errors instead of truncating or panicking."
        );
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
    fn block_nested_grid_sync_splits_into_two() {
        let program = Program::wrapped(
            vec![buffer()],
            [1, 1, 1],
            vec![Node::Block(vec![
                region("a", vec![Node::store("buf", Expr::u32(0), Expr::u32(1))]),
                Node::barrier_with_ordering(MemoryOrdering::GridSync),
                region("b", vec![Node::store("buf", Expr::u32(1), Expr::u32(2))]),
            ])],
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

    #[test]
    fn refresh_readwrite_inputs_swaps_owned_buffers_after_first_segment() {
        let segment = Program::wrapped(vec![buffer()], [1, 1, 1], vec![Node::Return]);
        let initial = [1u8, 0, 0, 0];
        let mut inputs = [GridSyncInput::Borrowed(initial.as_slice())];
        let mut outputs = vec![Vec::with_capacity(8)];
        let output_ptr = outputs[0].as_ptr() as usize;
        outputs[0].extend_from_slice(&[2, 0, 0, 0]);

        refresh_readwrite_inputs(&segment, &mut outputs, &mut inputs)
            .expect("Fix: test readwrite refresh should fit borrowed promotion storage");

        let first_owned_ptr = match &inputs[0] {
            GridSyncInput::Owned(bytes) => {
                assert_eq!(bytes, &[2, 0, 0, 0]);
                bytes.as_ptr() as usize
            }
            GridSyncInput::Borrowed(_) => panic!("ReadWrite input must become owned after refresh"),
        };
        assert_eq!(outputs[0].as_ptr() as usize, output_ptr);
        assert!(outputs[0].is_empty());

        outputs[0].extend_from_slice(&[3, 0, 0, 0]);
        let second_output_ptr = outputs[0].as_ptr() as usize;
        refresh_readwrite_inputs(&segment, &mut outputs, &mut inputs)
            .expect("Fix: test readwrite refresh should reuse owned storage");

        match &inputs[0] {
            GridSyncInput::Owned(bytes) => {
                assert_eq!(bytes, &[3, 0, 0, 0]);
                assert_eq!(
                    bytes.as_ptr() as usize,
                    second_output_ptr,
                    "owned ReadWrite input should take the backend output allocation instead of copying"
                );
            }
            GridSyncInput::Borrowed(_) => panic!("ReadWrite input must remain owned"),
        }
        assert_eq!(
            outputs[0].as_ptr() as usize,
            first_owned_ptr,
            "backend output slot should receive the previous owned input allocation for reuse"
        );
    }

    struct ReuseCheckingBackend {
        calls: AtomicUsize,
        final_outputs_addr: usize,
        final_slot_addr: usize,
    }

    impl crate::backend::private::Sealed for ReuseCheckingBackend {}

    impl VyreBackend for ReuseCheckingBackend {
        fn id(&self) -> &'static str {
            "grid-sync-reuse-checking"
        }

        fn dispatch(
            &self,
            _program: &Program,
            _inputs: &[Vec<u8>],
            _config: &DispatchConfig,
        ) -> Result<Vec<Vec<u8>>, BackendError> {
            unreachable!("test uses dispatch_borrowed_into")
        }

        fn dispatch_borrowed_into(
            &self,
            _program: &Program,
            inputs: &[&[u8]],
            _config: &DispatchConfig,
            outputs: &mut OutputBuffers,
        ) -> Result<(), BackendError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 1 && self.final_outputs_addr != 0 {
                assert_eq!(outputs.as_ptr() as usize, self.final_outputs_addr);
                assert_eq!(outputs[0].as_ptr() as usize, self.final_slot_addr);
            }
            if outputs.is_empty() {
                outputs.push(Vec::new());
            }
            outputs[0].clear();
            outputs[0].extend_from_slice(inputs[0]);
            if call == 0 {
                outputs[0][0] = 7;
            } else {
                outputs[0][0] = outputs[0][0].saturating_add(1);
            }
            Ok(())
        }
    }

    #[test]
    fn split_into_preserves_caller_output_slot_for_final_segment() {
        let program = Program::wrapped(
            vec![buffer()],
            [1, 1, 1],
            vec![
                region("a", vec![Node::Return]),
                Node::barrier_with_ordering(MemoryOrdering::GridSync),
                region("b", vec![Node::Return]),
            ],
        );
        let mut outputs = vec![Vec::with_capacity(8)];
        let outputs_addr = outputs.as_ptr() as usize;
        let slot_addr = outputs[0].as_ptr() as usize;
        let backend = ReuseCheckingBackend {
            calls: AtomicUsize::new(0),
            final_outputs_addr: outputs_addr,
            final_slot_addr: slot_addr,
        };
        let input = [0u8, 0, 0, 0];
        dispatch_with_grid_sync_split_into(
            &backend,
            &program,
            &[input.as_slice()],
            &DispatchConfig::default(),
            &mut outputs,
        )
        .expect("Fix: grid-sync split should write into caller-owned output storage");

        assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
        assert_eq!(outputs, vec![vec![8, 0, 0, 0]]);
        assert_eq!(outputs.as_ptr() as usize, outputs_addr);
        assert_eq!(outputs[0].as_ptr() as usize, slot_addr);
    }

    struct OwnedFinalReserveBackend {
        calls: AtomicUsize,
    }

    impl crate::backend::private::Sealed for OwnedFinalReserveBackend {}

    impl VyreBackend for OwnedFinalReserveBackend {
        fn id(&self) -> &'static str {
            "grid-sync-owned-final-reserve"
        }

        fn dispatch(
            &self,
            _program: &Program,
            _inputs: &[Vec<u8>],
            _config: &DispatchConfig,
        ) -> Result<Vec<Vec<u8>>, BackendError> {
            unreachable!("test uses dispatch_borrowed_into")
        }

        fn dispatch_borrowed_into(
            &self,
            _program: &Program,
            inputs: &[&[u8]],
            _config: &DispatchConfig,
            outputs: &mut OutputBuffers,
        ) -> Result<(), BackendError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if call == 1 {
                assert!(
                    outputs.capacity() >= 1,
                    "owned grid-sync split wrapper must pre-reserve final output slots before the final segment dispatch"
                );
            }
            if outputs.is_empty() {
                outputs.push(Vec::new());
            }
            outputs[0].clear();
            outputs[0].extend_from_slice(inputs[0]);
            outputs[0][0] = outputs[0][0].saturating_add(1);
            Ok(())
        }
    }

    #[test]
    fn split_owned_wrapper_reserves_final_output_vector_before_final_segment() {
        let program = Program::wrapped(
            vec![buffer()],
            [1, 1, 1],
            vec![
                region("a", vec![Node::Return]),
                Node::barrier_with_ordering(MemoryOrdering::GridSync),
                region("b", vec![Node::Return]),
            ],
        );
        let backend = OwnedFinalReserveBackend {
            calls: AtomicUsize::new(0),
        };
        let input = [4u8, 0, 0, 0];

        let outputs = dispatch_with_grid_sync_split(
            &backend,
            &program,
            &[input.as_slice()],
            &DispatchConfig::default(),
        )
        .expect("Fix: owned grid-sync split should reserve and return final outputs");

        assert_eq!(backend.calls.load(Ordering::SeqCst), 2);
        assert_eq!(outputs, vec![vec![6, 0, 0, 0]]);
    }

    #[test]
    fn grid_sync_split_records_segment_telemetry() {
        let program = Program::wrapped(
            vec![buffer()],
            [1, 1, 1],
            vec![
                region("a", vec![Node::Return]),
                Node::barrier_with_ordering(MemoryOrdering::GridSync),
                region("b", vec![Node::Return]),
                Node::barrier_with_ordering(MemoryOrdering::GridSync),
                region("c", vec![Node::Return]),
            ],
        );
        let backend = ReuseCheckingBackend {
            calls: AtomicUsize::new(0),
            final_outputs_addr: 0,
            final_slot_addr: 0,
        };
        let before = crate::observability::snapshot_dispatch_telemetry();
        let input = [0u8, 0, 0, 0];
        let mut outputs = Vec::new();

        dispatch_with_grid_sync_split_into(
            &backend,
            &program,
            &[input.as_slice()],
            &DispatchConfig::default(),
            &mut outputs,
        )
        .expect("Fix: grid-sync split should dispatch every segment");

        let after = crate::observability::snapshot_dispatch_telemetry();
        assert_eq!(backend.calls.load(Ordering::SeqCst), 3);
        assert!(after.grid_sync_splits >= before.grid_sync_splits + 1);
        assert!(after.grid_sync_segments >= before.grid_sync_segments + 3);
        assert!(after.grid_sync_points >= before.grid_sync_points + 2);
    }

    struct IntermediateReuseBackend {
        calls: AtomicUsize,
        first_outputs_addr: AtomicUsize,
        first_slot_addr: AtomicUsize,
    }

    impl crate::backend::private::Sealed for IntermediateReuseBackend {}

    impl VyreBackend for IntermediateReuseBackend {
        fn id(&self) -> &'static str {
            "grid-sync-intermediate-reuse"
        }

        fn dispatch(
            &self,
            _program: &Program,
            _inputs: &[Vec<u8>],
            _config: &DispatchConfig,
        ) -> Result<Vec<Vec<u8>>, BackendError> {
            unreachable!("test uses dispatch_borrowed_into")
        }

        fn dispatch_borrowed_into(
            &self,
            _program: &Program,
            inputs: &[&[u8]],
            _config: &DispatchConfig,
            outputs: &mut OutputBuffers,
        ) -> Result<(), BackendError> {
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            if outputs.is_empty() {
                outputs.push(Vec::with_capacity(8));
            }
            if call == 0 {
                self.first_outputs_addr
                    .store(outputs.as_ptr() as usize, Ordering::SeqCst);
                self.first_slot_addr
                    .store(outputs[0].as_ptr() as usize, Ordering::SeqCst);
            } else if call == 1 {
                assert_eq!(
                    outputs.as_ptr() as usize,
                    self.first_outputs_addr.load(Ordering::SeqCst)
                );
                assert_eq!(
                    outputs[0].as_ptr() as usize,
                    self.first_slot_addr.load(Ordering::SeqCst)
                );
            }
            outputs[0].clear();
            outputs[0].extend_from_slice(inputs[0]);
            outputs[0][0] = outputs[0][0].saturating_add(1);
            Ok(())
        }
    }

    #[test]
    fn split_reuses_intermediate_output_slot_between_segments() {
        let program = Program::wrapped(
            vec![buffer()],
            [1, 1, 1],
            vec![
                region("a", vec![Node::Return]),
                Node::barrier_with_ordering(MemoryOrdering::GridSync),
                region("b", vec![Node::Return]),
                Node::barrier_with_ordering(MemoryOrdering::GridSync),
                region("c", vec![Node::Return]),
            ],
        );
        let backend = IntermediateReuseBackend {
            calls: AtomicUsize::new(0),
            first_outputs_addr: AtomicUsize::new(0),
            first_slot_addr: AtomicUsize::new(0),
        };
        let input = [1u8, 0, 0, 0];
        let mut outputs = vec![Vec::with_capacity(8)];

        dispatch_with_grid_sync_split_into(
            &backend,
            &program,
            &[input.as_slice()],
            &DispatchConfig::default(),
            &mut outputs,
        )
        .expect("Fix: grid-sync split should reuse intermediate output scratch");

        assert_eq!(backend.calls.load(Ordering::SeqCst), 3);
        assert_eq!(outputs, vec![vec![4, 0, 0, 0]]);
    }

    struct ResidentReuseBackend {
        calls: AtomicUsize,
    }

    impl crate::backend::private::Sealed for ResidentReuseBackend {}

    impl VyreBackend for ResidentReuseBackend {
        fn id(&self) -> &'static str {
            "grid-sync-resident-reuse"
        }

        fn dispatch(
            &self,
            _program: &Program,
            _inputs: &[Vec<u8>],
            _config: &DispatchConfig,
        ) -> Result<Vec<Vec<u8>>, BackendError> {
            unreachable!("test uses dispatch_resident_timed")
        }

        fn dispatch_borrowed_into(
            &self,
            _program: &Program,
            _inputs: &[&[u8]],
            _config: &DispatchConfig,
            _outputs: &mut OutputBuffers,
        ) -> Result<(), BackendError> {
            unreachable!("resident grid-sync split must not refresh through host borrowed inputs")
        }

        fn dispatch_resident_timed(
            &self,
            _program: &Program,
            resources: &[Resource],
            _config: &DispatchConfig,
        ) -> Result<TimedDispatchResult, BackendError> {
            assert!(
                matches!(resources, [Resource::Resident(11), Resource::Resident(22)]),
                "Fix: resident grid-sync split must keep the original device handles bound across every segment."
            );
            let call = self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(TimedDispatchResult {
                outputs: vec![vec![call as u8]],
                wall_ns: 10,
                device_ns: Some(2),
                enqueue_ns: Some(3),
                wait_ns: Some(4),
            })
        }
    }

    #[test]
    fn resident_split_reuses_same_device_resources_across_segments() {
        let program = Program::wrapped(
            vec![buffer()],
            [1, 1, 1],
            vec![
                region("a", vec![Node::Return]),
                Node::barrier_with_ordering(MemoryOrdering::GridSync),
                region("b", vec![Node::Return]),
                Node::barrier_with_ordering(MemoryOrdering::GridSync),
                region("c", vec![Node::Return]),
            ],
        );
        let backend = ResidentReuseBackend {
            calls: AtomicUsize::new(0),
        };

        let timed = dispatch_resident_with_grid_sync_split_timed(
            &backend,
            &program,
            &[Resource::Resident(11), Resource::Resident(22)],
            &DispatchConfig::default(),
        )
        .expect("Fix: resident grid-sync split should run each segment on the same device handles");

        assert_eq!(backend.calls.load(Ordering::SeqCst), 3);
        assert_eq!(timed.outputs, vec![vec![2]]);
        assert_eq!(timed.device_ns, Some(6));
        assert_eq!(timed.enqueue_ns, Some(9));
        assert_eq!(timed.wait_ns, Some(12));
    }
}


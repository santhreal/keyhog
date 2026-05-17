//! Core `fuse_programs` family + multi-program implementation.

use rustc_hash::{FxHashMap, FxHashSet};
use std::sync::Arc;

use crate::execution_plan::SchedulingPolicy;
use crate::ir::{BufferAccess, BufferDecl, Expr, Ident, Node, Program};

use super::collectors::{
    collect_atomic_targets_from_node, collect_load_targets_from_node,
    collect_store_targets_from_node,
};
use super::divergence::has_divergent_invocation_gated_store;
use super::helpers::{fallback_composition_key, upgrade_buffer_access};
use super::{FusionError, FusionOverDispatchError, FusionSelfAliasingError};

/// Combine `programs` into one fused [`Program`]. Returns the input verbatim
/// for 0 or 1 program; multi-program runs go through the full hazard tracker.
///
/// # Errors
///
/// Returns [`FusionError`] when the batch contains conflicting buffer aliases,
/// non-composable self-fusion, or over-dispatches the shared launch geometry.
pub fn fuse_programs(programs: &[Program]) -> Result<Program, FusionError> {
    match programs.len() {
        0 => Ok(Program::empty()),
        1 => Ok(programs[0].clone()),
        _ => fuse_programs_multi(programs),
    }
}

/// Fuse `programs` when the caller already owns a `Vec`.
///
/// For a single program this returns that value directly (no deep clone).
/// Multi-arm batches delegate to the same implementation as [`fuse_programs`].
#[inline]
#[must_use]
pub fn fuse_programs_vec(mut programs: Vec<Program>) -> Result<Program, FusionError> {
    match programs.len() {
        0 => Ok(Program::empty()),
        1 => {
            let Some(program) = programs.pop() else {
                return Ok(Program::empty());
            };
            Ok(program)
        }
        _ => fuse_programs_multi(programs.as_slice()),
    }
}

fn fuse_programs_multi(programs: &[Program]) -> Result<Program, FusionError> {
    // ------------------------------------------------------------------
    // F-IR-23: self-composition gate  (O(P) single pass)
    // ------------------------------------------------------------------
    let mut seen_op_ids: FxHashMap<String, bool> = FxHashMap::default();
    for prog in programs {
        let key = prog
            .entry_op_id()
            .map(|s| s.to_string())
            .unwrap_or_else(|| fallback_composition_key(prog));
        let is_non_comp = prog.is_non_composable_with_self();
        match seen_op_ids.get_mut(&key) {
            Some(has_non_comp) => {
                if *has_non_comp || is_non_comp {
                    return Err(FusionError::SelfAliasing(FusionSelfAliasingError {
                        op_id: key,
                        fix: "rename the second parser's workgroup buffer or split into two separate dispatches",
                    }));
                }
            }
            None => {
                seen_op_ids.insert(key, is_non_comp);
            }
        }
    }

    // ------------------------------------------------------------------
    // Single pass over programs: collect entries, atomics, buffers,
    // hazards, and workgroup size in one go.
    // ------------------------------------------------------------------
    let mut merged_buffers: Vec<BufferDecl> = Vec::new();
    let mut name_to_index: FxHashMap<Ident, usize> = FxHashMap::default();
    let mut next_binding = 0_u32;

    let mut read_arms_per_buffer: FxHashMap<Ident, Vec<usize>> = FxHashMap::default();
    // Track write-arm history per buffer so a later READER can force
    // a barrier after the earlier writer. Without this, the fused
    // kernel runs writer + reader in the same launch with no
    // synchronization, and the reader sees stale data from threads
    // that haven't completed the writer's body yet — the exact
    // "stack_overflow_gets misses node 39" mode.
    let mut write_arms_per_buffer: FxHashMap<Ident, Vec<usize>> = FxHashMap::default();
    let mut barrier_after_arm: FxHashSet<usize> = FxHashSet::default();
    // Arms whose body contains a divergent store gated on InvocationId
    // (e.g. `if invocation_id == 0 { ... store ... }`). Workgroup-only
    // barriers (`SeqCst`) cannot propagate those writes across blocks —
    // a `bar.sync 0` waits for threads in the SAME block but issues no
    // grid-level fence. When the next arm reads what the divergent
    // store wrote, the barrier MUST upgrade to `MemoryOrdering::GridSync`
    // so the runtime kernel-split fallback flushes globally. This is
    // the recall=37.5% / "node 1000 doesn't fire" failure on the
    // surgec stack_overflow_gets rule, isolated 2026-04-30 in
    // `weir/tests/df_three_arm_fusion.rs`.
    let mut divergent_store_arms: FxHashSet<usize> = FxHashSet::default();

    let mut fused_workgroup = [1u32, 1, 1];
    let mut max_arm_threads: u64 = 1;

    let mut arm_entries: Vec<Vec<Node>> = Vec::with_capacity(programs.len());

    for (arm_idx, prog) in programs.iter().enumerate() {
        // Walk entry nodes once: clone into segment and collect both
        // atomic targets (writes) and Load targets (reads). Buffers
        // referenced inside the body but NOT declared in the arm's
        // own `buffers()` table — produced by an earlier arm — only
        // surface here. Without this, RAW hazards across arms that
        // read shared scalars (e.g. broadcast reading the scalar
        // written by a single-thread `bitset_any`) get no barrier
        // and silently produce stale reads on threads that haven't
        // observed the writer's flush.
        let entry = prog.entry();
        let mut segment = Vec::with_capacity(entry.len());
        let mut atomic_targets: FxHashSet<Ident> = FxHashSet::default();
        let mut load_targets: FxHashSet<Ident> = FxHashSet::default();
        let mut store_targets: FxHashSet<Ident> = FxHashSet::default();
        let mut divergent_store_seen = false;
        for node in entry {
            push_alpha_renamed_arm_entry_node(&mut segment, node, arm_idx);
            collect_atomic_targets_from_node(node, &mut atomic_targets);
            collect_load_targets_from_node(node, &mut load_targets);
            collect_store_targets_from_node(node, &mut store_targets);
            if has_divergent_invocation_gated_store(node, false) {
                divergent_store_seen = true;
            }
        }
        if divergent_store_seen {
            divergent_store_arms.insert(arm_idx);
        }
        arm_entries.push(segment);

        // Classify this arm's buffer accesses.
        let mut arm_reads: FxHashSet<Ident> = FxHashSet::default();
        let mut arm_explicit_writes: FxHashSet<Ident> = FxHashSet::default();

        for buf in prog.buffers() {
            let name = Ident::from(buf.name());
            match buf.access() {
                BufferAccess::ReadOnly | BufferAccess::Uniform => {
                    arm_reads.insert(name.clone());
                }
                BufferAccess::ReadWrite => {
                    arm_explicit_writes.insert(name.clone());
                }
                _ => {}
            }

            // Merge into shared buffer table. Take MAX of declared
            // counts so a later arm declaring a larger ceiling (e.g.
            // resolve_family's `pg_node_tags` count=65536) lifts an
            // earlier under-sized declaration (e.g. standard_buffers
            // count=0). Ignoring count in the merge silently capped
            // reads at the first-seen size and dropped recall on
            // every node id past that ceiling.
            if let Some(&idx) = name_to_index.get(&name) {
                let existing = &mut merged_buffers[idx];
                upgrade_buffer_access(existing, buf.access());
                if buf.count > existing.count {
                    existing.count = buf.count;
                }
                if buf.is_output() {
                    existing.is_output = true;
                    existing.pipeline_live_out = true;
                }
            } else {
                let mut merged = buf.clone();
                if merged.access() != BufferAccess::Workgroup {
                    merged.binding = next_binding;
                    next_binding += 1;
                }
                name_to_index.insert(Ident::from(merged.name()), merged_buffers.len());
                merged_buffers.push(merged);
            }
        }

        // Body-level reads from buffers declared by EARLIER arms.
        // The arm's own buffers().iter() loop already populated
        // `arm_reads` for declared ReadOnly inputs; this adds any
        // additional reads inferred from `Expr::Load` references.
        for target in &load_targets {
            arm_reads.insert(target.clone());
        }
        // Body-level stores to buffers declared by earlier arms.
        for target in &store_targets {
            arm_explicit_writes.insert(target.clone());
        }

        // Atomic writes count only for buffers not already read or explicitly written.
        let mut arm_writes = arm_explicit_writes.clone();
        for target in &atomic_targets {
            if !arm_reads.contains(target) && !arm_explicit_writes.contains(target) {
                arm_writes.insert(target.clone());
            }
        }

        // F-IR-22: WAR hazard — for each buffer this arm writes, if
        // any previous arm read it, mark a barrier after every such
        // earlier read arm so the new write can't clobber the read.
        for write_buf in &arm_writes {
            if let Some(read_arms) = read_arms_per_buffer.get(write_buf) {
                for &read_arm in read_arms {
                    barrier_after_arm.insert(read_arm);
                }
            }
        }

        // RAW hazard — for each buffer this arm reads, if any
        // previous arm wrote it, the writer's results must be
        // visible before this read. Insert a barrier after every
        // such earlier writer arm. Required because the fused
        // kernel runs as one backend launch; without a barrier,
        // threads in this arm may execute the load before the
        // writer arm's threads have completed their store, yielding
        // stale data and silently dropping rule findings (recall=0
        // mode previously observed on `stack_overflow_gets` for
        // node ids past the warp boundary).
        for read_buf in &arm_reads {
            if let Some(write_arms) = write_arms_per_buffer.get(read_buf) {
                for &write_arm in write_arms {
                    barrier_after_arm.insert(write_arm);
                }
            }
        }

        // Update read tracking for later arms.
        for read_buf in &arm_reads {
            read_arms_per_buffer
                .entry(read_buf.clone())
                .or_default()
                .push(arm_idx);
        }
        // Update write tracking for later RAW detection.
        for write_buf in &arm_writes {
            write_arms_per_buffer
                .entry(write_buf.clone())
                .or_default()
                .push(arm_idx);
        }

        // Workgroup size tracking.
        let wg = prog.workgroup_size();
        fused_workgroup[0] = fused_workgroup[0].max(wg[0]);
        fused_workgroup[1] = fused_workgroup[1].max(wg[1]);
        fused_workgroup[2] = fused_workgroup[2].max(wg[2]);
        let arm_threads = u64::from(wg[0]) * u64::from(wg[1]) * u64::from(wg[2]);
        max_arm_threads = max_arm_threads.max(arm_threads);
    }

    // ------------------------------------------------------------------
    // Flatten per-arm segments, splicing barriers where required.
    // ------------------------------------------------------------------
    let total_nodes: usize = arm_entries.iter().map(|s| s.len()).sum();
    let mut combined_entry: Vec<Node> = Vec::with_capacity(total_nodes + programs.len());
    for (arm_idx, segment) in arm_entries.into_iter().enumerate() {
        combined_entry.push(Node::Block(segment));
        if barrier_after_arm.contains(&arm_idx) {
            let ordering = if divergent_store_arms.contains(&arm_idx) {
                crate::memory_model::MemoryOrdering::GridSync
            } else {
                crate::memory_model::MemoryOrdering::SeqCst
            };
            combined_entry.push(Node::barrier_with_ordering(ordering));
        }
    }

    // CRITIQUE_FIX_REVIEW_2026-04-23 Finding #16: the fused kernel's
    // launch geometry is not `[1, 1, 1]` — it must cover every
    // original arm's requested dimensions so none of them under-
    // dispatch.
    //
    // VYRE_OPTIMIZER HIGH-03: the axis-wise max is correct but
    // pathological when arms are orthogonal — fusing `[1024,1,1]`
    // with `[1,1024,1]` yields `[1024,1024,1]` = 1 M threads where
    // the arms each wanted 1024. Reject fusion when the fused
    // total exceeds the shared scheduling policy's over-dispatch
    // multiplier relative to the largest
    // individual arm's thread count so callers fall back to
    // per-arm dispatch instead of paying a 1000× over-dispatch.
    let fused_threads = u64::from(fused_workgroup[0])
        * u64::from(fused_workgroup[1])
        * u64::from(fused_workgroup[2]);
    let policy = SchedulingPolicy::standard();
    if !policy.allow_fused_threads(fused_threads, max_arm_threads) {
        return Err(FusionError::OverDispatch(FusionOverDispatchError {
            max_arm_threads,
            fused_threads,
            fix: "split the batch or use per-arm dispatch; axis-wise max exceeds the shared over-dispatch policy",
        }));
    }
    Ok(Program::wrapped(
        merged_buffers,
        fused_workgroup,
        combined_entry,
    ))
}

fn push_alpha_renamed_arm_entry_node(out: &mut Vec<Node>, node: &Node, arm_idx: usize) {
    match node {
        Node::Region { body, .. } => out.extend(alpha_rename_arm_nodes(body, arm_idx)),
        _ => out.push(alpha_rename_arm_node(node, arm_idx)),
    }
}

fn alpha_rename_arm_node(node: &Node, arm_idx: usize) -> Node {
    match node {
        Node::Let { name, value } => Node::Let {
            name: arm_local_ident(arm_idx, name),
            value: alpha_rename_arm_expr(value, arm_idx),
        },
        Node::Assign { name, value } => Node::Assign {
            name: arm_local_ident(arm_idx, name),
            value: alpha_rename_arm_expr(value, arm_idx),
        },
        Node::Store {
            buffer,
            index,
            value,
        } => Node::Store {
            buffer: buffer.clone(),
            index: alpha_rename_arm_expr(index, arm_idx),
            value: alpha_rename_arm_expr(value, arm_idx),
        },
        Node::If {
            cond,
            then,
            otherwise,
        } => Node::If {
            cond: alpha_rename_arm_expr(cond, arm_idx),
            then: alpha_rename_arm_nodes(then, arm_idx),
            otherwise: alpha_rename_arm_nodes(otherwise, arm_idx),
        },
        Node::Loop {
            var,
            from,
            to,
            body,
        } => Node::Loop {
            var: arm_local_ident(arm_idx, var),
            from: alpha_rename_arm_expr(from, arm_idx),
            to: alpha_rename_arm_expr(to, arm_idx),
            body: alpha_rename_arm_nodes(body, arm_idx),
        },
        Node::Block(body) => Node::Block(alpha_rename_arm_nodes(body, arm_idx)),
        Node::Region {
            generator,
            source_region,
            body,
        } => Node::Region {
            generator: generator.clone(),
            source_region: source_region.clone(),
            body: Arc::new(alpha_rename_arm_nodes(body, arm_idx)),
        },
        Node::AsyncLoad {
            source,
            destination,
            offset,
            size,
            tag,
        } => Node::AsyncLoad {
            source: source.clone(),
            destination: destination.clone(),
            offset: Box::new(alpha_rename_arm_expr(offset, arm_idx)),
            size: Box::new(alpha_rename_arm_expr(size, arm_idx)),
            tag: arm_local_ident(arm_idx, tag),
        },
        Node::AsyncStore {
            source,
            destination,
            offset,
            size,
            tag,
        } => Node::AsyncStore {
            source: source.clone(),
            destination: destination.clone(),
            offset: Box::new(alpha_rename_arm_expr(offset, arm_idx)),
            size: Box::new(alpha_rename_arm_expr(size, arm_idx)),
            tag: arm_local_ident(arm_idx, tag),
        },
        Node::AsyncWait { tag } => Node::AsyncWait {
            tag: arm_local_ident(arm_idx, tag),
        },
        Node::Trap { address, tag } => Node::Trap {
            address: Box::new(alpha_rename_arm_expr(address, arm_idx)),
            tag: arm_local_ident(arm_idx, tag),
        },
        Node::Resume { tag } => Node::Resume {
            tag: arm_local_ident(arm_idx, tag),
        },
        Node::IndirectDispatch {
            count_buffer,
            count_offset,
        } => Node::IndirectDispatch {
            count_buffer: count_buffer.clone(),
            count_offset: *count_offset,
        },
        Node::Return => Node::Return,
        Node::Barrier { ordering } => Node::barrier_with_ordering(*ordering),
        Node::Opaque(extension) => Node::Opaque(Arc::clone(extension)),
    }
}

fn alpha_rename_arm_nodes(nodes: &[Node], arm_idx: usize) -> Vec<Node> {
    nodes
        .iter()
        .map(|node| alpha_rename_arm_node(node, arm_idx))
        .collect()
}

fn alpha_rename_arm_expr(expr: &Expr, arm_idx: usize) -> Expr {
    match expr {
        Expr::Var(name) => Expr::Var(arm_local_ident(arm_idx, name)),
        Expr::Load { buffer, index } => Expr::Load {
            buffer: buffer.clone(),
            index: Box::new(alpha_rename_arm_expr(index, arm_idx)),
        },
        Expr::BufLen { buffer } => Expr::BufLen {
            buffer: buffer.clone(),
        },
        Expr::BinOp { op, left, right } => Expr::BinOp {
            op: *op,
            left: Box::new(alpha_rename_arm_expr(left, arm_idx)),
            right: Box::new(alpha_rename_arm_expr(right, arm_idx)),
        },
        Expr::UnOp { op, operand } => Expr::UnOp {
            op: op.clone(),
            operand: Box::new(alpha_rename_arm_expr(operand, arm_idx)),
        },
        Expr::Call { op_id, args } => Expr::Call {
            op_id: op_id.clone(),
            args: args
                .iter()
                .map(|arg| alpha_rename_arm_expr(arg, arm_idx))
                .collect(),
        },
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => Expr::Select {
            cond: Box::new(alpha_rename_arm_expr(cond, arm_idx)),
            true_val: Box::new(alpha_rename_arm_expr(true_val, arm_idx)),
            false_val: Box::new(alpha_rename_arm_expr(false_val, arm_idx)),
        },
        Expr::Cast { target, value } => Expr::Cast {
            target: target.clone(),
            value: Box::new(alpha_rename_arm_expr(value, arm_idx)),
        },
        Expr::Fma { a, b, c } => Expr::Fma {
            a: Box::new(alpha_rename_arm_expr(a, arm_idx)),
            b: Box::new(alpha_rename_arm_expr(b, arm_idx)),
            c: Box::new(alpha_rename_arm_expr(c, arm_idx)),
        },
        Expr::Atomic {
            op,
            buffer,
            index,
            expected,
            value,
            ordering,
        } => Expr::Atomic {
            op: *op,
            buffer: buffer.clone(),
            index: Box::new(alpha_rename_arm_expr(index, arm_idx)),
            expected: expected
                .as_ref()
                .map(|expr| Box::new(alpha_rename_arm_expr(expr, arm_idx))),
            value: Box::new(alpha_rename_arm_expr(value, arm_idx)),
            ordering: *ordering,
        },
        Expr::SubgroupBallot { cond } => Expr::SubgroupBallot {
            cond: Box::new(alpha_rename_arm_expr(cond, arm_idx)),
        },
        Expr::SubgroupShuffle { value, lane } => Expr::SubgroupShuffle {
            value: Box::new(alpha_rename_arm_expr(value, arm_idx)),
            lane: Box::new(alpha_rename_arm_expr(lane, arm_idx)),
        },
        Expr::SubgroupAdd { value } => Expr::SubgroupAdd {
            value: Box::new(alpha_rename_arm_expr(value, arm_idx)),
        },
        Expr::LitU32(_)
        | Expr::LitI32(_)
        | Expr::LitF32(_)
        | Expr::LitBool(_)
        | Expr::InvocationId { .. }
        | Expr::WorkgroupId { .. }
        | Expr::LocalId { .. }
        | Expr::SubgroupLocalId
        | Expr::SubgroupSize
        | Expr::Opaque(_) => expr.clone(),
    }
}

fn arm_local_ident(arm_idx: usize, name: &Ident) -> Ident {
    Ident::from(format!("__vyre_fuse_a{arm_idx}_{}", name.as_str()))
}

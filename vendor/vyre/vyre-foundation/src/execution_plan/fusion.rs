#![allow(clippy::unwrap_used)]
//! Fuse multiple independent Programs into a single combined Program.
//!
//! This is the cross-dispatch fusion layer that the megakernel builder and
//! rule-composition pipeline use to collapse sibling dispatches into one
//! kernel body.  It is **not** the expression-level fusion pass
//! (`optimizer::passes::fusion`) — that pass lives inside one Program.
//!
//! # Safety invariants
//!
//! * Every buffer name that appears in more than one arm is treated as the
//!   *same* physical GPU buffer.  The caller must ensure this is intentional.
//! * Access-mode upgrades are applied automatically (ReadOnly → ReadWrite)
//!   when any arm needs to write.
//! * A `Node::Barrier` is inserted between arms when a later arm writes a
//!   buffer that an earlier arm reads, preventing write-after-read corruption.
//! * Programs marked `non_composable_with_self` cannot be fused with another
//!   copy of the same `entry_op_id`.

use crate::execution_plan::SchedulingPolicy;
use crate::ir::{BufferAccess, BufferDecl, Expr, Node, Program};
use rustc_hash::{FxHashMap, FxHashSet};

/// Error returned when a fusion batch cannot be combined safely.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FusionError {
    /// Two copies of a non-composable parser were placed in the same batch.
    SelfAliasing(FusionSelfAliasingError),
    /// A cross-arm buffer alias was detected that cannot be fixed by a
    /// barrier (e.g. both arms write the same buffer without an intervening
    /// read-only phase).
    Aliasing(FusionAliasingError),
    /// The fused launch geometry would over-dispatch the largest arm by
    /// more than the shared scheduling policy allows. Caller should fall back
    /// to per-arm dispatch or split the batch.
    OverDispatch(FusionOverDispatchError),
}

impl std::fmt::Display for FusionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FusionError::SelfAliasing(e) => write!(f, "{e}"),
            FusionError::Aliasing(e) => write!(f, "{e}"),
            FusionError::OverDispatch(e) => write!(f, "{e}"),
        }
    }
}

/// Axis-wise workgroup-max would over-dispatch far above any single arm.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FusionOverDispatchError {
    /// Total threads required by the largest single arm.
    pub max_arm_threads: u64,
    /// Total threads the fused launch geometry would request.
    pub fused_threads: u64,
    /// Actionable fix hint.
    pub fix: &'static str,
}

impl std::fmt::Display for FusionOverDispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "fusion would over-dispatch: fused geometry launches {} threads vs largest single arm {}. Fix: {}",
            self.fused_threads, self.max_arm_threads, self.fix
        )
    }
}

impl std::error::Error for FusionError {}

/// Two copies of the same parser appeared in one fusion batch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FusionSelfAliasingError {
    /// Operation id shared by both programs.
    pub op_id: String,
    /// Actionable fix hint.
    pub fix: &'static str,
}

impl std::fmt::Display for FusionSelfAliasingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "fusion self-aliasing on op_id `{}`: two copies of a non-composable parser were fused. Fix: {}",
            self.op_id, self.fix
        )
    }
}

/// Cross-arm buffer access hazard that cannot be repaired automatically.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FusionAliasingError {
    /// Buffer involved in the hazard.
    pub buffer_name: String,
    /// Index of the arm that reads the buffer.
    pub read_arm: usize,
    /// Index of the arm that writes the buffer.
    pub write_arm: usize,
    /// Actionable fix hint.
    pub fix_hint: &'static str,
}

impl std::fmt::Display for FusionAliasingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "fusion aliasing on buffer `{}`: arm {} reads and arm {} writes without a barrier. Fix: {}",
            self.buffer_name, self.read_arm, self.write_arm, self.fix_hint
        )
    }
}

/// Combine `programs` into one fused Program.
///
/// # Algorithm
///
/// 1. **Self-composition gate (F-IR-23)** – reject the batch if two
///    programs share the same `entry_op_id` and either is marked
///    `non_composable_with_self`.
/// 2. **Single forward pass** – for each arm in order:
///    * Clone its entry nodes into a segment and, in the same walk,
///      collect `Expr::Atomic` buffer targets.
///    * Merge its buffer declarations into the shared table, upgrading
///      access modes (`ReadOnly` → `ReadWrite`) and rebinding slots.
///    * Track read-after-write hazards incrementally: if the current
///      arm writes a buffer that any earlier arm read, mark a barrier
///      after every such earlier read arm.
///    * Accumulate axis-wise workgroup maxima.
/// 3. **Flatten** – concatenate the per-arm segments in order,
///    splicing `Node::Barrier` after arms that were marked.
///
/// # Why insert barriers instead of rejecting?
///
/// Rejecting would force the caller to split the dispatch, losing the
/// fusion benefit.  Renaming the buffer would break the caller's intent
/// (they passed the same name because it *is* the same physical buffer).
/// A barrier preserves the read-before-write ordering semantics while
/// keeping the dispatch fused.
#[inline]
#[must_use]
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
        1 => Ok(programs.pop().unwrap()),
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
    let mut name_to_index: FxHashMap<String, usize> = FxHashMap::default();
    let mut next_binding = 0_u32;

    let mut read_arms_per_buffer: FxHashMap<String, Vec<usize>> = FxHashMap::default();
    let mut barrier_after_arm: FxHashSet<usize> = FxHashSet::default();

    let mut fused_workgroup = [1u32, 1, 1];
    let mut max_arm_threads: u64 = 1;

    let mut arm_entries: Vec<Vec<Node>> = Vec::with_capacity(programs.len());

    for (arm_idx, prog) in programs.iter().enumerate() {
        // Walk entry nodes once: clone into segment and collect atomics.
        let entry = prog.entry();
        let mut segment = Vec::with_capacity(entry.len());
        let mut atomic_targets = FxHashSet::default();
        for node in entry {
            segment.push(node.clone());
            collect_atomic_targets_from_node(node, &mut atomic_targets);
        }
        arm_entries.push(segment);

        // Classify this arm's buffer accesses.
        let mut arm_reads: FxHashSet<String> = FxHashSet::default();
        let mut arm_explicit_writes: FxHashSet<String> = FxHashSet::default();

        for buf in prog.buffers() {
            let name = buf.name().to_string();
            match buf.access() {
                BufferAccess::ReadOnly | BufferAccess::Uniform => {
                    arm_reads.insert(name.clone());
                }
                BufferAccess::ReadWrite => {
                    arm_explicit_writes.insert(name.clone());
                }
                _ => {}
            }

            // Merge into shared buffer table.
            if let Some(&idx) = name_to_index.get(buf.name()) {
                let existing = &mut merged_buffers[idx];
                upgrade_buffer_access(existing, buf.access());
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
                name_to_index.insert(merged.name().to_string(), merged_buffers.len());
                merged_buffers.push(merged);
            }
        }

        // Atomic writes count only for buffers not already read or explicitly written.
        let mut arm_writes = arm_explicit_writes.clone();
        for target in &atomic_targets {
            if !arm_reads.contains(target.as_str())
                && !arm_explicit_writes.contains(target.as_str())
            {
                arm_writes.insert(target.clone());
            }
        }

        // F-IR-22: hazard detection (incremental).
        // For each buffer this arm writes, if any previous arm read it,
        // mark a barrier after every such earlier read arm.
        for write_buf in &arm_writes {
            if let Some(read_arms) = read_arms_per_buffer.get(write_buf) {
                for &read_arm in read_arms {
                    barrier_after_arm.insert(read_arm);
                }
            }
        }

        // Update read tracking for future arms.
        for read_buf in &arm_reads {
            read_arms_per_buffer
                .entry(read_buf.clone())
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
        combined_entry.extend(segment);
        if barrier_after_arm.contains(&arm_idx) {
            combined_entry.push(Node::Barrier);
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

fn collect_atomic_targets_from_node(node: &Node, targets: &mut FxHashSet<String>) {
    match node {
        Node::Let { value, .. } | Node::Assign { value, .. } => {
            collect_atomic_targets_from_expr(value, targets);
        }
        Node::Store { index, value, .. } => {
            collect_atomic_targets_from_expr(index, targets);
            collect_atomic_targets_from_expr(value, targets);
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            collect_atomic_targets_from_expr(cond, targets);
            for n in then.iter().chain(otherwise.iter()) {
                collect_atomic_targets_from_node(n, targets);
            }
        }
        Node::Loop { from, to, body, .. } => {
            collect_atomic_targets_from_expr(from, targets);
            collect_atomic_targets_from_expr(to, targets);
            for n in body {
                collect_atomic_targets_from_node(n, targets);
            }
        }
        Node::Block(body) => {
            for n in body {
                collect_atomic_targets_from_node(n, targets);
            }
        }
        Node::Region { body, .. } => {
            for n in body.iter() {
                collect_atomic_targets_from_node(n, targets);
            }
        }
        Node::IndirectDispatch { .. }
        | Node::Return
        | Node::Barrier
        | Node::AsyncLoad { .. }
        | Node::AsyncStore { .. }
        | Node::AsyncWait { .. }
        | Node::Trap { .. }
        | Node::Resume { .. }
        | Node::Opaque(_) => {}
    }
}

fn collect_atomic_targets_from_expr(expr: &Expr, targets: &mut FxHashSet<String>) {
    match expr {
        Expr::Atomic {
            buffer,
            index,
            expected,
            value,
            ..
        } => {
            targets.insert(buffer.to_string());
            collect_atomic_targets_from_expr(index, targets);
            if let Some(expected) = expected {
                collect_atomic_targets_from_expr(expected, targets);
            }
            collect_atomic_targets_from_expr(value, targets);
        }
        Expr::Load { index, .. } => collect_atomic_targets_from_expr(index, targets),
        Expr::BinOp { left, right, .. } => {
            collect_atomic_targets_from_expr(left, targets);
            collect_atomic_targets_from_expr(right, targets);
        }
        Expr::UnOp { operand, .. } | Expr::Cast { value: operand, .. } => {
            collect_atomic_targets_from_expr(operand, targets);
        }
        Expr::Fma { a, b, c } => {
            collect_atomic_targets_from_expr(a, targets);
            collect_atomic_targets_from_expr(b, targets);
            collect_atomic_targets_from_expr(c, targets);
        }
        Expr::Call { args, .. } => {
            for arg in args {
                collect_atomic_targets_from_expr(arg, targets);
            }
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            collect_atomic_targets_from_expr(cond, targets);
            collect_atomic_targets_from_expr(true_val, targets);
            collect_atomic_targets_from_expr(false_val, targets);
        }
        Expr::SubgroupBallot { cond } => collect_atomic_targets_from_expr(cond, targets),
        Expr::SubgroupShuffle { value, lane } => {
            collect_atomic_targets_from_expr(value, targets);
            collect_atomic_targets_from_expr(lane, targets);
        }
        Expr::SubgroupAdd { value } => collect_atomic_targets_from_expr(value, targets),
        _ => {}
    }
}

/// Derive a stable fallback key for programs that do not carry an
/// `entry_op_id`.  Two programs with the same buffers, workgroup size,
/// and entry-node count will hash to the same key, so the self-composition
/// gate can still reject duplicate non-composable copies.
fn fallback_composition_key(prog: &Program) -> String {
    let mut hasher = blake3::Hasher::new();
    for buf in prog.buffers() {
        hasher.update(buf.name().as_bytes());
        hasher.update(&[0]);
    }
    for dim in prog.workgroup_size() {
        hasher.update(&dim.to_le_bytes());
    }
    hasher.update(&(prog.entry().len() as u64).to_le_bytes());
    format!("{}", hasher.finalize().to_hex())
}

/// Upgrade `buffer.access` to the more permissive of the two modes.
fn upgrade_buffer_access(buffer: &mut BufferDecl, other: BufferAccess) {
    use BufferAccess::*;
    let current = buffer.access();
    buffer.access = match (&current, &other) {
        (ReadWrite, _) | (_, ReadWrite) => ReadWrite,
        (Uniform, _) | (_, Uniform) => Uniform,
        (Workgroup, _) | (_, Workgroup) => Workgroup,
        _ => ReadOnly,
    };
    // Keep kind in sync with the upgraded access.
    buffer.kind = match buffer.access {
        ReadOnly => crate::ir::MemoryKind::Readonly,
        ReadWrite => crate::ir::MemoryKind::Global,
        Uniform => crate::ir::MemoryKind::Uniform,
        Workgroup => crate::ir::MemoryKind::Shared,
        _ => crate::ir::MemoryKind::Global,
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::DataType;

    #[test]
    fn empty_batch_yields_empty_program() {
        let fused = fuse_programs(&[]).unwrap();
        assert!(fused.is_explicit_noop());
    }

    #[test]
    fn single_program_passthrough() {
        let p = Program::wrapped(
            vec![BufferDecl::read("x", 0, DataType::U32)],
            [64, 1, 1],
            vec![Node::let_bind(
                "a",
                crate::ir::Expr::load("x", crate::ir::Expr::u32(0)),
            )],
        );
        let fused = fuse_programs(&[p.clone()]).unwrap();
        assert_eq!(fused.entry().len(), p.entry().len());
    }

    #[test]
    fn single_program_vec_moves_without_clone() {
        let p = Program::wrapped(
            vec![BufferDecl::read("x", 0, DataType::U32)],
            [64, 1, 1],
            vec![Node::let_bind(
                "a",
                crate::ir::Expr::load("x", crate::ir::Expr::u32(0)),
            )],
        );
        let entry_len = p.entry().len();
        let fused = fuse_programs_vec(vec![p]).unwrap();
        assert_eq!(fused.entry().len(), entry_len);
    }

    #[test]
    fn barrier_inserted_for_read_then_atomic() {
        let reader = Program::wrapped(
            vec![BufferDecl::read("state", 0, DataType::U32).with_count(1)],
            [1, 1, 1],
            vec![Node::let_bind(
                "snap",
                crate::ir::Expr::load("state", crate::ir::Expr::u32(0)),
            )],
        );
        let writer = Program::wrapped(
            vec![BufferDecl::read_write("state", 0, DataType::U32).with_count(1)],
            [1, 1, 1],
            vec![Node::let_bind(
                "old",
                crate::ir::Expr::atomic_add(
                    "state",
                    crate::ir::Expr::u32(0),
                    crate::ir::Expr::u32(1),
                ),
            )],
        );

        let fused = fuse_programs(&[reader, writer]).unwrap();

        // The combined entry should have a Barrier between the two arms.
        // Because the top-level entry contains non-Region nodes (Barrier),
        // Program::wrapped inserts a root Region.  We need to look inside it.
        let body = match fused.entry() {
            [Node::Region { body, .. }] => body.as_ref(),
            entry => panic!("Fix: fused entry must be wrapped in a root Region, got {entry:?}"),
        };
        let barrier_positions: Vec<usize> = body
            .iter()
            .enumerate()
            .filter(|(_, n)| matches!(n, Node::Barrier))
            .map(|(i, _)| i)
            .collect();
        assert!(
            !barrier_positions.is_empty(),
            "Fix: fusion must insert Node::Barrier between a read arm and an atomic-write arm"
        );
    }

    #[test]
    fn self_composing_parser_rejected() {
        let parser = Program::wrapped(
            vec![BufferDecl::read("in", 0, DataType::U32)],
            [1, 1, 1],
            vec![Node::Return],
        )
        .with_entry_op_id("vyre-libs::parsing::test_parser")
        .with_non_composable_with_self(true);

        let result = fuse_programs(&[parser.clone(), parser]);
        assert!(
            matches!(result, Err(FusionError::SelfAliasing(_))),
            "Fix: fusing two copies of a non-composable parser must fail"
        );
    }

    #[test]
    fn duplicate_buffer_dedup_upgrades_access() {
        let a = Program::wrapped(
            vec![BufferDecl::read("x", 0, DataType::U32)],
            [1, 1, 1],
            vec![Node::Return],
        );
        let b = Program::wrapped(
            vec![BufferDecl::read_write("x", 0, DataType::U32)],
            [1, 1, 1],
            vec![Node::Return],
        );

        let fused = fuse_programs(&[a, b]).unwrap();
        assert_eq!(fused.buffers().len(), 1);
        assert_eq!(fused.buffers()[0].access(), BufferAccess::ReadWrite);
    }
}

//! Shared incremental/cached fact substrate for optimizer passes.
//!
//! Replaces ad-hoc per-pass re-computation (use-count tables, shape-fact
//! walks, type-inference maps) with a single derived structure that is
//! invalidated when the program changes.
//!
//! # Design
//!
//! * **Shape facts** — [`ProgramShapeFacts`] per buffer (already existed).
//! * **Use facts** — variable-use counts and buffer read/write sets.
//! * **Type facts** — best-effort expression-type map for float/int
//!   discrimination (used by FMA synthesis and vectorization).
//!
//! The substrate is keyed by the canonical 256-bit program fingerprint so
//! stale entries are never reused across fixpoint iterations.

use crate::ir::{Expr, Ident, Node, Program};
use crate::optimizer::program_shape_facts::ProgramShapeFacts;
use rustc_hash::{FxHashMap, FxHashSet};
use smallvec::SmallVec;
use std::sync::Arc;

mod type_facts;

/// Unified fact cache for a single program revision.
///
/// Passes that need shape, use, or type information call
/// [`FactSubstrate::derive`] once, then read the cached fields.  When a
/// pass mutates the program the scheduler calls [`FactSubstrate::invalidate`]
/// so the next reader re-derives.
#[derive(Default, Clone, Debug)]
pub struct FactSubstrate {
    /// Canonical fingerprint of the program these facts describe.
    fingerprint: [u8; 32],
    /// Per-buffer static shape facts.
    pub shape: Option<Arc<ProgramShapeFacts>>,
    /// Shared use facts derived in one walk over the program body.
    pub use_facts: Option<Arc<UseFacts>>,
    /// Per-variable use counts across the whole program entry.
    pub use_counts: Option<Arc<FxHashMap<Ident, usize>>>,
    /// Inferred scalar types for variables and expressions.
    pub type_map: Option<Arc<TypeFacts>>,
}

/// Best-effort type-inference results.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct TypeFacts {
    /// Inferred type for a variable binding.
    pub var_types: FxHashMap<Ident, crate::ir::DataType>,
    /// Inferred type for an expression (keyed by structural hash).
    pub expr_types: FxHashMap<u64, crate::ir::DataType>,
}

/// Optimizer facts derived from value uses and buffer accesses.
#[derive(Default, Clone, Debug, PartialEq, Eq)]
pub struct UseFacts {
    /// Number of times each variable is referenced.
    pub var_counts: Arc<FxHashMap<Ident, usize>>,
    /// Number of read-side references for each buffer.
    pub buffer_reads: FxHashMap<Ident, usize>,
    /// Number of write-side references for each buffer.
    pub buffer_writes: FxHashMap<Ident, usize>,
    /// Index-expression axis usage per buffer: `[x, y, z]`.
    pub buffer_index_axes: FxHashMap<Ident, [usize; 3]>,
    /// Conservative transitive source-buffer dependencies for scalar bindings.
    pub var_buffer_deps: FxHashMap<Ident, FxHashSet<Ident>>,
    /// Conservative direct source-buffer dependencies for each written buffer.
    pub buffer_write_deps: FxHashMap<Ident, FxHashSet<Ident>>,
    /// Buffers used as indirect-dispatch count inputs.
    pub indirect_dispatch_buffers: FxHashSet<Ident>,
    /// True when opaque IR prevents complete static dependency recovery.
    pub has_opaque: bool,
}

impl UseFacts {
    /// Most common invocation/local axis used to index `buffer`.
    #[must_use]
    pub fn dominant_index_axis(&self, buffer: &Ident) -> Option<u8> {
        let axes = self.buffer_index_axes.get(buffer)?;
        axes.iter()
            .enumerate()
            .max_by_key(|&(axis, count)| (*count, std::cmp::Reverse(axis)))
            .and_then(|(axis, count)| (*count > 0).then_some(axis as u8))
    }

    /// Total observed read/write references for `buffer`.
    #[must_use]
    pub fn access_count(&self, buffer: &Ident) -> usize {
        self.buffer_reads.get(buffer).copied().unwrap_or(0)
            + self.buffer_writes.get(buffer).copied().unwrap_or(0)
    }
}

#[derive(Default)]
struct UseFactBuilder {
    var_counts: FxHashMap<Ident, usize>,
    buffer_reads: FxHashMap<Ident, usize>,
    buffer_writes: FxHashMap<Ident, usize>,
    buffer_index_axes: FxHashMap<Ident, [usize; 3]>,
    var_buffer_deps: FxHashMap<Ident, FxHashSet<Ident>>,
    buffer_write_deps: FxHashMap<Ident, FxHashSet<Ident>>,
    indirect_dispatch_buffers: FxHashSet<Ident>,
    has_opaque: bool,
}

impl UseFactBuilder {
    fn finish(self) -> UseFacts {
        UseFacts {
            var_counts: Arc::new(self.var_counts),
            buffer_reads: self.buffer_reads,
            buffer_writes: self.buffer_writes,
            buffer_index_axes: self.buffer_index_axes,
            var_buffer_deps: self.var_buffer_deps,
            buffer_write_deps: self.buffer_write_deps,
            indirect_dispatch_buffers: self.indirect_dispatch_buffers,
            has_opaque: self.has_opaque,
        }
    }
}

impl FactSubstrate {
    /// Derive all facts for `program`.
    #[must_use]
    pub fn derive(program: &Program) -> Self {
        let fp = program.fingerprint();
        let use_facts = derive_use_facts(program);
        Self {
            fingerprint: fp,
            shape: Some(Arc::new(ProgramShapeFacts::derive(program))),
            use_counts: Some(Arc::clone(&use_facts.var_counts)),
            use_facts: Some(Arc::new(use_facts)),
            type_map: Some(Arc::new(type_facts::derive(program))),
        }
    }

    /// Derive shape and use facts without running type inference.
    #[must_use]
    pub fn derive_shape_and_use(program: &Program) -> Self {
        let fp = program.fingerprint();
        let use_facts = derive_use_facts(program);
        Self {
            fingerprint: fp,
            shape: Some(Arc::new(ProgramShapeFacts::derive(program))),
            use_counts: Some(Arc::clone(&use_facts.var_counts)),
            use_facts: Some(Arc::new(use_facts)),
            type_map: None,
        }
    }

    /// Derive only use facts for passes that do not need shape or type maps.
    #[must_use]
    pub fn derive_use_only(program: &Program) -> Self {
        let use_facts = derive_use_facts(program);
        Self {
            fingerprint: program.fingerprint(),
            shape: None,
            use_counts: Some(Arc::clone(&use_facts.var_counts)),
            use_facts: Some(Arc::new(use_facts)),
            type_map: None,
        }
    }

    /// Drop every cached fact. Called by the scheduler after a pass
    /// changes the program.
    pub fn invalidate(&mut self) {
        self.invalidate_shape();
        self.invalidate_use_facts();
        self.invalidate_type_map();
    }

    /// Drop only shape facts.
    pub fn invalidate_shape(&mut self) {
        self.shape = None;
    }

    /// Drop only use facts.
    pub fn invalidate_use_facts(&mut self) {
        self.use_facts = None;
        self.use_counts = None;
    }

    /// Drop only type facts.
    pub fn invalidate_type_map(&mut self) {
        self.type_map = None;
    }

    /// True when the cached facts are known to match `program`.
    #[must_use]
    pub fn is_fresh_for(&self, program: &Program) -> bool {
        self.fingerprint == program.fingerprint()
            && self.shape.is_some()
            && self.use_facts.is_some()
            && self.use_counts.is_some()
            && self.type_map.is_some()
    }

    /// True when cached use facts match `program`.
    #[must_use]
    pub fn has_fresh_use_facts_for(&self, program: &Program) -> bool {
        self.fingerprint == program.fingerprint() && self.use_facts.is_some()
    }

    /// True when cached shape and use facts match `program`.
    #[must_use]
    pub fn has_fresh_shape_and_use_for(&self, program: &Program) -> bool {
        self.fingerprint == program.fingerprint()
            && self.shape.is_some()
            && self.use_facts.is_some()
            && self.use_counts.is_some()
    }

    /// Shared use-fact lookup.
    #[must_use]
    pub fn use_facts(&self) -> Option<&UseFacts> {
        self.use_facts.as_deref()
    }

    /// Shared use-count lookup.
    #[must_use]
    pub fn use_counts(&self) -> Option<&FxHashMap<Ident, usize>> {
        self.use_counts.as_deref()
    }

    /// Number of uses for a variable, defaulting to `0`.
    #[must_use]
    pub fn use_count_of(&self, name: &Ident) -> usize {
        self.use_facts()
            .and_then(|facts| facts.var_counts.get(name))
            .copied()
            .or_else(|| self.use_counts().and_then(|m| m.get(name)).copied())
            .unwrap_or(0)
    }
}

// ---------------------------------------------------------------------------
// Use-count derivation
// ---------------------------------------------------------------------------

fn derive_use_facts(program: &Program) -> UseFacts {
    let mut facts = UseFactBuilder::default();
    derive_nodes_uses(program.entry(), &mut facts, &FxHashSet::default());
    facts.finish()
}

fn derive_nodes_uses(nodes: &[Node], facts: &mut UseFactBuilder, control_deps: &FxHashSet<Ident>) {
    for node in nodes {
        match node {
            Node::Let { name, value } | Node::Assign { name, value } => {
                let mut deps = record_expr_uses_and_buffer_deps(value, facts);
                deps.extend(control_deps.iter().cloned());
                facts
                    .var_buffer_deps
                    .entry(name.clone())
                    .or_default()
                    .extend(deps);
            }
            Node::Store {
                buffer,
                index,
                value,
            } => {
                *facts.buffer_writes.entry(buffer.clone()).or_insert(0) += 1;
                let mut deps = record_expr_uses_and_buffer_deps(index, facts);
                count_index_axes(index, buffer, facts);
                deps.extend(record_expr_uses_and_buffer_deps(value, facts));
                deps.extend(control_deps.iter().cloned());
                add_buffer_write_deps(facts, buffer, deps);
            }
            Node::If {
                cond,
                then,
                otherwise,
            } => {
                let cond_deps = record_expr_uses_and_buffer_deps(cond, facts);
                let branch_control = union_deps(control_deps, &cond_deps);
                derive_nodes_uses(then, facts, &branch_control);
                derive_nodes_uses(otherwise, facts, &branch_control);
            }
            Node::Loop { from, to, body, .. } => {
                let mut loop_deps = record_expr_uses_and_buffer_deps(from, facts);
                loop_deps.extend(record_expr_uses_and_buffer_deps(to, facts));
                let loop_control = union_deps(control_deps, &loop_deps);
                derive_nodes_uses(body, facts, &loop_control);
            }
            Node::Block(nodes) => {
                derive_nodes_uses(nodes, facts, control_deps);
            }
            Node::Region { body, .. } => {
                derive_nodes_uses(body, facts, control_deps);
            }
            Node::AsyncLoad {
                source,
                destination,
                offset,
                size,
                ..
            } => {
                *facts.buffer_reads.entry(source.clone()).or_insert(0) += 1;
                *facts.buffer_writes.entry(destination.clone()).or_insert(0) += 1;
                let mut deps = record_expr_uses_and_buffer_deps(offset, facts);
                deps.extend(record_expr_uses_and_buffer_deps(size, facts));
                deps.extend(control_deps.iter().cloned());
                deps.insert(source.clone());
                add_buffer_write_deps(facts, destination, deps);
            }
            Node::AsyncStore {
                source,
                destination,
                offset,
                size,
                ..
            } => {
                *facts.buffer_reads.entry(source.clone()).or_insert(0) += 1;
                *facts.buffer_writes.entry(destination.clone()).or_insert(0) += 1;
                let mut deps = record_expr_uses_and_buffer_deps(offset, facts);
                deps.extend(record_expr_uses_and_buffer_deps(size, facts));
                deps.extend(control_deps.iter().cloned());
                deps.insert(source.clone());
                add_buffer_write_deps(facts, destination, deps);
            }
            Node::Trap { address, .. } => {
                record_expr_uses_and_buffer_deps(address, facts);
            }
            Node::IndirectDispatch { count_buffer, .. } => {
                facts.indirect_dispatch_buffers.insert(count_buffer.clone());
                *facts.buffer_reads.entry(count_buffer.clone()).or_insert(0) += 1;
            }
            Node::Opaque(_) => {
                facts.has_opaque = true;
            }
            Node::Return | Node::Barrier { .. } | Node::AsyncWait { .. } | Node::Resume { .. } => {}
        }
    }
}

fn record_expr_uses_and_buffer_deps(expr: &Expr, facts: &mut UseFactBuilder) -> FxHashSet<Ident> {
    let mut deps = FxHashSet::default();
    let mut stack: SmallVec<[&Expr; 16]> = SmallVec::new();
    stack.push(expr);
    while let Some(expr) = stack.pop() {
        match expr {
            Expr::Var(name) => {
                *facts.var_counts.entry(name.clone()).or_insert(0) += 1;
                if let Some(var_deps) = facts.var_buffer_deps.get(name) {
                    deps.extend(var_deps.iter().cloned());
                }
            }
            Expr::Load { buffer, index } => {
                *facts.buffer_reads.entry(buffer.clone()).or_insert(0) += 1;
                count_index_axes(index, buffer, facts);
                deps.insert(buffer.clone());
            }
            Expr::BufLen { buffer } => {
                *facts.buffer_reads.entry(buffer.clone()).or_insert(0) += 1;
                deps.insert(buffer.clone());
            }
            Expr::Atomic { buffer, index, .. } => {
                *facts.buffer_reads.entry(buffer.clone()).or_insert(0) += 1;
                *facts.buffer_writes.entry(buffer.clone()).or_insert(0) += 1;
                count_index_axes(index, buffer, facts);
                deps.insert(buffer.clone());
            }
            Expr::Opaque(_) => {
                facts.has_opaque = true;
            }
            _ => {}
        }
        push_expr_children(expr, &mut stack);
    }
    deps
}

fn union_deps(a: &FxHashSet<Ident>, b: &FxHashSet<Ident>) -> FxHashSet<Ident> {
    let mut out = FxHashSet::default();
    out.reserve(a.len().saturating_add(b.len()));
    out.extend(a.iter().cloned());
    out.extend(b.iter().cloned());
    out
}

fn add_buffer_write_deps(facts: &mut UseFactBuilder, buffer: &Ident, deps: FxHashSet<Ident>) {
    if deps.is_empty() {
        return;
    }
    facts
        .buffer_write_deps
        .entry(buffer.clone())
        .or_default()
        .extend(deps);
}

fn count_index_axes(index: &Expr, buffer: &Ident, facts: &mut UseFactBuilder) {
    let mut stack: SmallVec<[&Expr; 16]> = SmallVec::new();
    stack.push(index);
    while let Some(expr) = stack.pop() {
        if let Expr::InvocationId { axis } | Expr::LocalId { axis } = expr {
            if let Some(slot) = facts
                .buffer_index_axes
                .entry(buffer.clone())
                .or_insert([0; 3])
                .get_mut(usize::from(*axis).min(2))
            {
                *slot += 1;
            }
        }
        push_expr_children(expr, &mut stack);
    }
}

fn push_expr_children<'a>(expr: &'a Expr, stack: &mut SmallVec<[&'a Expr; 16]>) {
    match expr {
        Expr::Load { index, .. } | Expr::UnOp { operand: index, .. } => stack.push(index),
        Expr::BinOp { left, right, .. } => {
            stack.push(left);
            stack.push(right);
        }
        Expr::Call { args, .. } => stack.extend(args),
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            stack.push(cond);
            stack.push(true_val);
            stack.push(false_val);
        }
        Expr::Cast { value, .. } => stack.push(value),
        Expr::Fma { a, b, c } => {
            stack.push(a);
            stack.push(b);
            stack.push(c);
        }
        Expr::Atomic {
            index,
            expected,
            value,
            ..
        } => {
            stack.push(index);
            if let Some(expected) = expected {
                stack.push(expected);
            }
            stack.push(value);
        }
        Expr::SubgroupBallot { cond } => stack.push(cond),
        Expr::SubgroupShuffle { value, lane } => {
            stack.push(value);
            stack.push(lane);
        }
        Expr::SubgroupAdd { value } => stack.push(value),
        Expr::LitU32(_)
        | Expr::LitI32(_)
        | Expr::LitF32(_)
        | Expr::LitBool(_)
        | Expr::Var(_)
        | Expr::BufLen { .. }
        | Expr::InvocationId { .. }
        | Expr::WorkgroupId { .. }
        | Expr::LocalId { .. }
        | Expr::SubgroupLocalId
        | Expr::SubgroupSize
        | Expr::Opaque(_) => {}
    }
}

#[cfg(test)]
mod tests;

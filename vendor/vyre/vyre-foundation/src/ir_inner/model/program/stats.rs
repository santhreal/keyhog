use super::Program;
use crate::ir::{DataType, Expr, Node};

const CAP_SUBGROUP_OPS: u32 = 1 << 0;
const CAP_F16: u32 = 1 << 1;
const CAP_BF16: u32 = 1 << 2;
const CAP_F64: u32 = 1 << 3;
const CAP_ASYNC_DISPATCH: u32 = 1 << 4;
const CAP_INDIRECT_DISPATCH: u32 = 1 << 5;
const CAP_TENSOR_OPS: u32 = 1 << 6;
const CAP_TRAP: u32 = 1 << 7;

/// Aggregated statistics computed from a single walk of a [`Program`].
///
/// This struct is cached inside [`Program`] via a [`std::sync::OnceLock`]
/// so that planning passes (execution plan, capability scan, provenance,
/// fusion) can read constant-time summaries instead of re-walking the IR.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct ProgramStats {
    /// Total statement-node count (includes nested children).
    pub node_count: usize,
    /// Number of `Node::Region` nodes in the full tree.
    pub region_count: u32,
    /// Number of `Expr::Call` expressions.
    pub call_count: u32,
    /// Number of `Node::Opaque` nodes and `Expr::Opaque` expressions.
    pub opaque_count: u32,
    /// Number of top-level `Node::Region` wrappers in `program.entry()`.
    pub top_level_regions: u32,
    /// Sum of statically-known buffer byte sizes.
    pub static_storage_bytes: u64,
    /// Bitmask of capability requirements (see `CAP_*` constants).
    pub capability_bits: u32,
}

impl ProgramStats {
    /// True when the program uses subgroup operations.
    #[inline]
    #[must_use]
    pub fn subgroup_ops(&self) -> bool {
        self.capability_bits & CAP_SUBGROUP_OPS != 0
    }

    /// True when the program uses IEEE-754 binary16 values.
    #[inline]
    #[must_use]
    pub fn f16(&self) -> bool {
        self.capability_bits & CAP_F16 != 0
    }

    /// True when the program uses bfloat16 values.
    #[inline]
    #[must_use]
    pub fn bf16(&self) -> bool {
        self.capability_bits & CAP_BF16 != 0
    }

    /// True when the program uses IEEE-754 binary64 values.
    #[inline]
    #[must_use]
    pub fn f64(&self) -> bool {
        self.capability_bits & CAP_F64 != 0
    }

    /// True when the program requires async dispatch semantics.
    #[inline]
    #[must_use]
    pub fn async_dispatch(&self) -> bool {
        self.capability_bits & CAP_ASYNC_DISPATCH != 0
    }

    /// True when the program requires indirect dispatch support.
    #[inline]
    #[must_use]
    pub fn indirect_dispatch(&self) -> bool {
        self.capability_bits & CAP_INDIRECT_DISPATCH != 0
    }

    /// True when the program uses tensor / tensor-core operand types.
    #[inline]
    #[must_use]
    pub fn tensor_ops(&self) -> bool {
        self.capability_bits & CAP_TENSOR_OPS != 0
    }

    /// True when the program uses `Node::Trap`.
    #[inline]
    #[must_use]
    pub fn trap(&self) -> bool {
        self.capability_bits & CAP_TRAP != 0
    }
}

impl Program {
    /// Return cached statistics for this program, computing them on first call.
    #[must_use]
    #[inline]
    pub fn stats(&self) -> &ProgramStats {
        self.stats
            .get_or_init(|| std::sync::Arc::new(compute_stats(self)))
            .as_ref()
    }
}

/// Single-pass preorder walk that accumulates every field of [`ProgramStats`].
pub(crate) fn compute_stats(program: &Program) -> ProgramStats {
    let mut node_count = 0usize;
    let mut region_count = 0u32;
    let mut call_count = 0u32;
    let mut opaque_count = 0u32;
    let mut capability_bits = 0u32;
    let mut static_storage_bytes = 0u64;

    for decl in program.buffers.iter() {
        let count = decl.count();
        if count != 0 {
            if let Some(elem) = decl.element().size_bytes() {
                static_storage_bytes =
                    static_storage_bytes.saturating_add(u64::from(count) * elem as u64);
            }
        }
        mark_datatype_bits(&decl.element(), &mut capability_bits);
    }

    for node in program.entry.iter() {
        walk_node(
            node,
            &mut node_count,
            &mut region_count,
            &mut call_count,
            &mut opaque_count,
            &mut capability_bits,
        );
    }

    let top_level_regions = program
        .entry()
        .iter()
        .filter(|n| matches!(n, Node::Region { .. }))
        .count() as u32;

    ProgramStats {
        node_count,
        region_count,
        call_count,
        opaque_count,
        top_level_regions,
        static_storage_bytes,
        capability_bits,
    }
}

#[inline]
fn mark_datatype_bits(ty: &DataType, bits: &mut u32) {
    match ty {
        DataType::F16 => *bits |= CAP_F16,
        DataType::BF16 => *bits |= CAP_BF16,
        DataType::F64 => *bits |= CAP_F64,
        DataType::Tensor | DataType::TensorShaped { .. } => *bits |= CAP_TENSOR_OPS,
        _ => {}
    }
}

fn walk_node(
    node: &Node,
    nodes: &mut usize,
    regions: &mut u32,
    calls: &mut u32,
    opaque: &mut u32,
    bits: &mut u32,
) {
    *nodes = nodes.saturating_add(1);
    match node {
        Node::Let { value, .. } | Node::Assign { value, .. } => {
            walk_expr(value, nodes, regions, calls, opaque, bits);
        }
        Node::Store { index, value, .. } => {
            walk_expr(index, nodes, regions, calls, opaque, bits);
            walk_expr(value, nodes, regions, calls, opaque, bits);
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            walk_expr(cond, nodes, regions, calls, opaque, bits);
            for child in then.iter().chain(otherwise.iter()) {
                walk_node(child, nodes, regions, calls, opaque, bits);
            }
        }
        Node::Loop { from, to, body, .. } => {
            walk_expr(from, nodes, regions, calls, opaque, bits);
            walk_expr(to, nodes, regions, calls, opaque, bits);
            for child in body.iter() {
                walk_node(child, nodes, regions, calls, opaque, bits);
            }
        }
        Node::Block(children) => {
            for child in children.iter() {
                walk_node(child, nodes, regions, calls, opaque, bits);
            }
        }
        Node::Region { body, .. } => {
            *regions = regions.saturating_add(1);
            for child in body.iter() {
                walk_node(child, nodes, regions, calls, opaque, bits);
            }
        }
        Node::AsyncLoad { offset, size, .. } | Node::AsyncStore { offset, size, .. } => {
            *bits |= CAP_ASYNC_DISPATCH;
            walk_expr(offset, nodes, regions, calls, opaque, bits);
            walk_expr(size, nodes, regions, calls, opaque, bits);
        }
        Node::AsyncWait { .. } => {
            *bits |= CAP_ASYNC_DISPATCH;
        }
        Node::IndirectDispatch { .. } => {
            *bits |= CAP_INDIRECT_DISPATCH;
        }
        Node::Trap { address, .. } => {
            *bits |= CAP_TRAP;
            walk_expr(address, nodes, regions, calls, opaque, bits);
        }
        Node::Opaque(_) => {
            *opaque = opaque.saturating_add(1);
        }
        Node::Return | Node::Barrier | Node::Resume { .. } => {}
    }
}

#[allow(clippy::only_used_in_recursion)]
fn walk_expr(
    expr: &Expr,
    nodes: &mut usize,
    regions: &mut u32,
    calls: &mut u32,
    opaque: &mut u32,
    bits: &mut u32,
) {
    match expr {
        Expr::SubgroupAdd { value } => {
            *bits |= CAP_SUBGROUP_OPS;
            walk_expr(value, nodes, regions, calls, opaque, bits);
        }
        Expr::SubgroupBallot { cond } => {
            *bits |= CAP_SUBGROUP_OPS;
            walk_expr(cond, nodes, regions, calls, opaque, bits);
        }
        Expr::SubgroupShuffle { value, lane } => {
            *bits |= CAP_SUBGROUP_OPS;
            walk_expr(value, nodes, regions, calls, opaque, bits);
            walk_expr(lane, nodes, regions, calls, opaque, bits);
        }
        Expr::BinOp { left, right, .. } => {
            walk_expr(left, nodes, regions, calls, opaque, bits);
            walk_expr(right, nodes, regions, calls, opaque, bits);
        }
        Expr::UnOp { operand, .. } => walk_expr(operand, nodes, regions, calls, opaque, bits),
        Expr::Fma { a, b, c } => {
            walk_expr(a, nodes, regions, calls, opaque, bits);
            walk_expr(b, nodes, regions, calls, opaque, bits);
            walk_expr(c, nodes, regions, calls, opaque, bits);
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            walk_expr(cond, nodes, regions, calls, opaque, bits);
            walk_expr(true_val, nodes, regions, calls, opaque, bits);
            walk_expr(false_val, nodes, regions, calls, opaque, bits);
        }
        Expr::Cast { target, value } => {
            mark_datatype_bits(target, bits);
            walk_expr(value, nodes, regions, calls, opaque, bits);
        }
        Expr::Load { index, .. } => walk_expr(index, nodes, regions, calls, opaque, bits),
        Expr::Call { op_id, args } => {
            if is_subgroup_intrinsic_id(op_id) {
                *bits |= CAP_SUBGROUP_OPS;
            }
            *calls = calls.saturating_add(1);
            for arg in args.iter() {
                walk_expr(arg, nodes, regions, calls, opaque, bits);
            }
        }
        Expr::Atomic {
            index,
            expected,
            value,
            ..
        } => {
            walk_expr(index, nodes, regions, calls, opaque, bits);
            if let Some(expected) = expected.as_deref() {
                walk_expr(expected, nodes, regions, calls, opaque, bits);
            }
            walk_expr(value, nodes, regions, calls, opaque, bits);
        }
        Expr::Opaque(_) => {
            *opaque = opaque.saturating_add(1);
        }
        Expr::SubgroupLocalId | Expr::SubgroupSize => {
            *bits |= CAP_SUBGROUP_OPS;
        }
        Expr::LitU32(_)
        | Expr::LitI32(_)
        | Expr::LitF32(_)
        | Expr::LitBool(_)
        | Expr::Var(_)
        | Expr::BufLen { .. }
        | Expr::InvocationId { .. }
        | Expr::WorkgroupId { .. }
        | Expr::LocalId { .. } => {}
    }
}

fn is_subgroup_intrinsic_id(op_id: &str) -> bool {
    const MARKERS: &[&str] = &[
        "subgroup_",
        "::subgroup::",
        "::subgroup",
        "wave_",
        "::wave::",
        "warp_",
        "::warp::",
    ];
    MARKERS.iter().any(|marker| op_id.contains(marker))
}

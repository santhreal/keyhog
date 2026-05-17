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
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
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
    /// Estimated scalar/vector IR instruction count.
    pub instruction_count: u64,
    /// Number of explicit memory operations (loads, stores, async copies).
    pub memory_op_count: u64,
    /// Number of atomic read-modify-write expressions.
    pub atomic_op_count: u64,
    /// Number of control-flow operations.
    pub control_flow_count: u64,
    /// Coarse register pressure estimate from simultaneously named SSA-ish values.
    pub register_pressure_estimate: u32,
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
    let mut ir = IrCounters::default();

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
            &mut ir,
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
        instruction_count: ir.instruction_count,
        memory_op_count: ir.memory_op_count,
        atomic_op_count: ir.atomic_op_count,
        control_flow_count: ir.control_flow_count,
        register_pressure_estimate: ir.register_pressure_estimate(),
        capability_bits,
    }
}

#[derive(Default)]
struct IrCounters {
    instruction_count: u64,
    memory_op_count: u64,
    atomic_op_count: u64,
    control_flow_count: u64,
    live_names: u32,
    max_live_names: u32,
}

impl IrCounters {
    fn instruction(&mut self) {
        self.instruction_count = self.instruction_count.saturating_add(1);
    }

    fn memory(&mut self) {
        self.memory_op_count = self.memory_op_count.saturating_add(1);
        self.instruction();
    }

    fn atomic(&mut self) {
        self.atomic_op_count = self.atomic_op_count.saturating_add(1);
        self.memory();
    }

    fn control_flow(&mut self) {
        self.control_flow_count = self.control_flow_count.saturating_add(1);
        self.instruction();
    }

    fn bind_name(&mut self) {
        self.live_names = self.live_names.saturating_add(1);
        self.max_live_names = self.max_live_names.max(self.live_names);
    }

    fn enter_scope(&mut self) -> u32 {
        self.live_names
    }

    fn leave_scope(&mut self, saved: u32) {
        self.live_names = saved;
    }

    fn register_pressure_estimate(&self) -> u32 {
        self.max_live_names
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
    ir: &mut IrCounters,
) {
    *nodes = nodes.saturating_add(1);
    match node {
        Node::Let { value, .. } | Node::Assign { value, .. } => {
            ir.instruction();
            if matches!(node, Node::Let { .. }) {
                ir.bind_name();
            }
            walk_expr(value, nodes, regions, calls, opaque, bits, ir);
        }
        Node::Store { index, value, .. } => {
            ir.memory();
            walk_expr(index, nodes, regions, calls, opaque, bits, ir);
            walk_expr(value, nodes, regions, calls, opaque, bits, ir);
        }
        Node::If {
            cond,
            then,
            otherwise,
        } => {
            ir.control_flow();
            walk_expr(cond, nodes, regions, calls, opaque, bits, ir);
            let saved = ir.enter_scope();
            for child in then.iter().chain(otherwise.iter()) {
                walk_node(child, nodes, regions, calls, opaque, bits, ir);
            }
            ir.leave_scope(saved);
        }
        Node::Loop { from, to, body, .. } => {
            ir.control_flow();
            walk_expr(from, nodes, regions, calls, opaque, bits, ir);
            walk_expr(to, nodes, regions, calls, opaque, bits, ir);
            let saved = ir.enter_scope();
            for child in body.iter() {
                walk_node(child, nodes, regions, calls, opaque, bits, ir);
            }
            ir.leave_scope(saved);
        }
        Node::Block(children) => {
            let saved = ir.enter_scope();
            for child in children.iter() {
                walk_node(child, nodes, regions, calls, opaque, bits, ir);
            }
            ir.leave_scope(saved);
        }
        Node::Region { body, .. } => {
            *regions = regions.saturating_add(1);
            let saved = ir.enter_scope();
            for child in body.iter() {
                walk_node(child, nodes, regions, calls, opaque, bits, ir);
            }
            ir.leave_scope(saved);
        }
        Node::AsyncLoad { offset, size, .. } | Node::AsyncStore { offset, size, .. } => {
            *bits |= CAP_ASYNC_DISPATCH;
            ir.memory();
            walk_expr(offset, nodes, regions, calls, opaque, bits, ir);
            walk_expr(size, nodes, regions, calls, opaque, bits, ir);
        }
        Node::AsyncWait { .. } => {
            *bits |= CAP_ASYNC_DISPATCH;
            ir.control_flow();
        }
        Node::IndirectDispatch { .. } => {
            *bits |= CAP_INDIRECT_DISPATCH;
            ir.control_flow();
        }
        Node::Trap { address, .. } => {
            *bits |= CAP_TRAP;
            ir.control_flow();
            walk_expr(address, nodes, regions, calls, opaque, bits, ir);
        }
        Node::Opaque(_) => {
            *opaque = opaque.saturating_add(1);
            ir.instruction();
        }
        Node::Return | Node::Barrier { .. } | Node::Resume { .. } => {
            ir.control_flow();
        }
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
    ir: &mut IrCounters,
) {
    match expr {
        Expr::SubgroupAdd { value } => {
            *bits |= CAP_SUBGROUP_OPS;
            ir.instruction();
            walk_expr(value, nodes, regions, calls, opaque, bits, ir);
        }
        Expr::SubgroupBallot { cond } => {
            *bits |= CAP_SUBGROUP_OPS;
            ir.instruction();
            walk_expr(cond, nodes, regions, calls, opaque, bits, ir);
        }
        Expr::SubgroupShuffle { value, lane } => {
            *bits |= CAP_SUBGROUP_OPS;
            ir.instruction();
            walk_expr(value, nodes, regions, calls, opaque, bits, ir);
            walk_expr(lane, nodes, regions, calls, opaque, bits, ir);
        }
        Expr::BinOp { left, right, .. } => {
            ir.instruction();
            walk_expr(left, nodes, regions, calls, opaque, bits, ir);
            walk_expr(right, nodes, regions, calls, opaque, bits, ir);
        }
        Expr::UnOp { operand, .. } => {
            ir.instruction();
            walk_expr(operand, nodes, regions, calls, opaque, bits, ir);
        }
        Expr::Fma { a, b, c } => {
            ir.instruction();
            walk_expr(a, nodes, regions, calls, opaque, bits, ir);
            walk_expr(b, nodes, regions, calls, opaque, bits, ir);
            walk_expr(c, nodes, regions, calls, opaque, bits, ir);
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            ir.instruction();
            walk_expr(cond, nodes, regions, calls, opaque, bits, ir);
            walk_expr(true_val, nodes, regions, calls, opaque, bits, ir);
            walk_expr(false_val, nodes, regions, calls, opaque, bits, ir);
        }
        Expr::Cast { target, value } => {
            mark_datatype_bits(target, bits);
            ir.instruction();
            walk_expr(value, nodes, regions, calls, opaque, bits, ir);
        }
        Expr::Load { index, .. } => {
            ir.memory();
            walk_expr(index, nodes, regions, calls, opaque, bits, ir);
        }
        Expr::Call { op_id, args } => {
            if is_subgroup_intrinsic_id(op_id) {
                *bits |= CAP_SUBGROUP_OPS;
            }
            *calls = calls.saturating_add(1);
            ir.instruction();
            for arg in args.iter() {
                walk_expr(arg, nodes, regions, calls, opaque, bits, ir);
            }
        }
        Expr::Atomic {
            index,
            expected,
            value,
            ..
        } => {
            ir.atomic();
            walk_expr(index, nodes, regions, calls, opaque, bits, ir);
            if let Some(expected) = expected.as_deref() {
                walk_expr(expected, nodes, regions, calls, opaque, bits, ir);
            }
            walk_expr(value, nodes, regions, calls, opaque, bits, ir);
        }
        Expr::Opaque(_) => {
            *opaque = opaque.saturating_add(1);
            ir.instruction();
        }
        Expr::SubgroupLocalId | Expr::SubgroupSize => {
            *bits |= CAP_SUBGROUP_OPS;
            ir.instruction();
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

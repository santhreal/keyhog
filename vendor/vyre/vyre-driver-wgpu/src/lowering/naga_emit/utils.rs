use super::{FunctionBuilder, LoweringError};
use naga::{
    AddressSpace, BinaryOperator, Binding, BuiltIn, Function, FunctionArgument, ResourceBinding,
    StorageAccess, Type,
};
use vyre_foundation::ir::{BinOp, BufferAccess, BufferDecl, DataType, Expr, MemoryKind, UnOp};

pub(crate) fn push_builtin_arg(
    function: &mut Function,
    name: &str,
    ty: naga::Handle<Type>,
    builtin: BuiltIn,
) -> u32 {
    let index = function.arguments.len() as u32;
    function.arguments.push(FunctionArgument {
        name: Some(name.to_string()),
        ty,
        binding: Some(Binding::BuiltIn(builtin)),
    });
    index
}

pub(crate) fn address_space(buffer: &BufferDecl) -> Result<AddressSpace, LoweringError> {
    match buffer.kind {
        MemoryKind::Shared => Ok(AddressSpace::WorkGroup),
        MemoryKind::Uniform => Ok(AddressSpace::Uniform),
        MemoryKind::Push => Ok(AddressSpace::PushConstant),
        MemoryKind::Local => Ok(AddressSpace::Private),
        MemoryKind::Persistent => Err(LoweringError::invalid(format!(
            "buffer `{}` uses MemoryKind::Persistent. Fix: resolve persistent storage into AsyncLoad/AsyncStore host transfers before wgpu lowering.",
            buffer.name()
        ))),
        MemoryKind::Readonly => Ok(AddressSpace::Storage {
            access: StorageAccess::LOAD,
        }),
        MemoryKind::Global => Ok(AddressSpace::Storage {
            access: storage_access(&buffer.access)?,
        }),
        _ => Err(LoweringError::invalid(format!(
            "buffer `{}` uses an unknown future MemoryKind. Fix: update vyre-wgpu Naga lowering before dispatching this Program.",
            buffer.name()
        ))),
    }
}

pub(crate) fn binding(buffer: &BufferDecl) -> Option<ResourceBinding> {
    match buffer.kind {
        MemoryKind::Shared | MemoryKind::Local | MemoryKind::Push => None,
        _ => Some(ResourceBinding {
            // Group placement is policy-driven via bind_group_for so
            // the wgpu lowering no longer hardcodes group 0. See the
            // doc-comment on bind_group_for in lowering/mod.rs.
            group: crate::lowering::bind_group_for(buffer.kind),
            binding: buffer.binding,
        }),
    }
}

pub(crate) fn storage_access(access: &BufferAccess) -> Result<StorageAccess, LoweringError> {
    match access {
        BufferAccess::ReadOnly | BufferAccess::Uniform => Ok(StorageAccess::LOAD),
        BufferAccess::WriteOnly => Ok(StorageAccess::STORE),
        BufferAccess::ReadWrite | BufferAccess::Workgroup => {
            Ok(StorageAccess::LOAD | StorageAccess::STORE)
        }
        _ => Err(LoweringError::invalid(format!(
            "buffer access `{access:?}` is not mapped to WGSL storage permissions. Fix: add an explicit storage-access mapping before lowering this Program."
        ))),
    }
}

/// Direct mapping from `BinOp` to `naga::BinaryOperator`. Ops that have no
/// direct naga binop (`AbsDiff`, `Min`, `Max`) are handled one level up, via
/// `emit_binop_with_helpers`.
pub(crate) fn binary_operator(op: BinOp) -> Result<BinaryOperator, LoweringError> {
    Ok(match op {
        BinOp::Add => BinaryOperator::Add,
        BinOp::Sub => BinaryOperator::Subtract,
        BinOp::Mul => BinaryOperator::Multiply,
        BinOp::Div => BinaryOperator::Divide,
        BinOp::Mod => BinaryOperator::Modulo,
        BinOp::BitAnd => BinaryOperator::And,
        BinOp::BitOr => BinaryOperator::InclusiveOr,
        BinOp::BitXor => BinaryOperator::ExclusiveOr,
        BinOp::Shl => BinaryOperator::ShiftLeft,
        BinOp::Shr => BinaryOperator::ShiftRight,
        BinOp::Eq => BinaryOperator::Equal,
        BinOp::Ne => BinaryOperator::NotEqual,
        BinOp::Lt => BinaryOperator::Less,
        BinOp::Gt => BinaryOperator::Greater,
        BinOp::Le => BinaryOperator::LessEqual,
        BinOp::Ge => BinaryOperator::GreaterEqual,
        BinOp::And => BinaryOperator::LogicalAnd,
        BinOp::Or => BinaryOperator::LogicalOr,
        BinOp::Shuffle => Err(LoweringError::invalid(
            "BinOp::Shuffle is a subgroup op; it cannot be lowered as a naga binary operator. Fix: lower via emit_subgroup_gather_expr using a shuffle lane.",
        ))?,
        BinOp::Ballot => Err(LoweringError::invalid(
            "BinOp::Ballot is a subgroup op; lower it via emit_subgroup_ballot_expr using a predicate expression.",
        ))?,
        BinOp::WaveReduce => Err(LoweringError::invalid(
            "BinOp::WaveReduce is a subgroup op; lower it via emit_subgroup_collective_expr with SubgroupOperation::Add.",
        ))?,
        BinOp::WaveBroadcast => Err(LoweringError::invalid(
            "BinOp::WaveBroadcast is a subgroup op; lower it via emit_subgroup_gather_expr with GatherMode::Broadcast.",
        ))?,
        BinOp::Opaque(op) => Err(LoweringError::invalid(format!(
            "opaque binop (id={:#010x}) requires extension lowering before binary_operator. Fix: add a `WgpuBinOpRegistration` or canonicalize to WGSL-native ops.",
            op.0
        )))?,
        _ => Err(LoweringError::invalid(
            "unknown future BinOp reached wgpu Naga lowering. Fix: update vyre-wgpu before dispatching this Program.",
        ))?,
    })
}

pub(crate) fn expr_type(
    expr: &Expr,
    builder: &FunctionBuilder<'_>,
) -> Result<DataType, LoweringError> {
    match expr {
        Expr::LitU32(_)
        | Expr::InvocationId { .. }
        | Expr::WorkgroupId { .. }
        | Expr::LocalId { .. }
        | Expr::BufLen { .. }
        | Expr::SubgroupLocalId
        | Expr::SubgroupSize
        | Expr::SubgroupBallot { .. } => Ok(DataType::U32),
        Expr::LitI32(_) => Ok(DataType::I32),
        Expr::LitF32(_) => Ok(DataType::F32),
        Expr::LitBool(_) => Ok(DataType::Bool),
        Expr::Var(name) => builder.local_types.get(name.as_str()).cloned().ok_or_else(|| {
            LoweringError::invalid(format!(
                "unknown local `{name}`. Fix: bind the variable before type inference."
            ))
        }),
        Expr::Load { buffer, .. } => Ok(builder
            .module
            .buffers
            .get(buffer.as_str())
            .ok_or_else(|| {
                LoweringError::invalid(format!(
                    "unknown buffer `{buffer}`. Fix: declare it before type inference."
                ))
            })?
            .decl
            .element
            .clone()),
        Expr::BinOp { op, left, .. } => match op {
            BinOp::Eq
            | BinOp::Ne
            | BinOp::Lt
            | BinOp::Gt
            | BinOp::Le
            | BinOp::Ge
            | BinOp::And
            | BinOp::Or => Ok(DataType::Bool),
            BinOp::Ballot => Ok(DataType::U32),
            BinOp::Shuffle | BinOp::WaveReduce | BinOp::WaveBroadcast => expr_type(left, builder),
            _ => expr_type(left, builder),
        },
        Expr::UnOp { op, operand } => match op {
            UnOp::LogicalNot | UnOp::IsNan | UnOp::IsInf | UnOp::IsFinite => Ok(DataType::Bool),
            _ => expr_type(operand, builder),
        },
        Expr::Select { true_val, .. } => expr_type(true_val, builder),
        Expr::Cast { target, .. } => Ok(target.clone()),
        Expr::Fma { .. } => Ok(DataType::F32),
        Expr::Call { op_id, .. } => Err(LoweringError::invalid(format!(
            "un-inlined call `{op_id}` reached type inference. Fix: inline before lowering."
        ))),
        Expr::Atomic { buffer, .. } => Ok(builder
            .module
            .buffers
            .get(buffer.as_str())
            .ok_or_else(|| {
                LoweringError::invalid(format!(
                    "unknown buffer `{buffer}`. Fix: declare it before type inference."
                ))
            })?
            .decl
            .element
            .clone()),
        Expr::Opaque(ext) => ext.result_type().ok_or_else(|| {
            LoweringError::invalid(format!(
                "opaque expression `{}` lacks a result type. Fix: provide result_type for type inference.",
                ext.extension_kind()
            ))
        }),
        Expr::SubgroupShuffle { value, .. } | Expr::SubgroupAdd { value } => {
            expr_type(value, builder)
        }
        _ => Err(LoweringError::invalid(
            "unknown future Expr variant reached wgpu type inference. Fix: update vyre-wgpu before dispatching this Program.",
        )),
    }
}

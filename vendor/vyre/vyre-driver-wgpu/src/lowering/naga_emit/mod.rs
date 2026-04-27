//! Naga AST emitter for vyre IR.
//!
//! This file constructs Naga IR directly. It does not assemble shader source
//! strings; WGSL text is produced only by `naga::back::wgsl` after validation.
use crate::lowering::naga_emit::utils::{address_space, binding, push_builtin_arg};

use super::LoweringError;
use naga::{
    ArraySize, BuiltIn, EntryPoint, Expression, Function, GlobalVariable, LocalVariable, Module,
    Scalar, ScalarKind, ShaderStage, Span, Statement, Type, TypeInner, VectorSize,
};
use rustc_hash::{FxHashMap, FxHashSet};
use std::num::NonZeroU32;
use std::ops::ControlFlow::{self, Continue};
use std::sync::Arc;
use vyre_foundation::ir::model::expr::GeneratorRef;
use vyre_foundation::ir::{BufferAccess, BufferDecl, DataType, Expr, MemoryKind, Node, Program};
use vyre_foundation::visit::{visit_node_preorder, visit_preorder, ExprVisitor, NodeVisitor};

use self::extension_ops::{scan_registered_atomic_expr, scan_registered_atomic_node};

pub(crate) trait WgpuEmitNode: std::any::Any {
    fn wgpu_emit_node(&self, builder: &mut FunctionBuilder<'_>) -> Result<(), LoweringError>;
}
pub(crate) mod expr;
pub(crate) mod extension_ops;
pub(crate) mod node;
pub(crate) mod utils;

pub(crate) trait WgpuEmitExpr: std::any::Any {
    fn wgpu_emit_expr(
        &self,
        builder: &mut FunctionBuilder<'_>,
    ) -> Result<naga::Handle<Expression>, LoweringError>;
}

pub(crate) const TRAP_SIDECAR_NAME: &str = "__vyre_wgpu_trap_sidecar";
pub(crate) const TRAP_SIDECAR_WORDS: u32 = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct TrapTag {
    pub(crate) code: u32,
    pub(crate) tag: Arc<str>,
}

#[derive(Clone, Copy)]
struct TypeHandles {
    bool_ty: naga::Handle<Type>,
    u32_ty: naga::Handle<Type>,
    i32_ty: naga::Handle<Type>,
    f32_ty: naga::Handle<Type>,
    vec2_u32_ty: naga::Handle<Type>,
    vec3_u32_ty: naga::Handle<Type>,
    vec4_u32_ty: naga::Handle<Type>,
    atomic_compare_exchange_u32_ty: naga::Handle<Type>,
    atomic_compare_exchange_i32_ty: naga::Handle<Type>,
}

struct BufferBinding {
    decl: BufferDecl,
    global: naga::Handle<GlobalVariable>,
}

pub(crate) struct ModuleBuilder {
    module: Module,
    types: TypeHandles,
    buffers: FxHashMap<String, BufferBinding>,
}

pub(crate) struct FunctionBuilder<'a> {
    pub(crate) module: &'a ModuleBuilder,
    pub(crate) function: Function,
    pub(crate) locals: FxHashMap<String, naga::Handle<LocalVariable>>,
    pub(crate) local_types: FxHashMap<String, DataType>,
    pub(crate) gid_arg: u32,
    pub(crate) wgid_arg: u32,
    pub(crate) lid_arg: u32,
    pub(crate) sgid_arg: Option<u32>,
    pub(crate) sgsize_arg: Option<u32>,
    pub(crate) temp_counter: u32,
    pub(crate) region_generators: Vec<String>,
    pub(crate) trap_tag_codes: FxHashMap<String, u32>,
}

/// Emit a validated Naga module for a vyre program.
///
/// # Errors
///
/// Returns [`LoweringError`] when the IR references unsupported types,
/// buffers, statements, or expressions, or when Naga validation rejects the
/// emitted module.
pub fn emit_module(
    program: &Program,
    _config: &vyre::DispatchConfig,
    workgroup_size: [u32; 3],
) -> Result<Module, LoweringError> {
    let program = prepared_program(program)?;
    let trap_tags = trap_tags_for_prepared_program(&program);

    // Pre-pass: collect every buffer name that appears as the target
    // of an `Expr::Atomic`. WGSL/Naga rejects atomic ops on
    // non-atomic-typed storage; element type for those buffers must
    // be `atomic<u32>` instead of plain `u32`. Without this scan the
    // validator emits `InvalidAtomic(InvalidPointer(...))`.
    let mut atomic_targets = FxHashSet::<String>::default();
    for node in program.entry() {
        scan_atomic_targets(node, &mut atomic_targets)?;
    }
    // Note: BufferAccess auto-inference happens in `prepared_program`
    // (one source of truth that flows to BOTH naga emission AND
    // pipeline-layout construction). By the time we reach this loop,
    // every ReadWrite buffer in `program.buffers()` is genuinely
    // written somewhere — pipeline.rs and naga see the same set.
    let mut builder = ModuleBuilder::new();
    for buffer in program.buffers() {
        let is_atomic = atomic_targets.contains(buffer.name());
        builder.add_buffer(buffer, is_atomic)?;
    }
    if !trap_tags.is_empty() {
        let trap_sidecar = trap_sidecar_decl(&program)?;
        atomic_targets.insert(TRAP_SIDECAR_NAME.to_string());
        builder.add_buffer(&trap_sidecar, true)?;
    }

    // workgroup_size is now passed explicitly from the optimal_workgroup_size heuristic
    let entry_point = builder.entry_point(&program, workgroup_size, &trap_tags)?;
    builder.module.entry_points.push(entry_point);

    // VYRE_NAGA_LOWER HIGH (mod.rs:107 + lowering/mod.rs:147):
    // previously validated the module here AND again inside
    // write_wgsl — O(n) × 2 per compile. Emission no longer
    // validates; the single validation at the writer boundary
    // produces the same correctness guarantee at half the cost.
    // If a consumer needs a standalone-validated Module (e.g. the
    // SPIR-V back-end without WGSL), it must call Validator itself
    // or route through the writer. The leaky println! diagnostic
    // previously guarded here is now handled in `write_wgsl` via
    // tracing::trace.

    Ok(builder.module)
}

pub(crate) fn prepared_program(program: &Program) -> Result<Program, LoweringError> {
    let program = vyre::ir::inline_calls(program)
        .map_err(|error| LoweringError::invalid(error.to_string()))?;
    let program = vyre::ir::optimize(program);
    // BufferAccess auto-inference. Walk the entry nodes and collect
    // the set of buffers that receive a write (Node::Store /
    // AsyncStore / AsyncLoad / IndirectDispatch / Expr::Atomic*). Any
    // ReadWrite buffer NOT in that set is auto-downgraded to
    // ReadOnly. The result flows to BOTH the naga emitter (which
    // emits the WGSL `var<storage, read>` access mode) AND the
    // pipeline-layout descriptor (which sets `read_only=true`) — they
    // agree by construction. Pre-fix: surgec's merge step defaulted
    // every intermediate buffer to ReadWrite for safety; pipeline
    // layout was built from BufferDecl.access (ReadWrite →
    // read_only=false) but the shader emitter saw only loads.
    // wgpu's validator rejected the mismatch.
    let mut atomic_targets = FxHashSet::<String>::default();
    let mut write_targets = FxHashSet::<String>::default();
    for node in program.entry() {
        scan_atomic_targets_into(node, &mut atomic_targets, &mut write_targets)?;
    }
    let new_buffers: Vec<BufferDecl> = program
        .buffers()
        .iter()
        .map(|buffer| {
            if matches!(buffer.access, vyre_foundation::ir::BufferAccess::ReadWrite)
                && !write_targets.contains(buffer.name())
                && !atomic_targets.contains(buffer.name())
            {
                let mut downgraded = buffer.clone();
                downgraded.access = vyre_foundation::ir::BufferAccess::ReadOnly;
                downgraded
            } else {
                buffer.clone()
            }
        })
        .collect();
    Ok(Program::wrapped(
        new_buffers,
        program.workgroup_size,
        program.entry().to_vec(),
    ))
}

pub(crate) fn trap_tags(program: &Program) -> Result<Arc<[TrapTag]>, LoweringError> {
    let program = prepared_program(program)?;
    Ok(trap_tags_for_prepared_program(&program).into())
}

pub(crate) fn trap_sidecar_decl(program: &Program) -> Result<BufferDecl, LoweringError> {
    Ok(BufferDecl::storage(
        TRAP_SIDECAR_NAME,
        trap_sidecar_binding(program)?,
        BufferAccess::ReadWrite,
        DataType::U32,
    )
    .with_count(TRAP_SIDECAR_WORDS))
}

fn trap_tags_for_prepared_program(program: &Program) -> Vec<TrapTag> {
    let mut collector = TrapTagCollector {
        tags: Vec::new(),
        seen: FxHashSet::default(),
    };
    for node in program.entry() {
        let _ = visit_node_preorder(&mut collector, node);
    }
    collector.tags
}

fn trap_sidecar_binding(program: &Program) -> Result<u32, LoweringError> {
    let trap_group = crate::lowering::bind_group_for(MemoryKind::Global);
    let mut next = 0u32;
    for buffer in program.buffers() {
        if crate::lowering::bind_group_for(buffer.kind()) == trap_group {
            next = next.max(buffer.binding().checked_add(1).ok_or_else(|| {
                LoweringError::invalid(
                    "program uses u32::MAX as a wgpu binding in the trap sidecar bind group. Fix: leave one free binding for backend-owned trap propagation.",
                )
            })?);
        }
    }
    Ok(next)
}

struct TrapTagCollector {
    tags: Vec<TrapTag>,
    seen: FxHashSet<String>,
}

impl NodeVisitor for TrapTagCollector {
    type Break = ();

    fn visit_let(&mut self, _: &Node, _: &vyre_foundation::ir::Ident, _: &Expr) -> ControlFlow<()> {
        Continue(())
    }

    fn visit_assign(
        &mut self,
        _: &Node,
        _: &vyre_foundation::ir::Ident,
        _: &Expr,
    ) -> ControlFlow<()> {
        Continue(())
    }

    fn visit_store(
        &mut self,
        _: &Node,
        _: &vyre_foundation::ir::Ident,
        _: &Expr,
        _: &Expr,
    ) -> ControlFlow<()> {
        Continue(())
    }

    fn visit_if(&mut self, _: &Node, _: &Expr, _: &[Node], _: &[Node]) -> ControlFlow<()> {
        Continue(())
    }

    fn visit_loop(
        &mut self,
        _: &Node,
        _: &vyre_foundation::ir::Ident,
        _: &Expr,
        _: &Expr,
        _: &[Node],
    ) -> ControlFlow<()> {
        Continue(())
    }

    fn visit_indirect_dispatch(
        &mut self,
        _: &Node,
        _: &vyre_foundation::ir::Ident,
        _: u64,
    ) -> ControlFlow<()> {
        Continue(())
    }

    fn visit_async_load(
        &mut self,
        _: &Node,
        _: &vyre_foundation::ir::Ident,
        _: &vyre_foundation::ir::Ident,
        _: &Expr,
        _: &Expr,
        _: &vyre_foundation::ir::Ident,
    ) -> ControlFlow<()> {
        Continue(())
    }

    fn visit_async_store(
        &mut self,
        _: &Node,
        _: &vyre_foundation::ir::Ident,
        _: &vyre_foundation::ir::Ident,
        _: &Expr,
        _: &Expr,
        _: &vyre_foundation::ir::Ident,
    ) -> ControlFlow<()> {
        Continue(())
    }

    fn visit_async_wait(&mut self, _: &Node, _: &vyre_foundation::ir::Ident) -> ControlFlow<()> {
        Continue(())
    }

    fn visit_trap(
        &mut self,
        _: &Node,
        _: &Expr,
        tag: &vyre_foundation::ir::Ident,
    ) -> ControlFlow<()> {
        let tag = tag.to_string();
        if self.seen.insert(tag.clone()) {
            let code = u32::try_from(self.tags.len())
                .unwrap_or(u32::MAX)
                .saturating_add(1);
            self.tags.push(TrapTag {
                code,
                tag: Arc::from(tag),
            });
        }
        Continue(())
    }

    fn visit_resume(&mut self, _: &Node, _: &vyre_foundation::ir::Ident) -> ControlFlow<()> {
        Continue(())
    }

    fn visit_return(&mut self, _: &Node) -> ControlFlow<()> {
        Continue(())
    }

    fn visit_barrier(&mut self, _: &Node) -> ControlFlow<()> {
        Continue(())
    }

    fn visit_block(&mut self, _: &Node, _: &[Node]) -> ControlFlow<()> {
        Continue(())
    }

    fn visit_region(
        &mut self,
        _: &Node,
        _: &vyre_foundation::ir::Ident,
        _: &Option<GeneratorRef>,
        _: &[Node],
    ) -> ControlFlow<()> {
        Continue(())
    }

    fn visit_opaque_node(
        &mut self,
        _: &Node,
        _: &dyn vyre_foundation::ir::NodeExtension,
    ) -> ControlFlow<()> {
        Continue(())
    }
}

impl ModuleBuilder {
    fn new() -> Self {
        let mut module = Module::default();
        let bool_ty = module.types.insert(
            Type {
                name: Some("bool".to_string()),
                inner: TypeInner::Scalar(Scalar {
                    kind: ScalarKind::Bool,
                    width: 1,
                }),
            },
            Span::UNDEFINED,
        );
        let u32_ty = module.types.insert(
            Type {
                name: Some("u32".to_string()),
                inner: TypeInner::Scalar(Scalar {
                    kind: ScalarKind::Uint,
                    width: 4,
                }),
            },
            Span::UNDEFINED,
        );
        let i32_ty = module.types.insert(
            Type {
                name: Some("i32".to_string()),
                inner: TypeInner::Scalar(Scalar {
                    kind: ScalarKind::Sint,
                    width: 4,
                }),
            },
            Span::UNDEFINED,
        );
        let f32_ty = module.types.insert(
            Type {
                name: Some("f32".to_string()),
                inner: TypeInner::Scalar(Scalar {
                    kind: ScalarKind::Float,
                    width: 4,
                }),
            },
            Span::UNDEFINED,
        );
        let vec2_u32_ty = module.types.insert(
            Type {
                name: Some("vec2_u32".to_string()),
                inner: TypeInner::Vector {
                    size: VectorSize::Bi,
                    scalar: Scalar {
                        kind: ScalarKind::Uint,
                        width: 4,
                    },
                },
            },
            Span::UNDEFINED,
        );
        let vec3_u32_ty = module.types.insert(
            Type {
                name: Some("vec3_u32".to_string()),
                inner: TypeInner::Vector {
                    size: VectorSize::Tri,
                    scalar: Scalar {
                        kind: ScalarKind::Uint,
                        width: 4,
                    },
                },
            },
            Span::UNDEFINED,
        );
        let vec4_u32_ty = module.types.insert(
            Type {
                name: Some("vec4_u32".to_string()),
                inner: TypeInner::Vector {
                    size: VectorSize::Quad,
                    scalar: Scalar {
                        kind: ScalarKind::Uint,
                        width: 4,
                    },
                },
            },
            Span::UNDEFINED,
        );
        let atomic_compare_exchange_u32_ty = module.types.insert(
            Type {
                name: Some("__atomic_compare_exchange_result_u32".to_string()),
                inner: TypeInner::Struct {
                    members: vec![
                        naga::StructMember {
                            name: Some("old_value".to_string()),
                            ty: u32_ty,
                            binding: None,
                            offset: 0,
                        },
                        naga::StructMember {
                            name: Some("exchanged".to_string()),
                            ty: bool_ty,
                            binding: None,
                            offset: 4,
                        },
                    ],
                    span: 8,
                },
            },
            Span::UNDEFINED,
        );
        let atomic_compare_exchange_i32_ty = module.types.insert(
            Type {
                name: Some("__atomic_compare_exchange_result_i32".to_string()),
                inner: TypeInner::Struct {
                    members: vec![
                        naga::StructMember {
                            name: Some("old_value".to_string()),
                            ty: i32_ty,
                            binding: None,
                            offset: 0,
                        },
                        naga::StructMember {
                            name: Some("exchanged".to_string()),
                            ty: bool_ty,
                            binding: None,
                            offset: 4,
                        },
                    ],
                    span: 8,
                },
            },
            Span::UNDEFINED,
        );
        Self {
            module,
            types: TypeHandles {
                bool_ty,
                u32_ty,
                i32_ty,
                f32_ty,
                vec2_u32_ty,
                vec3_u32_ty,
                vec4_u32_ty,
                atomic_compare_exchange_u32_ty,
                atomic_compare_exchange_i32_ty,
            },
            buffers: FxHashMap::default(),
        }
    }

    fn scalar_type(&self, data_type: DataType) -> Result<naga::Handle<Type>, LoweringError> {
        match data_type {
            DataType::Bool => Ok(self.types.bool_ty),
            DataType::U8 | DataType::U16 | DataType::U32 => Ok(self.types.u32_ty),
            DataType::I8 | DataType::I16 | DataType::I32 => Ok(self.types.i32_ty),
            DataType::U64 => Ok(self.types.vec2_u32_ty),
            DataType::F16 => Err(LoweringError::invalid(
                "F16 is not enabled in this wgpu/Naga stack because WGSL `enable f16` is rejected by the parser. Fix: route through an SPIR-V/Vulkan path with f16 support or lower F16 storage through an explicit u16 packing pass.",
            )),
            DataType::F32 => Ok(self.types.f32_ty),
            DataType::Vec2U32 => Ok(self.types.vec2_u32_ty),
            DataType::Vec4U32 => Ok(self.types.vec4_u32_ty),
            DataType::Bytes => Err(LoweringError::invalid(
                "Bytes buffers require a pack-to-u32 pre-pass before wgpu lowering. Fix: materialize a byte-addressable backend layout or pack the bytes into u32 words.",
            )),
            DataType::Array { element_size: 4 } => Ok(self.types.u32_ty),
            DataType::Array { element_size } => Err(LoweringError::invalid(format!(
                "array element size {element_size} is not representable in the current WGSL path. Fix: lower it to a struct-backed array or normalize it to 4-byte elements before wgpu emission."
            ))),
            DataType::F64 => Err(LoweringError::invalid(
                "F64 is not representable in WGSL 1.0. Fix: cast to F32 or lower it through the existing vec2<u32> emulation path before wgpu emission.",
            )),
            DataType::BF16 => Err(LoweringError::invalid(
                "BF16 has no direct WGSL scalar. Fix: convert it to F16/F32 before wgpu lowering.",
            )),
            DataType::I64 => Err(LoweringError::invalid(
                "I64 has no direct WGSL scalar. Fix: lower it through a vec2<u32> emulation path before wgpu emission.",
            )),
            DataType::Tensor
            | DataType::Handle(_)
            | DataType::Vec { .. }
            | DataType::TensorShaped { .. }
            | DataType::SparseCsr { .. }
            | DataType::SparseCoo { .. }
            | DataType::SparseBsr { .. }
            | DataType::F8E4M3
            | DataType::F8E5M2
            | DataType::I4
            | DataType::FP4
            | DataType::NF4
            | DataType::DeviceMesh { .. }
            | DataType::Opaque(_) => Err(LoweringError::unsupported_type(&data_type)),
            _ => Err(LoweringError::unsupported_type(&data_type)),
        }
    }

    /// Storage-safe scalar: WGSL's `bool` is not `HOST_SHAREABLE`, so buffers
    /// declared with `DataType::Bool` land as `u32` on the GPU side. The
    /// element type returned here is the one naga will emit for the buffer;
    /// expression-level loads/stores through the buffer cast through u32.
    fn storage_scalar_type(
        &self,
        data_type: DataType,
    ) -> Result<naga::Handle<Type>, LoweringError> {
        match data_type {
            DataType::Bool => Ok(self.types.u32_ty),
            other => self.scalar_type(other),
        }
    }

    fn add_buffer(
        &mut self,
        buffer: &BufferDecl,
        is_atomic_target: bool,
    ) -> Result<(), LoweringError> {
        let scalar_ty = self.storage_scalar_type(buffer.element.clone())?;
        // V7-ENGINE-1: when an `Expr::Atomic` writes to this buffer,
        // wrap each element in `atomic<scalar>` so naga's validator
        // accepts `Statement::Atomic { pointer: ..., }` against it.
        // Without this every atomic op fails with
        // `InvalidAtomic(InvalidPointer(...))` at validation time.
        let element_ty = if is_atomic_target {
            // Atomic only meaningful for u32/i32 in vyre 0.6 (matches
            // Naga's allowed atomic scalars). Bool / float buffers fall
            // through to plain scalar — the front-end op design rules
            // them out, so we don't need to handle them here.
            match buffer.element {
                DataType::U32 | DataType::I32 => self.module.types.insert(
                    Type {
                        name: Some(format!("{}_atomic_elem", buffer.name())),
                        inner: TypeInner::Atomic(Scalar {
                            kind: if matches!(buffer.element, DataType::U32) {
                                ScalarKind::Uint
                            } else {
                                ScalarKind::Sint
                            },
                            width: 4,
                        }),
                    },
                    Span::UNDEFINED,
                ),
                _ => {
                    return Err(LoweringError::invalid(format!(
                        "buffer `{}` is the target of `Expr::Atomic` but its element type is {:?} — vyre/Naga only support atomic ops over u32/i32 scalars. Fix: declare the buffer with DataType::U32 or DataType::I32.",
                        buffer.name(),
                        buffer.element
                    )));
                }
            }
        } else {
            scalar_ty
        };
        // CRITIQUE_NAGA_DEEPER_2026-04-23 FINDING-52: a silent `.unwrap_or(4)`
        // would pick 4 bytes for any future DataType whose size_bytes() is
        // None (Opaque, Tensor, ...), producing a shader whose declared
        // array stride disagrees with the actual element layout. Naga
        // validation still accepts the type because 4 is a valid stride;
        // the resulting shader reads/writes the wrong offsets silently.
        // Reject with a named error so the missing size_bytes arm is
        // visible at the construction site.
        let raw_stride_bytes = buffer.element.size_bytes().ok_or_else(|| {
            LoweringError::invalid(format!(
                "cannot determine array stride for buffer `{}` of element type {:?}: \
                 size_bytes() returned None. Fix: add a size_bytes() arm for this \
                 DataType in vyre-foundation, or reject the type at program \
                 construction time before lowering.",
                buffer.name(),
                buffer.element
            ))
        })?;
        let stride_bytes = if matches!(buffer.kind, MemoryKind::Uniform) {
            raw_stride_bytes
                .checked_add(15)
                .map(|bytes| (bytes / 16) * 16)
                .ok_or_else(|| {
                    LoweringError::invalid(format!(
                        "uniform buffer `{}` element stride overflows during 16-byte alignment. \
                         Fix: split the uniform payload or lower it as storage memory.",
                        buffer.name()
                    ))
                })?
        } else {
            raw_stride_bytes
        };
        // VYRE_NAGA_LOWER HIGH-2: `as u32` silently truncates. A future
        // DataType with size_bytes() > u32::MAX would yield a valid-
        // looking but wrong stride; naga validation still accepts the
        // type because any non-zero stride is syntactically legal.
        // Fail fast with a named error so the oversized element is
        // visible at the lowering boundary instead of corrupting
        // offsets at dispatch time.
        let stride: u32 = stride_bytes.try_into().map_err(|_| {
            LoweringError::invalid(format!(
                "array stride {stride_bytes} bytes for buffer `{}` overflows u32. \
                 Fix: split the element type or restructure the buffer so per-element \
                 size fits in 4 GiB.",
                buffer.name()
            ))
        })?;
        let size = if matches!(buffer.kind, MemoryKind::Global | MemoryKind::Readonly) {
            ArraySize::Dynamic
        } else {
            if buffer.count == 0 {
                return Err(LoweringError::invalid(format!(
                    "buffer `{}` has zero static element count. Fix: set count > 0 for non-storage memory.",
                    buffer.name()
                )));
            }
            if (buffer.count as u64).checked_mul(stride as u64).is_none()
                || (buffer.count as u64) * (stride as u64) > u32::MAX as u64
            {
                return Err(LoweringError::invalid(format!(
                    "buffer `{}` static byte size overflows naga limits. Fix: reduce static array dimension to stay within 4GB.",
                    buffer.name()
                )));
            }
            ArraySize::Constant(NonZeroU32::new(buffer.count).ok_or_else(|| {
                LoweringError::invalid(format!(
                    "buffer `{}` has zero static element count. Fix: set count > 0 for non-storage memory.",
                    buffer.name()
                ))
            })?)
        };
        let array_ty = self.module.types.insert(
            Type {
                name: Some(format!("{}_elements", buffer.name())),
                inner: TypeInner::Array {
                    base: element_ty,
                    size,
                    stride,
                },
            },
            Span::UNDEFINED,
        );
        let global = self.module.global_variables.append(
            GlobalVariable {
                name: Some(buffer.name().to_string()),
                space: address_space(buffer)?,
                binding: binding(buffer),
                ty: array_ty,
                init: None,
            },
            Span::UNDEFINED,
        );
        self.buffers.insert(
            buffer.name().to_string(),
            BufferBinding {
                decl: buffer.clone(),
                global,
            },
        );
        Ok(())
    }

    fn entry_point(
        &self,
        program: &Program,
        workgroup_size: [u32; 3],
        trap_tags: &[TrapTag],
    ) -> Result<EntryPoint, LoweringError> {
        let mut function = Function::default();
        function.name = Some("main".to_string());
        let gid_arg = push_builtin_arg(
            &mut function,
            "_vyre_gid",
            self.types.vec3_u32_ty,
            BuiltIn::GlobalInvocationId,
        );
        let wgid_arg = push_builtin_arg(
            &mut function,
            "_vyre_wgid",
            self.types.vec3_u32_ty,
            BuiltIn::WorkGroupId,
        );
        let lid_arg = push_builtin_arg(
            &mut function,
            "_vyre_lid",
            self.types.vec3_u32_ty,
            BuiltIn::LocalInvocationId,
        );

        let uses_subgroup_ops = vyre_foundation::program_caps::scan(program).subgroup_ops;
        let sgid_arg = if uses_subgroup_ops {
            Some(push_builtin_arg(
                &mut function,
                "_vyre_sgid",
                self.types.u32_ty,
                naga::BuiltIn::SubgroupInvocationId,
            ))
        } else {
            None
        };
        let sgsize_arg = if uses_subgroup_ops {
            Some(push_builtin_arg(
                &mut function,
                "_vyre_sgsize",
                self.types.u32_ty,
                naga::BuiltIn::SubgroupSize,
            ))
        } else {
            None
        };

        let mut builder = FunctionBuilder {
            module: self,
            function,
            locals: FxHashMap::default(),
            local_types: FxHashMap::default(),
            gid_arg,
            wgid_arg,
            lid_arg,
            sgid_arg,
            sgsize_arg,
            temp_counter: 0,
            region_generators: Vec::new(),
            trap_tag_codes: trap_tags
                .iter()
                .map(|tag| (tag.tag.to_string(), tag.code))
                .collect(),
        };
        builder.emit_nodes(program.entry())?;
        Ok(EntryPoint {
            name: "main".to_string(),
            stage: ShaderStage::Compute,
            early_depth_test: None,
            workgroup_size,
            workgroup_size_overrides: None,
            function: builder.function,
        })
    }
}
/// Walk every node + sub-expression collecting buffer names that
/// appear as the target of `Expr::Atomic`. The result drives
/// `add_buffer`'s decision to wrap an element type in `atomic<...>`.
fn scan_atomic_targets(node: &Node, out: &mut FxHashSet<String>) -> Result<(), LoweringError> {
    let mut scanner = AtomicTargetScanner { out };
    match visit_node_preorder(&mut scanner, node) {
        Continue(()) => Ok(()),
        std::ops::ControlFlow::Break(error) => Err(error),
    }
}

/// Mirror of [`scan_atomic_targets`] that ALSO collects buffers
/// that receive a write via `Node::Store` / `Node::AsyncStore` /
/// `Node::IndirectDispatch` / `Expr::Atomic*`. Both the atomic-target
/// set and the write-target set come out of one walk.
fn scan_atomic_targets_into(
    node: &Node,
    atomic_out: &mut FxHashSet<String>,
    write_out: &mut FxHashSet<String>,
) -> Result<(), LoweringError> {
    // Atomic-target scan reuses the existing scanner for naga's
    // atomic-element-type decision.
    scan_atomic_targets(node, atomic_out)?;
    // Write-target scan: traverse Node::Store / AsyncStore /
    // IndirectDispatch buffer names. We use the atomic set seed
    // (every atomic target is also a write target) and add the
    // direct-store destinations.
    write_out.extend(atomic_out.iter().cloned());
    collect_node_store_buffers(node, write_out);
    Ok(())
}

/// Recursively walk a Node tree (without going through the visitor
/// trait) and collect every buffer name that appears as the
/// destination of `Node::Store`, `Node::AsyncStore` (`dest_buffer`),
/// or `Node::IndirectDispatch` (the dispatch buffer is written by
/// the host but ALSO tagged as a write target so the storage class
/// reflects WG↔HOST shared writability).
fn collect_node_store_buffers(node: &Node, out: &mut FxHashSet<String>) {
    use vyre_foundation::ir::Node as N;
    match node {
        N::Store { buffer, .. } => {
            out.insert(buffer.as_ref().to_string());
        }
        N::AsyncStore { destination, .. } => {
            out.insert(destination.as_ref().to_string());
        }
        N::IndirectDispatch { count_buffer, .. } => {
            out.insert(count_buffer.as_ref().to_string());
        }
        N::If {
            then, otherwise, ..
        } => {
            for c in then.iter().chain(otherwise.iter()) {
                collect_node_store_buffers(c, out);
            }
        }
        N::Loop { body, .. } => {
            for c in body {
                collect_node_store_buffers(c, out);
            }
        }
        N::Block(body) => {
            for c in body {
                collect_node_store_buffers(c, out);
            }
        }
        N::Region { body, .. } => {
            for c in body.as_ref() {
                collect_node_store_buffers(c, out);
            }
        }
        // Other variants (Let, Assign, Return, Barrier, AsyncLoad,
        // AsyncWait, Trap, Resume, Opaque) either don't write to a
        // buffer or write to one already covered by the atomic scan
        // (atomic-result is captured via scan_atomic_targets).
        _ => {}
    }
}

struct AtomicTargetScanner<'a> {
    out: &'a mut FxHashSet<String>,
}

impl ExprVisitor for AtomicTargetScanner<'_> {
    type Break = LoweringError;

    fn visit_lit_u32(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_lit_i32(&mut self, _: &Expr, _: i32) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_lit_f32(&mut self, _: &Expr, _: f32) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_lit_bool(&mut self, _: &Expr, _: bool) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_var(&mut self, _: &Expr, _: &vyre_foundation::ir::Ident) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_load(
        &mut self,
        expr: &Expr,
        _: &vyre_foundation::ir::Ident,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }

    fn visit_buf_len(
        &mut self,
        _: &Expr,
        _: &vyre_foundation::ir::Ident,
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_invocation_id(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_workgroup_id(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_local_id(&mut self, _: &Expr, _: u32) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_bin_op(
        &mut self,
        expr: &Expr,
        _: &vyre_foundation::ir::BinOp,
        _: &Expr,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }

    fn visit_un_op(
        &mut self,
        expr: &Expr,
        _: &vyre_foundation::ir::UnOp,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }

    fn visit_call(&mut self, expr: &Expr, _: &str, _: &[Expr]) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }

    fn visit_sequence(&mut self, _: &[Expr]) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_fma(&mut self, expr: &Expr, _: &Expr, _: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }

    fn visit_select(
        &mut self,
        expr: &Expr,
        _: &Expr,
        _: &Expr,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }

    fn visit_cast(&mut self, expr: &Expr, _: &DataType, _: &Expr) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }

    fn visit_atomic(
        &mut self,
        expr: &Expr,
        _: &vyre_foundation::ir::AtomicOp,
        buffer: &vyre_foundation::ir::Ident,
        _: &Expr,
        _: Option<&Expr>,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        self.out.insert(buffer.as_str().to_string());
        let _ = expr;
        Continue(())
    }

    fn visit_subgroup_ballot(&mut self, expr: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }

    fn visit_subgroup_shuffle(
        &mut self,
        expr: &Expr,
        _: &Expr,
        _: &Expr,
    ) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }

    fn visit_subgroup_add(&mut self, expr: &Expr, _: &Expr) -> ControlFlow<Self::Break> {
        let _ = expr;
        Continue(())
    }

    fn visit_subgroup_local_id(&mut self, _: &Expr) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_subgroup_size(&mut self, _: &Expr) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_opaque_expr(
        &mut self,
        _: &Expr,
        ext: &dyn vyre_foundation::ir::ExprNode,
    ) -> ControlFlow<Self::Break> {
        match scan_registered_atomic_expr(ext, self.out) {
            Ok(true) => return Continue(()),
            Ok(false) => {
                return ControlFlow::Break(LoweringError::invalid(format!(
                    "unsupported opaque expression `{}` in atomic scan. Fix: register WgpuScanAtomicExpr for this extension or lower it before wgpu atomic-target analysis.",
                    ext.debug_identity()
                )));
            }
            Err(error) => return ControlFlow::Break(error),
        }
    }
}

impl NodeVisitor for AtomicTargetScanner<'_> {
    type Break = LoweringError;

    fn visit_let(
        &mut self,
        _: &Node,
        _: &vyre_foundation::ir::Ident,
        value: &Expr,
    ) -> ControlFlow<Self::Break> {
        visit_preorder(self, value)
    }

    fn visit_assign(
        &mut self,
        _: &Node,
        _: &vyre_foundation::ir::Ident,
        value: &Expr,
    ) -> ControlFlow<Self::Break> {
        visit_preorder(self, value)
    }

    fn visit_store(
        &mut self,
        _: &Node,
        _: &vyre_foundation::ir::Ident,
        index: &Expr,
        value: &Expr,
    ) -> ControlFlow<Self::Break> {
        visit_preorder(self, index)?;
        visit_preorder(self, value)
    }

    fn visit_if(
        &mut self,
        node: &Node,
        cond: &Expr,
        _: &[Node],
        _: &[Node],
    ) -> ControlFlow<Self::Break> {
        visit_preorder(self, cond)?;
        let _ = node;
        Continue(())
    }

    fn visit_loop(
        &mut self,
        node: &Node,
        _: &vyre_foundation::ir::Ident,
        from: &Expr,
        to: &Expr,
        _: &[Node],
    ) -> ControlFlow<Self::Break> {
        visit_preorder(self, from)?;
        visit_preorder(self, to)?;
        let _ = node;
        Continue(())
    }

    fn visit_indirect_dispatch(
        &mut self,
        _: &Node,
        _: &vyre_foundation::ir::Ident,
        _: u64,
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_async_load(
        &mut self,
        _: &Node,
        _: &vyre_foundation::ir::Ident,
        _: &vyre_foundation::ir::Ident,
        offset: &Expr,
        size: &Expr,
        _: &vyre_foundation::ir::Ident,
    ) -> ControlFlow<Self::Break> {
        visit_preorder(self, offset)?;
        visit_preorder(self, size)
    }

    fn visit_async_store(
        &mut self,
        _: &Node,
        _: &vyre_foundation::ir::Ident,
        _: &vyre_foundation::ir::Ident,
        offset: &Expr,
        size: &Expr,
        _: &vyre_foundation::ir::Ident,
    ) -> ControlFlow<Self::Break> {
        visit_preorder(self, offset)?;
        visit_preorder(self, size)
    }

    fn visit_async_wait(
        &mut self,
        _: &Node,
        _: &vyre_foundation::ir::Ident,
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_trap(
        &mut self,
        _: &Node,
        address: &Expr,
        _: &vyre_foundation::ir::Ident,
    ) -> ControlFlow<Self::Break> {
        visit_preorder(self, address)
    }

    fn visit_resume(
        &mut self,
        _: &Node,
        _: &vyre_foundation::ir::Ident,
    ) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_return(&mut self, _: &Node) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_barrier(&mut self, _: &Node) -> ControlFlow<Self::Break> {
        Continue(())
    }

    fn visit_block(&mut self, node: &Node, _: &[Node]) -> ControlFlow<Self::Break> {
        let _ = node;
        Continue(())
    }

    fn visit_region(
        &mut self,
        node: &Node,
        _: &vyre_foundation::ir::Ident,
        _: &Option<GeneratorRef>,
        _: &[Node],
    ) -> ControlFlow<Self::Break> {
        let _ = node;
        Continue(())
    }

    fn visit_opaque_node(
        &mut self,
        _: &Node,
        ext: &dyn vyre_foundation::ir::NodeExtension,
    ) -> ControlFlow<Self::Break> {
        match scan_registered_atomic_node(ext, self.out) {
            Ok(true) => return Continue(()),
            Ok(false) => {}
            Err(error) => return ControlFlow::Break(error),
        }
        ControlFlow::Break(LoweringError::invalid(format!(
            "unsupported opaque node `{}` in atomic scan. Fix: register WgpuScanAtomicNode for this extension before lowering to wgpu.",
            ext.extension_kind()
        )))
    }
}

impl FunctionBuilder<'_> {
    pub(crate) fn append_expr(&mut self, expr: Expression) -> naga::Handle<Expression> {
        let needs_emit = !expr.needs_pre_emit();
        let handle = self.function.expressions.append(expr, Span::UNDEFINED);
        if needs_emit {
            self.function.body.push(
                Statement::Emit(naga::Range::new_from_bounds(handle, handle)),
                Span::UNDEFINED,
            );
        }
        handle
    }

    pub(crate) fn next_temp_name(&mut self, prefix: &str) -> String {
        let name = format!("__vyre_{prefix}_{}", self.temp_counter);
        self.temp_counter = self.temp_counter.checked_add(1).expect(
            "Fix: temp-counter overflowed; split the generated function before it exceeds u32.",
        );
        name
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use vyre_foundation::ir::{BufferDecl, DataType};
    use vyre_foundation::ir::{Expr, ExprNode, Node, Program};

    struct OpaqueAtomicExpr;

    impl std::fmt::Debug for OpaqueAtomicExpr {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            write!(f, "OpaqueAtomicExpr")
        }
    }

    impl ExprNode for OpaqueAtomicExpr {
        fn extension_kind(&self) -> &'static str {
            "test::scan::opaque-atomic"
        }
        fn debug_identity(&self) -> &str {
            "test::scan::opaque-atomic"
        }
        fn result_type(&self) -> Option<DataType> {
            Some(DataType::U32)
        }
        fn cse_safe(&self) -> bool {
            true
        }
        fn stable_fingerprint(&self) -> [u8; 32] {
            [0x42; 32]
        }
        fn validate_extension(&self) -> Result<(), String> {
            Ok(())
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    struct OpaqueAtomicExprScanner;

    impl extension_ops::WgpuScanAtomicExpr for OpaqueAtomicExprScanner {
        fn wgpu_scan_atomic_expr(
            &self,
            ext: &dyn ExprNode,
            out: &mut rustc_hash::FxHashSet<String>,
        ) -> Result<(), LoweringError> {
            ext.as_any()
                .downcast_ref::<OpaqueAtomicExpr>()
                .ok_or_else(|| {
                    LoweringError::invalid(
                        "opaque atomic scanner received the wrong expression payload. Fix: register scanner kinds with matching payload types.",
                    )
                })?;
            out.insert("opaque_target".to_string());
            Ok(())
        }
    }

    static OPAQUE_ATOMIC_EXPR_SCANNER: OpaqueAtomicExprScanner = OpaqueAtomicExprScanner;

    inventory::submit! {
        extension_ops::WgpuScanAtomicExprRegistration {
            kind: "test::scan::opaque-atomic",
            scanner: &OPAQUE_ATOMIC_EXPR_SCANNER,
        }
    }

    #[derive(Debug)]
    struct OpaqueUnknownExpr;
    impl ExprNode for OpaqueUnknownExpr {
        fn extension_kind(&self) -> &'static str {
            "test::scan::opaque-unknown"
        }
        fn debug_identity(&self) -> &str {
            "test::scan::opaque-unknown"
        }
        fn result_type(&self) -> Option<DataType> {
            Some(DataType::U32)
        }
        fn cse_safe(&self) -> bool {
            true
        }
        fn stable_fingerprint(&self) -> [u8; 32] {
            [0x99; 32]
        }
        fn validate_extension(&self) -> Result<(), String> {
            Ok(())
        }
        fn as_any(&self) -> &dyn std::any::Any {
            self
        }
    }

    #[test]
    fn atomic_scan_collects_targets_from_opaque_expr_extensions() {
        let mut scanner = rustc_hash::FxHashSet::default();
        let expr = Expr::Opaque(Arc::new(OpaqueAtomicExpr));
        let node = Node::let_bind("x", expr);
        scan_atomic_targets(&node, &mut scanner)
            .expect("Fix: atomic scanner should honor extension scan traits.");
        assert!(scanner.contains("opaque_target"));
    }

    #[test]
    fn atomic_scan_rejects_unknown_opaque_expr_extensions() {
        let program = Program::wrapped(
            vec![BufferDecl::output("out", 1, DataType::U32)],
            [1, 1, 1],
            vec![Node::store(
                "out",
                Expr::u32(0),
                Expr::Opaque(Arc::new(OpaqueUnknownExpr)),
            )],
        );
        let mut scanner = rustc_hash::FxHashSet::default();
        let err = scan_atomic_targets(&program.entry()[0], &mut scanner)
            .expect_err("Fix: unsupported opaque atomics should fail with actionable error.");
        let message = err.to_string();
        assert!(message.contains("unsupported opaque expression"));
        assert!(message.contains("Fix:"));
    }
}

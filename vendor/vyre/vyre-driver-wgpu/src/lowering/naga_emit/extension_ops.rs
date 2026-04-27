use super::{FunctionBuilder, LoweringError};
use naga::Expression;
use rustc_hash::FxHashSet;
use std::sync::LazyLock;
use vyre_foundation::extension::{resolve_atomic_op, resolve_bin_op, resolve_un_op};
use vyre_foundation::ir::{ExprNode, NodeExtension};
use vyre_spec::extension::{ExtensionAtomicOpId, ExtensionBinOpId, ExtensionUnOpId};

pub(crate) trait WgpuEmitBinOp: Send + Sync + 'static {
    fn wgpu_emit_bin_op(
        &self,
        builder: &mut FunctionBuilder<'_>,
        left: &vyre_foundation::ir::Expr,
        right: &vyre_foundation::ir::Expr,
    ) -> Result<naga::Handle<Expression>, LoweringError>;
}

pub(crate) trait WgpuEmitUnOp: Send + Sync + 'static {
    fn wgpu_emit_un_op(
        &self,
        builder: &mut FunctionBuilder<'_>,
        operand: &vyre_foundation::ir::Expr,
    ) -> Result<naga::Handle<Expression>, LoweringError>;
}

pub(crate) trait WgpuEmitAtomicOp: Send + Sync + 'static {
    fn wgpu_emit_atomic_op(
        &self,
        builder: &mut FunctionBuilder<'_>,
        buffer: &str,
        index: &vyre_foundation::ir::Expr,
        expected: Option<&vyre_foundation::ir::Expr>,
        value: &vyre_foundation::ir::Expr,
    ) -> Result<naga::Handle<Expression>, LoweringError>;
}

pub(crate) trait WgpuScanAtomicExpr: Send + Sync + 'static {
    fn wgpu_scan_atomic_expr(
        &self,
        ext: &dyn ExprNode,
        out: &mut FxHashSet<String>,
    ) -> Result<(), LoweringError>;
}

pub(crate) trait WgpuScanAtomicNode: Send + Sync + 'static {
    fn wgpu_scan_atomic_node(
        &self,
        ext: &dyn NodeExtension,
        out: &mut FxHashSet<String>,
    ) -> Result<(), LoweringError>;
}

pub(crate) struct WgpuBinOpRegistration {
    pub id: ExtensionBinOpId,
    pub emitter: &'static dyn WgpuEmitBinOp,
}

pub(crate) struct WgpuUnOpRegistration {
    pub id: ExtensionUnOpId,
    pub emitter: &'static dyn WgpuEmitUnOp,
}

pub(crate) struct WgpuAtomicOpRegistration {
    pub id: ExtensionAtomicOpId,
    pub emitter: &'static dyn WgpuEmitAtomicOp,
}

pub(crate) struct WgpuScanAtomicExprRegistration {
    pub kind: &'static str,
    pub scanner: &'static dyn WgpuScanAtomicExpr,
}

pub(crate) struct WgpuScanAtomicNodeRegistration {
    pub kind: &'static str,
    pub scanner: &'static dyn WgpuScanAtomicNode,
}

inventory::collect!(WgpuBinOpRegistration);
inventory::collect!(WgpuUnOpRegistration);
inventory::collect!(WgpuAtomicOpRegistration);
inventory::collect!(WgpuScanAtomicExprRegistration);
inventory::collect!(WgpuScanAtomicNodeRegistration);

pub(crate) fn scan_registered_atomic_expr(
    ext: &dyn ExprNode,
    out: &mut FxHashSet<String>,
) -> Result<bool, LoweringError> {
    for registration in inventory::iter::<WgpuScanAtomicExprRegistration> {
        if registration.kind == ext.extension_kind() {
            registration.scanner.wgpu_scan_atomic_expr(ext, out)?;
            return Ok(true);
        }
    }
    Ok(false)
}

pub(crate) fn scan_registered_atomic_node(
    ext: &dyn NodeExtension,
    out: &mut FxHashSet<String>,
) -> Result<bool, LoweringError> {
    for registration in inventory::iter::<WgpuScanAtomicNodeRegistration> {
        if registration.kind == ext.extension_kind() {
            registration.scanner.wgpu_scan_atomic_node(ext, out)?;
            return Ok(true);
        }
    }
    Ok(false)
}

fn frozen_bin_registry(
) -> &'static rustc_hash::FxHashMap<ExtensionBinOpId, &'static dyn WgpuEmitBinOp> {
    static FROZEN: LazyLock<rustc_hash::FxHashMap<ExtensionBinOpId, &'static dyn WgpuEmitBinOp>> =
        LazyLock::new(|| {
            inventory::iter::<WgpuBinOpRegistration>
                .into_iter()
                .map(|registration| (registration.id, registration.emitter))
                .collect()
        });
    &FROZEN
}

fn frozen_un_registry() -> &'static rustc_hash::FxHashMap<ExtensionUnOpId, &'static dyn WgpuEmitUnOp>
{
    static FROZEN: LazyLock<rustc_hash::FxHashMap<ExtensionUnOpId, &'static dyn WgpuEmitUnOp>> =
        LazyLock::new(|| {
            inventory::iter::<WgpuUnOpRegistration>
                .into_iter()
                .map(|registration| (registration.id, registration.emitter))
                .collect()
        });
    &FROZEN
}

fn frozen_atomic_registry(
) -> &'static rustc_hash::FxHashMap<ExtensionAtomicOpId, &'static dyn WgpuEmitAtomicOp> {
    static FROZEN: LazyLock<
        rustc_hash::FxHashMap<ExtensionAtomicOpId, &'static dyn WgpuEmitAtomicOp>,
    > = LazyLock::new(|| {
        inventory::iter::<WgpuAtomicOpRegistration>
            .into_iter()
            .map(|registration| (registration.id, registration.emitter))
            .collect()
    });
    &FROZEN
}

pub(crate) fn emit_registered_bin_op(
    id: ExtensionBinOpId,
    builder: &mut FunctionBuilder<'_>,
    left: &vyre_foundation::ir::Expr,
    right: &vyre_foundation::ir::Expr,
) -> Result<naga::Handle<Expression>, LoweringError> {
    if let Some(emitter) = frozen_bin_registry().get(&id) {
        return emitter.wgpu_emit_bin_op(builder, left, right);
    }
    let display = resolve_bin_op(id)
        .map(|op| op.display_name())
        .unwrap_or("unknown_bin_op");
    Err(LoweringError::invalid(format!(
        "opaque bin op `{display}` (id={:#010x}) has no wgpu lowering. Fix: register a `WgpuBinOpRegistration` for this extension id.",
        id.0
    )))
}

pub(crate) fn emit_registered_un_op(
    id: ExtensionUnOpId,
    builder: &mut FunctionBuilder<'_>,
    operand: &vyre_foundation::ir::Expr,
) -> Result<naga::Handle<Expression>, LoweringError> {
    if let Some(emitter) = frozen_un_registry().get(&id) {
        return emitter.wgpu_emit_un_op(builder, operand);
    }
    let display = resolve_un_op(id)
        .map(|op| op.display_name())
        .unwrap_or("unknown_un_op");
    Err(LoweringError::invalid(format!(
        "opaque unary op `{display}` (id={:#010x}) has no wgpu lowering. Fix: register a `WgpuUnOpRegistration` for this extension id.",
        id.0
    )))
}

pub(crate) fn emit_registered_atomic_op(
    id: ExtensionAtomicOpId,
    builder: &mut FunctionBuilder<'_>,
    buffer: &str,
    index: &vyre_foundation::ir::Expr,
    expected: Option<&vyre_foundation::ir::Expr>,
    value: &vyre_foundation::ir::Expr,
) -> Result<naga::Handle<Expression>, LoweringError> {
    if let Some(emitter) = frozen_atomic_registry().get(&id) {
        return emitter.wgpu_emit_atomic_op(builder, buffer, index, expected, value);
    }
    let display = resolve_atomic_op(id)
        .map(|op| op.display_name())
        .unwrap_or("unknown_atomic_op");
    Err(LoweringError::invalid(format!(
        "opaque atomic op `{display}` (id={:#010x}) has no wgpu lowering. Fix: register a `WgpuAtomicOpRegistration` for this extension id.",
        id.0
    )))
}

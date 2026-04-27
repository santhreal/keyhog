use crate::ir_inner::model::expr::Expr;
use crate::ir_inner::model::program::{BufferDecl, Program};
use crate::ir_inner::model::types::{BufferAccess, DataType};
use crate::validate::atomic_rules;
use crate::validate::bytes_rejection;
use crate::validate::cast::{cast_is_narrowing, cast_is_valid};
use crate::validate::depth;
use crate::validate::report::warn;
use crate::validate::typecheck::{self, expr_type};
use crate::validate::{err, Binding, ValidationError, ValidationOptions, ValidationReport};
use rustc_hash::FxHashMap;

#[allow(clippy::too_many_lines)]
#[inline]
pub(crate) fn validate_expr(
    expr: &Expr,
    buffers: &FxHashMap<&str, &BufferDecl>,
    scope: &FxHashMap<String, Binding>,
    options: ValidationOptions<'_>,
    report: &mut ValidationReport,
    depth_level: usize,
) {
    if !depth::check_expr_depth(depth_level, &mut report.errors) {
        return;
    }
    match expr {
        Expr::LitU32(_) | Expr::LitI32(_) | Expr::LitF32(_) | Expr::LitBool(_) => {}
        Expr::Var(name) => {
            if !scope.contains_key(name.as_str()) {
                report.errors.push(err(format!(
                    "reference to undeclared variable `{name}`. Fix: add `let {name} = ...;` before this use."
                )));
            }
        }
        Expr::Load { buffer, index } => {
            bytes_rejection::check_load(buffer, buffers, &mut report.errors);
            validate_expr(index, buffers, scope, options, report, depth_level + 1);
        }
        Expr::BufLen { buffer } => {
            if !buffers.contains_key(buffer.as_str()) {
                report.errors.push(err(format!(
                    "buflen of unknown buffer `{buffer}`. Fix: declare it in Program::buffers."
                )));
            }
        }
        Expr::InvocationId { axis } | Expr::WorkgroupId { axis } | Expr::LocalId { axis } => {
            if *axis > 2 {
                report.errors.push(err(format!(
                    "invocation/workgroup ID axis {axis} out of range. Fix: use 0 (x), 1 (y), or 2 (z)."
                )));
            }
        }
        Expr::BinOp { op, left, right } => {
            validate_expr(left, buffers, scope, options, report, depth_level + 1);
            validate_expr(right, buffers, scope, options, report, depth_level + 1);
            typecheck::validate_binop_operands(op, left, right, buffers, scope, &mut report.errors);
        }
        Expr::UnOp { op, operand } => {
            validate_expr(operand, buffers, scope, options, report, depth_level + 1);
            typecheck::validate_unop_operand(op, operand, buffers, scope, &mut report.errors);
        }
        Expr::Call { op_id: _, args } => {
            // Foundation validation cannot resolve op ids without a dialect
            // registry (foundation does not own one). Drivers run a second
            // registry-aware validation pass that emits V016/V020/V021/V022
            // with full context; here we only recurse into arguments so
            // their expression structure is still validated.
            for arg in args {
                validate_expr(arg, buffers, scope, options, report, depth_level + 1);
            }
        }
        Expr::Fma { a, b, c } => {
            validate_expr(a, buffers, scope, options, report, depth_level + 1);
            validate_expr(b, buffers, scope, options, report, depth_level + 1);
            validate_expr(c, buffers, scope, options, report, depth_level + 1);
            // VAL-002: Fma requires f32 operands on every input. WGSL `fma`
            // (and the reference interpreter's Fma path) are defined for
            // floats; integer operands silently become (a * b + c) via
            // u32 arithmetic today, which is NOT what the node promises.
            for (slot, operand) in [("a", a.as_ref()), ("b", b.as_ref()), ("c", c.as_ref())] {
                if let Some(ty) = expr_type(operand, buffers, scope) {
                    if ty != DataType::F32 {
                        report.errors.push(err(format!(
                            "V028: Fma operand `{slot}` has type `{ty}`, must be `f32`. Fix: cast the operand to F32 before Fma, or use the integer mul/add form explicitly."
                        )));
                    }
                }
            }
        }
        Expr::Select {
            cond,
            true_val,
            false_val,
        } => {
            validate_expr(cond, buffers, scope, options, report, depth_level + 1);
            validate_expr(true_val, buffers, scope, options, report, depth_level + 1);
            validate_expr(false_val, buffers, scope, options, report, depth_level + 1);
            // VAL-002: Select requires the two branches to agree on type.
            // Divergent branch types give the node an ambiguous static type
            // and break downstream lowering + reference evaluation.
            let t_ty = expr_type(true_val, buffers, scope);
            let f_ty = expr_type(false_val, buffers, scope);
            if let (Some(t), Some(f)) = (&t_ty, &f_ty) {
                if t != f {
                    report.errors.push(err(format!(
                        "V029: Select branches have mismatched types: true=`{t}`, false=`{f}`. Fix: cast both branches to the same type before Select."
                    )));
                }
            }
        }
        Expr::Cast { target, value } => {
            validate_expr(value, buffers, scope, options, report, depth_level + 1);
            if !options.supports_cast_target(target) {
                report.errors.push(err(format!(
                    "V034: backend `{}` does not support cast target `{target}`. Fix: choose a target type this backend supports, or validate against a backend that advertises `{target}` cast support.",
                    options.backend_name()
                )));
            }
            if let Some(src) = expr_type(value, buffers, scope) {
                if target == &DataType::Bytes && src != DataType::Bytes {
                    report.errors.push(err(
                        "V023: cast to Bytes is unsupported in WGSL lowering. Fix: use buffer load/store directly for byte data."
                            .to_string(),
                    ));
                } else if !cast_is_valid(&src, target) {
                    let legal_targets = cast_target_set(&src);
                    report.errors.push(err(format!(
                        "V012: unsupported cast from `{src}` to `{target}`. Source type `{src}` legal targets are {legal_targets}. Choose one of those targets or rewrite this cast expression before validation."
                    )));
                } else if cast_is_narrowing(&src, target) {
                    let legal_targets = cast_target_set(&src);
                    report.warnings.push(warn(format!(
                        "V035: narrowing cast from `{src}` to `{target}` may truncate high bits. Source type `{src}` legal targets are {legal_targets}. Use a non-narrowing target or prove the source value fits before casting."
                    )));
                }
            }
        }
        Expr::Atomic {
            op,
            buffer,
            index,
            expected,
            value,
        } => {
            atomic_rules::validate_atomic(
                op,
                buffer,
                index,
                expected.as_deref(),
                value,
                buffers,
                scope,
                &mut report.errors,
            );
            validate_expr(index, buffers, scope, options, report, depth_level + 1);
            if let Some(expected) = expected {
                validate_expr(expected, buffers, scope, options, report, depth_level + 1);
            }
            validate_expr(value, buffers, scope, options, report, depth_level + 1);
        }
        Expr::SubgroupBallot { cond } => {
            validate_expr(cond, buffers, scope, options, report, depth_level + 1);
            validate_subgroup_expr_support(&mut report.errors, options);
        }
        Expr::SubgroupShuffle { value, lane } => {
            validate_expr(value, buffers, scope, options, report, depth_level + 1);
            validate_expr(lane, buffers, scope, options, report, depth_level + 1);
            validate_subgroup_expr_support(&mut report.errors, options);
        }
        Expr::SubgroupAdd { value } => {
            validate_expr(value, buffers, scope, options, report, depth_level + 1);
            validate_subgroup_expr_support(&mut report.errors, options);
        }
        Expr::SubgroupLocalId | Expr::SubgroupSize => {
            validate_subgroup_expr_support(&mut report.errors, options);
        }
        Expr::Opaque(extension) => {
            validate_expr_extension(extension.as_ref(), &mut report.errors);
        }
    }
}

#[inline]
fn cast_target_set(source: &DataType) -> String {
    let mut legal_targets = Vec::new();
    let candidate_targets = [
        source.clone(),
        DataType::U8,
        DataType::U16,
        DataType::U32,
        DataType::U64,
        DataType::I8,
        DataType::I16,
        DataType::I32,
        DataType::I64,
        DataType::Bool,
        DataType::Bytes,
        DataType::Vec2U32,
        DataType::Vec4U32,
        DataType::F32,
    ];

    for target in candidate_targets {
        if cast_is_valid(source, &target) && !legal_targets.contains(&target) {
            legal_targets.push(target);
        }
    }

    let formatted = legal_targets
        .into_iter()
        .map(|target| format!("`{target}`"))
        .collect::<Vec<_>>()
        .join(", ");

    format!("[{formatted}]")
}

#[inline]
fn validate_subgroup_expr_support(
    errors: &mut Vec<ValidationError>,
    options: ValidationOptions<'_>,
) {
    if !options.requires_subgroup_ops() {
        errors.push(err(
            "V041: subgroup expressions require backend subgroup-ops support. Fix: Validate with ValidationOptions::with_backend(backend) where backend.supports_subgroup_ops() == true.".to_string(),
        ));
    }
}

fn validate_expr_extension(
    extension: &dyn crate::ir_inner::model::expr::ExprNode,
    errors: &mut Vec<ValidationError>,
) {
    if extension.extension_kind().is_empty() {
        errors.push(err(
            "V030: opaque expression extension has an empty extension_kind. Fix: return a stable non-empty namespace from ExprNode::extension_kind.",
        ));
    }
    if extension.debug_identity().is_empty() {
        errors.push(err(format!(
            "V030: opaque expression extension `{}` has an empty debug_identity. Fix: return a stable human-readable identity from ExprNode::debug_identity.",
            extension.extension_kind()
        )));
    }
    if extension.result_type().is_none() {
        errors.push(err(format!(
            "V030: opaque expression extension `{}`/`{}` has no static result type. Fix: implement ExprNode::result_type so validation, CSE, and backends know the produced DataType.",
            extension.extension_kind(),
            extension.debug_identity()
        )));
    }
    if let Err(message) = extension.validate_extension() {
        errors.push(err(format!(
            "V030: opaque expression extension `{}`/`{}` failed validation: {message}",
            extension.extension_kind(),
            extension.debug_identity()
        )));
    }
}

#[inline]
pub(crate) fn validate_output_markers(buffers: &[BufferDecl], errors: &mut Vec<ValidationError>) {
    let outputs = output_marker_count(buffers);
    if outputs > 1 {
        errors.push(err(format!(
            "V022: program declares {outputs} output buffers. Fix: mark at most one result buffer with BufferDecl::output(...)."
        )));
    }
}

#[inline]
#[must_use]
pub(crate) fn output_marker_count(buffers: &[BufferDecl]) -> usize {
    buffers.iter().filter(|buf| buf.is_output()).count()
}

#[inline]
#[must_use]
pub(crate) fn call_input_count(program: &Program) -> usize {
    program
        .buffers
        .iter()
        .filter(|buf| matches!(buf.access, BufferAccess::ReadOnly | BufferAccess::Uniform))
        .count()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir_inner::model::expr::{ExprNode, Ident};
    use crate::validate::BackendValidationCapabilities;
    use rustc_hash::FxHashMap;
    use std::any::Any;
    use std::sync::Arc;

    #[derive(Debug)]
    struct SubgroupBackend {
        supports_subgroup_ops: bool,
    }

    impl BackendValidationCapabilities for SubgroupBackend {
        fn backend_name(&self) -> &'static str {
            "test-backend"
        }

        fn supports_cast_target(&self, target: &DataType) -> bool {
            matches!(target, DataType::U32)
        }

        fn supports_subgroup_ops(&self) -> bool {
            self.supports_subgroup_ops
        }
    }

    fn validate_subgroup_expr(expr: Expr, options: ValidationOptions<'_>) -> ValidationReport {
        let mut report = ValidationReport::default();
        let buffers = FxHashMap::default();
        let scope = FxHashMap::default();
        validate_expr(&expr, &buffers, &scope, options, &mut report, 0);
        report
    }

    #[derive(Debug)]
    struct TestExprExtension;

    impl ExprNode for TestExprExtension {
        fn extension_kind(&self) -> &'static str {
            "test.expr"
        }

        fn debug_identity(&self) -> &str {
            "test-expr"
        }

        fn result_type(&self) -> Option<DataType> {
            Some(DataType::U32)
        }

        fn cse_safe(&self) -> bool {
            true
        }

        fn stable_fingerprint(&self) -> [u8; 32] {
            [7; 32]
        }

        fn validate_extension(&self) -> Result<(), String> {
            Ok(())
        }

        fn as_any(&self) -> &dyn Any {
            self
        }
    }

    #[test]
    fn expr_match_guard_stays_exhaustive() {
        fn guard(expr: &Expr) {
            match expr {
                Expr::LitU32(_)
                | Expr::LitI32(_)
                | Expr::LitF32(_)
                | Expr::LitBool(_)
                | Expr::Var(_)
                | Expr::Load { .. }
                | Expr::BufLen { .. }
                | Expr::InvocationId { .. }
                | Expr::WorkgroupId { .. }
                | Expr::LocalId { .. }
                | Expr::SubgroupLocalId
                | Expr::SubgroupSize
                | Expr::BinOp { .. }
                | Expr::UnOp { .. }
                | Expr::Call { .. }
                | Expr::Select { .. }
                | Expr::Cast { .. }
                | Expr::Fma { .. }
                | Expr::Atomic { .. }
                | Expr::SubgroupBallot { .. }
                | Expr::SubgroupShuffle { .. }
                | Expr::SubgroupAdd { .. }
                | Expr::Opaque(_) => {}
            }
        }

        let exprs = [
            Expr::LitU32(1),
            Expr::LitI32(-1),
            Expr::LitF32(1.0),
            Expr::LitBool(true),
            Expr::Var(Ident::from("x")),
            Expr::Load {
                buffer: Ident::from("buf"),
                index: Box::new(Expr::LitU32(0)),
            },
            Expr::BufLen {
                buffer: Ident::from("buf"),
            },
            Expr::InvocationId { axis: 0 },
            Expr::WorkgroupId { axis: 0 },
            Expr::LocalId { axis: 0 },
            Expr::BinOp {
                op: crate::ir_inner::model::types::BinOp::Add,
                left: Box::new(Expr::LitU32(1)),
                right: Box::new(Expr::LitU32(2)),
            },
            Expr::UnOp {
                op: crate::ir_inner::model::types::UnOp::LogicalNot,
                operand: Box::new(Expr::LitBool(false)),
            },
            Expr::Call {
                op_id: Ident::from("op"),
                args: vec![Expr::LitU32(1)],
            },
            Expr::Select {
                cond: Box::new(Expr::LitBool(true)),
                true_val: Box::new(Expr::LitU32(1)),
                false_val: Box::new(Expr::LitU32(0)),
            },
            Expr::Cast {
                target: DataType::U32,
                value: Box::new(Expr::LitU32(1)),
            },
            Expr::Fma {
                a: Box::new(Expr::LitF32(1.0)),
                b: Box::new(Expr::LitF32(2.0)),
                c: Box::new(Expr::LitF32(3.0)),
            },
            Expr::Atomic {
                op: crate::ir_inner::model::types::AtomicOp::Add,
                buffer: Ident::from("buf"),
                index: Box::new(Expr::LitU32(0)),
                expected: None,
                value: Box::new(Expr::LitU32(1)),
            },
            Expr::SubgroupBallot {
                cond: Box::new(Expr::bool(true)),
            },
            Expr::SubgroupShuffle {
                value: Box::new(Expr::u32(1)),
                lane: Box::new(Expr::u32(0)),
            },
            Expr::SubgroupAdd {
                value: Box::new(Expr::u32(1)),
            },
            Expr::Opaque(Arc::new(TestExprExtension)),
        ];

        for expr in &exprs {
            guard(expr);
        }
    }

    #[test]
    fn subgroup_expression_without_backend_is_rejected() {
        let report = validate_subgroup_expr(
            Expr::SubgroupAdd {
                value: Box::new(Expr::u32(1)),
            },
            ValidationOptions::default(),
        );
        assert!(
            report.errors.iter().any(|error| error
                .message()
                .contains("subgroup expressions require backend subgroup-ops support")),
            "subgroup expression without backend capability must be rejected, got {:?}",
            report.errors
        );
    }

    #[test]
    fn subgroup_expression_with_supported_backend_is_accepted() {
        let backend = SubgroupBackend {
            supports_subgroup_ops: true,
        };
        let report = validate_subgroup_expr(
            Expr::SubgroupShuffle {
                value: Box::new(Expr::u32(1)),
                lane: Box::new(Expr::u32(0)),
            },
            ValidationOptions::default().with_backend(&backend),
        );
        assert!(
            report.errors.is_empty(),
            "supported subgroup backend must allow validation, got {:?}",
            report.errors
        );
    }
}

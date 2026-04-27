import os

base_dir = "/media/mukund-thiru/SanthData/Santh/libs/performance/matching/vyre/vyre-foundation/src"

fixes = [
    (
        "visit/expr.rs",
        [
            ("Expr::Telemetry { .. } => std::ops::ControlFlow::Continue(()),\n            Expr::Telemetry { .. } => std::ops::ControlFlow::Continue(()) ,", "Expr::Telemetry { .. } => std::ops::ControlFlow::Continue(()),"),
            ("Expr::Opaque(extension) => visitor.visit_opaque_expr(expr, extension.as_ref()),\n    }", "Expr::Opaque(extension) => visitor.visit_opaque_expr(expr, extension.as_ref()),\n        Expr::Telemetry { .. } => std::ops::ControlFlow::Continue(()),\n    }"),
        ]
    ),
    (
        "validate/typecheck.rs",
        [
            ("Expr::Telemetry { .. } => values.push(crate::ir::DataType::U32),", "Expr::Telemetry { .. } => values.push(Some(crate::ir::DataType::U32)),")
        ]
    ),
    (
        "optimizer/passes/fusion.rs",
        [
            ("Expr::Opaque(_) => {}", "Expr::Opaque(_) => {},\n            Expr::Telemetry { .. } => {}"),
            ("Expr::Opaque(_) => false,", "Expr::Opaque(_) => false,\n            Expr::Telemetry { .. } => false,"),
        ]
    ),
    (
        "serial/wire/encode/put_expr.rs",
        [
            ("        }", "        }\n        Expr::Telemetry { counter_id } => {\n            put_tag(out, 0x7E);\n            put_u32(out, *counter_id);\n        }")
        ]
    ),
    (
        "transform/inline/expand/impl_calleeexpander/primitive.rs",
        [
            ("Expr::Opaque(_) => Err(crate::error::Error::compile(", "Expr::Telemetry { .. } => Ok(()),\n            Expr::Opaque(_) => Err(crate::error::Error::compile(")
        ]
    ),
    (
        "transform/optimize/cse/expr_has_effect.rs",
        [
            ("Expr::Opaque(extension) => !extension.cse_safe(),", "Expr::Opaque(extension) => !extension.cse_safe(),\n        Expr::Telemetry { .. } => true,")
        ]
    ),
    (
        "transform/optimize/cse/impl_exprkey.rs",
        [
            ("Expr::Opaque(_) => return None,", "Expr::Opaque(_) => return None,\n            Expr::Telemetry { .. } => return None,")
        ]
    ),
    (
        "transform/optimize/dce/expr_has_effect.rs",
        [
            ("Expr::Opaque(extension) => !extension.dce_safe(),", "Expr::Opaque(extension) => !extension.dce_safe(),\n            Expr::Telemetry { .. } => true,")
        ]
    ),
    (
        "validate/expr_rules.rs",
        [
            ("Expr::Opaque(_) => {}", "Expr::Opaque(_) => {},\n        Expr::Telemetry { .. } => {}")
        ]
    ),
]

for fname, replacements in fixes:
    path = os.path.join(base_dir, fname)
    if os.path.exists(path):
        with open(path, "r") as f:
            content = f.read()
        
        for old, new in replacements:
            content = content.replace(old, new)
            
        with open(path, "w") as f:
            f.write(content)
        print(f"Fixed {path}")
    else:
        print(f"Not found: {path}")


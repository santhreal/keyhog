//! Assertion classification — SHAPE vs TRUTH.

#![allow(clippy::unnecessary_map_or)]

use syn::parse::Parser;
use syn::visit::Visit;
use syn::{Expr, ExprBinary, ExprUnary, ItemFn, Lit, Stmt, UnOp};

use super::Classification;
#[cfg(test)]
use super::{is_test_function, visit_items};

/// Classify a test function by walking its body for assert*! macros.
pub(crate) fn classify_test(func: &ItemFn) -> (Classification, String) {
    let mut collector = AssertCollector::default();
    collector.visit_item_fn(func);

    if collector.asserts.is_empty() {
        return (
            Classification::NoAsserts,
            "no assert*! macros found".to_string(),
        );
    }

    let mut shape_reasons = Vec::new();
    for (name, args) in &collector.asserts {
        if is_shape_assert(name, args) {
            shape_reasons.push(format!("{name}!(... shape-only ...)"));
        } else {
            return (
                Classification::Truth,
                format!("truth assertion: {name}!(...)"),
            );
        }
    }

    (
        Classification::Shape,
        format!(
            "all assertions are shape-only: {}",
            shape_reasons.join(", ")
        ),
    )
}

/// Accumulate every `assert*!` macro invocation inside a syntax subtree.
#[derive(Default)]
struct AssertCollector {
    asserts: Vec<(String, Vec<Expr>)>,
}

impl<'ast> Visit<'ast> for AssertCollector {
    fn visit_expr_macro(&mut self, node: &'ast syn::ExprMacro) {
        if let Some(ident) = node.mac.path.get_ident() {
            let name = ident.to_string();
            if name.starts_with("assert") {
                let parser = syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated;
                if let Ok(args) = parser.parse2(node.mac.tokens.clone()) {
                    self.asserts.push((name, args.into_iter().collect()));
                }
            }
        }
        syn::visit::visit_expr_macro(self, node);
    }

    fn visit_stmt_macro(&mut self, node: &'ast syn::StmtMacro) {
        if let Some(ident) = node.mac.path.get_ident() {
            let name = ident.to_string();
            if name.starts_with("assert") {
                let parser = syn::punctuated::Punctuated::<Expr, syn::Token![,]>::parse_terminated;
                if let Ok(args) = parser.parse2(node.mac.tokens.clone()) {
                    self.asserts.push((name, args.into_iter().collect()));
                }
            }
        }
        syn::visit::visit_stmt_macro(self, node);
    }
}

/// Return `true` if the given assert macro invocation matches a known
/// shape-only pattern.
fn is_shape_assert(name: &str, args: &[Expr]) -> bool {
    match name {
        "assert" => {
            let Some(first) = args.first() else {
                return false;
            };
            is_ok_call(first) || is_err_call(first) || is_not_empty(first) || is_len_gt_zero(first)
        }
        "assert_eq" => {
            let (Some(left), Some(right)) = (args.first(), args.get(1)) else {
                return false;
            };
            is_roundtrip(left, right)
        }
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// Shape-pattern recognisers
// ---------------------------------------------------------------------------

fn is_ok_call(expr: &Expr) -> bool {
    matches!(expr, Expr::MethodCall(m) if m.method == "is_ok")
}

fn is_err_call(expr: &Expr) -> bool {
    matches!(expr, Expr::MethodCall(m) if m.method == "is_err")
}

fn is_not_empty(expr: &Expr) -> bool {
    let Expr::Unary(ExprUnary {
        op: UnOp::Not(_),
        expr: inner,
        ..
    }) = expr
    else {
        return false;
    };
    matches!(inner.as_ref(), Expr::MethodCall(m) if m.method == "is_empty")
}

fn is_len_gt_zero(expr: &Expr) -> bool {
    let Expr::Binary(ExprBinary {
        op, left, right, ..
    }) = expr
    else {
        return false;
    };
    let is_gt = matches!(op, syn::BinOp::Gt(_));
    let left_is_len = matches!(left.as_ref(), Expr::MethodCall(m) if m.method == "len");
    let right_is_zero = is_literal_zero(right);
    is_gt && left_is_len && right_is_zero
}

fn is_literal_zero(expr: &Expr) -> bool {
    matches!(expr, Expr::Lit(l) if matches!(&l.lit, Lit::Int(i) if i.base10_parse::<i64>().unwrap_or(1) == 0))
}

/// Detect `assert_eq!(roundtrip(x), x)` — both arguments are the same
/// expression, or the right-hand side is an identifier that appears as an
/// argument in a call expression on the left-hand side.
fn is_roundtrip(left: &Expr, right: &Expr) -> bool {
    // Case 1: both sides are syntactically identical simple identifiers.
    if let (Expr::Path(a), Expr::Path(b)) = (left, right) {
        if a.path.get_ident() == b.path.get_ident() {
            return true;
        }
    }

    // Case 2: right is a simple identifier and left is a call that contains it.
    let Expr::Path(right_path) = right else {
        return false;
    };
    let Some(right_ident) = right_path.path.get_ident() else {
        return false;
    };
    let right_str = right_ident.to_string();

    if !is_call_expr(left) {
        return false;
    }
    expr_contains_ident(left, &right_str)
}

fn is_call_expr(expr: &Expr) -> bool {
    matches!(expr, Expr::Call(_) | Expr::MethodCall(_))
}

fn expr_contains_ident(expr: &Expr, target: &str) -> bool {
    match expr {
        Expr::Path(p) => p.path.get_ident().map(|i| i == target).unwrap_or(false),
        Expr::Call(c) => {
            c.args.iter().any(|a| expr_contains_ident(a, target))
                || expr_contains_ident(&c.func, target)
        }
        Expr::MethodCall(m) => {
            m.args.iter().any(|a| expr_contains_ident(a, target))
                || expr_contains_ident(&m.receiver, target)
        }
        Expr::Unary(u) => expr_contains_ident(&u.expr, target),
        Expr::Binary(b) => {
            expr_contains_ident(&b.left, target) || expr_contains_ident(&b.right, target)
        }
        Expr::Paren(p) => expr_contains_ident(&p.expr, target),
        Expr::Reference(r) => expr_contains_ident(&r.expr, target),
        Expr::Block(b) => b.block.stmts.iter().any(|s| stmt_contains_ident(s, target)),
        Expr::If(i) => {
            expr_contains_ident(&i.cond, target)
                || i.then_branch
                    .stmts
                    .iter()
                    .any(|s| stmt_contains_ident(s, target))
                || i.else_branch
                    .as_ref()
                    .map_or(false, |(_, e)| expr_contains_ident(e, target))
        }
        Expr::Match(m) => {
            expr_contains_ident(&m.expr, target)
                || m.arms.iter().any(|a| {
                    a.guard
                        .as_ref()
                        .map_or(false, |(_, g)| expr_contains_ident(g, target))
                        || expr_contains_ident(&a.body, target)
                })
        }
        Expr::Tuple(t) => t.elems.iter().any(|e| expr_contains_ident(e, target)),
        Expr::Array(a) => a.elems.iter().any(|e| expr_contains_ident(e, target)),
        Expr::Index(i) => {
            expr_contains_ident(&i.expr, target) || expr_contains_ident(&i.index, target)
        }
        Expr::Field(f) => expr_contains_ident(&f.base, target),
        Expr::Cast(c) => expr_contains_ident(&c.expr, target),
        Expr::Let(l) => expr_contains_ident(&l.expr, target),
        Expr::Loop(l) => l.body.stmts.iter().any(|s| stmt_contains_ident(s, target)),
        Expr::While(w) => {
            expr_contains_ident(&w.cond, target)
                || w.body.stmts.iter().any(|s| stmt_contains_ident(s, target))
        }
        Expr::ForLoop(f) => {
            expr_contains_ident(&f.expr, target)
                || f.body.stmts.iter().any(|s| stmt_contains_ident(s, target))
        }
        Expr::Closure(c) => expr_contains_ident(&c.body, target),
        Expr::Async(a) => a.block.stmts.iter().any(|s| stmt_contains_ident(s, target)),
        Expr::Await(a) => expr_contains_ident(&a.base, target),
        Expr::Try(t) => expr_contains_ident(&t.expr, target),
        Expr::TryBlock(t) => t.block.stmts.iter().any(|s| stmt_contains_ident(s, target)),
        Expr::Struct(s) => s
            .fields
            .iter()
            .any(|f| expr_contains_ident(&f.expr, target)),
        _ => false,
    }
}

fn stmt_contains_ident(stmt: &Stmt, target: &str) -> bool {
    match stmt {
        Stmt::Local(l) => l
            .init
            .as_ref()
            .map_or(false, |i| expr_contains_ident(&i.expr, target)),
        Stmt::Expr(e, _) => expr_contains_ident(e, target),
        Stmt::Item(_) => false,
        Stmt::Macro(m) => {
            // Best-effort: we can't parse the macro body generically, but if it
            // contains the target identifier as a token it'll still count.
            m.mac.tokens.to_string().contains(target)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;

    fn parse_func(source: &str) -> ItemFn {
        syn::parse_str(source).expect("valid test function")
    }

    #[test]
    fn shape_is_ok() {
        let f = parse_func(r#"#[test] fn t() { assert!(result.is_ok()); }"#);
        let (cls, _) = classify_test(&f);
        assert_eq!(cls, Classification::Shape);
    }

    #[test]
    fn shape_is_err() {
        let f = parse_func(r#"#[test] fn t() { assert!(result.is_err()); }"#);
        let (cls, _) = classify_test(&f);
        assert_eq!(cls, Classification::Shape);
    }

    #[test]
    fn shape_not_empty() {
        let f = parse_func(r#"#[test] fn t() { assert!(!findings.is_empty()); }"#);
        let (cls, _) = classify_test(&f);
        assert_eq!(cls, Classification::Shape);
    }

    #[test]
    fn shape_len_gt_zero() {
        let f = parse_func(r#"#[test] fn t() { assert!(vec.len() > 0); }"#);
        let (cls, _) = classify_test(&f);
        assert_eq!(cls, Classification::Shape);
    }

    #[test]
    fn shape_parse_is_ok() {
        let f = parse_func(r#"#[test] fn t() { assert!(parse(s).is_ok()); }"#);
        let (cls, _) = classify_test(&f);
        assert_eq!(cls, Classification::Shape);
    }

    #[test]
    fn shape_roundtrip() {
        let f = parse_func(r#"#[test] fn t() { assert_eq!(parse_then_serialize(x), x); }"#);
        let (cls, _) = classify_test(&f);
        assert_eq!(cls, Classification::Shape);
    }

    #[test]
    fn truth_specific_value() {
        let f = parse_func(r#"#[test] fn t() { assert_eq!(x.line_start, 12); }"#);
        let (cls, _) = classify_test(&f);
        assert_eq!(cls, Classification::Truth);
    }

    #[test]
    fn truth_cwe_field() {
        let f = parse_func(r#"#[test] fn t() { assert_eq!(f.cwe, Some("CWE-190")); }"#);
        let (cls, _) = classify_test(&f);
        assert_eq!(cls, Classification::Truth);
    }

    #[test]
    fn truth_filter_count() {
        let f = parse_func(
            r#"#[test] fn t() { assert_eq!(findings.filter(|f| f.rule_name == "X").count(), 1); }"#,
        );
        let (cls, _) = classify_test(&f);
        assert_eq!(cls, Classification::Truth);
    }

    #[test]
    fn mixed_shape_and_truth_is_truth() {
        let f = parse_func(
            r#"
            #[test] fn t() {
                assert!(result.is_ok());
                assert_eq!(x.line_start, 12);
            }
        "#,
        );
        let (cls, _) = classify_test(&f);
        assert_eq!(cls, Classification::Truth);
    }

    #[test]
    fn no_asserts_classified_noasserts() {
        let f = parse_func(r#"#[test] fn t() { let _ = 1 + 1; }"#);
        let (cls, _) = classify_test(&f);
        assert_eq!(cls, Classification::NoAsserts);
    }

    #[test]
    fn tokio_test_detected() {
        let f = parse_func(r#"#[tokio::test] async fn t() { assert!(result.is_ok()); }"#);
        assert!(is_test_function(&f));
        let (cls, _) = classify_test(&f);
        assert_eq!(cls, Classification::Shape);
    }

    #[test]
    fn nested_mod_test_found() {
        let source = r#"
            mod inner {
                #[test]
                fn t() {
                    assert!(result.is_ok());
                }
            }
        "#;
        let file = syn::parse_file(source).unwrap();
        let mut findings = Vec::new();
        visit_items(&file.items, "", Path::new("test.rs"), "demo", &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].module_path, "inner");
        assert_eq!(findings[0].classification, Classification::Shape);
    }
}

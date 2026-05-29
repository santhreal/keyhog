//! Integration test crate for the containing Vyre package.

use super::*;

#[test]
fn shift_add_mul_by_3() {
    // x * 3 → (x<<2) - x under non-adjacent-form decomposition.
    let result = reduce_expr(&Expr::mul(Expr::var("x"), Expr::u32(3)));
    assert!(result.is_some(), "x*3 must decompose");
    let r = result.unwrap();
    assert!(
        matches!(&r, Expr::BinOp { op: BinOp::Sub, .. }),
        "must be sub: {r:?}"
    );
}

#[test]
fn shift_add_mul_by_5() {
    // x * 5 → (x<<2) + (x<<0)
    let result = reduce_expr(&Expr::mul(Expr::var("x"), Expr::u32(5)));
    assert!(result.is_some(), "x*5 must decompose");
    let r = result.unwrap();
    assert!(
        matches!(&r, Expr::BinOp { op: BinOp::Add, .. }),
        "must be add: {r:?}"
    );
}

#[test]
fn shift_add_mul_by_7() {
    // x * 7 → (x<<3) - (x<<0)
    let result = reduce_expr(&Expr::mul(Expr::var("x"), Expr::u32(7)));
    assert!(result.is_some(), "x*7 must decompose");
    let r = result.unwrap();
    assert!(
        matches!(&r, Expr::BinOp { op: BinOp::Sub, .. }),
        "must be sub: {r:?}"
    );
}

#[test]
fn shift_add_mul_by_9() {
    // x * 9 → (x<<3) + (x<<0)
    let result = reduce_expr(&Expr::mul(Expr::var("x"), Expr::u32(9)));
    assert!(result.is_some(), "x*9 must decompose");
}

#[test]
fn shift_add_mul_by_15() {
    // x * 15 → (x<<4) - (x<<0)
    let result = reduce_expr(&Expr::mul(Expr::var("x"), Expr::u32(15)));
    assert!(result.is_some(), "x*15 must decompose");
    let r = result.unwrap();
    assert!(
        matches!(&r, Expr::BinOp { op: BinOp::Sub, .. }),
        "must be sub: {r:?}"
    );
}

#[test]
fn shift_add_decomposes_prime_11_with_naf() {
    // 11 = 16 - 4 - 1, which was missed by the old two-term recognizer.
    let result = reduce_expr(&Expr::mul(Expr::var("x"), Expr::u32(11)));
    assert!(result.is_some(), "x*11 must use the bounded NAF chain");
    let r = result.unwrap();
    assert!(
        matches!(&r, Expr::BinOp { op: BinOp::Sub, .. }),
        "must be a subtractive chain: {r:?}"
    );
}

#[test]
fn shift_add_skips_expensive_operands_to_avoid_duplication() {
    let expensive = Expr::add(Expr::load("input", Expr::gid_x()), Expr::u32(1));
    let result = reduce_expr(&Expr::mul(expensive, Expr::u32(11)));
    assert!(
        result.is_none(),
        "bounded shift/add chains must not duplicate non-trivial operands"
    );
}

#[test]
fn integer_mul_zero_and_one_fold() {
    assert_eq!(
        reduce_expr(&Expr::mul(Expr::var("x"), Expr::u32(0))),
        Some(Expr::u32(0))
    );
    assert_eq!(
        reduce_expr(&Expr::mul(Expr::u32(1), Expr::var("x"))),
        Some(Expr::var("x"))
    );
}

#[test]
fn shift_add_does_not_fire_for_floats() {
    // Float multiply should not trigger shift-add
    let result = shift_add_decompose(&Expr::var("x"), &Expr::f32(3.0));
    assert!(result.is_none());
}

#[test]
fn horner_rewrites_expanded_u32_quadratic() {
    let x = Expr::var("x");
    let quadratic = Expr::mul(Expr::mul(Expr::u32(3), x.clone()), x.clone());
    let linear = Expr::mul(Expr::u32(5), x.clone());
    let expanded = Expr::add(Expr::add(quadratic, linear), Expr::u32(7));

    let result = reduce_expr(&expanded).expect("Fix: u32 quadratic must rewrite to Horner form");
    let expected = Expr::add(
        Expr::mul(
            Expr::add(Expr::mul(Expr::u32(3), Expr::var("x")), Expr::u32(5)),
            Expr::var("x"),
        ),
        Expr::u32(7),
    );
    assert_eq!(result, expected);
}

#[test]
fn horner_accepts_commuted_terms_and_implicit_coefficients() {
    let expanded = Expr::add(
        Expr::u32(9),
        Expr::add(Expr::var("x"), Expr::mul(Expr::var("x"), Expr::var("x"))),
    );

    let result = reduce_expr(&expanded).expect("Fix: x*x + x + c must rewrite");
    let expected = Expr::add(
        Expr::mul(
            Expr::add(Expr::mul(Expr::u32(1), Expr::var("x")), Expr::u32(1)),
            Expr::var("x"),
        ),
        Expr::u32(9),
    );
    assert_eq!(result, expected);
}

#[test]
fn horner_rejects_float_quadratic_to_preserve_rounding_contract() {
    let x = Expr::var("x");
    let quadratic = Expr::mul(Expr::mul(Expr::f32(3.0), x.clone()), x.clone());
    let linear = Expr::mul(Expr::f32(5.0), x);
    let expanded = Expr::add(Expr::add(quadratic, linear), Expr::f32(7.0));

    assert!(
        horner_quadratic_u32(&expanded).is_none(),
        "float polynomial reassociation changes rounding and must stay untouched"
    );
}

// ── Shift fusion + shift-by-zero ─────────────────────────────────

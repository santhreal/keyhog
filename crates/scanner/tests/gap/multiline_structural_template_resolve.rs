//! Gap test: the structural template-interpolation resolver.
//!
//! A credential split across template-literal interpolation —
//! `const a = "xoxb-"; const b = "..."; token = `${a}${b}`;` — reassembles only
//! when every `${ident}` / `${"lit"}` in the template RHS resolves to a recorded
//! literal. `resolve_template_reference` does that join: each `${ident}` becomes
//! its bound value, each `${"lit"}`/`${'lit'}` becomes the inner literal, plain
//! template text is kept, and if ANY interpolation is unresolved it returns
//! `None` so a partial/garbage candidate is never emitted. Pin all three.
//!
//! The structural pass is multiline-feature-gated, so this test is too.
#![cfg(feature = "multiline")]

use keyhog_scanner::testing::multiline::resolve_template_reference_for_test as resolve;

#[test]
fn adjacent_ident_interpolations_concatenate_their_values() {
    // `${a}${b}` glues the two recorded literals into one token.
    assert_eq!(
        resolve("token = `${a}${b}`;", &[("a", "xoxb-"), ("b", "SECRET")]),
        Some("xoxb-SECRET".to_string())
    );
}

#[test]
fn quoted_literal_interpolation_uses_the_inner_bytes() {
    // `${"AB"}` contributes the inner `AB`; the `${c}` ident resolves to `CD`.
    assert_eq!(
        resolve("k = `${\"AB\"}${c}`", &[("c", "CD")]),
        Some("ABCD".to_string())
    );
}

#[test]
fn an_unresolved_reference_yields_none() {
    // `${missing}` has no binding, so no partial candidate is emitted.
    assert_eq!(resolve("k = `${missing}`", &[("a", "x")]), None);
}

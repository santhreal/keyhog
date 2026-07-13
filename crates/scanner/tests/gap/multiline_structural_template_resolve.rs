//! Gap test: the structural template-interpolation resolver.
//!
//! A credential split across template-literal interpolation
//! `const a = "xoxb-"; const b = "..."; token = `${a}${b}`;`: reassembles only
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

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vectors pin one example per interpolation kind; these SWEEP the join.
// Adjacent `${ident}` interpolations concatenate their bound values (only the
// template-literal RHS reaches the output, not the `token = ` prefix); a
// `${"lit"}` contributes its inner bytes; and ANY unresolved `${ident}` returns
// None so a partial candidate is never emitted. Traced against
// `resolve_template_reference`. No proptest before.

use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// `${a}${b}` glues the two bound values in order (the surrounding non-template
    /// text is dropped; only the resolved backtick body is returned).
    #[test]
    fn adjacent_ident_interpolations_concatenate_their_values_sweep(
        va in "[A-Za-z0-9._-]{1,10}",
        vb in "[A-Za-z0-9._-]{1,10}",
    ) {
        let out = resolve("token = `${a}${b}`;", &[("a", va.as_str()), ("b", vb.as_str())]);
        prop_assert_eq!(out, Some(format!("{va}{vb}")));
    }

    /// A `${"lit"}` interpolation contributes its inner literal, joined with a
    /// following `${ident}` value.
    #[test]
    fn quoted_literal_interpolation_uses_inner_bytes_sweep(
        lit in "[A-Za-z0-9]{1,8}",
        vc in "[A-Za-z0-9]{1,8}",
    ) {
        let template = format!("k = `${{\"{lit}\"}}${{c}}`");
        let out = resolve(&template, &[("c", vc.as_str())]);
        prop_assert_eq!(out, Some(format!("{lit}{vc}")));
    }

    /// An unresolved `${ident}` (no matching binding) yields None, no partial
    /// candidate is ever emitted.
    #[test]
    fn an_unresolved_reference_yields_none_sweep(
        name in "[a-z]{2,8}",
        val in "[A-Za-z0-9]{1,8}",
    ) {
        // The only binding is `a`; `name` has >=2 chars so it never collides with it.
        let template = format!("k = `${{{name}}}`");
        prop_assert_eq!(resolve(&template, &[("a", val.as_str())]), None);
    }
}

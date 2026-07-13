//! `fn`-boundary / test-function look-back contract for `context/inference.rs`,
//! reached via the `keyhog_scanner::testing` facade. Migrated out of an inline
//! `#[cfg(test)] mod fn_boundary_tests` block to satisfy the scanner folder
//! contract (KH-GAP-129 `context_inference_has_no_cfg_test_literal_in_src`: the
//! inline block put a literal `#[cfg(test)]` in src that tripped the gate).

use keyhog_scanner::testing::context::{
    is_in_test_function_for_test as is_in_test_function,
    is_rust_fn_signature_for_test as is_rust_fn_signature,
    strip_comment_prefix_for_test as strip_comment_prefix,
};

#[test]
fn recognizes_full_fn_qualifier_family() {
    for sig in [
        "fn foo()",
        "pub fn foo()",
        "pub(crate) fn foo()",
        "pub(super) fn foo()",
        "pub(in crate::x) fn foo()",
        "const fn foo()",
        "unsafe fn foo()",
        "async fn foo()",
        "pub async fn foo()",
        "pub(crate) async fn foo()",
        "pub const fn foo()",
        "pub unsafe fn foo()",
        "extern \"C\" fn foo()",
        "pub extern \"C\" fn foo()",
        "default fn foo()",
    ] {
        assert!(
            is_rust_fn_signature(sig),
            "should be a fn signature: {sig:?}"
        );
    }
    for non_sig in ["pub_key = \"x\"", "func foo()", "let fnord = 1", "define()"] {
        assert!(
            !is_rust_fn_signature(non_sig),
            "should NOT be a fn signature: {non_sig:?}"
        );
    }
}

#[test]
fn pub_crate_fn_is_a_boundary_between_test_and_real_code() {
    // The secret sits inside a real `pub(crate) fn`, below a sibling test fn
    // within the 100-line window. The look-back must stop at the real fn and
    // classify the body as NON-test, not walk past it to the `#[test]`.
    let lines = [
        "#[test]",
        "fn test_helper() {",
        "    assert!(true);",
        "}",
        "pub(crate) fn production() {",
        "    let api = \"AKIAIOSFODNN7EXAMPLE\";",
        "}",
    ];
    assert!(
        !is_in_test_function(&lines, 5),
        "match inside pub(crate) fn must NOT be classified as test code"
    );
}

#[test]
fn powershell_and_block_comment_markers_strip() {
    // Canonical COMMENT_MARKERS shared with false_positive.rs.
    assert_eq!(strip_comment_prefix("<# fake key #>"), Some(" fake key #>"));
    assert_eq!(
        strip_comment_prefix("* not a real secret"),
        Some("not a real secret")
    );
    assert_eq!(strip_comment_prefix("--- yaml doc"), None);
    assert_eq!(strip_comment_prefix("-- sql comment"), Some(" sql comment"));
}

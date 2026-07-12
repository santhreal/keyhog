//! `resolve_template_reference` must track string spans inside a `${...}`
//! interpolation so a `}` INSIDE a quoted literal (`${"a}b"}`) does not end the
//! interpolation early and drop the tail of the value.

use keyhog_scanner::testing::multiline::resolve_template_reference_for_test;

#[test]
fn template_reference_keeps_brace_inside_string_literal() {
    let line = "value = `${\"sk_live_A}B_secret12\"}`;";
    let resolved = resolve_template_reference_for_test(line, &[]);
    assert_eq!(
        resolved.as_deref(),
        Some("sk_live_A}B_secret12"),
        "brace inside the quoted literal must not truncate the reassembled value"
    );
}

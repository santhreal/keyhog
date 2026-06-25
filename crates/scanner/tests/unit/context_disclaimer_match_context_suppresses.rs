//! Disclaimer comments in match window suppress via match context.

use keyhog_scanner::testing::context::is_false_positive_match_context;

#[test]
fn context_disclaimer_match_context_suppresses() {
    let text = concat!(
        "const KEY = \"",
        "AK",
        "IA1234567890ABCD12\"; // not a real aws key\n"
    );
    let offset = text.find("AKIA").expect("fixture contains AKIA");
    assert!(
        is_false_positive_match_context(text, offset, None),
        "trailing disclaimer comment must suppress match"
    );
}

#[test]
fn neighboring_disclaimer_comment_does_not_suppress_real_match_line() {
    let text = concat!(
        "// not a real aws key in the docs below\n",
        "const KEY = \"",
        "AK",
        "IA1234567890ABCD12\";\n"
    );
    let offset = text.find("AKIA").expect("fixture contains AKIA");
    assert!(
        !is_false_positive_match_context(text, offset, None),
        "a disclaimer comment on a neighboring line must not suppress the credential line"
    );
}

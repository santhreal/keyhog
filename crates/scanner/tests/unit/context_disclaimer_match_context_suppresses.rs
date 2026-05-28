//! Disclaimer comments in match window suppress via match context.

use keyhog_scanner::context::is_false_positive_match_context;

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

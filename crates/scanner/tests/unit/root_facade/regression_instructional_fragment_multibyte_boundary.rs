//! Regression: the INSTRUCTIONAL_FRAGMENTS word-boundary guard in
//! `suppression::doc_markers::check_markers` mixed a BYTE offset (from
//! `upper.match_indices(frag)`) with a CHAR index (`upper.chars().nth(idx - 1)`).
//! For a credential containing multibyte characters before an embedded
//! `CHANGE` / `INSERT` / `REPLACE` / `YOUR_` run, the inflated byte offset
//! made `.nth(idx - 1)` read the wrong character - or, when `idx - 1` ran
//! past the char count, return `None`. `is_none_or(|c| !c.is_alphanumeric())`
//! then treated the (missing) boundary as satisfied and wrongly suppressed a
//! real secret: a recall hole. The fix reads the preceding char on a byte
//! boundary (`upper[..idx].chars().next_back()`), matching the
//! `upper_contains_token` helper the module header documents.
//!
//! Observable through the public `should_suppress_known_example_credential`.

use keyhog_scanner::context::CodeContext;
use keyhog_scanner::testing::should_suppress_known_example_credential;

/// `K-ÎÏÁÊÔÓÇ7CHANGE` is 16 chars / 23 bytes. The embedded `CHANGE` begins at
/// BYTE offset 17 but its real preceding character is `7` (alphanumeric, so
/// NOT a word boundary). Under the old byte/char mix, `chars().nth(17 - 1)` =
/// `chars().nth(16)` indexed past the 16-char string and returned `None`,
/// satisfying the boundary guard and suppressing this value as an
/// "instructional fragment". With the byte-correct boundary read the `7`
/// boundary is rejected, the fragment gate falls through, and the value -
/// which trips no other suppression gate - is correctly NOT suppressed.
#[test]
fn multibyte_prefixed_change_run_is_not_a_word_boundary() {
    assert!(
        !should_suppress_known_example_credential(
            "K-ÎÏÁÊÔÓÇ7CHANGE",
            None,
            CodeContext::Assignment,
        ),
        "multibyte-prefixed CHANGE run with an alphanumeric char immediately \
         before the fragment must not be treated as an instructional \
         placeholder (byte/char index mix recall hole)"
    );
}

/// Precision twin: genuine instructional placeholders, where the fragment is
/// preceded by a real word boundary (separator or start-of-string), must STILL
/// be suppressed after the byte-correct fix. These are pure ASCII, so the old
/// and new code agreed here; the assertion pins that the fix did not weaken
/// the intended suppression.
#[test]
fn genuine_instructional_placeholders_still_suppressed() {
    for placeholder in [
        "API-CHANGE-ME-PLEASE",
        "CHANGEME-NOW-OK",
        "INSERT-TOKEN-VALUE",
        "YOUR_API_TOKEN_HERE",
        "secret-REPLACE-this",
    ] {
        assert!(
            should_suppress_known_example_credential(placeholder, None, CodeContext::Assignment,),
            "instructional placeholder {placeholder:?} must remain suppressed",
        );
    }
}

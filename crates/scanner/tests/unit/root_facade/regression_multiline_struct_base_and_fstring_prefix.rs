//! Regression tests for two multiline-preprocessor bugs, both observed through
//! the public `preprocess_multiline` / `PreprocessedText::line_for_offset` path.
//!
//! C11: when a concatenation join (`will_append`) and a structural fragment
//! cluster co-occur in one chunk, the structural region's base offset was
//! computed one byte too high (`original_end + 1 + 1 + joined_text.len()`),
//! because it double-counted a separator '\n' that is NOT emitted on that path.
//! The structural finding was then attributed to the prior (concat) line via
//! `line_for_offset`, or its [start,end) window was shifted by one byte.
//!
//! M13: `extract_quoted_content` flagged a value as a Python f-string whenever
//! ANY `f`/`F` preceded the opening quote, so f-bearing identifiers (`prefix`,
//! `config`, `final`, ...) caused `{...}` spans to be silently dropped from the
//! reassembled fragment value.

use keyhog_scanner::testing::fragment_cache::FragmentCache;
use keyhog_scanner::testing::multiline::{preprocess_multiline, MultilineConfig};

/// C11: a chunk with BOTH a real `+`-concat join and a >=2 structural cluster.
/// The cluster's reassembled secret must map back to its true source line, not
/// to the url-concat line that precedes the appended join region.
#[test]
fn structural_cluster_offset_not_shifted_by_cooccurring_concat_join() {
    let text = concat!(
        "url = \"https://\" +\n",
        "      \"example.com\"\n",
        "aws_key_part1 = \"AKIAIOSFODNN7EXAMPLE\"\n",
        "aws_key_part2 = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\"\n",
    );
    let pre = preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));

    // The two `aws_key_partN` assignments form a cluster whose joined value is
    // appended as a structural fragment after the url-concat join region.
    let joined_secret = "AKIAIOSFODNN7EXAMPLEwJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
    let secret_offset = pre
        .text
        .find(joined_secret)
        .expect("structural cluster secret present in preprocessed text");

    // The cluster originates at line 3 (`aws_key_part1`). With the off-by-one
    // the structural LineMapping started one byte late, so a lookup at the very
    // first byte of the secret fell back to the preceding (url-concat) mapping
    // and reported the wrong line.
    assert_eq!(
        pre.line_for_offset(secret_offset),
        Some(3),
        "first byte of the reassembled cluster secret must map to its true source line",
    );

    // A byte in the middle of the secret must also stay on line 3: with the
    // shifted window the whole [start,end) range moved +1.
    assert_eq!(
        pre.line_for_offset(secret_offset + joined_secret.len() / 2),
        Some(3),
    );
}

/// M13: an f-bearing identifier (`prefix_token`) must NOT cause the quoted value
/// to be parsed as an f-string. The brace span in the value must survive the
/// reassembly intact.
#[test]
fn f_bearing_identifier_does_not_drop_brace_span_from_value() {
    // Backslash continuation: `extract_string_content` -> `extract_quoted_content`
    // runs on the raw trimmed line (identifier still present). `prefix_token`
    // contains an `f`, but it does not abut the quote, so f-string handling must
    // stay off and the `{live}` span must be preserved.
    let text = "prefix_token = \"sk-{live}-abcdef1234567890\" \\\n    \"_continuation\"\n";
    let pre = preprocess_multiline(text, &MultilineConfig::default(), &FragmentCache::new(100));

    assert!(
        pre.text.contains("sk-{live}-abcdef1234567890"),
        "brace span must be preserved when the preceding 'f' is not adjacent to the quote; got: {:?}",
        pre.text,
    );
    assert!(
        !pre.text.contains("sk--abcdef1234567890"),
        "the `{{live}}` span must not be stripped as an f-string interpolation",
    );
}

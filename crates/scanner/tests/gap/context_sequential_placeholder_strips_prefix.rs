//! KH-GAP-018: sequential placeholder detection must strip known prefixes first.

use keyhog_scanner::testing::context::is_known_example_credential;

#[test]
fn context_sequential_placeholder_strips_prefix() {
    assert!(
        is_known_example_credential("ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
        "all-same-char body after ghp_ prefix must suppress as placeholder"
    );
}

// ── Property tier ────────────────────────────────────────────────────────────
// The fixed vector pins one all-same-body case; these SWEEP three structural
// placeholder branches with constructive positives (each an independent
// suppression reason, not a shape mirror): (1) any string ending in EXAMPLE /
// EXAMPLEKEY in any ASCII case is a documentation placeholder; (2) an all-same-char
// body of >= 8 chars is a placeholder whether bare or after a known prefix (the
// prefix is stripped before the sequential check); (3) an x/X-dominated filler
// (>3/4 x's over >= 16 chars) is masking filler. Traced against
// `is_known_example_credential` (context/placeholder.rs:15). No proptest before.

use proptest::prelude::*;

/// Case variants of the documentation EXAMPLE / EXAMPLEKEY suffix.
const EXAMPLE_SUFFIXES: &[&str] = &[
    "example",
    "EXAMPLE",
    "Example",
    "eXaMpLe",
    "examplekey",
    "EXAMPLEKEY",
    "ExampleKey",
];
/// Body chars for the all-same-char placeholder sweep.
const BODY_CHARS: &[char] = &['a', 'b', 'c', 'q', 'z', '5', '9', '0'];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// Any string ending in EXAMPLE/EXAMPLEKEY (any ASCII case) is a placeholder.
    #[test]
    fn any_case_example_suffix_is_placeholder(
        prefix in "[a-zA-Z0-9_-]{0,20}",
        si in 0usize..EXAMPLE_SUFFIXES.len(),
    ) {
        let cred = format!("{prefix}{}", EXAMPLE_SUFFIXES[si]);
        prop_assert!(is_known_example_credential(&cred));
    }

    /// An all-same-char body of >= 8 chars is a placeholder, bare or after a known
    /// service prefix (the prefix is stripped before the sequential check).
    #[test]
    fn all_same_char_body_is_placeholder(
        ci in 0usize..BODY_CHARS.len(),
        n in 8usize..40,
    ) {
        let body: String = std::iter::repeat(BODY_CHARS[ci]).take(n).collect();
        prop_assert!(is_known_example_credential(&body), "bare all-same body");
        let prefixed = format!("ghp_{body}");
        prop_assert!(is_known_example_credential(&prefixed), "prefixed all-same body");
    }

    /// An x/X-dominated filler (>3/4 x's over >= 16 chars) is masking filler, even
    /// when interspersed with non-x chars so it is not all-same.
    #[test]
    fn x_dominated_filler_is_placeholder(
        pad in "[0-9]{3}",
        extra_x in 0usize..12,
    ) {
        // len = 16 + extra_x, x_count = 13 + extra_x > len*3/4 for all extra_x.
        let xs = "x".repeat(13 + extra_x);
        let cred = format!("{xs}{pad}");
        prop_assert!(is_known_example_credential(&cred));
    }
}

use keyhog_scanner::testing::anchored_regex_capture_for_test;

/// WHY: a well-formed detector source must match only when its value begins at
/// offset zero, so the anchored fast path remains equivalent to a whole-chunk
/// verifier.
#[test]
fn get_returns_a_working_anchor_at_start() {
    assert_eq!(
        anchored_regex_capture_for_test("[A-Z]{3}[0-9]{2}", false, false, "ABC12tail"),
        Some((0, 5))
    );
    assert_eq!(
        anchored_regex_capture_for_test("[A-Z]{3}[0-9]{2}", false, false, "xxABC12"),
        None,
        "\\A must reject a value that does not start at offset 0"
    );
}

/// WHY: a baked-in wrapper compile failure must abort loudly instead of being
/// swallowed into silent recall loss on the anchored fast path.
#[test]
#[should_panic(expected = "BUILD-INVARIANT VIOLATION")]
fn no_context_compile_failure_panics_fail_closed() {
    let _ = anchored_regex_capture_for_test(")unbalanced", false, false, "anything");
}

/// WHY: the left-context verifier has the same fail-closed obligation as the
/// no-context verifier and cannot silently drop a detector on wrapper failure.
#[test]
#[should_panic(expected = "BUILD-INVARIANT VIOLATION")]
fn left_context_compile_failure_panics_fail_closed() {
    let _ = anchored_regex_capture_for_test(")unbalanced", false, true, "anything");
}

/// WHY: the anchored verifier must reproduce the base compiler's coupled case
/// and CRLF flags. Uniformly enabling CRLF would break case-sensitive detector
/// parity on carriage-return input.
#[test]
fn anchored_crlf_and_case_flags_mirror_the_two_branch_base_compile() {
    let haystack = "A\rB";

    assert_eq!(
        anchored_regex_capture_for_test("A.B", false, false, haystack),
        Some((0, 3)),
        "case-sensitive anchored verifier mirrors crlf(false): dot matches CR"
    );
    assert_eq!(
        anchored_regex_capture_for_test("A.B", true, false, haystack),
        None,
        "case-insensitive anchored verifier mirrors crlf(true): dot excludes CR"
    );
}

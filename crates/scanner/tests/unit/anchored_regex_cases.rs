use crate::anchored_regex::AnchoredRegex;

#[test]
fn get_returns_a_working_anchor_at_start() {
    // A well-formed detector source compiles into a `\A`-anchored verifier:
    // it matches only when the pattern begins at offset 0 of the haystack.
    let ar = AnchoredRegex::new("[A-Z]{3}[0-9]{2}", false);
    let re = ar.get();
    let mut locs = re.capture_locations();
    let m = re
        .captures_read(&mut locs, "ABC12tail")
        .expect("anchored verifier must match a value at the start");
    assert_eq!(m.start(), 0);
    assert_eq!(m.end(), 5, "matches exactly the 5-char shape ABC12");
    // Embedded (not at offset 0): `\A` blocks it (proving the anchor is real).
    assert!(
        re.captures_read(&mut locs, "xxABC12").is_none(),
        "\\A must reject a value that does not start at offset 0"
    );
}

#[test]
#[should_panic(expected = "BUILD-INVARIANT VIOLATION")]
fn no_context_compile_failure_panics_fail_closed() {
    // A source that makes the hardcoded `\A(?:<src>)` wrapper unbalanced forces
    // the anchored build to fail. Per Law 10 that is a build-invariant violation
    // of a baked-in transform and MUST abort loudly, the former handling
    // returned `None`, which the anchored-scan consumer swallowed into a silent
    // early `return`, dropping every match for this pattern.
    let ar = AnchoredRegex::new(")unbalanced", false);
    ar.get();
}

#[test]
#[should_panic(expected = "BUILD-INVARIANT VIOLATION")]
fn left_context_compile_failure_panics_fail_closed() {
    // The left-context variant (`\A(?s:.)(?:<src>)`) fails closed identically:
    // no path is allowed to swallow the compile failure into silent recall loss.
    let ar = AnchoredRegex::new(")unbalanced", false);
    ar.get_with_left_context();
}

// ── CRLF/case-flag parity with the two-branch base compile ──────────────
// The anchored verifier couples BOTH `case_insensitive` and `crlf` to the
// detector's `case_insensitive` bit. This is NOT a copy-paste of crlf<-ci:
// the base detector regex (`LazyRegex::get`) is itself compiled on two
// branches that pair the flags exactly the same way
//   ci detector  -> `shared_regex`  => case_insensitive(true)  + crlf(true)
//   non-ci       -> `Regex::new`    => case_insensitive(false) + crlf(false)
// The anchored verifier's whole purpose is whole-chunk-equivalence with that
// base, so it MUST reproduce whichever branch applies. Under crlf(true) the
// dot excludes `\r`; under crlf(false) it matches `\r`. That makes a ci and a
// non-ci verifier legitimately DIVERGE on a CR-bearing haystack, mirroring
// their base regexes. This pins the coupling so a future "crlf should always
// be true" edit, which would silently break case-sensitive-detector parity
// on CRLF input (fails loudly here instead).
#[test]
fn anchored_crlf_and_case_flags_mirror_the_two_branch_base_compile() {
    use regex::{Regex, RegexBuilder};

    let hay = "A\rB";

    // Base branch A, case-sensitive detector: `Regex::new` default, crlf
    // false, so the dot matches CR and the whole shape matches.
    let base_cs = Regex::new("A.B").expect("base cs regex compiles");
    assert!(
        base_cs.is_match(hay),
        "crlf(false) base: the dot matches CR, so `A.B` matches `A\\rB`"
    );
    // Base branch B, case-insensitive detector: `shared_regex` flags, crlf
    // true, so the dot excludes CR and the shape does NOT match.
    let base_ci = RegexBuilder::new("A.B")
        .case_insensitive(true)
        .crlf(true)
        .build()
        .expect("base ci regex compiles");
    assert!(
        !base_ci.is_match(hay),
        "crlf(true) base: the dot excludes CR, so `A.B` does NOT match `A\\rB`"
    );

    // The anchored verifier for each detector kind must AGREE with its own
    // base branch, proving the flag coupling reproduces the base, not that
    // crlf is uniformly true.
    let anch_cs = AnchoredRegex::new("A.B", false);
    assert!(
        anch_cs.get().is_match(hay),
        "case-sensitive anchored verifier mirrors crlf(false): dot matches CR"
    );
    let anch_ci = AnchoredRegex::new("A.B", true);
    assert!(
        !anch_ci.get().is_match(hay),
        "case-insensitive anchored verifier mirrors crlf(true): dot excludes CR"
    );
}

#[test]
fn anchored_regex_compilation_ticks_compile_event_counter() {
    let ar = AnchoredRegex::new("KHTEST_[A-Z0-9]{12}", false);
    let before_get = crate::types::lazy_regex_compile_events();
    let _ = ar.get();
    let after_get = crate::types::lazy_regex_compile_events();
    assert!(
        after_get >= before_get + 1,
        "AnchoredRegex::get must tick lazy_regex_compile_events on cold compilation"
    );

    let before_ctx = crate::types::lazy_regex_compile_events();
    let _ = ar.get_with_left_context();
    let after_ctx = crate::types::lazy_regex_compile_events();
    assert!(
        after_ctx >= before_ctx + 1,
        "AnchoredRegex::get_with_left_context must tick lazy_regex_compile_events on cold compilation"
    );
}

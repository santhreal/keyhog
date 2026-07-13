//! Contract for `compiler::compiler_compile::compile_companion`: the compiler
//! that turns a detector's `CompanionSpec` (a nearby-value regex used to enrich
//! or gate a finding, e.g. an AWS secret-key companion beside an access-key ID)
//! into a `CompiledCompanion`. Previously untested directly.
//!
//! The load-bearing behavior is the CAPTURE-GROUP resolution: `find_companion`
//! extracts `capture_group` when present (the value inside the group) and falls
//! back to the whole match otherwise, so a wrong verdict here would extract the
//! wrong companion substring. `capture_group` must be `Some(1)` exactly when the
//! regex declares a capturing group and `None` otherwise (a non-capturing
//! `(?:…)` group must NOT count). An un-compilable regex must fail closed with an
//! error that names the detector, never silently yield an empty companion.

use keyhog_scanner::testing::compile_companion_for_test as compile_companion;

#[test]
fn a_capturing_group_resolves_to_group_one() {
    let (name, cg) = compile_companion(
        "secret_key",
        r"secret=([A-Za-z0-9/+]{40})",
        "aws-access-key",
    )
    .expect("a valid regex with a group compiles");
    assert_eq!(name, "secret_key", "the spec name is carried through");
    assert_eq!(
        cg,
        Some(1),
        "a regex with one capturing group extracts group 1"
    );
}

#[test]
fn a_named_capturing_group_also_resolves_to_group_one() {
    let (_, cg) =
        compile_companion("tok", r"tok=(?P<v>[A-Za-z0-9]+)", "svc").expect("named group compiles");
    assert_eq!(
        cg,
        Some(1),
        "a named capturing group still counts as group 1"
    );
}

#[test]
fn no_group_yields_none() {
    let (_, cg) =
        compile_companion("marker", r"password\s*=\s*[A-Za-z0-9]+", "generic").expect("compiles");
    assert_eq!(
        cg, None,
        "a regex with no capturing group has no capture group"
    );
}

#[test]
fn a_non_capturing_group_does_not_count_as_a_capture_group() {
    // `(?:…)` groups for alternation/quantification must NOT be treated as a
    // value-extraction capture group.
    let (_, cg) = compile_companion("marker", r"key=(?:foo|bar)[0-9]+", "svc").expect("compiles");
    assert_eq!(
        cg, None,
        "a non-capturing (?:...) group must resolve to None"
    );
}

#[test]
fn an_uncompilable_regex_fails_closed_naming_the_detector() {
    let err = compile_companion("bad", r"(unclosed", "my-detector-id")
        .expect_err("an invalid regex must not compile to an empty companion");
    assert!(
        err.contains("my-detector-id"),
        "the compile error must name the detector for operator triage, got: {err}"
    );
}

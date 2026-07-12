//! Gate: production engine callers use the typed known-example suppression context.

use super::support::*;

#[test]
fn engine_uses_typed_known_example_suppression_context() {
    let api = read(&scanner_src().join("suppression/api.rs"));
    assert!(
        api.contains("struct KnownExampleSuppressionCtx")
            && api.contains("fn suppress_known_example_credential_stage("),
        "suppression::api must expose the typed stage-returning known-example suppression entry point"
    );
    for forbidden in [
        "fn suppress_known_example_credential(",
        "fn should_suppress_known_example_credential(",
        "fn should_suppress_known_example_credential_with_source(",
        "fn should_suppress_known_example_credential_with_source_and_entropy(",
    ] {
        assert!(
            !api.contains(forbidden),
            "suppression::api must not expose known-example rigor wrapper `{forbidden}`"
        );
    }

    let suppression_mod = read(&scanner_src().join("suppression/mod.rs"));
    assert!(
        !suppression_mod.contains("should_suppress_known_example_credential"),
        "suppression::mod must not re-export known-example rigor wrappers"
    );

    let mut files = Vec::new();
    collect_rs_files(&scanner_src().join("engine"), &mut files);
    let mut offenders = Vec::new();
    for path in files {
        let code = uncommented_code(&read(&path));
        for forbidden in [
            "should_suppress_known_example_credential(",
            "should_suppress_known_example_credential_with_source(",
            "should_suppress_known_example_credential_with_source_and_entropy(",
        ] {
            if code.contains(forbidden) {
                offenders.push(format!("{} contains {forbidden}", path.display()));
            }
        }
    }

    assert!(
        offenders.is_empty(),
        "production engine callers must use KnownExampleSuppressionCtx, not public rigor-tier wrappers: {offenders:#?}"
    );
}

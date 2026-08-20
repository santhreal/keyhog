use super::*;

#[test]
fn ci_workflow_path_matches_cross_platform_ci_files() {
    assert!(path_is_ci_workflow_file(Some(
        ".github/workflows/release.yml"
    )));
    assert!(path_is_ci_workflow_file(Some(
        r".github\actions\setup\action.yml"
    )));
    assert!(path_is_ci_workflow_file(Some(".circleci/config.yml")));
    assert!(path_is_ci_workflow_file(Some("azure-pipelines.yml")));
    assert!(path_is_ci_workflow_file(Some("bitbucket-pipelines.yml")));
    assert!(path_is_ci_workflow_file(Some(
        "/repo/.github/workflows/release.yml"
    )));
    assert!(path_is_ci_workflow_file(Some(
        r"C:\repo\.github\actions\setup\action.yml"
    )));
    assert!(path_is_ci_workflow_file(Some("/repo/.gitlab-ci.yml")));
    assert!(path_is_ci_workflow_file(Some(r"C:\repo\Jenkinsfile")));
    assert!(!path_is_ci_workflow_file(Some("/repo/src/Jenkinsfile.txt")));
}

#[test]
fn i18n_path_matches_translation_file_shapes() {
    assert!(path_is_i18n_file(Some("locale/messages.json")));
    assert!(path_is_i18n_file(Some(r"translations\messages.json")));
    assert!(path_is_i18n_file(Some("/repo/locale/messages.po")));
    assert!(path_is_i18n_file(Some(r"C:\repo\i18n\strings.json")));
    assert!(path_is_i18n_file(Some(
        "/repo/config/messages_en.properties"
    )));
    assert!(!path_is_i18n_file(Some("/repo/config/messages_en.rs")));
}

/// Classification only. Uses the pure predicate so the assertion cannot be
/// perturbed by another test in this binary flipping the suppression policy.
#[test]
fn vendored_paths_match_repository_relative_sources() {
    assert!(path_is_vendored_minified(Some("dist/vendor/library.js")));
    assert!(path_is_vendored_minified(Some(
        "app/assets/javascripts/jquery.js"
    )));
    assert!(path_is_vendored_minified(Some("dist/assets/app.js")));
    assert!(path_is_vendored_minified(Some("wp-includes/config.php")));
    assert!(path_is_vendored_minified(Some("build/app.min.js")));
    assert!(!path_is_vendored_minified(Some("src/app.js")));
}

/// Every dropped credential must be counted exactly once. An uncounted drop is
/// the silent miss: a `sk_live_` key inlined into `app.min.js` reached the
/// report as "No secrets detected" precisely because nothing incremented here.
/// A double count is the opposite lie: the summary promised two recoverable
/// credentials where `--no-default-excludes` reports one.
///
/// Asserts a DELTA, not an absolute: the count is process-global and other
/// tests in this binary suppress vendored paths too.
#[test]
fn a_suppressed_vendored_credential_is_counted_once_per_identity() {
    const PATH: &str = "node_modules/pkg/dist/bundle.min.js";
    let before = crate::telemetry::vendored_path_suppression_count();
    assert!(vendored_minified_path_policy_applies(Some(PATH)));

    crate::telemetry::record_vendored_path_suppression(Some(PATH), "sk_live_abcdef0123456789");
    let after = crate::telemetry::vendored_path_suppression_count();
    assert_eq!(
        after,
        before + 1,
        "a dropped credential must be counted so the CLI can report it"
    );

    // Every detector that can match the credential adjudicates it, and gates
    // downstream of this one would have dropped some of those candidates
    // anyway. Identity keying is what keeps the count equal to what the
    // recovery flag reports.
    crate::telemetry::record_vendored_path_suppression(Some(PATH), "sk_live_abcdef0123456789");
    assert_eq!(
        crate::telemetry::vendored_path_suppression_count(),
        after,
        "the same (path, credential) must not be counted twice"
    );

    crate::telemetry::record_vendored_path_suppression(Some(PATH), "sk_live_9876543210fedcba");
    assert_eq!(
        crate::telemetry::vendored_path_suppression_count(),
        after + 1,
        "a second distinct credential in the same bundle is a second drop"
    );
}

/// A path the policy does not match is never offered to the counter, so the
/// reported gap count is not pure noise.
#[test]
fn a_non_vendored_path_does_not_apply_the_policy() {
    let before = crate::telemetry::vendored_path_suppression_count();
    assert!(!vendored_minified_path_policy_applies(Some(
        "src/config.js"
    )));
    assert_eq!(
        crate::telemetry::vendored_path_suppression_count(),
        before,
        "only an actual suppression may be counted"
    );
}

#[test]
fn raw_base64_path_policies_preserve_call_site_contracts() {
    assert!(looks_like_raw_base64_file_path(Some(
        "/repo/assets/blob.B64"
    )));
    assert!(looks_like_raw_base64_file_path(Some("/repo/base64.txt")));
    assert!(!looks_like_entropy_raw_base64_file_path(Some(
        "/repo/base64.txt"
    )));
    assert!(looks_like_entropy_raw_base64_file_path(Some(
        "/repo/base64_string.txt"
    )));
}

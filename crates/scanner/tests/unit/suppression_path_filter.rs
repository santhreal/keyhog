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

/// Every drop must be counted. An uncounted drop is the silent miss: a
/// `sk_live_` key inlined into `app.min.js` reached the report as
/// "No secrets detected" precisely because nothing incremented here.
///
/// Asserts a DELTA, not an absolute: the counter is process-global and other
/// tests in this binary suppress vendored paths too.
#[test]
fn suppressing_a_vendored_path_increments_the_reported_counter() {
    let before = crate::telemetry::vendored_path_suppression_count();
    assert!(looks_like_vendored_minified_path(Some(
        "node_modules/pkg/dist/bundle.min.js"
    )));
    let after = crate::telemetry::vendored_path_suppression_count();
    assert!(
        after > before,
        "a dropped finding must be counted so the CLI can report it; {before} -> {after}"
    );
}

/// A path the policy does not match must not be counted as a drop, or the
/// reported gap count would be pure noise.
#[test]
fn a_non_vendored_path_does_not_increment_the_counter() {
    let before = crate::telemetry::vendored_path_suppression_count();
    assert!(!looks_like_vendored_minified_path(Some("src/config.js")));
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

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

#[test]
fn vendored_paths_match_repository_relative_sources() {
    assert!(looks_like_vendored_minified_path(Some(
        "dist/vendor/library.js"
    )));
    assert!(looks_like_vendored_minified_path(Some(
        "app/assets/javascripts/jquery.js"
    )));
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

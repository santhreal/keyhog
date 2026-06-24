//! Source names are CLI/factory routing contracts, not display copy.

use keyhog_core::Source;

fn assert_source_name(source: impl Source, expected: &str) {
    assert_eq!(source.name(), expected);
}

#[test]
fn always_on_source_names_are_stable() {
    assert_source_name(
        keyhog_sources::FilesystemSource::new(std::path::PathBuf::from(".")),
        "filesystem",
    );
    assert_source_name(keyhog_sources::StdinSource, "stdin");
}

#[cfg(feature = "binary")]
#[test]
fn binary_source_name_is_stable() {
    assert_source_name(
        keyhog_sources::BinarySource::new(std::path::PathBuf::from(".")),
        "binary",
    );
}

#[cfg(feature = "git")]
#[test]
fn git_source_names_are_stable() {
    assert_source_name(
        keyhog_sources::GitSource::new(std::path::PathBuf::from(".")),
        "git",
    );
    assert_source_name(
        keyhog_sources::GitHistorySource::new(std::path::PathBuf::from(".")),
        "git-history",
    );
    assert_source_name(
        keyhog_sources::GitDiffSource::new(std::path::PathBuf::from("."), "main"),
        "git-diff",
    );
}

#[cfg(feature = "docker")]
#[test]
fn docker_source_name_is_stable() {
    assert_source_name(keyhog_sources::DockerImageSource::new("image"), "docker");
}

#[cfg(feature = "s3")]
#[test]
fn s3_source_name_is_stable() {
    assert_source_name(keyhog_sources::S3Source::new("bucket"), "s3");
}

#[cfg(feature = "gcs")]
#[test]
fn gcs_source_name_is_stable() {
    assert_source_name(keyhog_sources::GcsSource::new("bucket"), "gcs");
}

#[cfg(feature = "azure")]
#[test]
fn azure_blob_source_name_is_stable() {
    assert_source_name(
        keyhog_sources::AzureBlobSource::new("https://example.blob.core.windows.net/container"),
        "azure_blob",
    );
}

#[cfg(feature = "web")]
#[test]
fn web_source_name_is_stable() {
    assert_source_name(
        keyhog_sources::WebSource::new(vec!["https://example.com/app.js".to_string()]),
        "web",
    );
}

#[cfg(feature = "slack")]
#[test]
fn slack_source_name_is_stable() {
    assert_source_name(keyhog_sources::SlackSource::new("xoxb-token"), "slack");
}

#[cfg(feature = "github")]
#[test]
fn github_org_source_name_is_stable() {
    assert_source_name(
        keyhog_sources::GitHubOrgSource::new("org".to_string(), "token".to_string()),
        "github-org",
    );
}

#[cfg(feature = "gitlab")]
#[test]
fn gitlab_group_factory_source_name_is_stable() {
    let source = keyhog_sources::create_source("gitlab-group", Some("group\ntoken"))
        .expect("create gitlab-group source");
    assert_eq!(source.name(), "gitlab-group");
}

#[cfg(feature = "bitbucket")]
#[test]
fn bitbucket_workspace_factory_source_name_is_stable() {
    let source = keyhog_sources::create_source(
        "bitbucket-workspace",
        Some("workspace\nusername\napp-password"),
    )
    .expect("create bitbucket-workspace source");
    assert_eq!(source.name(), "bitbucket-workspace");
}

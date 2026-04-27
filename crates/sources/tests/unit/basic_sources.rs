use keyhog_core::Source;
use keyhog_sources::StdinSource;

#[test]
fn stdin_source_name_is_stable() {
    assert_eq!(StdinSource.name(), "stdin");
}

#[cfg(feature = "web")]
#[test]
fn web_source_empty_urls_produce_no_chunks() {
    let source = keyhog_sources::WebSource::new(vec![]);
    let chunks: Vec<_> = source.chunks().collect();

    assert_eq!(source.name(), "web");
    assert!(chunks.is_empty());
}

#[cfg(feature = "web")]
#[test]
fn web_source_from_url_is_constructible() {
    let source = keyhog_sources::WebSource::from_url("https://example.com/app.js");
    assert_eq!(source.name(), "web");
}

#[cfg(feature = "git")]
#[test]
fn git_source_name_is_stable() {
    let source = keyhog_sources::GitSource::new(std::path::PathBuf::from("/tmp"));
    assert_eq!(source.name(), "git");
}

#[cfg(feature = "s3")]
#[test]
fn s3_source_name_is_stable() {
    let source = keyhog_sources::S3Source::new("bucket");
    assert_eq!(source.name(), "s3");
}

#[cfg(feature = "docker")]
#[test]
fn docker_source_name_is_stable() {
    let source = keyhog_sources::DockerImageSource::new("ghcr.io/acme/app:1.2.3");
    assert_eq!(source.name(), "docker");
}

#[cfg(feature = "github")]
#[test]
fn github_org_source_name_is_stable() {
    let source = keyhog_sources::GitHubOrgSource::new("acme".into(), "ghp_example".into());
    assert_eq!(source.name(), "github-org");
}

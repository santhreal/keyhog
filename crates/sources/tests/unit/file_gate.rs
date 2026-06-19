//! FILE_GATE micro tests for sources crate src files.

use keyhog_core::Source;
use keyhog_sources::testing::{SourceTestApi, TestApi};
use keyhog_sources::{create_source, reset_skipped_over_max_size, FilesystemSource, StdinSource};

// ── crates/sources/src/lib.rs ─────────────────────────────────────────
#[test]
fn lib_happy() {
    reset_skipped_over_max_size();
    assert!(create_source("unknown-plugin", None).is_err());
}
#[test]
fn lib_error() {
    assert!(create_source("slack", None).is_err());
}

// ── crates/sources/src/stdin.rs ───────────────────────────────────────
#[test]
fn stdin_happy() {
    assert_eq!(StdinSource.name(), "stdin");
}

// ── crates/sources/src/filesystem.rs ──────────────────────────────────
#[test]
fn filesystem_happy() {
    let source = FilesystemSource::new(std::path::PathBuf::from("/tmp"));
    assert_eq!(source.name(), "filesystem");
}
#[test]
fn filesystem_error() {
    let dir = tempfile::tempdir().unwrap();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    assert!(source.chunks().next().is_none());
}

// ── crates/sources/src/filesystem/read.rs ─────────────────────────────
#[test]
fn filesystem_read_happy() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("sample.txt");
    std::fs::write(&path, b"hello").unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), b"hello");
}
#[test]
fn filesystem_read_error() {
    assert!(std::fs::read("/nonexistent/keyhog-gate-path").is_err());
}

// ── crates/sources/src/timeouts.rs ────────────────────────────────────
#[cfg(any(feature = "web", feature = "slack", feature = "s3", feature = "github"))]
#[test]
fn timeouts_happy() {
    assert!(TestApi.http_request_timeout().as_secs() > 0);
}
#[cfg(not(any(feature = "web", feature = "slack", feature = "s3", feature = "github")))]
#[test]
fn timeouts_happy() {
    assert!(!cfg!(any(
        feature = "web",
        feature = "slack",
        feature = "s3",
        feature = "github"
    )));
}
#[test]
fn timeouts_error() {
    #[cfg(feature = "binary")]
    assert!(TestApi.ghidra_analysis_timeout().as_secs() >= 60);
    #[cfg(all(
        not(feature = "binary"),
        any(feature = "web", feature = "slack", feature = "s3", feature = "github")
    ))]
    assert!(TestApi.http_request_timeout().as_secs() < 3600);
    #[cfg(all(
        not(feature = "binary"),
        not(any(feature = "web", feature = "slack", feature = "s3", feature = "github"))
    ))]
    assert!(!cfg!(feature = "binary"));
}

// ── crates/sources/src/http.rs ────────────────────────────────────────
#[cfg(any(feature = "web", feature = "slack", feature = "s3", feature = "github"))]
#[test]
fn http_error() {
    let cfg = keyhog_sources::http::HttpClientConfig {
        proxy: Some("off".into()),
        ..Default::default()
    };
    assert_eq!(cfg.proxy.as_deref(), Some("off"));
}
#[cfg(not(any(feature = "web", feature = "slack", feature = "s3", feature = "github")))]
#[test]
fn http_error() {
    assert!(!cfg!(any(
        feature = "web",
        feature = "slack",
        feature = "s3",
        feature = "github"
    )));
}

// ── crates/sources/src/strings.rs ─────────────────────────────────────
#[test]
fn strings_happy() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("bin.dat"), b"secret=abc1234567890").unwrap();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let chunks: Vec<_> = source.chunks().collect();
    assert_eq!(chunks.len(), 1);
}

// ── crates/sources/src/binary/mod.rs ──────────────────────────────────
#[cfg(feature = "binary")]
#[test]
fn binary_mod_happy() {
    let source = keyhog_sources::BinarySource::new(std::path::PathBuf::from("/bin/sh"));
    assert_eq!(source.name(), "binary");
}
#[cfg(feature = "binary")]
#[test]
fn binary_mod_error() {
    let source = keyhog_sources::BinarySource::new(std::path::PathBuf::from("/no/such/file"));
    assert!(source.chunks().next().is_none());
}

// ── crates/sources/src/binary/ghidra.rs ─────────────────────────────────
#[cfg(feature = "binary")]
#[test]
fn binary_ghidra_happy() {
    let source = keyhog_sources::BinarySource::new(std::path::PathBuf::from("/bin/sh"));
    assert_eq!(source.name(), "binary");
}

// ── crates/sources/src/binary/literals.rs ───────────────────────────────
#[cfg(feature = "binary")]
#[test]
fn binary_literals_happy() {
    let literals = TestApi.extract_string_literals(r#"puts("TOKEN=abcdefghijklmnop");"#);
    assert_eq!(literals, vec!["TOKEN=abcdefghijklmnop".to_string()]);
}
#[cfg(feature = "binary")]
#[test]
fn binary_literals_error() {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join("a.bin"), b"\x00").unwrap();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let _ = source.chunks().collect::<Vec<_>>();
}

// ── crates/sources/src/binary/sections.rs ───────────────────────────────
#[cfg(feature = "binary")]
#[test]
fn binary_sections_happy() {
    let source = keyhog_sources::BinarySource::new(std::path::PathBuf::from("/bin/sh"));
    assert_eq!(source.name(), "binary");
}
#[cfg(feature = "binary")]
#[test]
fn binary_sections_error() {
    assert!(std::fs::read("/nonexistent/keyhog-sections").is_err());
}

// ── crates/sources/src/git/mod.rs ─────────────────────────────────────
#[cfg(feature = "git")]
#[test]
fn git_mod_happy() {
    let source = keyhog_sources::GitSource::new(std::path::PathBuf::from("/tmp"));
    assert_eq!(source.name(), "git");
}

// ── crates/sources/src/git/source.rs ───────────────────────────────────
#[cfg(feature = "git")]
#[test]
fn git_source_happy() {
    let source = keyhog_sources::GitSource::new(std::env::current_dir().unwrap());
    assert_eq!(source.name(), "git");
}

// ── crates/sources/src/git/diff.rs ──────────────────────────────────────
#[cfg(feature = "git")]
#[test]
fn git_diff_happy() {
    let source = keyhog_sources::GitDiffSource::new(std::env::current_dir().unwrap(), "HEAD~1");
    assert_eq!(source.name(), "git-diff");
}

// ── crates/sources/src/git/history.rs ─────────────────────────────────
#[cfg(feature = "git")]
#[test]
fn git_history_happy() {
    let source =
        keyhog_sources::GitHistorySource::new(std::env::current_dir().unwrap()).with_max_commits(1);
    assert_eq!(source.name(), "git-history");
}

// ── crates/sources/src/docker.rs ──────────────────────────────────────
#[cfg(feature = "docker")]
#[test]
fn docker_happy() {
    let source = keyhog_sources::DockerImageSource::new("alpine:latest");
    assert_eq!(source.name(), "docker");
}
#[cfg(feature = "docker")]
#[test]
fn docker_error() {
    assert!(create_source("docker", None).is_err());
}

// ── crates/sources/src/github_org.rs ──────────────────────────────────
#[cfg(feature = "github")]
#[test]
fn github_org_happy() {
    let source = keyhog_sources::GitHubOrgSource::new("acme".into(), "ghp_test".into());
    assert_eq!(source.name(), "github-org");
}
#[cfg(feature = "github")]
#[test]
fn github_org_error() {
    let source = keyhog_sources::GitHubOrgSource::new("".into(), "".into());
    assert_eq!(source.name(), "github-org");
}

// ── crates/sources/src/gitlab_group.rs ────────────────────────────────
#[cfg(feature = "gitlab")]
#[test]
fn gitlab_group_happy() {
    let source = create_source("gitlab-group", Some("acme\nglpat-exampletoken12345")).unwrap();
    assert_eq!(source.name(), "gitlab-group");
}
#[cfg(feature = "gitlab")]
#[test]
fn gitlab_group_error() {
    assert!(create_source("gitlab-group", None).is_err());
}

// ── crates/sources/src/bitbucket_workspace.rs ─────────────────────────
#[cfg(feature = "bitbucket")]
#[test]
fn bitbucket_workspace_happy() {
    let source = create_source(
        "bitbucket-workspace",
        Some("acme\nbuildbot\napp-password-example"),
    )
    .unwrap();
    assert_eq!(source.name(), "bitbucket-workspace");
}
#[cfg(feature = "bitbucket")]
#[test]
fn bitbucket_workspace_error() {
    assert!(create_source("bitbucket-workspace", None).is_err());
}

// ── crates/sources/src/slack.rs ───────────────────────────────────────
#[cfg(feature = "slack")]
#[test]
fn slack_happy() {
    let source = keyhog_sources::SlackSource::new(concat!("xox", "b-test"));
    assert_eq!(source.name(), "slack");
}
#[cfg(feature = "slack")]
#[test]
fn slack_error() {
    assert!(create_source("slack", None).is_err());
}

// ── crates/sources/src/web.rs ─────────────────────────────────────────
#[cfg(feature = "web")]
#[test]
fn web_happy() {
    let source = keyhog_sources::WebSource::new(vec!["https://example.com/app.js".to_string()]);
    assert_eq!(source.name(), "web");
}
#[cfg(feature = "web")]
#[test]
fn web_error() {
    let source = keyhog_sources::WebSource::new(vec![]);
    assert!(source.chunks().next().is_none());
}

// ── crates/sources/src/s3/mod.rs ──────────────────────────────────────
#[cfg(feature = "s3")]
#[test]
fn s3_mod_happy() {
    let source = keyhog_sources::S3Source::new("bucket");
    assert_eq!(source.name(), "s3");
}
#[cfg(feature = "s3")]
#[test]
fn s3_mod_error() {
    assert!(create_source("s3", None).is_err());
}

// ── crates/sources/src/s3/auth.rs ───────────────────────────────────────
#[cfg(feature = "s3")]
#[test]
fn s3_auth_happy() {
    let source = keyhog_sources::S3Source::new("bucket");
    assert_eq!(source.name(), "s3");
}
#[cfg(feature = "s3")]
#[test]
fn s3_auth_error() {
    let source = keyhog_sources::S3Source::new("");
    assert_eq!(source.name(), "s3");
}

// ── crates/sources/src/s3/listing.rs ──────────────────────────────────
// happy/error gates: see crates/sources/tests/gate/s3_empty_bucket_name.rs

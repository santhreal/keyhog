//! LR1-A8 replacement gate: `sources.rs` build filesystem source for `.`.

use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};

fn build_sources_error(args: &ScanArgs) -> String {
    match API.build_sources(args, vec![], None) {
        Ok(_) => panic!("build_sources unexpectedly accepted invalid source configuration"),
        Err(error) => error.to_string(),
    }
}

#[test]
fn build_sources_accepts_current_directory() {
    let args = ScanArgs::try_parse_from(["scan", "--path", "."]).unwrap();
    let sources = API.build_sources(&args, vec![], None);
    assert!(
        sources.is_ok(),
        "scan of '.' must build at least one source: {:?}",
        sources.err()
    );
    let built = sources.unwrap();
    assert!(
        !built.is_empty(),
        "filesystem scan must produce a non-empty source list"
    );
}

#[test]
fn build_sources_accepts_positional_path_without_orchestrator_normalization() {
    let args = ScanArgs::try_parse_from(["scan", "."]).unwrap();
    let sources = API.build_sources(&args, vec![], None);
    assert!(
        sources.is_ok(),
        "source factory must honor positional PATH even when called before orchestrator normalization: {:?}",
        sources.err()
    );
    let built = sources.unwrap();
    assert!(
        !built.is_empty(),
        "positional filesystem scan must produce a source"
    );
}

#[cfg(feature = "binary")]
#[test]
fn build_sources_rejects_binary_flag_without_filesystem_path() {
    let mut args = ScanArgs::try_parse_from(["scan"]).unwrap();
    args.binary = true;
    let text = build_sources_error(&args);
    assert!(
        text.contains("--binary") && text.contains("--path <PATH>"),
        "binary source companion error must explain the missing path; got: {text}"
    );
}

#[cfg(feature = "github")]
#[test]
fn build_sources_rejects_partial_github_source_even_with_filesystem_path() {
    let mut args = ScanArgs::try_parse_from(["scan", "--path", "."]).unwrap();
    args.github_org = Some("acme".to_string());
    let text = build_sources_error(&args);
    assert!(
        (text.contains("GitHub source") || text.contains("GitHub organization source"))
            && text.contains("--github-token"),
        "partial GitHub source error must name the missing companion flag; got: {text}"
    );
}

#[cfg(feature = "gitlab")]
#[test]
fn build_sources_rejects_partial_gitlab_source_even_with_filesystem_path() {
    let mut args = ScanArgs::try_parse_from(["scan", "--path", "."]).unwrap();
    args.gitlab_token = Some("glpat-redacted".to_string());
    let text = build_sources_error(&args);
    assert!(
        text.contains("GitLab group source") && text.contains("--gitlab-group"),
        "partial GitLab source error must name the missing group flag; got: {text}"
    );
}

#[cfg(feature = "bitbucket")]
#[test]
fn build_sources_rejects_partial_bitbucket_source_even_with_filesystem_path() {
    let mut args = ScanArgs::try_parse_from(["scan", "--path", "."]).unwrap();
    args.bitbucket_workspace = Some("acme".to_string());
    args.bitbucket_username = Some("alice".to_string());
    let text = build_sources_error(&args);
    assert!(
        text.contains("Bitbucket workspace source") && text.contains("--bitbucket-token"),
        "partial Bitbucket source error must name the missing token flag; got: {text}"
    );
}

#[cfg(feature = "s3")]
#[test]
fn build_sources_rejects_s3_companion_flags_without_bucket() {
    let mut args = ScanArgs::try_parse_from(["scan", "--path", "."]).unwrap();
    args.s3_prefix = Some("config/".to_string());
    let text = build_sources_error(&args);
    assert!(
        text.contains("--s3-prefix") && text.contains("--s3-bucket"),
        "S3 source companion error must name the missing bucket; got: {text}"
    );
}

#[cfg(feature = "gcs")]
#[test]
fn build_sources_accepts_gcs_bucket_flags() {
    let args = ScanArgs::try_parse_from([
        "scan",
        "--gcs-bucket",
        "bucket-name",
        "--gcs-prefix",
        "config/",
        "--gcs-endpoint",
        "https://storage.googleapis.com",
    ])
    .unwrap();
    let sources = API
        .build_sources(&args, vec![], None)
        .expect("build sources");
    assert_eq!(sources.len(), 1, "GCS flags should build one source");
    assert_eq!(sources[0].name(), "gcs");
}

#[cfg(feature = "azure")]
#[test]
fn build_sources_accepts_azure_container_flags() {
    let args = ScanArgs::try_parse_from([
        "scan",
        "--azure-container-url",
        "https://account.blob.core.windows.net/container?sv=2024-11-04&sig=redacted",
        "--azure-prefix",
        "config/",
    ])
    .unwrap();
    let sources = API
        .build_sources(&args, vec![], None)
        .expect("build sources");
    assert_eq!(sources.len(), 1, "Azure flags should build one source");
    assert_eq!(sources[0].name(), "azure_blob");
}

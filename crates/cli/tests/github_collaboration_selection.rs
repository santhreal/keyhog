#![cfg(feature = "github")]

use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};

#[test]
fn collaboration_target_requires_an_explicit_surface() {
    let args = ScanArgs::try_parse_from([
        "scan",
        "--github-collaboration",
        "acme/rocket",
        "--github-token",
        "test-token",
    ])
    .expect("flags parse before cross-field validation");
    let error = match API.build_sources(&args, vec![], None) {
        Ok(_) => panic!("surface-free collaboration source must be rejected"),
        Err(error) => error.to_string(),
    };
    assert!(error.contains("requires an explicit surface"), "{error}");
}

#[test]
fn independently_selected_surfaces_build_one_collaboration_source() {
    for flag in [
        "--github-issues",
        "--github-pull-requests",
        "--github-discussions",
        "--github-wiki",
        "--github-gists",
    ] {
        let args = ScanArgs::try_parse_from([
            "scan",
            "--github-collaboration",
            "acme/rocket",
            flag,
            "--github-token",
            "test-token",
        ])
        .unwrap_or_else(|error| panic!("{flag} must parse: {error}"));
        let sources = API
            .build_sources(&args, vec![], None)
            .unwrap_or_else(|error| panic!("{flag} must build: {error}"));
        assert_eq!(sources.len(), 1, "{flag}");
        assert_eq!(sources[0].name(), "github-collaboration", "{flag}");
    }
}

#[test]
fn repository_only_source_does_not_construct_collaboration_adapter() {
    let args = ScanArgs::try_parse_from([
        "scan",
        "--github-org",
        "acme",
        "--github-token",
        "test-token",
    ])
    .expect("repository-only source parses");
    let sources = API
        .build_sources(&args, vec![], None)
        .expect("repository-only source builds");
    assert_eq!(sources.len(), 1);
    assert_eq!(sources[0].name(), "github-org");
}

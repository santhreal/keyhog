//! LR1-A8 replacement gate: `sources.rs` build filesystem source for `.`.

use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};

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

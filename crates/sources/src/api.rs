//! Curated public re-export surface for `keyhog-sources`.
//!
//! Source implementations remain owned by their modules; this file is the
//! single root compatibility export point.

#[cfg(feature = "binary")]
pub use crate::binary::BinarySource;
#[cfg(feature = "binary")]
pub use crate::binary::{binary_degraded_to_strings, binary_unreadable, reset_binary_counters};
#[cfg(feature = "azure")]
pub use crate::cloud::azure_blob::AzureBlobSource;
#[cfg(feature = "docker")]
pub use crate::docker::DockerImageSource;
pub use crate::filesystem::FilesystemSource;
#[cfg(feature = "gcs")]
pub use crate::gcs::GcsSource;
#[cfg(feature = "git")]
pub use crate::git::{GitDiffSource, GitHistorySource, GitSource};
#[cfg(feature = "github")]
pub use crate::github_org::GitHubOrgSource;
#[cfg(feature = "s3")]
pub use crate::s3::S3Source;
#[cfg(feature = "slack")]
pub use crate::slack::SlackSource;
pub use crate::stdin::{ConfiguredStdinSource, StdinSource};
#[cfg(feature = "web")]
pub use crate::web::WebSource;
pub use crate::{
    decode::decode_file_bytes,
    factory::{
        create_source, create_source_with_http_config, create_source_with_http_config_and_limits,
        create_source_with_http_config_limits_and_policy,
    },
    limits::{SourceLimits, DEFAULT_SOURCE_LIMITS},
    safe_read::read_file_safe_bytes,
    skip::{
        git_object_unreadable, reset_skipped_over_max_size, skip_counts, ScanCounterScope,
        SkipCounts,
    },
};

/// Fuzz-only PDF byte extractor.
#[cfg(fuzzing)]
pub use crate::filesystem::fuzz_extract_pdf_text;
/// Fuzz-only HAR byte expander.
#[cfg(fuzzing)]
pub use crate::har::fuzz_try_expand_har;

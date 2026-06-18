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

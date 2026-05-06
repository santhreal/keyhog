//! Pluggable input sources for KeyHog.
//!
//! Each source implements the [`keyhog_core::Source`] trait and yields [`keyhog_core::Chunk`]
//! values for the scanner. Sources are gated behind cargo features so only the
//! transitive dependencies you actually need are compiled.

#![allow(clippy::too_many_arguments)]

mod timeouts;

/// Local HTTP compatibility shim backed by reqwest. Only present when
/// at least one feature that pulls in `reqwest` is enabled —
/// otherwise this module would `pub use reqwest::*` against a crate
/// that wasn't compiled in, which fails resolution on stable rustc
/// (especially on Windows where `--no-default-features` is the
/// release profile we ship for the no-Hyperscan build).
#[cfg(any(feature = "web", feature = "github", feature = "slack", feature = "s3"))]
pub mod reqwest {
    pub use ::reqwest::*;
}

#[cfg(feature = "binary")]
mod binary;
#[cfg(feature = "docker")]
mod docker;
mod filesystem;
#[cfg(feature = "git")]
mod git;
#[cfg(feature = "github")]
mod github_org;
#[cfg(feature = "s3")]
mod s3;
#[cfg(feature = "slack")]
mod slack;
mod stdin;
pub mod strings;
#[cfg(feature = "web")]
mod web;

#[cfg(feature = "binary")]
pub use binary::BinarySource;
#[cfg(feature = "docker")]
pub use docker::DockerImageSource;
pub use filesystem::FilesystemSource;
#[cfg(feature = "git")]
pub use git::GitDiffSource;
#[cfg(feature = "git")]
pub use git::GitHistorySource;
#[cfg(feature = "git")]
pub use git::GitSource;
#[cfg(feature = "github")]
pub use github_org::GitHubOrgSource;
#[cfg(feature = "s3")]
pub use s3::S3Source;
#[cfg(feature = "slack")]
pub use slack::SlackSource;
pub use stdin::StdinSource;
#[cfg(feature = "web")]
pub use web::WebSource;

use keyhog_core::registry::get_source_registry;
#[cfg(any(feature = "slack", feature = "docker", feature = "s3"))]
use std::sync::Arc;

/// Create a source instance from a name and optional parameters.
/// This allows the CLI to remain agnostic of specific source implementations.
pub fn create_source(
    name: &str,
    params: Option<&str>,
) -> Result<Box<dyn keyhog_core::Source>, keyhog_core::SourceError> {
    match name {
        "slack" => {
            if let Some(token) = params {
                #[cfg(feature = "slack")]
                return Ok(Box::new(SlackSource::new(token)));
                #[cfg(not(feature = "slack"))]
                {
                    let _ = token;
                    return Err(keyhog_core::SourceError::Other(
                        "slack feature not enabled".into(),
                    ));
                }
            }
            Err(keyhog_core::SourceError::Other(
                "slack source requires a token: slack:TOKEN".into(),
            ))
        }
        "docker" => {
            if let Some(image) = params {
                #[cfg(feature = "docker")]
                return Ok(Box::new(DockerImageSource::new(image)));
                #[cfg(not(feature = "docker"))]
                {
                    let _ = image;
                    return Err(keyhog_core::SourceError::Other(
                        "docker feature not enabled".into(),
                    ));
                }
            }
            Err(keyhog_core::SourceError::Other(
                "docker source requires an image name: docker:IMAGE".into(),
            ))
        }
        "s3" => {
            if let Some(bucket) = params {
                #[cfg(feature = "s3")]
                return Ok(Box::new(S3Source::new(bucket)));
                #[cfg(not(feature = "s3"))]
                {
                    let _ = bucket;
                    return Err(keyhog_core::SourceError::Other(
                        "s3 feature not enabled".into(),
                    ));
                }
            }
            Err(keyhog_core::SourceError::Other(
                "s3 source requires a bucket name: s3:BUCKET".into(),
            ))
        }
        _ => Err(keyhog_core::SourceError::Other(format!(
            "unknown source plugin: {}",
            name
        ))),
    }
}

/// Register all compiled-in source plugins into the global registry.
/// This allows the CLI to discover sources like `slack` or `s3` via the
/// generic `--source` flag without hardcoded logic in the main crate.
pub fn register_plugins() {
    #[allow(unused_variables)]
    let registry = get_source_registry();

    #[cfg(feature = "slack")]
    if let Ok(token) = std::env::var("SLACK_TOKEN") {
        registry.register(Arc::new(SlackSource::new(token)));
    }

    #[cfg(feature = "s3")]
    if let Ok(bucket) = std::env::var("S3_BUCKET") {
        registry.register(Arc::new(S3Source::new(bucket)));
    }
}

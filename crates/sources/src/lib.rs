//! Pluggable input sources for KeyHog.
//!
//! Each source implements the [`keyhog_core::Source`] trait and yields [`keyhog_core::Chunk`]
//! values for the scanner. Sources are gated behind cargo features so only the
//! transitive dependencies you actually need are compiled.

#![allow(clippy::too_many_arguments)]

mod api;
mod decode;
mod factory;
mod limits;
#[cfg(any(
    feature = "azure",
    feature = "s3",
    feature = "gcs",
    feature = "slack",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket"
))]
mod parallel_fetch;
mod skip;
pub(crate) mod timeouts;

/// Shared HTTP-client policy (proxy, TLS, UA) used by every source
/// + verifier site that talks to the network. Always compiled - the
/// `HttpClientConfig` type is the thread-through even when the
/// reqwest-backed builders are feature-gated out - so the CLI can
/// construct one without caring about which feature set is active.
pub mod http;

#[cfg(feature = "binary")]
mod binary;
#[cfg(feature = "bitbucket")]
mod bitbucket_workspace;
#[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
mod cloud;
#[cfg(feature = "docker")]
mod docker;
mod filesystem;
#[cfg(feature = "gcs")]
mod gcs;
#[cfg(feature = "git")]
mod git;
#[cfg(feature = "github")]
mod github_org;
#[cfg(feature = "gitlab")]
mod gitlab_group;
mod har;
#[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
mod hosted_git;
#[cfg(feature = "s3")]
mod s3;
#[cfg(feature = "slack")]
mod slack;
mod stdin;
mod strings;
#[cfg(feature = "web")]
mod web;

pub use api::*;
pub use decode::decode_file_bytes;
pub use factory::{
    create_source, create_source_with_http_config, create_source_with_http_config_and_limits,
};
pub use limits::{SourceLimits, DEFAULT_SOURCE_LIMITS};
pub(crate) use skip::{
    record_skip_event, record_skip_events, reset_skip_counters, SourceSkipEvent,
};
pub use skip::{reset_skipped_over_max_size, skip_counts, SkipCounts};

#[doc(hidden)]
pub use testing_facade::testing;

mod testing_facade;

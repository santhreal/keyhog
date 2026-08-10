//! Pluggable input sources for KeyHog.
//!
//! Each source implements the [`keyhog_core::Source`] trait and yields [`keyhog_core::Chunk`]
//! values for the scanner. Sources are gated behind cargo features so only the
//! transitive dependencies you actually need are compiled.

#![doc = include_str!("../README.md")]
#![allow(clippy::too_many_arguments)]

mod api;
mod blocking_thread;
mod capped_read;
mod compression_limits;
mod decode;
#[cfg(any(
    feature = "azure",
    feature = "s3",
    feature = "gcs",
    feature = "web",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket"
))]
mod endpoint_screen;
mod factory;
/// Guard event normalization and subscribe-first reconciliation protocol.
pub mod guard;
mod limits;
mod magic;
#[cfg(any(
    feature = "azure",
    feature = "s3",
    feature = "gcs",
    feature = "slack",
    feature = "docker",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket"
))]
mod parallel_fetch;
#[cfg(any(
    feature = "git",
    feature = "docker",
    feature = "github",
    feature = "gitlab",
    feature = "bitbucket"
))]
mod process_excerpt;
mod profile;
mod safe_read;
mod skip;
pub(crate) mod timeouts;
// Unconditional: the always-on HAR expander tags every chunk with its captured
// request URL, which routinely carries `?access_token=` / userinfo, so the
// redaction owner has to exist even in a no-network feature build. The
// reqwest-dependent half of the module is gated inside it.
mod url_redaction;

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
mod github_collaboration;
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
pub use filesystem::DiscoveryCounts;
#[cfg(feature = "git")]
pub use git::{
    read_staged_blob, verify_staged_fingerprint, StagedEntryKind, StagedManifest,
    StagedManifestEntry,
};
pub(crate) use skip::{
    acquire_scan_read_lease, attach_scan_lease, enter_exclusive_scan_scope, gate_scan,
    record_skip_event, record_skip_events, reset_skip_counters, SourceSkipEvent,
};

/// Directory path components owned by the source default-exclude policy.
///
/// CLI filesystem surfaces compose this with their own consumer-specific
/// traversal policy so pre-scan traversal cannot drift from the scanner's
/// source-owned default excludes.
pub fn default_exclude_dir_components() -> &'static [String] {
    filesystem::default_exclude_dirs()
}

#[doc(hidden)]
pub use testing_facade::testing;

mod testing_facade;

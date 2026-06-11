// Lint bars for keyhog-core.
//
// Hard floor (kept in `deny`): the *security* lints. Every panic-y shortcut in
// production code is a real bug. These never relax.
//
// `missing_docs` is `warn` at the crate floor (Santh STANDARD.md). Debt-bucket
// modules (spec, finding, registry, source, credential, hardening, calibration)
// carry per-module `allow(missing_docs)` that names the debt explicitly; each
// per-module allow is removed once that module is fully documented and the
// warn fires at full strength for it.
#![warn(missing_docs)]
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::panic
    )
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::must_use_candidate,
    clippy::missing_errors_doc,
    clippy::pedantic
)]

//! Core types shared across all KeyHog crates.
pub mod allowlist;
/// Offline AWS account-ID decode + canary-token classification (single source
/// of truth shared by the scanner's finding metadata and the verifier's
/// suppress-live-verification-for-canaries gate).
pub mod aws;
/// ANSI-colored CLI startup banner with detector counts.
pub mod banner;
/// Configuration system for KeyHog scanning options.
pub mod config;
/// Secure credential storage and redaction.
pub mod credential;
mod dedup;
/// Shared standard Base64 decode (wire / K8s), bounded for DoS safety.
pub mod encoding;
mod finding;
/// Security hardening: memory zeroization and process isolation helpers.
pub mod hardening;
/// Structured reporting (JSON, SARIF, Text).
pub mod report;
/// Safe absolute-path resolution for external binaries.
pub mod safe_bin;
mod source;
mod spec;
use std::borrow::Cow;

/// Global registry for sources and verifiers.
pub mod registry;

pub use allowlist::*;
pub use config::*;
pub use credential::{Credential, SensitiveString};
pub use dedup::*;
pub use finding::*;
pub use report::*;
pub use source::*;
/// Auto-fix suggestion logic for SARIF output.
pub mod auto_fix;
/// Bayesian confidence calibration for detectors.
pub mod calibration;
/// Incremental scan state via BLAKE3 Merkle index.
pub mod merkle_index;
mod merkle_spec_hash;
pub use merkle_spec_hash::compute_spec_hash;
/// Declarative `.keyhogignore.toml` rule-based finding suppression.
/// Wraps vyre's CPU rule evaluator with a TOML schema scoped to
/// keyhog's finding shape (detector / service / severity / path /
/// credential_hash predicates).
pub mod rule_filter;
pub use rule_filter::{RuleSuppressor, RuleSuppressorError};
pub use spec::*;

// Embedded detectors compiled into the binary at build time.
// These are used when no external detectors directory is found.
mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_detectors.rs"));
}

/// Load detectors from embedded data (compiled into the binary).
/// Returns detector TOML strings that can be parsed by the spec loader.
pub fn embedded_detector_tomls() -> &'static [(&'static str, &'static str)] {
    embedded::EMBEDDED_DETECTORS
}

/// Number of embedded detector specs (authoritative for banners and tests).
#[inline]
pub fn embedded_detector_count() -> usize {
    embedded_detector_tomls().len()
}

/// Git commit SHA the binary was built from, or `"unknown"` for a build with no
/// reachable `.git` tree (e.g. a `cargo package` / crates.io build). Stamped by
/// `build.rs` via `cargo:rustc-env=GIT_HASH`; `env!` resolves here because the
/// rustc-env applies to THIS crate's compilation. Surfaced in `keyhog --version`
/// and meant to be embedded in every result so a scan traces back to an exact
/// commit (MC-06: the false "F1 regression" was a stale binary benched against
/// HEAD, undetectable while every build reported the same empty version).
#[inline]
pub fn git_hash() -> &'static str {
    env!("GIT_HASH")
}

/// Digest identifying the EXACT embedded detector set compiled into this binary
/// (`<count>-<fnv1a_hex>`). Stamped by `build.rs` via
/// `cargo:rustc-env=KEYHOG_DETECTOR_DIGEST`. Lets the benchmark and `--version`
/// assert the running binary's detectors match the on-disk `detectors/` tree —
/// the authoritative answer to "what got compiled in" when cargo's
/// `rerun-if-changed` can't be trusted across in-place TOML edits.
#[inline]
pub fn detector_digest() -> &'static str {
    env!("KEYHOG_DETECTOR_DIGEST")
}

/// Redact a sensitive credential string for safe display.
pub fn redact(s: &str) -> Cow<'static, str> {
    // ASCII fast path: byte indexing is valid (no UTF-8 boundary risk),
    // skips the O(n) `chars().count()` walk plus two intermediate `String`
    // allocations from `take(4).collect()` / `skip(n).collect()`. Most
    // credentials are pure ASCII (provider keys, hashes, base64 tokens).
    if s.is_ascii() {
        if s.len() <= 8 {
            return Cow::Borrowed("****");
        }
        let mut out = String::with_capacity(s.len().min(11));
        out.push_str(&s[..4]);
        out.push_str("...");
        out.push_str(&s[s.len() - 4..]);
        return Cow::Owned(out);
    }
    // UTF-8 path: char-count for grapheme correctness.
    let char_count = s.chars().count();
    if char_count <= 8 {
        return Cow::Borrowed("****");
    }
    let first_four: String = s.chars().take(4).collect();
    let last_four: String = s.chars().skip(char_count.saturating_sub(4)).collect();
    Cow::Owned(format!("{first_four}...{last_four}"))
}

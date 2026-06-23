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
mod allowlist;
mod api;
/// Offline AWS account-ID decode + canary-token classification (single source
/// of truth shared by the scanner's finding metadata and the verifier's
/// suppress-live-verification-for-canaries gate).
mod aws;
/// Configuration system for KeyHog scanning options.
mod config;
/// Secure credential storage and redaction.
mod credential;
mod dedup;
mod display;
/// Shared standard Base64 decode (wire / K8s), bounded for DoS safety.
mod encoding;
mod finding;
/// Security hardening: memory zeroization and process isolation helpers.
mod hardening;
mod hyperscan_cache;
/// Structured reporting (JSON, SARIF, Text).
mod report;
/// Safe absolute-path resolution for external binaries.
mod safe_bin;
mod source;
mod spec;
use std::borrow::Cow;

/// Global registry for sources and verifiers.
mod registry;

pub use api::*;
pub use hyperscan_cache::{
    HYPERSCAN_CACHE_FILE_BYTES, HYPERSCAN_CACHE_HEADER_LEN, HYPERSCAN_CACHE_MAGIC,
    HYPERSCAN_CACHE_VERSION, hyperscan_cache_header_is_valid, write_hyperscan_cache_header,
};
/// Auto-fix suggestion logic for SARIF output.
mod auto_fix;
/// Bayesian confidence calibration for detectors.
mod calibration;
/// Incremental scan state via BLAKE3 Merkle index.
mod merkle_index;
mod merkle_spec_hash;
/// Declarative `.keyhogignore.toml` rule-based finding suppression.
/// Wraps vyre's CPU rule evaluator with a TOML schema scoped to
/// keyhog's finding shape (detector / service / severity / path /
/// credential_hash predicates).
mod rule_filter;

// Embedded detectors compiled into the binary at build time.
// These are used when no external detectors directory is found.
mod embedded {
    include!(concat!(env!("OUT_DIR"), "/embedded_detectors.rs"));
}

/// Load detectors from embedded data (compiled into the binary).
/// Returns detector TOML strings that can be parsed by the spec loader.
pub(crate) fn embedded_detector_tomls() -> &'static [(&'static str, &'static str)] {
    embedded::EMBEDDED_DETECTORS
}

/// Number of embedded detector specs (authoritative for banners and tests).
#[inline]
pub fn embedded_detector_count() -> usize {
    embedded_detector_tomls().len()
}

/// Parse the embedded detector corpus, FAILING CLOSED on any malformed TOML.
///
/// This is the SINGLE loader every entrypoint shares (the `scan` orchestrator
/// via `cli::orchestrator_config`, and every other scan entry point) so the
/// fail-closed contract holds uniformly — there is exactly one way to turn the
/// compiled-in corpus into `DetectorSpec`s.
///
/// Law 10 (NO SILENT FALLBACKS): the embedded set is baked into the binary by
/// `build.rs`; a TOML that fails to parse is a BUILD/SOURCE bug, never a runtime
/// condition the operator can act on (the user cannot have edited a compiled-in
/// string). The old per-callsite `tracing::debug!`-then-`continue` shape silently
/// dropped the offender — exactly how the dead `discord-bot-token` detector (a
/// single-quoted TOML literal that broke parsing) reached a benched release as an
/// invisible recall hole. So this collects every offender and returns
/// [`SpecError::EmbeddedCorpusCorrupt`] naming each, making a corrupt corpus a
/// hard error rather than a buried log line. Each embedded TOML holds exactly one
/// detector, so on success `result.len() == embedded_detector_count()`.
pub fn load_embedded_detectors_or_fail() -> Result<Vec<DetectorSpec>, SpecError> {
    let embedded = embedded_detector_tomls();
    let mut detectors = Vec::with_capacity(embedded.len());
    let mut failed: Vec<(String, String)> = Vec::new();
    for (name, toml_content) in embedded {
        match toml::from_str::<DetectorFile>(toml_content) {
            Ok(file) => detectors.push(file.detector),
            Err(error) => failed.push(((*name).to_string(), error.to_string())),
        }
    }
    if !failed.is_empty() {
        let detail = failed
            .iter()
            .map(|(name, error)| format!("  - {name}: {error}"))
            .collect::<Vec<_>>()
            .join("\n");
        return Err(SpecError::EmbeddedCorpusCorrupt {
            failed_count: failed.len(),
            total: embedded.len(),
            detail,
        });
    }
    Ok(detectors)
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
        let edge = redaction_edge_len(s.len());
        let mut out = String::with_capacity((edge * 2) + 3);
        out.push_str(&s[..edge]);
        out.push_str("...");
        out.push_str(&s[s.len() - edge..]);
        return Cow::Owned(out);
    }
    // UTF-8 path: char-count for grapheme correctness.
    let char_count = s.chars().count();
    if char_count <= 8 {
        return Cow::Borrowed("****");
    }
    let edge = redaction_edge_len(char_count);
    let prefix: String = s.chars().take(edge).collect();
    let suffix: String = s.chars().skip(char_count.saturating_sub(edge)).collect();
    Cow::Owned(format!("{prefix}...{suffix}"))
}

fn redaction_edge_len(char_count: usize) -> usize {
    (char_count / 4).clamp(1, 4)
}

#[doc(hidden)]
pub mod testing;

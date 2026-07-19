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
pub mod ascii_ci;
/// Offline AWS account-ID decode + canary-token classification (single source
/// of truth shared by the scanner's finding metadata and the verifier's
/// suppress-live-verification-for-canaries gate).
mod aws;
/// Configuration system for KeyHog scanning options.
mod config;
/// Secure credential storage and redaction.
mod credential;
mod dedup;
mod detector_file_io;
mod display;
/// Shared standard Base64 decode (wire / K8s), bounded for DoS safety.
mod encoding;
mod finding;
/// Git-LFS pointer recognition, shared by the scanner (oid suppression) and
/// sources (unscanned-blob coverage gap).
pub mod git_lfs;
/// Security hardening: memory zeroization and process isolation helpers.
mod hardening;
mod hyperscan_cache;
/// Detector verification response selector grammar and evaluator.
pub mod json_selector;
/// Structured reporting (JSON, SARIF, Text).
mod report;
/// Safe absolute-path resolution for external binaries.
mod safe_bin;
mod source;
mod spec;
mod state_file;
/// Shared paired performance statistics used by release gates and routing evidence.
pub mod timing;
/// Verification-domain policy shared by detector validation and the network
/// verifier.
pub mod verification_domain;
pub mod winpath;
use std::borrow::Cow;

pub use api::*;
/// Auto-fix suggestion logic for SARIF output.
mod auto_fix;
/// Bayesian confidence calibration for detectors.
mod calibration;
/// Incremental scan state via BLAKE3 Merkle index.
mod merkle_index;
mod merkle_spec_hash;
/// Declarative `.keyhogignore.toml` rule-based finding suppression.
/// Wraps VYRE's CPU rule evaluator with a TOML schema scoped to
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

/// Age (seconds) after which an abandoned `*.tmp` working file is considered
/// stale and safe to remove. ONE owner for the tmp-file hygiene policy shared by
/// `calibration` (calibration cache) and `merkle_index::tmp_hygiene` (index
/// build), both used to define their own `60 * 60` const, which could silently
/// drift apart.
pub(crate) const STALE_TMP_CUTOFF_SECS: u64 = 60 * 60;

/// The `keyhog` path component under the OS cache root. ONE owner for the
/// cache-root segment shared by the calibration cache, the merkle index, and the
/// lockdown past-findings gate, a rename here moves all three together so the
/// lockdown scan can never desynchronize from where scan artifacts actually land.
pub(crate) const KEYHOG_CACHE_SUBDIR: &str = "keyhog";

/// Absolute path of keyhog's per-user cache root (`<os-cache>/keyhog`), or
/// `None` when the platform exposes no cache directory.
pub(crate) fn keyhog_cache_root() -> Option<std::path::PathBuf> {
    dirs::cache_dir().map(|dir| dir.join(KEYHOG_CACHE_SUBDIR))
}

/// Parse the embedded detector corpus, FAILING CLOSED on any malformed TOML.
///
/// This is the SINGLE loader every entrypoint shares (the `scan` orchestrator
/// via `cli::orchestrator_config`, and every other scan entry point) so the
/// fail-closed contract holds uniformly, there is exactly one way to turn the
/// compiled-in corpus into `DetectorSpec`s.
///
/// Law 10 (NO SILENT FALLBACKS): the embedded set is baked into the binary by
/// `build.rs`; a TOML that fails to parse is a BUILD/SOURCE bug, never a runtime
/// condition the operator can act on (the user cannot have edited a compiled-in
/// string). The old per-callsite `tracing::debug!`-then-`continue` shape silently
/// dropped the offender, exactly how the dead `discord-bot-token` detector (a
/// single-quoted TOML literal that broke parsing) reached a benched release as an
/// invisible recall hole. So this collects every offender and returns
/// [`SpecError::EmbeddedCorpusCorrupt`] naming each, making a corrupt corpus a
/// hard error rather than a buried log line. Each embedded TOML holds exactly one
/// detector, so on success `result.len() == embedded_detector_count()`.
pub fn load_embedded_detectors_or_fail() -> Result<Vec<DetectorSpec>, SpecError> {
    let embedded = embedded_detector_tomls();
    let mut detectors = Vec::with_capacity(embedded.len());
    let mut failed = Vec::new();
    for (name, toml_content) in embedded {
        match parse_embedded_detector(name, toml_content) {
            Ok(detector) => detectors.push(detector),
            Err(error) => failed.push(error),
        }
    }
    if !failed.is_empty() {
        let detail = failed
            .iter()
            .map(|error| format!("  - {error}"))
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

fn parse_embedded_detector(name: &str, toml_content: &str) -> Result<DetectorSpec, String> {
    let file =
        toml::from_str::<DetectorFile>(toml_content).map_err(|error| format!("{name}: {error}"))?;
    let errors: Vec<String> = spec::validate_detector(&file.detector)
        .into_iter()
        .filter_map(|issue| match issue {
            spec::QualityIssue::Error(error) => Some(error),
            spec::QualityIssue::Warning(_) => None,
        })
        .collect();
    if errors.is_empty() {
        Ok(file.detector)
    } else {
        Err(format!(
            "{name}: detector quality gate rejected the embedded spec: {}",
            errors.join("; ")
        ))
    }
}

/// Every embedded detector spec, parsed EXACTLY ONCE for the whole process.
///
/// This is the single materialization of the compiled-in corpus: both the
/// id-keyed lookup ([`detector_spec_by_id`]) and whole-corpus consumers (the ML
/// service-vocabulary derivation in `keyhog-scanner`, registry audits) borrow
/// from this one `Vec` instead of re-running [`load_embedded_detectors_or_fail`]
/// and holding their own copy of every spec. Fails closed on a corrupt embedded
/// corpus: a bundled TOML that will not parse is a build/source defect, never a
/// silent empty set (Law 10).
pub fn embedded_detector_specs() -> &'static [DetectorSpec] {
    static SPECS: std::sync::LazyLock<Vec<DetectorSpec>> =
        std::sync::LazyLock::new(|| match load_embedded_detectors_or_fail() {
            Ok(specs) => specs,
            Err(error) => panic!(
                "embedded detector corpus failed to load: {error}. The detector \
                 specifications live in the bundled TOMLs; refusing to run without them."
            ),
        });
    &SPECS
}

/// Canonical `id → DetectorSpec` lookup over the embedded corpus, built EXACTLY
/// ONCE.
///
/// This is the single owner every "give me the spec for detector id X" consumer
/// shares (entropy plausibility gates, entropy-scanner resolution, adjudication
/// confidence/length floors). Before this, three separate
/// `LazyLock<HashMap<String, DetectorSpec>>` statics each called
/// [`load_embedded_detectors_or_fail`] and rebuilt an identical map, the
/// compiled-in corpus was parsed three times at startup (Law 7) and the same
/// lookup lived in three places (ONE PLACE). The map borrows from
/// [`embedded_detector_specs`] (the one materialized corpus) rather than holding
/// a second by-value copy of every spec. Fails closed on a corrupt embedded
/// corpus, matching every prior consumer's contract.
pub fn detector_spec_by_id(id: &str) -> Option<&'static DetectorSpec> {
    static BY_ID: std::sync::LazyLock<
        std::collections::HashMap<&'static str, &'static DetectorSpec>,
    > = std::sync::LazyLock::new(|| {
        embedded_detector_specs()
            .iter()
            .map(|spec| (spec.id.as_str(), spec))
            .collect()
    });
    BY_ID.get(id).copied()
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
/// assert the running binary's detectors match the on-disk `detectors/` tree
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
    (char_count / 8).clamp(1, 4)
}

#[doc(hidden)]
pub mod testing;

//! Service-name vocabulary for the keyword-specificity ML feature
//! (`ml_features::SERVICE_CONTEXT_FEATURE_INDEX`, feature 42. DET-1).
//!
//! # What this feature separates
//!
//! The CredData/mirror analysis showed the MoE's dominant confusion is
//! UUID/opaque-token shapes: `CODECOV_TOKEN = "7b3e5d8c-…"` (a real credential <!-- keyhog:ignore detector=generic-secret -->
//! 171 contract positives across 62 detectors carry exactly this shape) versus
//! `SESSION_ID = "50bcba48-…"` / `API_KEY = "<uuid>"` (an identifier, mirror
//! labels these negative, and they are 68-76% of the CredData FP flood). The
//! shape features cannot split these: the VALUE is identical. What differs is
//! the CONTEXT: real UUID-shaped secrets ride next to a SPECIFIC service name
//! (codecov, equinix, grafana, …); identifier UUIDs ride next to GENERIC
//! credential role-words only (api_key, secret, token). Feature 17 already says
//! "context mentions a generic credential word"; this module powers feature 42,
//! "context names a specific service", so the model can learn
//! `service-context + UUID → secret` / `generic-context-only + UUID → reject`.
//!
//! # ONE-PLACE derivation (never a hand-curated list)
//!
//! The vocabulary is DERIVED from the embedded detector corpus, the single
//! definitional home of "which services keyhog knows", via
//! [`keyhog_core::embedded_detector_specs`]. Every detector TOML's prefilter
//! `keywords` feed in; three deterministic filters remove non-service noise:
//!
//! 1. **Length floor** ([`MIN_SERVICE_KEYWORD_LEN`]): 1-3 byte keywords are
//!    value prefixes (`cko`, `dt0`, `sk-`) or symbols (`$`, `://`) that
//!    collide with random credential bytes in the context window, not names.
//! 2. **Generic-family exclusion**: any keyword listed by a `generic-*` (or
//!    future `entropy*`) detector spec is a credential ROLE word by
//!    definition (api_key, secret, token, password, …), the exact vocabulary
//!    feature 42 must NOT fire on. SUBSTRINGS of those words are excluded
//!    too: as a `contains` needle, `api_` fires everywhere `api_key` does,
//!    making it strictly more generic than the word itself.
//! 3. **Stem-spread genericity** ([`GENERIC_STEM_SPREAD_LIMIT`]): a keyword
//!    used by detectors of ≥ 3 DISTINCT id stems (stem = the id's first
//!    `-`-separated token) names a cross-vendor concept (`client_secret`
//!    spans 14 stems, `bearer` 6, `webhook_secret` 6), not a service. A
//!    keyword spread across many detectors of ONE stem (`gitlab` appears in 9
//!    `gitlab-*` detectors) stays: that is one service with many token kinds.
//!
//! The result is lowercased, deduplicated (this also collapses the 562
//! defensive case-variant keyword pairs like `ADOBE`/`adobe`), and sorted, so
//! the vocabulary is a deterministic function of the detector corpus alone.
//!
//! # Train/serve parity contract
//!
//! Training features come from the Rust `dump_features` serve path, so training
//! and serving share THIS implementation. The independent Python parity oracle
//! (`ml/feature_parity.py::_service_vocabulary`) re-derives the vocabulary from
//! `detectors/*.toml` with byte-identical rules; `ml/parity_check.py` fails
//! loudly on any disagreement. Change the rules here and there together.

use std::sync::LazyLock;

#[cfg(test)]
use super::service_vocab_build::{
    build_service_vocabulary as derive_vocabulary, ServiceVocabularyDetector,
};
#[cfg(test)]
pub(crate) use super::service_vocab_build::{GENERIC_STEM_SPREAD_LIMIT, MIN_SERVICE_KEYWORD_LEN};

/// The vocabulary policy lives in `service_vocab_build` so the build script and
/// unit-test oracle execute one implementation.

/// Pure vocabulary builder over an explicit spec slice (unit-testable without
/// the embedded corpus). See the module doc for the three filter rules.
#[cfg(test)]
pub(crate) fn build_service_vocabulary(specs: &[keyhog_core::DetectorSpec]) -> Vec<String> {
    derive_vocabulary(specs.iter().map(|detector| ServiceVocabularyDetector {
        id: &detector.id,
        generic_family: detector.owns_entropy_policy(),
        keywords: &detector.keywords,
    }))
}

/// The build script derives this exact corpus vocabulary from detector TOML.
/// Ordinary scans map static string data and never reconstruct detector specs.
pub(crate) fn service_vocabulary() -> &'static [&'static str] {
    static VOCABULARY: &[&str] = include!(concat!(env!("OUT_DIR"), "/ml_service_vocabulary.rs"));
    VOCABULARY
}

/// One case-insensitive multi-pattern automaton over the whole vocabulary.
/// `contains_any` over ~2.4k needles per ML candidate would be O(needles ×
/// context) (Law 7); Aho-Corasick makes the probe a single pass over the ±5-line
/// context window. Build failure is a build-time-data defect (the corpus is
/// compiled in), so it fails closed like every other embedded-corpus consumer.
static SERVICE_AC: LazyLock<aho_corasick::AhoCorasick> = LazyLock::new(|| {
    match aho_corasick::AhoCorasick::builder()
        .ascii_case_insensitive(true)
        .build(service_vocabulary())
    {
        Ok(automaton) => automaton,
        Err(error) => panic!(
            "service-vocabulary Aho-Corasick failed to build: {error}. The vocabulary \
                 derives from the embedded detector corpus; refusing to run without it."
        ),
    }
});

/// Feature-42 probe: does the ML context window (±5 lines + `file:` path)
/// mention any known service name? ASCII-case-insensitive `contains`, matching
/// the semantics of the sibling context probes (features 17/18/20).
pub(crate) fn context_names_service(context: &[u8]) -> bool {
    !context.is_empty() && SERVICE_AC.is_match(context)
}

//! Service-name vocabulary for the keyword-specificity ML feature
//! (`ml_features::SERVICE_CONTEXT_FEATURE_INDEX`, feature 42. DET-1).
//!
//! # What this feature separates
//!
//! The CredData/mirror analysis showed the MoE's dominant confusion is
//! UUID/opaque-token shapes: `CODECOV_TOKEN = "7b3e5d8c-…"` (a real credential
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

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

/// Keywords shorter than this never enter the service vocabulary: at 1-3 bytes
/// they are credential value-prefixes or separators, and as case-insensitive
/// `contains` needles they false-fire inside random base64/hex bytes that share
/// the ±5-line ML context window with the candidate.
pub(crate) const MIN_SERVICE_KEYWORD_LEN: usize = 4;
const MIN_ACTIVE_SERVICE_NAME_LEN: usize = 3;

/// A keyword used by detectors of this many DISTINCT id stems (or more) is a
/// cross-vendor role word, not a service name. 2 keeps two-spelling vendors
/// (`aws-*` + `amazon-*` both carrying `amazonaws`); 3 is where genuine
/// role-words start (`x-api-key` spans 9 stems, `authorization` 10).
pub(crate) const GENERIC_STEM_SPREAD_LIMIT: usize = 3;

/// Preserve the shipped model's exact vocabulary contract until the service
/// context feature is retrained with detector-local vocabulary policy.
fn is_generic_family(detector_id: &str) -> bool {
    crate::detector_ids::is_generic_or_entropy_detector(detector_id)
}

/// The id's first `-`-separated token: `gitlab-pipeline-trigger-token` →
/// `gitlab`. Groups sibling detectors of one service so per-service keyword
/// reuse is not mistaken for cross-vendor genericity.
fn detector_id_stem(detector_id: &str) -> &str {
    detector_id
        .split('-')
        .next()
        .map_or(detector_id, |stem| stem)
}

/// Pure vocabulary builder over an explicit spec slice (unit-testable without
/// the embedded corpus). See the module doc for the three filter rules.
pub(crate) fn build_service_vocabulary(specs: &[keyhog_core::DetectorSpec]) -> Vec<String> {
    let mut generic_words: BTreeSet<String> = BTreeSet::new();
    let mut stems_by_keyword: BTreeMap<String, BTreeSet<&str>> = BTreeMap::new();

    for spec in specs {
        if is_generic_family(&spec.id) {
            for keyword in &spec.keywords {
                generic_words.insert(keyword.to_ascii_lowercase());
            }
            continue;
        }
        let stem = detector_id_stem(&spec.id);
        for keyword in &spec.keywords {
            stems_by_keyword
                .entry(keyword.to_ascii_lowercase())
                .or_default()
                .insert(stem);
        }
    }

    stems_by_keyword
        .into_iter()
        .filter(|(keyword, stems)| {
            keyword.len() >= MIN_SERVICE_KEYWORD_LEN
                && stems.len() < GENERIC_STEM_SPREAD_LIMIT
                // A candidate that is a SUBSTRING of a generic role word
                // (`api_` ⊂ `api_key`) fires everywhere that word does, as a
                // `contains` needle it is strictly MORE generic than the word
                // itself, so both exact members and substrings are excluded.
                // (Containing a generic word is fine: `virustotal_api_key`
                // only fires when the service name is present too.)
                && !generic_words.iter().any(|g| g.contains(keyword.as_str()))
        })
        .map(|(keyword, _)| keyword)
        .collect()
}

/// The service vocabulary derived from the embedded corpus, built exactly once.
pub(crate) fn service_vocabulary() -> &'static [String] {
    static VOCAB: LazyLock<Vec<String>> =
        LazyLock::new(|| build_service_vocabulary(keyhog_core::embedded_detector_specs()));
    &VOCAB
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

/// Whether context names the service owned by this exact detector rather than
/// merely any service in the corpus. The canonical TOML `service` value is the
/// allocation-free identity probe; generic and one/two-byte labels cannot
/// masquerade as positive evidence.
pub(crate) fn context_names_detector_service(detector_service: &str, context: &[u8]) -> bool {
    if context.is_empty()
        || detector_service.len() < MIN_ACTIVE_SERVICE_NAME_LEN
        || detector_service.eq_ignore_ascii_case("generic")
    {
        return false;
    }
    crate::ascii_ci::ci_find_nonempty(context, detector_service.as_bytes())
}

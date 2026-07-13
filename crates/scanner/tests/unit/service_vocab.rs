//! Unit + adversarial coverage for the service-name vocabulary that powers ML
//! feature 42 (`service_vocab.rs`, DET-1).
//!
//! Two surfaces are proven here:
//!
//!  * [`build_service_vocabulary`], the pure builder over an explicit spec
//!    slice. Every one of the module's three documented filter rules (length
//!    floor, generic-family exclusion incl. the substring asymmetry, and
//!    stem-spread genericity) gets a positive twin and a negative twin on
//!    synthetic specs we fully control, so the test asserts the exact behavior
//!    the module doc claims (not merely a non-empty result).
//!  * [`context_names_service`], the live Aho-Corasick probe over the embedded
//!    corpus. It is checked against a naive `contains` oracle (differential:
//!    the automaton must agree with the O(n·m) reference on every input) plus
//!    the empty-guard and case-insensitivity boundaries, and the live
//!    vocabulary is pinned to its construction invariants and the feature-42
//!    contract that generic credential role words never leak in.

use keyhog_core::DetectorSpec;
use keyhog_scanner::ml_scorer::service_vocab::{
    build_service_vocabulary, context_names_service, service_vocabulary, GENERIC_STEM_SPREAD_LIMIT,
    MIN_SERVICE_KEYWORD_LEN,
};

/// Minimal spec fixture: only the two fields the builder reads (`id` + prefilter
/// `keywords`); everything else is `DetectorSpec::default()`.
fn spec(id: &str, keywords: &[&str]) -> DetectorSpec {
    DetectorSpec {
        id: id.to_string(),
        keywords: keywords.iter().map(|k| k.to_string()).collect(),
        ..DetectorSpec::default()
    }
}

fn vocab_of(specs: &[DetectorSpec]) -> Vec<String> {
    build_service_vocabulary(specs)
}

// ─────────────────────────── the three filter rules ───────────────────────────

#[test]
fn constants_match_documented_contract() {
    // The rules below are written against these exact thresholds; pin them so a
    // silent constant change cannot leave the tests asserting the wrong shape.
    assert_eq!(MIN_SERVICE_KEYWORD_LEN, 4);
    assert_eq!(GENERIC_STEM_SPREAD_LIMIT, 3);
}

#[test]
fn rule1_length_floor_drops_short_keeps_long() {
    // A 3-byte keyword ("cko") is a value-prefix, not a service name → dropped;
    // a 4-byte keyword on the same single real detector survives.
    let vocab = vocab_of(&[spec("checkout-secret-key", &["cko", "vend"])]);
    assert!(
        !vocab.iter().any(|v| v == "cko"),
        "3-byte keyword must be below the length floor: {vocab:?}"
    );
    assert!(
        vocab.iter().any(|v| v == "vend"),
        "4-byte single-stem service keyword must survive: {vocab:?}"
    );
}

#[test]
fn rule2_generic_family_keyword_excluded_even_when_a_real_detector_shares_it() {
    // "apikeyword" is declared by a `generic-*` spec → it is a credential ROLE
    // word by definition and must not enter the vocabulary, even though a real
    // vendor detector also lists it.
    let vocab = vocab_of(&[
        spec("generic-api-key", &["apikeyword"]),
        spec("realvendor-token", &["apikeyword", "realname"]),
    ]);
    assert!(
        !vocab.iter().any(|v| v == "apikeyword"),
        "generic-family keyword must be excluded: {vocab:?}"
    );
    assert!(
        vocab.iter().any(|v| v == "realname"),
        "a genuine service keyword on the same real detector still survives: {vocab:?}"
    );
}

#[test]
fn rule2_substring_of_generic_word_is_excluded_but_superstring_is_kept() {
    // The documented asymmetry (lines 114-120 of the module):
    //  * "service" ⊂ generic "servicekey"  → as a `contains` needle it fires
    //    everywhere the generic word does → EXCLUDED.
    //  * "vaultservicekey" ⊃ generic "servicekey" → only fires when the extra
    //    service-specific bytes are present → KEPT.
    let vocab = vocab_of(&[
        spec("generic-secret", &["servicekey"]),
        spec("realvendor-a", &["service"]),
        spec("realvendor-b", &["vaultservicekey"]),
    ]);
    assert!(
        !vocab.iter().any(|v| v == "service"),
        "substring of a generic word must be excluded: {vocab:?}"
    );
    assert!(
        vocab.iter().any(|v| v == "vaultservicekey"),
        "superstring of a generic word must be kept: {vocab:?}"
    );
}

#[test]
fn rule3_stem_spread_excludes_cross_vendor_word_keeps_single_service() {
    // "shared" appears across 3 DISTINCT id stems (alpha/beta/gamma) → it names
    // a cross-vendor concept → EXCLUDED (>= GENERIC_STEM_SPREAD_LIMIT).
    // "onevendor" appears across 3 detectors of ONE stem (gitlab) → one service
    // with many token kinds → KEPT.
    let vocab = vocab_of(&[
        spec("alpha-token", &["shared"]),
        spec("beta-token", &["shared"]),
        spec("gamma-token", &["shared"]),
        spec("gitlab-a", &["onevendor"]),
        spec("gitlab-b", &["onevendor"]),
        spec("gitlab-c", &["onevendor"]),
    ]);
    assert!(
        !vocab.iter().any(|v| v == "shared"),
        "keyword spanning >=3 stems must be excluded: {vocab:?}"
    );
    assert!(
        vocab.iter().any(|v| v == "onevendor"),
        "keyword across many detectors of ONE stem must be kept: {vocab:?}"
    );
}

#[test]
fn rule3_two_stem_keyword_is_kept_boundary() {
    // Exactly 2 stems is BELOW the limit of 3 (keeps two-spelling vendors like
    // aws/amazon carrying `amazonaws`) → KEPT.
    let vocab = vocab_of(&[
        spec("aws-x", &["amazonaws"]),
        spec("amazon-y", &["amazonaws"]),
    ]);
    assert!(
        vocab.iter().any(|v| v == "amazonaws"),
        "two-stem keyword is below the spread limit and must be kept: {vocab:?}"
    );
}

// ───────────────────────── shape of the built vocabulary ─────────────────────

#[test]
fn output_is_lowercased_deduped_and_sorted() {
    // Case variants collapse to one entry; output is ascending and dup-free.
    let vocab = vocab_of(&[
        spec("adobe-api-key", &["Adobe", "ADOBE", "adobe"]),
        spec("zendesk-token", &["zendesk"]),
    ]);
    assert_eq!(
        vocab.iter().filter(|v| *v == "adobe").count(),
        1,
        "case variants must collapse to a single lowercased entry: {vocab:?}"
    );
    assert!(vocab.contains(&"adobe".to_string()));
    assert!(vocab.contains(&"zendesk".to_string()));
    let mut sorted = vocab.clone();
    sorted.sort();
    assert_eq!(vocab, sorted, "vocabulary must be sorted ascending");
    sorted.dedup();
    assert_eq!(
        vocab.len(),
        sorted.len(),
        "vocabulary must be duplicate-free"
    );
}

#[test]
fn empty_corpus_yields_empty_vocabulary() {
    assert!(vocab_of(&[]).is_empty());
}

// ─────────────────────── context_names_service (live) ────────────────────────

#[test]
fn context_probe_empty_input_is_false() {
    assert!(!context_names_service(b""));
    assert!(!context_names_service(&[]));
}

/// Naive reference oracle: the automaton MUST agree with an ASCII-case-insensitive
/// substring scan over the whole vocabulary on every input.
fn oracle_contains_any(context: &str) -> bool {
    let haystack = context.to_ascii_lowercase();
    service_vocabulary()
        .iter()
        .any(|needle| haystack.contains(needle.as_str()))
}

#[test]
fn context_probe_matches_naive_substring_oracle_differentially() {
    let sample = service_vocabulary()
        .first()
        .expect("live service vocabulary is non-empty")
        .clone();

    let cases = [
        String::new(),
        format!("export {}_TOKEN=abc123", sample.to_uppercase()), // known positive, upper
        format!("  {sample}  "),                                  // known positive, lower
        "API_KEY = 00000000-0000-0000-0000-000000000000".to_string(), // generic-role only
        "SESSION_ID = 50bcba48deadbeef".to_string(),
        "the quick brown fox jumps over the lazy dog".to_string(),
        "1234567890 !@#$%^&*() ????".to_string(),
        "ΩΨΔ 壱弐参 🔥".to_string(), // non-ASCII: probe must not panic and must agree
    ];
    for ctx in cases {
        assert_eq!(
            context_names_service(ctx.as_bytes()),
            oracle_contains_any(&ctx),
            "AC probe disagreed with the naive substring oracle on {ctx:?}"
        );
    }
}

#[test]
fn context_probe_is_case_insensitive_on_a_real_service_name() {
    let sample = service_vocabulary()
        .first()
        .expect("live service vocabulary is non-empty")
        .clone();
    assert!(context_names_service(sample.as_bytes()));
    assert!(context_names_service(sample.to_uppercase().as_bytes()));
}

// ─────────────────── live-vocabulary construction invariants ─────────────────

#[test]
fn live_vocabulary_holds_construction_invariants() {
    let vocab = service_vocabulary();
    assert!(!vocab.is_empty(), "embedded corpus must yield a vocabulary");
    for entry in vocab {
        assert_eq!(
            entry,
            &entry.to_ascii_lowercase(),
            "every vocabulary entry is lowercased: {entry:?}"
        );
        assert!(
            entry.len() >= MIN_SERVICE_KEYWORD_LEN,
            "every entry clears the length floor: {entry:?}"
        );
    }
    let mut sorted = vocab.to_vec();
    sorted.sort();
    assert_eq!(vocab, sorted.as_slice(), "live vocabulary is sorted");
    let deduped_len = {
        let mut d = sorted.clone();
        d.dedup();
        d.len()
    };
    assert_eq!(
        vocab.len(),
        deduped_len,
        "live vocabulary is duplicate-free"
    );
}

#[test]
fn live_vocabulary_excludes_generic_credential_role_words() {
    // Feature 42's entire purpose is to separate a SPECIFIC service name from a
    // GENERIC credential role word (feature 17 already covers the latter). If any
    // of these canonical role words, the ones the module doc names, leaked into
    // the service vocabulary, feature 42 would fire on every `API_KEY=<uuid>`
    // identifier and the split it exists to make would collapse.
    let vocab = service_vocabulary();
    for role_word in [
        "api_key",
        "apikey",
        "token",
        "secret",
        "password",
        "client_secret",
        "authorization",
        "bearer",
        "x-api-key",
        "access_token",
        "secret_key",
    ] {
        assert!(
            !vocab.iter().any(|v| v == role_word),
            "generic role word {role_word:?} must never be treated as a service name"
        );
    }
}

#[test]
fn live_vocabulary_is_deterministic_across_calls() {
    assert_eq!(service_vocabulary(), service_vocabulary());
}

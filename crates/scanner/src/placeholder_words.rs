//! Canonical placeholder-word vocabulary.
//!
//! The words live in the Tier-B `rules/placeholder_words.toml` file and are
//! parsed once here. Surface-form suppression, decoded-form suppression, and
//! doc-marker suppression all consume this module so the product has one
//! vocabulary instead of path-dependent copies.

use std::collections::BTreeSet;
use std::sync::LazyLock;

#[derive(Debug)]
pub(crate) struct PlaceholderWord {
    lower: String,
    upper: String,
}

impl PlaceholderWord {
    pub(crate) fn lower(&self) -> &str {
        &self.lower
    }

    pub(crate) fn upper(&self) -> &str {
        &self.upper
    }

    pub(crate) fn lower_bytes(&self) -> &[u8] {
        self.lower.as_bytes()
    }

    pub(crate) fn is_example(&self) -> bool {
        self.lower == "example"
    }
}

#[derive(serde::Deserialize)]
struct PlaceholderWordFile {
    placeholder_words: PlaceholderWordSection,
    /// Optional so hand-written test TOMLs carrying only `[placeholder_words]`
    /// still parse; the bundled file always provides it and the loader below
    /// fails closed if either marker list is empty.
    #[serde(default)]
    doc_markers: DocMarkerSection,
}

#[derive(serde::Deserialize)]
struct PlaceholderWordSection {
    words: Vec<String>,
}

#[derive(serde::Deserialize, Default)]
struct DocMarkerSection {
    #[serde(default)]
    instructional_fragments: Vec<String>,
    #[serde(default)]
    marker_substrings: Vec<String>,
}

/// All placeholder / doc-marker vocabularies parsed once from the Tier-B file.
/// `words` stay lowercase (matched case-insensitively via their `upper()` form);
/// the two marker lists are stored UPPERCASE here because the suppression
/// decision tree matches them against the already-uppercased credential.
#[derive(Debug)]
pub(crate) struct PlaceholderVocab {
    words: Vec<PlaceholderWord>,
    instructional_fragments: Vec<String>,
    marker_substrings: Vec<String>,
}

static VOCAB: LazyLock<PlaceholderVocab> = LazyLock::new(|| {
    match parse_vocab(include_str!("../../../rules/placeholder_words.toml")) {
        Ok(vocab) => {
            // Fail closed (Law 10): the bundled file MUST carry both marker
            // vocabularies. An empty list would silently disable a whole
            // suppression path with no operator-visible signal.
            assert!(
                !vocab.instructional_fragments.is_empty(),
                "rules/placeholder_words.toml [doc_markers].instructional_fragments is empty; \
                 refusing to run without instructional-fragment suppression truth"
            );
            assert!(
                !vocab.marker_substrings.is_empty(),
                "rules/placeholder_words.toml [doc_markers].marker_substrings is empty; \
                 refusing to run without doc-marker-substring suppression truth"
            );
            vocab
        }
        Err(error) => {
            panic!(
                "rules/placeholder_words.toml is invalid: {error}. Fix the bundled Tier-B \
                 placeholder vocabulary; refusing to run without placeholder suppression truth."
            )
        }
    }
});

pub(crate) fn words() -> &'static [PlaceholderWord] {
    &VOCAB.words
}

/// Leading-word-boundary instructional fragments (UPPERCASE), e.g. `YOUR_`,
/// `CHANGE`. Consumed by `suppression::doc_markers::check_markers`.
pub(crate) fn instructional_fragments() -> &'static [String] {
    &VOCAB.instructional_fragments
}

/// Plain-substring documentation markers (UPPERCASE), e.g. `EXAMPLE`,
/// `PLACEHOLDER`. Consumed by `suppression::doc_markers::check_markers`.
pub(crate) fn doc_marker_substrings() -> &'static [String] {
    &VOCAB.marker_substrings
}

pub(crate) fn example_word() -> Option<&'static PlaceholderWord> {
    words().iter().find(|word| word.is_example())
}

pub(crate) fn contains_placeholder_word(credential: &str) -> bool {
    contains_placeholder_word_with_entropy_hint(credential, None)
}

pub(crate) fn contains_placeholder_word_with_entropy_hint(
    credential: &str,
    entropy_hint: Option<f64>,
) -> bool {
    let upper = credential.to_ascii_uppercase();
    words()
        .iter()
        .any(|word| placeholder_word_suppresses(credential, &upper, word.upper(), entropy_hint))
}

pub(crate) fn contains_non_example_placeholder_word_with_entropy_hint(
    credential: &str,
    upper: &str,
    entropy_hint: Option<f64>,
) -> bool {
    words()
        .iter()
        .filter(|word| !word.is_example())
        .any(|word| placeholder_word_suppresses(credential, upper, word.upper(), entropy_hint))
}

pub(crate) fn bytes_contain_placeholder_word(bytes: &[u8]) -> bool {
    words()
        .iter()
        .any(|word| crate::ascii_ci::ci_find(bytes, word.lower_bytes()))
}

pub(crate) fn bytes_contain_entropy_placeholder_marker(bytes: &[u8]) -> bool {
    crate::ascii_ci::ci_find(bytes, b"your_")
        || crate::ascii_ci::ci_find(bytes, b"replace_me")
        || crate::ascii_ci::ci_find(bytes, b"change_me")
        || crate::ascii_ci::ci_find(bytes, b"insert_here")
        || crate::ascii_ci::ci_find(bytes, b"fake_")
        || crate::ascii_ci::ci_find(bytes, b"dummy_")
        || crate::ascii_ci::ci_find(bytes, b"mock_")
        || (crate::ascii_ci::ci_find(bytes, b"secret_key") && bytes.len() < 20)
        || (crate::ascii_ci::starts_with_ignore_ascii_case(bytes, b"AKIA")
            && (crate::ascii_ci::ends_with_ignore_ascii_case(bytes, b"EXAMPLE")
                || crate::ascii_ci::ci_find(bytes, b"1234567890")))
        || bytes.contains(&b'<')
        || bytes.contains(&b'>')
        || matches!(
            bytes,
            b"null" | b"none" | b"undefined" | b"empty" | b"default" | b"secret" | b"password"
        )
}

pub(crate) fn placeholder_word_suppresses(
    credential: &str,
    upper: &str,
    token: &str,
    entropy_hint: Option<f64>,
) -> bool {
    upper.match_indices(token).any(|(idx, _)| {
        let before = upper[..idx].chars().next_back();
        let after = upper[idx + token.len()..].chars().next();
        let left_boundary = before.is_none_or(|c| !c.is_alphanumeric());
        let right_boundary = after.is_none_or(|c| !c.is_alphanumeric());
        if !(left_boundary || right_boundary) {
            return false;
        }
        if left_boundary && right_boundary {
            return true;
        }
        !looks_like_high_entropy_marker_collision(credential, entropy_hint)
    })
}

fn looks_like_high_entropy_marker_collision(credential: &str, entropy_hint: Option<f64>) -> bool {
    // Shannon-entropy floor (bits per byte) at or above which a long, `+`/`/`
    // bearing credential is treated as a genuine high-entropy secret that merely
    // COLLIDES with a placeholder substring rather than an actual placeholder.
    // Below it, a one-sided placeholder-word match still suppresses.
    const HIGH_ENTROPY_MARKER_COLLISION_ENTROPY: f64 = 4.8;
    if credential.len() < 40 || !(credential.contains('+') || credential.contains('/')) {
        return false;
    }
    let entropy = match entropy_hint {
        Some(entropy) => entropy,
        None => crate::entropy::shannon_entropy(credential.as_bytes()),
    };
    entropy >= HIGH_ENTROPY_MARKER_COLLISION_ENTROPY
}

/// Back-compat wrapper: parse only the placeholder-word list. Kept so the
/// `parse_placeholder_words_for_test` facade and its callers (which pass
/// `[placeholder_words]`-only TOMLs) keep working unchanged (Law 3).
pub(crate) fn parse_placeholder_words(raw: &str) -> Result<Vec<PlaceholderWord>, String> {
    Ok(parse_vocab(raw)?.words)
}

/// Parse the full Tier-B file into every placeholder / doc-marker vocabulary in a
/// single pass. The `[doc_markers]` section is optional here (permissive for
/// partial test TOMLs); the bundled-file `VOCAB` loader separately fails closed on
/// an empty marker list.
pub(crate) fn parse_vocab(raw: &str) -> Result<PlaceholderVocab, String> {
    let parsed: PlaceholderWordFile =
        toml::from_str(raw).map_err(|error| format!("invalid placeholder_words.toml: {error}"))?;
    let mut seen = BTreeSet::new();
    let mut words = Vec::with_capacity(parsed.placeholder_words.words.len());

    for raw_word in parsed.placeholder_words.words {
        let word = raw_word.trim();
        if word.is_empty() {
            return Err("placeholder word entries must not be empty".to_string());
        }
        if word != word.to_ascii_lowercase() {
            return Err(format!("placeholder word {word:?} must be lowercase ASCII"));
        }
        if !word.bytes().all(|byte| byte.is_ascii_alphanumeric()) {
            return Err(format!(
                "placeholder word {word:?} must be ASCII alphanumeric"
            ));
        }
        if !seen.insert(word.to_string()) {
            return Err(format!("duplicate placeholder word {word:?}"));
        }
        words.push(PlaceholderWord {
            lower: word.to_string(),
            upper: word.to_ascii_uppercase(),
        });
    }

    if words.is_empty() {
        return Err("placeholder_words.words must contain at least one entry".to_string());
    }

    let instructional_fragments = validate_markers(
        parsed.doc_markers.instructional_fragments,
        "instructional_fragment",
    )?;
    let marker_substrings =
        validate_markers(parsed.doc_markers.marker_substrings, "marker_substring")?;

    Ok(PlaceholderVocab {
        words,
        instructional_fragments,
        marker_substrings,
    })
}

/// Validate one marker vocabulary and return it UPPERCASED for matching against
/// the uppercased credential. Markers are stored lowercase in the Tier-B file
/// (uniform with `words`) but, unlike words, may carry `_`/`-` separators. An
/// empty input list is allowed here (permissive for partial test TOMLs); the
/// bundled-file loader fails closed on an empty list.
fn validate_markers(raw: Vec<String>, kind: &str) -> Result<Vec<String>, String> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(raw.len());
    for raw_marker in raw {
        let marker = raw_marker.trim();
        if marker.is_empty() {
            return Err(format!("{kind} entries must not be empty"));
        }
        if marker != marker.to_ascii_lowercase() {
            return Err(format!(
                "{kind} {marker:?} must be lowercase in the Tier-B file (the loader uppercases it)"
            ));
        }
        if !marker
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-')
        {
            return Err(format!(
                "{kind} {marker:?} must be ASCII alphanumeric with optional '_'/'-' separators"
            ));
        }
        if !seen.insert(marker.to_string()) {
            return Err(format!("duplicate {kind} {marker:?}"));
        }
        out.push(marker.to_ascii_uppercase());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    // The exact UPPERCASE forms the scanner matched BEFORE the Tier-B move (the old
    // `INSTRUCTIONAL_FRAGMENTS` / `DOC_MARKER_SUBSTRINGS` consts in
    // `suppression/doc_markers.rs`). The loaded vocab must reproduce them
    // byte-for-byte — this is the zero-behavior-change parity proof.
    const LEGACY_INSTRUCTIONAL: &[&str] = &["YOUR_", "YOUR-", "INSERT", "CHANGE", "REPLACE"];
    const LEGACY_SUBSTRINGS: &[&str] = &[
        "EXAMPLE",
        "PLACEHOLDER",
        "NOT_A_REAL",
        "NOTAREAL",
        "INSERT_TOKEN_HERE",
        "INSERT-TOKEN-HERE",
        "CHANGE-ME",
        "CHANGEME",
        "REPLACE_ME",
        "REPLACEME",
        "REDACTED",
        "FAKE_KEY",
        "FAKEKEY",
        "TEST_KEY",
        "TESTKEY",
        "SAMPLE_KEY",
        "SAMPLEKEY",
    ];

    /// A valid TOML with the given `[doc_markers]` body appended to a minimal
    /// `[placeholder_words]` section.
    fn toml_with_markers(body: &str) -> String {
        format!("[placeholder_words]\nwords = [\"example\"]\n[doc_markers]\n{body}")
    }

    #[test]
    fn instructional_fragments_reproduce_the_legacy_const_exactly() {
        let loaded: Vec<&str> = instructional_fragments()
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(loaded.as_slice(), LEGACY_INSTRUCTIONAL);
    }

    #[test]
    fn marker_substrings_reproduce_the_legacy_const_exactly() {
        let loaded: Vec<&str> = doc_marker_substrings().iter().map(String::as_str).collect();
        assert_eq!(loaded.as_slice(), LEGACY_SUBSTRINGS);
    }

    #[test]
    fn instructional_fragments_are_nonempty() {
        assert!(!instructional_fragments().is_empty());
    }

    #[test]
    fn marker_substrings_are_nonempty() {
        assert!(!doc_marker_substrings().is_empty());
    }

    #[test]
    fn loaded_instructional_fragments_are_all_uppercase() {
        for frag in instructional_fragments() {
            assert_eq!(
                frag,
                &frag.to_ascii_uppercase(),
                "stored non-uppercase: {frag}"
            );
        }
    }

    #[test]
    fn loaded_marker_substrings_are_all_uppercase() {
        for marker in doc_marker_substrings() {
            assert_eq!(
                marker,
                &marker.to_ascii_uppercase(),
                "stored non-uppercase: {marker}"
            );
        }
    }

    #[test]
    fn no_duplicate_instructional_fragments() {
        let mut seen = BTreeSet::new();
        for frag in instructional_fragments() {
            assert!(seen.insert(frag), "duplicate fragment {frag}");
        }
    }

    #[test]
    fn no_duplicate_marker_substrings() {
        let mut seen = BTreeSet::new();
        for marker in doc_marker_substrings() {
            assert!(seen.insert(marker), "duplicate marker {marker}");
        }
    }

    #[test]
    fn bundled_markers_include_known_specimens() {
        let subs = doc_marker_substrings();
        for expected in [
            "EXAMPLE",
            "PLACEHOLDER",
            "TESTKEY",
            "NOT_A_REAL",
            "REDACTED",
        ] {
            assert!(subs.iter().any(|m| m == expected), "missing {expected}");
        }
        assert!(instructional_fragments().iter().any(|f| f == "YOUR_"));
    }

    #[test]
    fn parse_vocab_uppercases_lowercase_markers() {
        let vocab = parse_vocab(&toml_with_markers(
            "instructional_fragments = [\"your_\"]\nmarker_substrings = [\"not_a_real\"]\n",
        ))
        .expect("valid");
        assert_eq!(vocab.instructional_fragments, vec!["YOUR_".to_string()]);
        assert_eq!(vocab.marker_substrings, vec!["NOT_A_REAL".to_string()]);
    }

    #[test]
    fn parse_vocab_allows_underscore_and_hyphen_markers() {
        let vocab = parse_vocab(&toml_with_markers(
            "marker_substrings = [\"change-me\", \"test_key\"]\n",
        ))
        .expect("valid");
        assert_eq!(
            vocab.marker_substrings,
            vec!["CHANGE-ME".to_string(), "TEST_KEY".to_string()]
        );
    }

    #[test]
    fn parse_vocab_rejects_uppercase_marker_in_file() {
        let err =
            parse_vocab(&toml_with_markers("marker_substrings = [\"EXAMPLE\"]\n")).unwrap_err();
        assert!(err.contains("must be lowercase"), "got: {err}");
    }

    #[test]
    fn parse_vocab_rejects_empty_marker() {
        let err = parse_vocab(&toml_with_markers("marker_substrings = [\"\"]\n")).unwrap_err();
        assert!(err.contains("must not be empty"), "got: {err}");
    }

    #[test]
    fn parse_vocab_rejects_duplicate_marker() {
        let err = parse_vocab(&toml_with_markers(
            "marker_substrings = [\"example\", \"example\"]\n",
        ))
        .unwrap_err();
        assert!(err.contains("duplicate"), "got: {err}");
    }

    #[test]
    fn parse_vocab_rejects_marker_with_space() {
        let err =
            parse_vocab(&toml_with_markers("marker_substrings = [\"bad marker\"]\n")).unwrap_err();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn parse_vocab_rejects_non_ascii_marker() {
        let err =
            parse_vocab(&toml_with_markers("marker_substrings = [\"caf\u{e9}\"]\n")).unwrap_err();
        assert!(err.contains("alphanumeric"), "got: {err}");
    }

    #[test]
    fn parse_vocab_without_doc_markers_section_parses_with_empty_markers() {
        // Back-compat: a `[placeholder_words]`-only TOML (what confidence_penalties
        // passes) still parses; markers default empty (permissive parse — the
        // fail-closed non-empty check lives on the bundled-file VOCAB loader).
        let vocab = parse_vocab("[placeholder_words]\nwords = [\"example\"]\n").expect("valid");
        assert!(vocab.instructional_fragments.is_empty());
        assert!(vocab.marker_substrings.is_empty());
        assert_eq!(vocab.words.len(), 1);
    }

    #[test]
    fn parse_vocab_with_explicit_empty_marker_lists_parses() {
        let vocab = parse_vocab(&toml_with_markers(
            "instructional_fragments = []\nmarker_substrings = []\n",
        ))
        .expect("valid");
        assert!(vocab.instructional_fragments.is_empty());
        assert!(vocab.marker_substrings.is_empty());
    }

    #[test]
    fn parse_placeholder_words_wrapper_returns_only_words() {
        let words =
            parse_placeholder_words(&toml_with_markers("marker_substrings = [\"example\"]\n"))
                .expect("valid");
        assert!(words.iter().any(|w| w.lower() == "example"));
    }

    #[test]
    fn parse_vocab_preserves_word_validation_uppercase_rejected() {
        let err = parse_vocab("[placeholder_words]\nwords = [\"Example\"]\n").unwrap_err();
        assert!(err.contains("lowercase"), "got: {err}");
    }

    #[test]
    fn parse_vocab_preserves_word_validation_empty_list_rejected() {
        let err = parse_vocab("[placeholder_words]\nwords = []\n").unwrap_err();
        assert!(err.contains("at least one"), "got: {err}");
    }

    #[test]
    fn bundled_file_parses_and_matches_accessors() {
        // The real bundled file parses cleanly and a fresh parse equals the VOCAB
        // accessors — no drift between the cached static and the parser.
        let vocab = parse_vocab(include_str!("../../../rules/placeholder_words.toml"))
            .expect("bundled file valid");
        assert_eq!(
            vocab.instructional_fragments.as_slice(),
            instructional_fragments()
        );
        assert_eq!(vocab.marker_substrings.as_slice(), doc_marker_substrings());
    }

    #[test]
    fn validate_markers_is_order_preserving() {
        let vocab = parse_vocab(&toml_with_markers(
            "marker_substrings = [\"zebra\", \"alpha\", \"mid\"]\n",
        ))
        .expect("valid");
        assert_eq!(
            vocab.marker_substrings,
            vec!["ZEBRA".to_string(), "ALPHA".to_string(), "MID".to_string()]
        );
    }
}

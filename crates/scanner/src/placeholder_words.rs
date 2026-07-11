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
    /// Optional for the same reason as `doc_markers`; the bundled file always
    /// provides it and the loader fails closed on an empty list.
    #[serde(default)]
    entropy_markers: EntropyMarkerSection,
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

#[derive(serde::Deserialize, Default)]
struct EntropyMarkerSection {
    #[serde(default)]
    ci_substrings: Vec<String>,
    #[serde(default)]
    exact_values: Vec<String>,
}

/// All placeholder / doc-marker / entropy-marker vocabularies parsed once from the
/// Tier-B file. `words` stay lowercase (matched case-insensitively via their
/// `upper()` form); the doc-marker lists are stored UPPERCASE because the
/// suppression decision tree matches them against the already-uppercased
/// credential; the entropy-marker lists are stored lowercase (ci_substrings are
/// matched case-insensitively over raw bytes; exact_values are matched
/// case-sensitively as whole raw-byte values, so only the lowercase whole value
/// suppresses — the pinned current behavior).
#[derive(Debug)]
pub(crate) struct PlaceholderVocab {
    words: Vec<PlaceholderWord>,
    instructional_fragments: Vec<String>,
    marker_substrings: Vec<String>,
    entropy_ci_substrings: Vec<String>,
    entropy_exact_values: Vec<String>,
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
            assert!(
                !vocab.entropy_ci_substrings.is_empty(),
                "rules/placeholder_words.toml [entropy_markers].ci_substrings is empty; \
                 refusing to run without entropy-marker substring suppression truth"
            );
            assert!(
                !vocab.entropy_exact_values.is_empty(),
                "rules/placeholder_words.toml [entropy_markers].exact_values is empty; \
                 refusing to run without entropy-marker exact-value suppression truth"
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

/// Entropy-plausibility case-insensitive substring markers (lowercase), e.g.
/// `your_`, `mock_`. Matched via `ascii_ci` over raw bytes by
/// `bytes_contain_entropy_placeholder_marker`.
pub(crate) fn entropy_marker_ci_substrings() -> &'static [String] {
    &VOCAB.entropy_ci_substrings
}

/// Entropy-plausibility whole-value EXACT markers (lowercase), e.g. `null`,
/// `password`. Matched case-sensitively against the raw value bytes.
pub(crate) fn entropy_marker_exact_values() -> &'static [String] {
    &VOCAB.entropy_exact_values
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
    // Category 1: case-insensitive substring markers (Tier-B
    // `[entropy_markers].ci_substrings`).
    if entropy_marker_ci_substrings()
        .iter()
        .any(|marker| crate::ascii_ci::ci_find(bytes, marker.as_bytes()))
    {
        return true;
    }
    // Category 2: length-gated substring (bespoke rule, not a list — `secret_key`
    // counts as a decoy ONLY for short values; a long value merely containing it is
    // a real secret and must not be suppressed).
    if crate::ascii_ci::ci_find(bytes, b"secret_key") && bytes.len() < 20 {
        return true;
    }
    // Category 3: compound prefix+suffix (bespoke rule — an `AKIA…` shape whose body
    // ends `EXAMPLE` or carries the `1234567890` sequential filler is a docs decoy).
    if crate::ascii_ci::starts_with_ignore_ascii_case(bytes, b"AKIA")
        && (crate::ascii_ci::ends_with_ignore_ascii_case(bytes, b"EXAMPLE")
            || crate::ascii_ci::ci_find(bytes, b"1234567890"))
    {
        return true;
    }
    // Category 4: structural angle-bracket presence (bespoke rule — `<...>` marks a
    // fill-in-the-blank placeholder).
    if bytes.contains(&b'<') || bytes.contains(&b'>') {
        return true;
    }
    // Category 5: whole-value EXACT, case-sensitive (Tier-B
    // `[entropy_markers].exact_values`).
    entropy_marker_exact_values()
        .iter()
        .any(|marker| bytes == marker.as_bytes())
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
/// `[placeholder_words]`-only TOMLs) keep working unchanged (Law 3). Test-only:
/// production parses the full vocabulary through [`parse_vocab`].
#[cfg(test)]
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

    // Doc-markers are matched against the UPPERCASED credential, so uppercase them
    // at load; entropy-markers are matched over raw bytes (ci_substrings
    // case-insensitively, exact_values case-sensitively), so they stay lowercase.
    let instructional_fragments = validate_markers(
        parsed.doc_markers.instructional_fragments,
        "instructional_fragment",
    )?
    .into_iter()
    .map(|marker| marker.to_ascii_uppercase())
    .collect();
    let marker_substrings =
        validate_markers(parsed.doc_markers.marker_substrings, "marker_substring")?
            .into_iter()
            .map(|marker| marker.to_ascii_uppercase())
            .collect();
    let entropy_ci_substrings =
        validate_markers(parsed.entropy_markers.ci_substrings, "entropy ci_substring")?;
    let entropy_exact_values =
        validate_markers(parsed.entropy_markers.exact_values, "entropy exact_value")?;

    Ok(PlaceholderVocab {
        words,
        instructional_fragments,
        marker_substrings,
        entropy_ci_substrings,
        entropy_exact_values,
    })
}

/// Validate one marker vocabulary (lowercase-in-file, non-empty, ASCII with
/// optional `_`/`-` separators, no dups) and return the entries VERBATIM
/// (lowercase). Markers are stored lowercase in the Tier-B file (uniform with
/// `words`) but, unlike words, may carry `_`/`-` separators. Callers that match
/// against an uppercased credential map the result through `to_ascii_uppercase`;
/// callers matching raw bytes use it as-is. An empty input list is allowed here
/// (permissive for partial test TOMLs); the bundled-file loader fails closed on an
/// empty list.
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
                "{kind} {marker:?} must be lowercase in the Tier-B file"
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
        out.push(marker.to_string());
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

    // ── entropy_markers (bytes_contain_entropy_placeholder_marker) ──

    // The exact lowercase forms the old hardcoded `||` chain matched (categories 1
    // and 5 of `bytes_contain_entropy_placeholder_marker`). Categories 2/3/4
    // (secret_key length-gate, AKIA compound, angle brackets) are bespoke rules that
    // stay in code, not lists.
    const LEGACY_ENTROPY_CI: &[&str] = &[
        "your_",
        "replace_me",
        "change_me",
        "insert_here",
        "fake_",
        "dummy_",
        "mock_",
    ];
    const LEGACY_ENTROPY_EXACT: &[&str] = &[
        "null",
        "none",
        "undefined",
        "empty",
        "default",
        "secret",
        "password",
    ];

    fn toml_with_entropy(body: &str) -> String {
        format!("[placeholder_words]\nwords = [\"example\"]\n[entropy_markers]\n{body}")
    }

    #[test]
    fn entropy_ci_substrings_reproduce_legacy_exactly() {
        let loaded: Vec<&str> = entropy_marker_ci_substrings()
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(loaded.as_slice(), LEGACY_ENTROPY_CI);
    }

    #[test]
    fn entropy_exact_values_reproduce_legacy_exactly() {
        let loaded: Vec<&str> = entropy_marker_exact_values()
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(loaded.as_slice(), LEGACY_ENTROPY_EXACT);
    }

    #[test]
    fn entropy_ci_substrings_are_stored_lowercase() {
        // Unlike doc-markers (uppercased at load), entropy markers stay lowercase.
        for marker in entropy_marker_ci_substrings() {
            assert_eq!(
                marker,
                &marker.to_ascii_lowercase(),
                "not lowercase: {marker}"
            );
        }
    }

    #[test]
    fn entropy_exact_values_are_stored_lowercase() {
        for marker in entropy_marker_exact_values() {
            assert_eq!(
                marker,
                &marker.to_ascii_lowercase(),
                "not lowercase: {marker}"
            );
        }
    }

    #[test]
    fn entropy_marker_lists_are_nonempty() {
        assert!(!entropy_marker_ci_substrings().is_empty());
        assert!(!entropy_marker_exact_values().is_empty());
    }

    #[test]
    fn no_duplicate_entropy_markers() {
        let mut seen = BTreeSet::new();
        for marker in entropy_marker_ci_substrings() {
            assert!(seen.insert(marker), "dup ci marker {marker}");
        }
        let mut seen = BTreeSet::new();
        for marker in entropy_marker_exact_values() {
            assert!(seen.insert(marker), "dup exact marker {marker}");
        }
    }

    #[test]
    fn parse_vocab_keeps_entropy_markers_lowercase_not_uppercased() {
        let vocab = parse_vocab(&toml_with_entropy(
            "ci_substrings = [\"your_\"]\nexact_values = [\"null\"]\n",
        ))
        .expect("valid");
        assert_eq!(vocab.entropy_ci_substrings, vec!["your_".to_string()]);
        assert_eq!(vocab.entropy_exact_values, vec!["null".to_string()]);
    }

    #[test]
    fn parse_vocab_rejects_uppercase_entropy_marker() {
        let err = parse_vocab(&toml_with_entropy("ci_substrings = [\"YOUR_\"]\n")).unwrap_err();
        assert!(err.contains("must be lowercase"), "got: {err}");
    }

    #[test]
    fn parse_vocab_rejects_duplicate_entropy_marker() {
        let err =
            parse_vocab(&toml_with_entropy("exact_values = [\"null\", \"null\"]\n")).unwrap_err();
        assert!(err.contains("duplicate"), "got: {err}");
    }

    #[test]
    fn parse_vocab_without_entropy_section_parses_empty() {
        let vocab = parse_vocab("[placeholder_words]\nwords = [\"example\"]\n").expect("valid");
        assert!(vocab.entropy_ci_substrings.is_empty());
        assert!(vocab.entropy_exact_values.is_empty());
    }

    #[test]
    fn bundled_entropy_markers_match_accessors() {
        let vocab = parse_vocab(include_str!("../../../rules/placeholder_words.toml"))
            .expect("bundled file valid");
        assert_eq!(
            vocab.entropy_ci_substrings.as_slice(),
            entropy_marker_ci_substrings()
        );
        assert_eq!(
            vocab.entropy_exact_values.as_slice(),
            entropy_marker_exact_values()
        );
    }

    // Behavioral parity spot-checks (the full truth-table lives in
    // tests/unit/root_facade/entropy_placeholder_marker_truth_table.rs); these
    // confirm the Tier-B-backed fn preserves each category through this module.

    #[test]
    fn entropy_ci_substring_still_suppresses() {
        assert!(bytes_contain_entropy_placeholder_marker(b"YOUR_API_TOKEN"));
        assert!(bytes_contain_entropy_placeholder_marker(
            b"please_replace_me_now"
        ));
    }

    #[test]
    fn entropy_exact_value_suppresses_case_sensitively() {
        assert!(bytes_contain_entropy_placeholder_marker(b"null"));
        assert!(
            !bytes_contain_entropy_placeholder_marker(b"NULL"),
            "uppercase NULL is not the case-sensitive exact marker (pinned behavior)"
        );
        assert!(
            !bytes_contain_entropy_placeholder_marker(b"null_value"),
            "`null` as a substring is not the whole-value exact marker"
        );
    }

    #[test]
    fn entropy_secret_key_length_gate_preserved() {
        assert!(
            bytes_contain_entropy_placeholder_marker(b"secret_key"),
            "short secret_key is a decoy"
        );
        assert!(
            !bytes_contain_entropy_placeholder_marker(b"my_secret_key_padding_xx"),
            "secret_key at >= 20 bytes is past the length gate (recall boundary)"
        );
    }

    #[test]
    fn entropy_real_secret_not_suppressed() {
        assert!(!bytes_contain_entropy_placeholder_marker(
            b"aB3xK9mQ2pL7vR4nT8wZ"
        ));
        assert!(!bytes_contain_entropy_placeholder_marker(b""));
    }
}

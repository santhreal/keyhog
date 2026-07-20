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
/// suppresses (the pinned current behavior)).
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
    let upper_scratch = crate::ascii_ci::ascii_upper_scratch(credential);
    let upper = upper_scratch.as_str();
    words()
        .iter()
        .any(|word| placeholder_word_suppresses(credential, upper, word.upper(), entropy_hint))
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
    // Category 2: length-gated substring (bespoke rule, not a list. `secret_key`
    // counts as a decoy ONLY for short values; a long value merely containing it is
    // a real secret and must not be suppressed).
    if crate::ascii_ci::ci_find(bytes, b"secret_key") && bytes.len() < 20 {
        return true;
    }
    // Category 3: compound prefix+suffix (bespoke rule, an `AKIA…` shape whose body
    // ends `EXAMPLE` or carries the `1234567890` sequential filler is a docs decoy).
    if crate::ascii_ci::starts_with_ignore_ascii_case(bytes, b"AKIA")
        && (crate::ascii_ci::ends_with_ignore_ascii_case(bytes, b"EXAMPLE")
            || crate::ascii_ci::ci_find(bytes, b"1234567890"))
    {
        return true;
    }
    // Category 4: structural angle-bracket presence (bespoke rule. `<...>` marks a
    // fill-in-the-blank placeholder).
    if bytes.contains(&b'<') || bytes.contains(&b'>') {
        return true;
    }
    // Category 5: whole-value EXACT, case-sensitive (Tier-B
    // `[entropy_markers].exact_values`).
    is_exact_entropy_placeholder(bytes)
}

/// Whole-value EXACT, case-sensitive match against the Tier-B
/// `[entropy_markers].exact_values` (`null`/`none`/`undefined`/`empty`/`default`/
/// `secret`/`password`). A credential that *is* one of these words is a
/// placeholder on ANY detector path, so this is the ONE owner shared by the
/// entropy-marker check ([`bytes_contain_entropy_placeholder_marker`] Category 5)
/// and the named-detector suppression Tier-A gate, named/vendor detectors
/// otherwise bypass the entropy-path check and emit a bare `password` value.
pub(crate) fn is_exact_entropy_placeholder(bytes: &[u8]) -> bool {
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
/// `[placeholder_words]`-only TOMLs) keep working unchanged (Law 3). Test-only
/// production parses the full vocab via `parse_vocab`, so this is `#[cfg(test)]`
/// to stay dead-code-warning-clean in the lib build (its sole callers are the
/// `#[cfg(test)]` facade + the inline parse tests).
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
        if !keyhog_core::ascii_ci::is_ascii_alphanumeric_bytes(word.as_bytes()) {
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
#[path = "../tests/unit/placeholder_words.rs"]
mod tests;

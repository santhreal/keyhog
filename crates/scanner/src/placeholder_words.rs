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
}

#[derive(serde::Deserialize)]
struct PlaceholderWordSection {
    words: Vec<String>,
}

static PLACEHOLDER_WORDS: LazyLock<Vec<PlaceholderWord>> = LazyLock::new(|| {
    match parse_placeholder_words(include_str!("../../../rules/placeholder_words.toml")) {
        Ok(words) => words,
        Err(error) => {
            panic!(
                "rules/placeholder_words.toml is invalid: {error}. Fix the bundled Tier-B \
                 placeholder vocabulary; refusing to run without placeholder suppression truth."
            )
        }
    }
});

pub(crate) fn words() -> &'static [PlaceholderWord] {
    &PLACEHOLDER_WORDS
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
    let upper = String::from_utf8_lossy(bytes).to_uppercase();
    upper.contains("YOUR_")
        || upper.contains("REPLACE_ME")
        || upper.contains("CHANGE_ME")
        || upper.contains("INSERT_HERE")
        || upper.contains("FAKE_")
        || upper.contains("DUMMY_")
        || upper.contains("MOCK_")
        || (upper.contains("SECRET_KEY") && upper.len() < 20)
        || (upper.starts_with("AKIA")
            && (upper.ends_with("EXAMPLE") || upper.contains("1234567890")))
        || bytes.contains(&b'<')
        || bytes.contains(&b'>')
        || matches!(
            bytes,
            b"null" | b"none" | b"undefined" | b"empty" | b"default" | b"secret" | b"password"
        )
}

fn placeholder_word_suppresses(
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
    if credential.len() < 40 || !(credential.contains('+') || credential.contains('/')) {
        return false;
    }
    let entropy = match entropy_hint {
        Some(entropy) => entropy,
        None => crate::entropy::shannon_entropy(credential.as_bytes()),
    };
    entropy >= 4.8
}

pub(crate) fn parse_placeholder_words(raw: &str) -> Result<Vec<PlaceholderWord>, String> {
    let parsed: PlaceholderWordFile =
        toml::from_str(raw).map_err(|error| format!("invalid placeholder_words.toml: {error}"))?;
    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(parsed.placeholder_words.words.len());

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
        out.push(PlaceholderWord {
            lower: word.to_string(),
            upper: word.to_ascii_uppercase(),
        });
    }

    if out.is_empty() {
        return Err("placeholder_words.words must contain at least one entry".to_string());
    }
    Ok(out)
}

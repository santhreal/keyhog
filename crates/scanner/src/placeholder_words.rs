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
    #[cfg(any(feature = "ml", test))]
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
    bytes_contain_placeholder_word(credential.as_bytes())
}

pub(crate) fn bytes_contain_placeholder_word(bytes: &[u8]) -> bool {
    words()
        .iter()
        .any(|word| crate::ascii_ci::ci_find(bytes, word.lower_bytes()))
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

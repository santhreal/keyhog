//! Compiled detector-owned canonical and transport-decoded hex policy.
//!
//! Detector TOMLs own the policy. This module turns their flexible schema into
//! compact immutable programs once at scanner construction so candidate paths
//! never walk `DetectorSpec` vectors or normalize declared keywords repeatedly.

use keyhog_core::{CanonicalHexKeyMaterialSpec, DetectorSpec};

#[derive(Debug)]
struct CompiledCanonicalHexRule {
    lengths: Box<[usize]>,
    keywords: Box<[Box<[u8]>]>,
    suffixes: Box<[Box<[u8]>]>,
    excluded_keywords: Box<[Box<[u8]>]>,
}

impl CompiledCanonicalHexRule {
    fn compile(spec: &CanonicalHexKeyMaterialSpec) -> Self {
        Self {
            lengths: sorted_lengths(&spec.lengths),
            keywords: compact_keywords(&spec.keywords),
            suffixes: compact_keywords(&spec.suffixes),
            excluded_keywords: compact_keywords(&spec.excluded_keywords),
        }
    }

    #[inline]
    fn admits(&self, keyword: &str, value_len: usize) -> bool {
        self.lengths.binary_search(&value_len).is_ok()
            && !self
                .excluded_keywords
                .iter()
                .any(|excluded| compact_keyword_eq(keyword, excluded))
            && (self
                .keywords
                .iter()
                .any(|owned| compact_keyword_eq(keyword, owned))
                || self
                    .suffixes
                    .iter()
                    .any(|suffix| compact_keyword_ends_with(keyword, suffix)))
    }
}

/// Compact policy for one loaded detector.
#[derive(Debug)]
pub(crate) struct CompiledDetectorKeyMaterialPolicy {
    decoded_hex_lengths: Box<[usize]>,
    canonical_hex_rules: Box<[CompiledCanonicalHexRule]>,
}

impl CompiledDetectorKeyMaterialPolicy {
    pub(crate) fn compile(detector: &DetectorSpec) -> Self {
        Self {
            decoded_hex_lengths: sorted_lengths(&detector.decoded_hex_key_material_lengths),
            canonical_hex_rules: detector
                .canonical_hex_key_material
                .iter()
                .map(CompiledCanonicalHexRule::compile)
                .collect(),
        }
    }

    /// Whether this detector admits an exact assignment key and pure-hex value.
    #[inline]
    pub(crate) fn allows_canonical_hex(&self, keyword: &str, value: &str) -> bool {
        value.bytes().all(|byte| byte.is_ascii_hexdigit())
            && self
                .canonical_hex_rules
                .iter()
                .any(|rule| rule.admits(keyword, value.len()))
    }

    /// Whether this detector admits an already decoded pure-hex value.
    #[inline]
    pub(crate) fn allows_decoded_hex(&self, value: &str) -> bool {
        value.bytes().all(|byte| byte.is_ascii_hexdigit())
            && self.allows_decoded_hex_len(Some(value.len()))
    }

    /// Whether this detector admits a transport wrapper whose decoded payload
    /// is pure hex at the declared character count.
    #[inline]
    pub(crate) fn allows_decoded_hex_len(&self, decoded_len: Option<usize>) -> bool {
        decoded_len.is_some_and(|len| self.decoded_hex_lengths.binary_search(&len).is_ok())
    }

    /// Whether any canonical rule admits this already-proven pure-hex length.
    /// Named-regex processing no longer retains the assignment key, so this is
    /// the same length-only evidence that path historically consumed.
    #[inline]
    #[cfg(feature = "entropy")]
    pub(crate) fn allows_canonical_hex_len(&self, value_len: usize) -> bool {
        self.canonical_hex_rules
            .iter()
            .any(|rule| rule.lengths.binary_search(&value_len).is_ok())
    }
}

fn sorted_lengths(lengths: &[usize]) -> Box<[usize]> {
    let mut compiled = lengths.to_vec();
    compiled.sort_unstable();
    compiled.dedup();
    compiled.into_boxed_slice()
}

fn compact_keywords(keywords: &[String]) -> Box<[Box<[u8]>]> {
    keywords
        .iter()
        .map(|keyword| compact_keyword_bytes(keyword).collect())
        .collect()
}

#[inline]
fn compact_keyword_eq(keyword: &str, compiled: &[u8]) -> bool {
    compact_keyword_bytes(keyword).eq(compiled.iter().copied())
}

#[inline]
fn compact_keyword_ends_with(keyword: &str, suffix: &[u8]) -> bool {
    let keyword_len = compact_keyword_bytes(keyword).count();
    !suffix.is_empty()
        && keyword_len > suffix.len()
        && compact_keyword_bytes(keyword)
            .skip(keyword_len - suffix.len())
            .eq(suffix.iter().copied())
}

#[inline]
fn compact_keyword_bytes(keyword: &str) -> impl Iterator<Item = u8> + '_ {
    keyword
        .bytes()
        .filter(|byte| !matches!(byte, b'_' | b'-' | b'.'))
        .map(|byte| byte.to_ascii_lowercase())
}

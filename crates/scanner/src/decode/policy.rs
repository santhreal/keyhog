use aho_corasick::AhoCorasick;
use keyhog_core::DetectorSpec;
use std::collections::BTreeSet;
use std::sync::{Arc, LazyLock};

/// Active-corpus admission program for detector-owned evasion transforms.
#[derive(Debug)]
pub(crate) struct CompiledDecodeTransformPolicy {
    identity: u64,
    reverse_prefixes: Option<AhoCorasick>,
    caesar_plain_prefixes: Option<AhoCorasick>,
    caesar_rotated_prefixes: Option<AhoCorasick>,
}

impl CompiledDecodeTransformPolicy {
    pub(crate) fn compile(detectors: &[DetectorSpec]) -> Result<Self, String> {
        for detector in detectors {
            let issues = detector.decode_transforms.validate();
            if !issues.is_empty() {
                return Err(format!(
                    "detector {:?} has invalid decode_transforms: {}",
                    detector.id,
                    issues.join("; ")
                ));
            }
        }
        let reverse = detectors
            .iter()
            .flat_map(|detector| detector.decode_transforms.reverse_prefixes.iter());
        let caesar = detectors
            .iter()
            .flat_map(|detector| detector.decode_transforms.caesar_prefixes.iter());
        Self::compile_prefixes(reverse, caesar)
    }

    fn compile_prefixes<'a>(
        reverse: impl IntoIterator<Item = &'a String>,
        caesar: impl IntoIterator<Item = &'a String>,
    ) -> Result<Self, String> {
        let reverse = reverse
            .into_iter()
            .map(|prefix| super::reverse::reverse_str(prefix))
            .collect::<BTreeSet<_>>();
        let caesar = caesar
            .into_iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>();

        let identity = policy_identity(&reverse, &caesar);

        let reverse_prefixes = compile_automaton(reverse.iter().map(String::as_str), "reverse")?;
        let caesar_plain_prefixes = compile_automaton(caesar.iter().copied(), "Caesar plaintext")?;

        let mut rotated = Vec::with_capacity(caesar.len().saturating_mul(25));
        for prefix in caesar {
            for shift in 1..=25u8 {
                rotated.push(super::caesar::caesar_shift(
                    prefix,
                    super::caesar::ALPHABET_LEN - shift,
                ));
            }
        }
        let caesar_rotated_prefixes =
            compile_automaton(rotated.iter().map(String::as_str), "Caesar rotated")?;

        Ok(Self {
            identity,
            reverse_prefixes,
            caesar_plain_prefixes,
            caesar_rotated_prefixes,
        })
    }

    #[inline]
    pub(crate) const fn identity(&self) -> u64 {
        self.identity
    }

    #[inline]
    pub(crate) fn reverse_matches(&self, candidate: &str) -> bool {
        self.reverse_prefixes
            .as_ref()
            .is_some_and(|prefixes| prefixes.is_match(candidate))
    }

    #[inline]
    pub(crate) fn caesar_matches_plaintext(&self, candidate: &str) -> bool {
        self.caesar_plain_prefixes
            .as_ref()
            .is_some_and(|prefixes| has_token_boundary_match(prefixes, candidate))
    }

    pub(crate) fn matched_caesar_shifts(&self, candidate: &str) -> [bool; 26] {
        let mut shifts = [false; 26];
        let Some(prefixes) = &self.caesar_rotated_prefixes else {
            return shifts;
        };
        for matched in prefixes.find_overlapping_iter(candidate) {
            shifts[(matched.pattern().as_usize() % 25) + 1] = true;
        }
        shifts
    }
}

#[inline]
fn has_token_boundary_match(prefixes: &AhoCorasick, candidate: &str) -> bool {
    prefixes.find_overlapping_iter(candidate).any(|matched| {
        matched.start() == 0
            || !matches!(
                candidate.as_bytes()[matched.start() - 1],
                b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'_'
            )
    })
}

fn policy_identity(reverse: &BTreeSet<String>, caesar: &BTreeSet<&str>) -> u64 {
    let mut hasher = blake3::Hasher::new();
    for prefix in reverse {
        hasher.update(b"reverse\0");
        hasher.update(&(prefix.len() as u64).to_le_bytes());
        hasher.update(prefix.as_bytes());
    }
    for prefix in caesar {
        hasher.update(b"caesar\0");
        hasher.update(&(prefix.len() as u64).to_le_bytes());
        hasher.update(prefix.as_bytes());
    }
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&hasher.finalize().as_bytes()[..8]);
    u64::from_le_bytes(bytes)
}

fn compile_automaton<'a>(
    needles: impl IntoIterator<Item = &'a str>,
    label: &str,
) -> Result<Option<AhoCorasick>, String> {
    let needles = needles.into_iter().collect::<Vec<_>>();
    if needles.is_empty() {
        return Ok(None);
    }
    AhoCorasick::new(needles).map(Some).map_err(|error| {
        format!("could not compile detector-owned {label} prefix program: {error}")
    })
}

static BUNDLED_COMPAT_POLICY: LazyLock<Arc<CompiledDecodeTransformPolicy>> = LazyLock::new(|| {
    Arc::new(
        match CompiledDecodeTransformPolicy::compile_prefixes(
            crate::confidence::KNOWN_PREFIXES
                .iter()
                .filter(|prefix| prefix.len() >= 3),
            crate::confidence::KNOWN_PREFIXES.iter(),
        ) {
            Ok(policy) => policy,
            Err(error) => panic!("bundled decode transform test policy is invalid: {error}"),
        },
    )
});

/// Compatibility policy for standalone primitive APIs and direct tests.
/// Product scans execute the active corpus compiled by `CompiledScanner`.
pub(crate) fn bundled_compat_policy() -> &'static CompiledDecodeTransformPolicy {
    BUNDLED_COMPAT_POLICY.as_ref()
}

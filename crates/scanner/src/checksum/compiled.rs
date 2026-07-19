use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;

use super::{crc32, ChecksumConfidenceDecision, ChecksumResult};

thread_local! {
    /// Reused per worker thread so offline base64 validation does not allocate
    /// for every candidate. Bytes are overwritten before the buffer is cleared.
    static BASE64_SCRATCH: std::cell::RefCell<Vec<u8>> =
        std::cell::RefCell::new(Vec::with_capacity(128));
}

#[derive(Debug)]
enum CompiledValidatorKind {
    Crc32Base62 {
        entropy_len: usize,
        checksum_len: usize,
        reject_overlong: bool,
    },
    GithubFineGrainedCrc32 {
        left_len: usize,
        right_len: usize,
        checksum_len: usize,
    },
    Base64Payload {
        alphabet: keyhog_core::DetectorBase64Alphabet,
        min_encoded_len: usize,
        max_encoded_len: usize,
        min_decoded_len: usize,
    },
    PatternShape {
        full: regex::RegexSet,
        prefix: regex::RegexSet,
        allow_overlong: bool,
    },
}

#[derive(Debug)]
struct CompiledValidator {
    prefixes: Box<[Box<str>]>,
    kind: CompiledValidatorKind,
    confidence_floor: Option<f64>,
}

impl CompiledValidator {
    fn compile(
        detector: &keyhog_core::DetectorSpec,
        spec: &keyhog_core::DetectorValidatorSpec,
    ) -> Result<Self, String> {
        let prefixes = spec
            .prefixes()
            .iter()
            .map(|prefix| prefix.clone().into_boxed_str())
            .collect();
        let kind = match spec {
            keyhog_core::DetectorValidatorSpec::Crc32Base62 {
                entropy_len,
                checksum_len,
                reject_overlong,
                ..
            } => CompiledValidatorKind::Crc32Base62 {
                entropy_len: *entropy_len,
                checksum_len: *checksum_len,
                reject_overlong: *reject_overlong,
            },
            keyhog_core::DetectorValidatorSpec::GithubFineGrainedCrc32 {
                left_len,
                right_len,
                checksum_len,
                ..
            } => CompiledValidatorKind::GithubFineGrainedCrc32 {
                left_len: *left_len,
                right_len: *right_len,
                checksum_len: *checksum_len,
            },
            keyhog_core::DetectorValidatorSpec::Base64Payload {
                alphabet,
                min_encoded_len,
                max_encoded_len,
                min_decoded_len,
                ..
            } => CompiledValidatorKind::Base64Payload {
                alphabet: *alphabet,
                min_encoded_len: *min_encoded_len,
                max_encoded_len: *max_encoded_len,
                min_decoded_len: *min_decoded_len,
            },
            keyhog_core::DetectorValidatorSpec::PatternShape { allow_overlong, .. } => {
                let patterns: Vec<_> = detector
                    .patterns
                    .iter()
                    .filter(|pattern| pattern.group.is_none() || pattern.group == Some(0))
                    .map(|pattern| pattern.regex.as_str())
                    .collect();
                let full =
                    regex::RegexSet::new(patterns.iter().map(|pattern| format!("^(?:{pattern})$")))
                        .map_err(|error| {
                            format!(
                                "detector {:?} pattern-shape validator failed to compile: {error}",
                                detector.id
                            )
                        })?;
                let prefix =
                    regex::RegexSet::new(patterns.iter().map(|pattern| format!("^(?:{pattern})")))
                        .map_err(|error| {
                            format!(
                        "detector {:?} pattern-shape prefix validator failed to compile: {error}",
                        detector.id
                    )
                        })?;
                CompiledValidatorKind::PatternShape {
                    full,
                    prefix,
                    allow_overlong: *allow_overlong,
                }
            }
        };
        Ok(Self {
            prefixes,
            kind,
            confidence_floor: spec.confidence_floor(),
        })
    }

    #[inline]
    fn claims(&self, credential: &str) -> bool {
        self.prefixes
            .iter()
            .any(|prefix| credential.starts_with(prefix.as_ref()))
    }

    #[inline]
    fn matched_prefix_len(&self, credential: &str) -> Option<usize> {
        self.prefixes
            .iter()
            .find(|prefix| credential.starts_with(prefix.as_ref()))
            .map(|prefix| prefix.len())
    }

    fn validate(&self, credential: &str, pattern_proven: bool) -> ChecksumConfidenceDecision {
        let Some(prefix_len) = self.matched_prefix_len(credential) else {
            return ChecksumConfidenceDecision::not_applicable();
        };
        let payload = &credential[prefix_len..];
        let result = match &self.kind {
            CompiledValidatorKind::Crc32Base62 {
                entropy_len,
                checksum_len,
                reject_overlong,
            } => validate_crc32_base62(payload, *entropy_len, *checksum_len, *reject_overlong),
            CompiledValidatorKind::GithubFineGrainedCrc32 {
                left_len,
                right_len,
                checksum_len,
            } => validate_github_fine_grained(payload, *left_len, *right_len, *checksum_len),
            CompiledValidatorKind::Base64Payload {
                alphabet,
                min_encoded_len,
                max_encoded_len,
                min_decoded_len,
            } => validate_base64_payload(
                payload,
                *alphabet,
                *min_encoded_len,
                *max_encoded_len,
                *min_decoded_len,
            ),
            CompiledValidatorKind::PatternShape {
                full,
                prefix,
                allow_overlong,
            } => {
                if pattern_proven || full.is_match(credential) {
                    ChecksumResult::StructurallyValid
                } else if *allow_overlong
                    && prefix.is_match(credential)
                    && credential.bytes().all(is_provider_token_byte)
                {
                    // A complete detector-shaped prefix followed by more token
                    // bytes may be a newer provider format. Do not certify it,
                    // but do not label it fabricated either.
                    ChecksumResult::NotApplicable
                } else {
                    ChecksumResult::Invalid
                }
            }
        };
        ChecksumConfidenceDecision::new(result, self.confidence_floor)
    }
}

#[inline]
fn is_provider_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.')
}

#[derive(Debug, Default)]
pub(crate) struct CompiledDetectorValidators {
    validators: Box<[CompiledValidator]>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ValidatorRef {
    owner_index: usize,
    validator_index: usize,
}

/// First-byte index shared by the active detector plan and the embedded
/// compatibility catalog. It owns both candidate narrowing and result
/// precedence so validator lookup cannot drift between those surfaces.
#[derive(Debug)]
pub(crate) struct CompiledValidatorIndex {
    refs: Box<[ValidatorRef]>,
    ref_offsets: [usize; 257],
}

impl CompiledValidatorIndex {
    pub(crate) fn compile<'a>(
        validator_sets: impl IntoIterator<Item = &'a CompiledDetectorValidators>,
    ) -> Self {
        let mut refs: [Vec<ValidatorRef>; 256] = std::array::from_fn(|_| Vec::new());
        for (owner_index, set) in validator_sets.into_iter().enumerate() {
            for (validator_index, prefix) in set.indexed_prefixes() {
                let Some(first) = prefix.as_bytes().first().copied() else {
                    continue;
                };
                let validator_ref = ValidatorRef {
                    owner_index,
                    validator_index,
                };
                if !refs[first as usize].contains(&validator_ref) {
                    refs[first as usize].push(validator_ref);
                }
            }
        }
        let mut flat_refs = Vec::new();
        let mut ref_offsets = [0usize; 257];
        for (first, bucket) in refs.into_iter().enumerate() {
            ref_offsets[first] = flat_refs.len();
            flat_refs.extend(bucket);
        }
        ref_offsets[256] = flat_refs.len();
        Self {
            refs: flat_refs.into_boxed_slice(),
            ref_offsets,
        }
    }

    pub(crate) fn validate_any(
        &self,
        credential: &str,
        mut validate_indexed: impl FnMut(usize, usize, &str) -> ChecksumConfidenceDecision,
    ) -> ChecksumConfidenceDecision {
        let Some(first) = credential.as_bytes().first().copied() else {
            return ChecksumConfidenceDecision::not_applicable();
        };
        let mut invalid = None;
        let mut unknown = None;
        let mut structural = None;
        let first = first as usize;
        for validator_ref in &self.refs[self.ref_offsets[first]..self.ref_offsets[first + 1]] {
            let decision = validate_indexed(
                validator_ref.owner_index,
                validator_ref.validator_index,
                credential,
            );
            match decision.result() {
                ChecksumResult::Valid => return decision,
                ChecksumResult::StructurallyValid => structural = Some(decision),
                ChecksumResult::Invalid => invalid = Some(decision),
                ChecksumResult::NotApplicable if decision.claims_family() => {
                    unknown = Some(decision)
                }
                ChecksumResult::NotApplicable => {}
            }
        }
        structural
            .or(unknown)
            .or(invalid)
            .unwrap_or_else(ChecksumConfidenceDecision::not_applicable)
    }
}

#[derive(Debug)]
pub(crate) struct CompiledValidatorCatalog {
    detector_ids: Box<[Box<str>]>,
    validators: Box<[CompiledDetectorValidators]>,
    index: CompiledValidatorIndex,
}

impl CompiledValidatorCatalog {
    pub(crate) fn compile(detectors: &[keyhog_core::DetectorSpec]) -> Result<Self, String> {
        let validators: Box<[_]> = detectors
            .iter()
            .map(CompiledDetectorValidators::compile)
            .collect::<Result<_, _>>()?;
        let index = CompiledValidatorIndex::compile(validators.iter());
        Ok(Self {
            detector_ids: detectors
                .iter()
                .map(|detector| detector.id.clone().into_boxed_str())
                .collect(),
            validators,
            index,
        })
    }

    pub(crate) fn validate_any(&self, credential: &str) -> ChecksumConfidenceDecision {
        self.index
            .validate_any(credential, |detector_index, validator_index, candidate| {
                self.validators[detector_index].validate_indexed(validator_index, candidate)
            })
    }

    pub(crate) fn validate_for_detector(
        &self,
        detector_id: &str,
        credential: &str,
    ) -> ChecksumConfidenceDecision {
        self.detector_ids
            .iter()
            .position(|candidate| candidate.as_ref() == detector_id)
            .map(|index| self.validators[index].validate(credential, false))
            .unwrap_or_else(ChecksumConfidenceDecision::not_applicable)
    }

    pub(crate) fn prefixes(&self) -> Vec<&str> {
        self.validators
            .iter()
            .flat_map(CompiledDetectorValidators::indexed_prefixes)
            .map(|(_, prefix)| prefix)
            .collect()
    }
}

impl CompiledDetectorValidators {
    pub(crate) fn compile(detector: &keyhog_core::DetectorSpec) -> Result<Self, String> {
        Ok(Self {
            validators: detector
                .validators
                .iter()
                .map(|validator| CompiledValidator::compile(detector, validator))
                .collect::<Result<Box<[_]>, _>>()?,
        })
    }

    #[inline]
    pub(crate) fn validate(
        &self,
        credential: &str,
        pattern_proven: bool,
    ) -> ChecksumConfidenceDecision {
        for validator in &self.validators {
            if validator.claims(credential) {
                return validator.validate(credential, pattern_proven);
            }
        }
        ChecksumConfidenceDecision::not_applicable()
    }

    pub(crate) fn indexed_prefixes(&self) -> impl Iterator<Item = (usize, &str)> {
        self.validators
            .iter()
            .enumerate()
            .flat_map(|(index, validator)| {
                validator
                    .prefixes
                    .iter()
                    .map(move |prefix| (index, prefix.as_ref()))
            })
    }

    #[inline]
    pub(crate) fn validate_indexed(
        &self,
        validator_index: usize,
        credential: &str,
    ) -> ChecksumConfidenceDecision {
        self.validators[validator_index].validate(credential, false)
    }
}

fn validate_crc32_base62(
    payload: &str,
    entropy_len: usize,
    checksum_len: usize,
    reject_overlong: bool,
) -> ChecksumResult {
    let body_len = entropy_len.saturating_add(checksum_len);
    if payload.len() != body_len {
        return if reject_overlong && payload.len() > body_len {
            ChecksumResult::Invalid
        } else {
            ChecksumResult::NotApplicable
        };
    }
    if !keyhog_core::ascii_ci::is_ascii_alphanumeric_str(payload) {
        return ChecksumResult::Invalid;
    }
    let entropy = &payload.as_bytes()[..entropy_len];
    let checksum = &payload.as_bytes()[entropy_len..];
    if base62_u32_matches(crc32(entropy), checksum) {
        ChecksumResult::Valid
    } else {
        ChecksumResult::Invalid
    }
}

fn validate_github_fine_grained(
    payload: &str,
    left_len: usize,
    right_len: usize,
    checksum_len: usize,
) -> ChecksumResult {
    let Some((left, right)) = payload.split_once('_') else {
        return ChecksumResult::Invalid;
    };
    if right.contains('_') || left.len() != left_len || right.len() != right_len {
        return ChecksumResult::Invalid;
    }
    if !keyhog_core::ascii_ci::is_ascii_alphanumeric_str(left)
        || !keyhog_core::ascii_ci::is_ascii_alphanumeric_str(right)
    {
        return ChecksumResult::Invalid;
    }
    if crc_suffix_matches(payload.as_bytes(), checksum_len)
        || crc_suffix_matches(right.as_bytes(), checksum_len)
    {
        ChecksumResult::Valid
    } else {
        ChecksumResult::Invalid
    }
}

#[inline]
fn crc_suffix_matches(payload: &[u8], checksum_len: usize) -> bool {
    if payload.len() <= checksum_len {
        return false;
    }
    let split = payload.len() - checksum_len;
    base62_u32_matches(crc32(&payload[..split]), &payload[split..])
}

fn validate_base64_payload(
    payload: &str,
    alphabet: keyhog_core::DetectorBase64Alphabet,
    min_encoded_len: usize,
    max_encoded_len: usize,
    min_decoded_len: usize,
) -> ChecksumResult {
    if payload.len() < min_encoded_len || payload.len() > max_encoded_len {
        return ChecksumResult::Invalid;
    }
    let decoded_len = BASE64_SCRATCH.with_borrow_mut(|scratch| {
        scratch.clear();
        let result = match alphabet {
            keyhog_core::DetectorBase64Alphabet::Standard => STANDARD.decode_vec(payload, scratch),
            keyhog_core::DetectorBase64Alphabet::StandardNoPad => {
                STANDARD_NO_PAD.decode_vec(payload, scratch)
            }
            keyhog_core::DetectorBase64Alphabet::UrlSafe => URL_SAFE.decode_vec(payload, scratch),
            keyhog_core::DetectorBase64Alphabet::UrlSafeNoPad => {
                URL_SAFE_NO_PAD.decode_vec(payload, scratch)
            }
        };
        let decoded_len = result.map(|_| scratch.len());
        scratch.fill(0);
        scratch.clear();
        decoded_len
    });
    match decoded_len {
        Ok(decoded_len) if decoded_len >= min_decoded_len => ChecksumResult::Valid,
        Ok(_) | Err(_) => ChecksumResult::Invalid,
    }
}

#[inline]
fn base62_u32_matches(mut value: u32, encoded: &[u8]) -> bool {
    for &actual in encoded.iter().rev() {
        let expected = super::BASE62_DIGITS[(value % 62) as usize];
        if actual != expected {
            return false;
        }
        value /= 62;
    }
    value == 0
}

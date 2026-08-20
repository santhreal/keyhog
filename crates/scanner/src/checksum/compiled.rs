use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};
use base64::Engine as _;
use std::sync::{Arc, OnceLock};

use super::{crc32, ChecksumConfidenceDecision, ChecksumResult};

thread_local! {
    /// Reused per worker thread so offline base64 validation does not allocate
    /// for every candidate. Bytes are overwritten before the buffer is cleared.
    static BASE64_SCRATCH: std::cell::RefCell<Vec<u8>> =
        const { std::cell::RefCell::new(Vec::new()) };
}

#[derive(Debug)]
struct LazyPatternShape {
    detector_id: Arc<str>,
    patterns: Box<[Arc<str>]>,
    full: OnceLock<regex::RegexSet>,
    prefix: OnceLock<regex::RegexSet>,
}

impl LazyPatternShape {
    fn new(detector_id: &str, patterns: &[keyhog_core::PatternSpec]) -> Self {
        Self {
            detector_id: Arc::from(detector_id),
            patterns: patterns
                .iter()
                .filter(|pattern| pattern.group.is_none() || pattern.group == Some(0))
                .map(|pattern| Arc::from(pattern.regex.as_str()))
                .collect(),
            full: OnceLock::new(),
            prefix: OnceLock::new(),
        }
    }

    fn full(&self) -> &regex::RegexSet {
        self.full.get_or_init(|| self.compile(true))
    }

    fn prefix(&self) -> &regex::RegexSet {
        self.prefix.get_or_init(|| self.compile(false))
    }

    fn compile(&self, full: bool) -> regex::RegexSet {
        regex::RegexSet::new(self.patterns.iter().map(|pattern| {
            if full {
                format!("^(?:{pattern})$")
            } else {
                format!("^(?:{pattern})")
            }
        }))
        // LAW10: invalid built-in validator regexes terminate with a loud build-invariant panic.
        .unwrap_or_else(|error| {
            panic!(
                "BUILD-INVARIANT VIOLATION: detector {:?} pattern-shape validator failed to compile: {error}",
                self.detector_id
            )
        })
    }
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
        validator: LazyPatternShape,
        allow_overlong: bool,
    },
    Jwt {
        reject_alg_none: bool,
    },
    Uuid,
    HexHash {
        expected_len: usize,
        lowercase_only: bool,
    },
    LuhnChecksum {
        min_len: usize,
        max_len: usize,
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
        detector_id: &str,
        patterns: &[keyhog_core::PatternSpec],
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
                CompiledValidatorKind::PatternShape {
                    validator: LazyPatternShape::new(detector_id, patterns),
                    allow_overlong: *allow_overlong,
                }
            }
            keyhog_core::DetectorValidatorSpec::Jwt {
                reject_alg_none, ..
            } => CompiledValidatorKind::Jwt {
                reject_alg_none: *reject_alg_none,
            },
            keyhog_core::DetectorValidatorSpec::Uuid { .. } => CompiledValidatorKind::Uuid,
            keyhog_core::DetectorValidatorSpec::HexHash {
                expected_len,
                lowercase_only,
                ..
            } => CompiledValidatorKind::HexHash {
                expected_len: *expected_len,
                lowercase_only: *lowercase_only,
            },
            keyhog_core::DetectorValidatorSpec::LuhnChecksum {
                min_len, max_len, ..
            } => CompiledValidatorKind::LuhnChecksum {
                min_len: *min_len,
                max_len: *max_len,
            },
        };
        Ok(Self {
            prefixes,
            kind,
            confidence_floor: spec.confidence_floor(),
        })
    }

    #[inline]
    fn claims(&self, credential: &str) -> bool {
        if self.prefixes.is_empty() {
            true
        } else {
            self.prefixes
                .iter()
                .any(|prefix| credential.starts_with(prefix.as_ref()))
        }
    }

    #[inline]
    fn matched_prefix_len(&self, credential: &str) -> Option<usize> {
        if self.prefixes.is_empty() {
            Some(0)
        } else {
            self.prefixes
                .iter()
                .find(|prefix| credential.starts_with(prefix.as_ref()))
                .map(|prefix| prefix.len())
        }
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
                validator,
                allow_overlong,
            } => {
                if pattern_proven || validator.full().is_match(credential) {
                    ChecksumResult::StructurallyValid
                } else if *allow_overlong
                    && validator.prefix().is_match(credential)
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
            CompiledValidatorKind::Jwt { reject_alg_none } => {
                let jwt_candidate = if payload.starts_with(crate::jwt::JWT_BASE64_HEADER_PREFIX) {
                    payload
                } else {
                    credential
                };
                validate_jwt(jwt_candidate, *reject_alg_none)
            }
            CompiledValidatorKind::Uuid => validate_uuid(payload),
            CompiledValidatorKind::HexHash {
                expected_len,
                lowercase_only,
            } => validate_hex_hash(payload, *expected_len, *lowercase_only),
            CompiledValidatorKind::LuhnChecksum { min_len, max_len } => {
                validate_luhn(payload, *min_len, *max_len)
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
pub struct CompiledDetectorValidators {
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
        keyhog_profile::record_compile_surface_invocation(
            keyhog_profile::CompileSurfaceId::ValidatorCatalog,
        );
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
            // LAW10: recall-preserving; no applicable validator is an explicit policy outcome, and callers preserve the finding without a checksum adjustment.
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
        keyhog_profile::record_compile_surface_invocation(
            keyhog_profile::CompileSurfaceId::ValidatorCatalog,
        );
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
            // LAW10: recall-preserving; no validator mapped to this pattern is an explicit detector-plan outcome, not a runtime validation failure.
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
    pub fn compile(detector: &keyhog_core::DetectorSpec) -> Result<Self, String> {
        keyhog_profile::record_compile_surface_invocation(
            keyhog_profile::CompileSurfaceId::ValidatorCatalog,
        );
        Self::hydrate_parts(&detector.id, &detector.patterns, &detector.validators)
    }

    pub(crate) fn hydrate(
        detector: &crate::execution_pack::detector_plan::DetectorPlanRecord,
    ) -> Result<Self, String> {
        keyhog_profile::record_compile_surface_load(
            keyhog_profile::CompileSurfaceId::ValidatorCatalog,
        );
        Self::hydrate_parts(&detector.id, &detector.patterns, &detector.validators)
    }

    fn hydrate_parts(
        detector_id: &str,
        patterns: &[keyhog_core::PatternSpec],
        validators: &[keyhog_core::DetectorValidatorSpec],
    ) -> Result<Self, String> {
        Ok(Self {
            validators: validators
                .iter()
                .map(|validator| CompiledValidator::compile(detector_id, patterns, validator))
                .collect::<Result<Box<[_]>, _>>()?,
        })
    }

    #[inline]
    pub fn validate(&self, credential: &str, pattern_proven: bool) -> ChecksumConfidenceDecision {
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
        if scratch.capacity() > crate::types::MAX_SCAN_CHUNK_BYTES {
            *scratch = Vec::new();
        }
        decoded_len
    });
    match decoded_len {
        Ok(decoded_len) if decoded_len >= min_decoded_len => ChecksumResult::Valid,
        // LAW10: malformed or undersized decoded payloads fail closed as `Invalid`; no finding is accepted through another validator.
        Ok(_) | Err(_) => ChecksumResult::Invalid,
    }
}

#[cfg(test)]
pub(crate) fn base64_scratch_capacity_after_payload_for_test(payload: &str) -> usize {
    // LAW10: the test helper intentionally discards the validation verdict and inspects zeroized scratch capacity.
    let _ = validate_base64_payload(
        payload,
        keyhog_core::DetectorBase64Alphabet::Standard,
        0,
        usize::MAX,
        0,
    );
    BASE64_SCRATCH.with_borrow(Vec::capacity)
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
fn validate_jwt(candidate: &str, reject_alg_none: bool) -> ChecksumResult {
    let Some(analysis) = crate::jwt::analyze(candidate) else {
        return ChecksumResult::Invalid;
    };
    if reject_alg_none && analysis.alg.eq_ignore_ascii_case("none") {
        return ChecksumResult::Invalid;
    }
    ChecksumResult::Valid
}

fn validate_uuid(payload: &str) -> ChecksumResult {
    let bytes = payload.as_bytes();
    if bytes.len() != 36 {
        return ChecksumResult::Invalid;
    }
    if bytes[8] != b'-' || bytes[13] != b'-' || bytes[18] != b'-' || bytes[23] != b'-' {
        return ChecksumResult::Invalid;
    }
    let is_hex = |b: u8| b.is_ascii_hexdigit();
    let is_slice_hex = |slice: &[u8]| slice.iter().copied().all(is_hex);
    if is_slice_hex(&bytes[0..8])
        && is_slice_hex(&bytes[9..13])
        && is_slice_hex(&bytes[14..18])
        && is_slice_hex(&bytes[19..23])
        && is_slice_hex(&bytes[24..36])
    {
        ChecksumResult::Valid
    } else {
        ChecksumResult::Invalid
    }
}

fn validate_hex_hash(payload: &str, expected_len: usize, lowercase_only: bool) -> ChecksumResult {
    let bytes = payload.as_bytes();
    if bytes.len() != expected_len {
        return ChecksumResult::Invalid;
    }
    let valid = if lowercase_only {
        bytes
            .iter()
            .all(|&b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    } else {
        bytes.iter().all(|&b| b.is_ascii_hexdigit())
    };
    if valid {
        ChecksumResult::Valid
    } else {
        ChecksumResult::Invalid
    }
}

fn validate_luhn(payload: &str, min_len: usize, max_len: usize) -> ChecksumResult {
    let bytes = payload.as_bytes();
    if bytes.len() < min_len || bytes.len() > max_len {
        return ChecksumResult::Invalid;
    }
    if !bytes.iter().all(|&b| b.is_ascii_digit()) {
        return ChecksumResult::Invalid;
    }
    let mut sum = 0u32;
    let mut alternate = false;
    for &b in bytes.iter().rev() {
        let mut d = (b - b'0') as u32;
        if alternate {
            d *= 2;
            if d > 9 {
                d -= 9;
            }
        }
        sum += d;
        alternate = !alternate;
    }
    if sum % 10 == 0 {
        ChecksumResult::Valid
    } else {
        ChecksumResult::Invalid
    }
}

use super::{CanonicalDetectorExecutionIr, ExecutionPackBackend, ExecutionPackError};
use crate::compiler::compiler_build::{
    build_compile_state, build_compile_state_invocations, CompileState, CompiledLocalizationHints,
};
use crate::compiler::compiler_compile::compile_companion;
use crate::types::{CompiledPattern, LazyRegex};
use keyhog_core::{
    CompanionSpec, EvidenceDirection, EvidenceRequirement, EvidenceScope, EvidenceValueRelation,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const ROUTE_MATCHER_SECTION_VERSION: u16 = 6;
std::thread_local! {
    static RUNTIME_LOCALIZATION_HINT_FALLBACKS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
std::thread_local! {
    static RUNTIME_CANONICAL_REENCODES: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}
std::thread_local! {
    static RUNTIME_COMPANION_VALIDATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[doc(hidden)]
pub fn runtime_localization_hint_fallbacks() -> usize {
    RUNTIME_LOCALIZATION_HINT_FALLBACKS.get()
}

pub(crate) fn record_runtime_localization_hint_fallback() {
    RUNTIME_LOCALIZATION_HINT_FALLBACKS
        .set(RUNTIME_LOCALIZATION_HINT_FALLBACKS.get().saturating_add(1));
}

#[doc(hidden)]
pub fn runtime_canonical_reencodes() -> usize {
    RUNTIME_CANONICAL_REENCODES.get()
}

#[doc(hidden)]
pub fn runtime_companion_validations() -> usize {
    RUNTIME_COMPANION_VALIDATIONS.get()
}
#[doc(hidden)]
pub fn compile_state_builder_invocations() -> usize {
    build_compile_state_invocations()
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompiledRouteMatcherSections {
    pub backend: ExecutionPackBackend,
    pub literal_index: Vec<u8>,
    pub regex_programs: Vec<u8>,
    pub suppression_policy: Vec<u8>,
}

#[derive(Deserialize, Serialize)]
struct LiteralEnvelope {
    version: u16,
    backend: String,
    detector_ir_digest: [u8; 32],
    detector_count: u32,
    ac_literals: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct RegexEnvelope {
    version: u16,
    backend: String,
    detector_ir_digest: [u8; 32],
    detector_count: u32,
    ac_patterns: Vec<PackedPattern>,
    phase2_patterns: Vec<PackedPhase2Pattern>,
    companions: Vec<Vec<PackedCompanion>>,
    quality_warnings: Vec<String>,
    localization_hints: CompiledLocalizationHints,
}

#[derive(Deserialize, Serialize)]
struct PackedPattern {
    detector_index: u32,
    pattern_index: u32,
    regex: String,
    case_insensitive: bool,
    group: Option<u32>,
    client_safe: bool,
    weak_anchor: bool,
    structural_password_slot: bool,
    match_proves_keyword_nearby: bool,
    allows_repeated_keyword_separator: bool,
    homoglyph_variant: bool,
}

#[derive(Deserialize, Serialize)]
struct PackedPhase2Pattern {
    pattern: PackedPattern,
    keywords: Vec<String>,
}

#[derive(Deserialize, Serialize)]
struct PackedCompanion {
    name: String,
    regex: String,
    capture_group: Option<u32>,
    within_lines: u32,
    within_bytes: Option<u32>,
    direction: EvidenceDirection,
    scope: EvidenceScope,
    requirement: EvidenceRequirement,
    value_relation: EvidenceValueRelation,
}

#[derive(Deserialize, Serialize)]
struct SuppressionEnvelope {
    version: u16,
    backend: String,
    detector_ir_digest: [u8; 32],
    detector_count: u32,
}
trait MatcherEnvelopeIdentity {
    fn version(&self) -> u16;
    fn backend(&self) -> &str;
}

macro_rules! impl_matcher_envelope_identity {
    ($($ty:ty),+ $(,)?) => {
        $(
            impl MatcherEnvelopeIdentity for $ty {
                fn version(&self) -> u16 {
                    self.version
                }

                fn backend(&self) -> &str {
                    &self.backend
                }
            }
        )+
    };
}

impl_matcher_envelope_identity!(LiteralEnvelope, RegexEnvelope, SuppressionEnvelope);

impl CompiledRouteMatcherSections {
    /// Serializes the canonical install-compiled matcher graph for one route.
    pub fn compile(
        ir: &CanonicalDetectorExecutionIr,
        backend: ExecutionPackBackend,
    ) -> Result<Self, ExecutionPackError> {
        Ok(Self::compile_with_state(ir, backend)?.0)
    }

    /// Compile route-matcher sections and retain the live [`CompileState`].
    ///
    /// Pack builders that only need the serialized envelopes can keep calling
    /// [`Self::compile`]. MatcherArtifact miss/rebuild paths use this variant so
    /// they can persist the envelopes without throwing away the just-built state
    /// and paying a serialize/hydrate round-trip on the same process.
    pub(crate) fn compile_with_state(
        ir: &CanonicalDetectorExecutionIr,
        backend: ExecutionPackBackend,
    ) -> Result<(Self, CompileState), ExecutionPackError> {
        let state = build_compile_state(ir.detectors()).map_err(|error| {
            ExecutionPackError::InvalidCompilerInput(format!(
                "cannot compile canonical route matcher graph: {error}"
            ))
        })?;
        let localization_hints = CompiledLocalizationHints {
            confirmed_prefixes: state
                .ac_map
                .iter()
                .map(|pattern| {
                    crate::engine::required_prefix_literals_with_cap(
                        pattern.regex.as_str(),
                        crate::engine::CONFIRMED_MAX_LITERALS_PER_PATTERN,
                    )
                })
                .collect(),
            confirmed_suffixes: state
                .ac_map
                .iter()
                .map(|pattern| crate::engine::suffix_gate_literals(pattern.regex.as_str()))
                .collect(),
            phase2: state
                .phase2_patterns
                .iter()
                .map(|(pattern, _)| {
                    crate::engine::phase2_anchor::compile_localization_hint(pattern)
                })
                .collect(),
        };
        let detector_count = u32::try_from(ir.detectors().len()).map_err(|_| {
            ExecutionPackError::InvalidCompilerInput(
                "route matcher detector count exceeds u32".to_owned(),
            )
        })?;
        let ac_patterns = state
            .ac_map
            .iter()
            .map(pack_pattern)
            .collect::<Result<Vec<_>, _>>()?;
        let phase2_patterns = state
            .phase2_patterns
            .iter()
            .map(|(pattern, keywords)| {
                Ok(PackedPhase2Pattern {
                    pattern: pack_pattern(pattern)?,
                    keywords: keywords.clone(),
                })
            })
            .collect::<Result<Vec<_>, ExecutionPackError>>()?;
        let companions = state
            .companions
            .iter()
            .map(|detector_companions| {
                detector_companions
                    .iter()
                    .map(|companion| {
                        Ok(PackedCompanion {
                            name: companion.name.to_string(),
                            regex: companion.regex.as_str().to_owned(),
                            capture_group: companion
                                .capture_group
                                .map(u32::try_from)
                                .transpose()
                                .map_err(|_| {
                                ExecutionPackError::InvalidCompilerInput(
                                    "companion capture group exceeds u32".to_owned(),
                                )
                            })?,
                            within_lines: u32::try_from(companion.within_lines).map_err(|_| {
                                ExecutionPackError::InvalidCompilerInput(
                                    "companion line distance exceeds u32".to_owned(),
                                )
                            })?,
                            within_bytes: companion
                                .within_bytes
                                .map(u32::try_from)
                                .transpose()
                                .map_err(|_| {
                                    ExecutionPackError::InvalidCompilerInput(
                                        "companion byte distance exceeds u32".to_owned(),
                                    )
                                })?,
                            direction: companion.direction,
                            scope: companion.scope,
                            requirement: companion.requirement,
                            value_relation: companion.value_relation,
                        })
                    })
                    .collect()
            })
            .collect::<Result<Vec<Vec<_>>, ExecutionPackError>>()?;
        let backend_name = backend.pascal_name().to_owned();
        let literal_index = canonical_json(&LiteralEnvelope {
            version: ROUTE_MATCHER_SECTION_VERSION,
            backend: backend_name.clone(),
            detector_ir_digest: ir.digest(),
            detector_count,
            ac_literals: state.ac_literals.clone(),
        })?;
        let regex_programs = canonical_json(&RegexEnvelope {
            version: ROUTE_MATCHER_SECTION_VERSION,
            backend: backend_name.clone(),
            detector_ir_digest: ir.digest(),
            detector_count,
            ac_patterns,
            phase2_patterns,
            companions,
            quality_warnings: state.quality_warnings.clone(),
            localization_hints,
        })?;
        let suppression_policy = canonical_json(&SuppressionEnvelope {
            version: ROUTE_MATCHER_SECTION_VERSION,
            backend: backend_name,
            detector_ir_digest: ir.digest(),
            detector_count,
        })?;
        Ok((
            Self {
                backend,
                literal_index,
                regex_programs,
                suppression_policy,
            },
            state,
        ))
    }

    pub fn content_digest(&self) -> [u8; 32] {
        Self::content_digest_for(
            &self.literal_index,
            &self.regex_programs,
            &self.suppression_policy,
        )
    }

    pub(crate) fn content_digest_for(
        literal_index: &[u8],
        regex_programs: &[u8],
        suppression_policy: &[u8],
    ) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        for bytes in [literal_index, regex_programs, suppression_policy] {
            hasher.update(&(bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }
        *hasher.finalize().as_bytes()
    }

    pub fn validate_canonical(&self) -> Result<(), ExecutionPackError> {
        validate_compile_state_sections(
            self.backend,
            &self.literal_index,
            &self.regex_programs,
            &self.suppression_policy,
        )
    }

    pub(crate) fn decode_compile_state(
        &self,
        detectors: &[keyhog_core::DetectorSpec],
    ) -> Result<CompileState, ExecutionPackError> {
        let detector_ir_digest = CanonicalDetectorExecutionIr::compile(detectors)?.digest();
        decode_compile_state_sections(
            self.backend,
            &self.literal_index,
            &self.regex_programs,
            &self.suppression_policy,
            detector_ir_digest,
            detectors,
        )
    }
}

pub(crate) fn validate_compile_state_sections(
    backend: ExecutionPackBackend,
    literal_index: &[u8],
    regex_programs: &[u8],
    suppression_policy: &[u8],
) -> Result<(), ExecutionPackError> {
    decode_validated_compile_state_sections(
        backend,
        literal_index,
        regex_programs,
        suppression_policy,
        SectionDecodeTrust::Untrusted,
    )
    .map(|_| ())
}

/// How strictly matcher-section bytes are validated during hydrate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SectionDecodeTrust {
    /// Signed/authenticated execution pack: skip canonical re-encode and
    /// companion re-validation (already sealed by the pack signature path).
    AuthenticatedPack,
    /// Local MatcherArtifact cache: outer identity/content digests already
    /// checked the bytes, so skip the expensive JSON canonical re-encode, but
    /// still run `compile_companion` validation before LazyRegex construction.
    LocalDigestCheckedCache,
    /// Fully untrusted input: canonical re-encode + companion validation.
    Untrusted,
}

impl SectionDecodeTrust {
    fn skip_canonical_reencode(self) -> bool {
        matches!(
            self,
            Self::AuthenticatedPack | Self::LocalDigestCheckedCache
        )
    }

    fn skip_companion_validation(self) -> bool {
        matches!(self, Self::AuthenticatedPack)
    }
}

fn decode_validated_compile_state_sections(
    backend: ExecutionPackBackend,
    literal_index: &[u8],
    regex_programs: &[u8],
    suppression_policy: &[u8],
    trust: SectionDecodeTrust,
) -> Result<(LiteralEnvelope, RegexEnvelope, SuppressionEnvelope), ExecutionPackError> {
    let literal: LiteralEnvelope =
        decode_canonical("literal index", literal_index, backend, trust)?;
    let regex: RegexEnvelope = decode_canonical("regex programs", regex_programs, backend, trust)?;
    let suppression: SuppressionEnvelope =
        decode_canonical("suppression policy", suppression_policy, backend, trust)?;
    if literal.detector_count != regex.detector_count
        || literal.detector_count != suppression.detector_count
    {
        return Err(ExecutionPackError::InvalidPack(
            "compiled route matcher sections disagree on detector count".to_owned(),
        ));
    }
    if literal.detector_ir_digest != regex.detector_ir_digest
        || literal.detector_ir_digest != suppression.detector_ir_digest
    {
        return Err(ExecutionPackError::InvalidPack(
            "compiled route matcher sections disagree on detector IR identity".to_owned(),
        ));
    }
    if literal.ac_literals.len() != regex.ac_patterns.len() {
        return Err(ExecutionPackError::InvalidPack(format!(
            "compiled route has {} phase-one literals but {} phase-one pattern routes",
            literal.ac_literals.len(),
            regex.ac_patterns.len()
        )));
    }
    if regex.companions.len() != literal.detector_count as usize {
        return Err(ExecutionPackError::InvalidPack(
            "compiled route companion detector cardinality is invalid".to_owned(),
        ));
    }
    if regex.localization_hints.confirmed_prefixes.len() != regex.ac_patterns.len()
        || regex.localization_hints.confirmed_suffixes.len() != regex.ac_patterns.len()
        || regex.localization_hints.phase2.len() != regex.phase2_patterns.len()
    {
        return Err(ExecutionPackError::InvalidPack(
            "compiled route localization-hint cardinality is invalid".to_owned(),
        ));
    }
    let sections = [
        ("literal index", literal_index),
        ("regex programs", regex_programs),
        ("suppression policy", suppression_policy),
    ];
    if trust.skip_canonical_reencode() {
        for (index, (name, bytes)) in sections.iter().enumerate() {
            if sections[..index]
                .iter()
                .any(|(_, prior)| prior.len() == bytes.len() && *prior == *bytes)
            {
                return Err(ExecutionPackError::InvalidPack(format!(
                    "compiled route {name} duplicates another matcher section"
                )));
            }
        }
    } else {
        let mut seen = BTreeSet::new();
        for (name, bytes) in sections {
            if !seen.insert(*blake3::hash(bytes).as_bytes()) {
                return Err(ExecutionPackError::InvalidPack(format!(
                    "compiled route {name} duplicates another matcher section"
                )));
            }
        }
    }
    Ok((literal, regex, suppression))
}

pub(crate) fn decode_authenticated_compile_state_sections(
    backend: ExecutionPackBackend,
    literal_index: &[u8],
    regex_programs: &[u8],
    suppression_policy: &[u8],
    expected_detector_ir_digest: [u8; 32],
    detectors: &[keyhog_core::DetectorSpec],
) -> Result<CompileState, ExecutionPackError> {
    let detector_ids = detectors
        .iter()
        .map(|detector| detector.id.as_str())
        .collect::<Vec<_>>();
    let detector_pattern_counts = detectors
        .iter()
        .map(|detector| detector.patterns.len())
        .collect::<Vec<_>>();
    decode_compile_state_sections_from_ids_inner(
        backend,
        literal_index,
        regex_programs,
        suppression_policy,
        expected_detector_ir_digest,
        &detector_ids,
        &detector_pattern_counts,
        SectionDecodeTrust::AuthenticatedPack,
    )
}

pub(crate) fn decode_compile_state_sections(
    backend: ExecutionPackBackend,
    literal_index: &[u8],
    regex_programs: &[u8],
    suppression_policy: &[u8],
    expected_detector_ir_digest: [u8; 32],
    detectors: &[keyhog_core::DetectorSpec],
) -> Result<CompileState, ExecutionPackError> {
    let detector_ids = detectors
        .iter()
        .map(|detector| detector.id.as_str())
        .collect::<Vec<_>>();
    let detector_pattern_counts = detectors
        .iter()
        .map(|detector| detector.patterns.len())
        .collect::<Vec<_>>();
    decode_compile_state_sections_from_ids_inner(
        backend,
        literal_index,
        regex_programs,
        suppression_policy,
        expected_detector_ir_digest,
        &detector_ids,
        &detector_pattern_counts,
        SectionDecodeTrust::Untrusted,
    )
}

pub(crate) fn decode_authenticated_compile_state_sections_from_ids(
    backend: ExecutionPackBackend,
    literal_index: &[u8],
    regex_programs: &[u8],
    suppression_policy: &[u8],
    expected_detector_ir_digest: [u8; 32],
    detector_ids: &[&str],
    detector_pattern_counts: &[usize],
) -> Result<CompileState, ExecutionPackError> {
    decode_compile_state_sections_from_ids_inner(
        backend,
        literal_index,
        regex_programs,
        suppression_policy,
        expected_detector_ir_digest,
        detector_ids,
        detector_pattern_counts,
        SectionDecodeTrust::AuthenticatedPack,
    )
}

pub(crate) fn decode_compile_state_sections_from_ids(
    backend: ExecutionPackBackend,
    literal_index: &[u8],
    regex_programs: &[u8],
    suppression_policy: &[u8],
    expected_detector_ir_digest: [u8; 32],
    detector_ids: &[&str],
    detector_pattern_counts: &[usize],
) -> Result<CompileState, ExecutionPackError> {
    decode_compile_state_sections_from_ids_inner(
        backend,
        literal_index,
        regex_programs,
        suppression_policy,
        expected_detector_ir_digest,
        detector_ids,
        detector_pattern_counts,
        SectionDecodeTrust::Untrusted,
    )
}

/// Hydrate CompileState from a local MatcherArtifact whose outer identity and
/// content digests have already been checked against the live process.
pub(crate) fn decode_local_matcher_artifact_compile_state_sections(
    backend: ExecutionPackBackend,
    literal_index: &[u8],
    regex_programs: &[u8],
    suppression_policy: &[u8],
    expected_detector_ir_digest: [u8; 32],
    detectors: &[keyhog_core::DetectorSpec],
) -> Result<CompileState, ExecutionPackError> {
    let detector_ids = detectors
        .iter()
        .map(|detector| detector.id.as_str())
        .collect::<Vec<_>>();
    let detector_pattern_counts = detectors
        .iter()
        .map(|detector| detector.patterns.len())
        .collect::<Vec<_>>();
    decode_compile_state_sections_from_ids_inner(
        backend,
        literal_index,
        regex_programs,
        suppression_policy,
        expected_detector_ir_digest,
        &detector_ids,
        &detector_pattern_counts,
        SectionDecodeTrust::LocalDigestCheckedCache,
    )
}

fn decode_compile_state_sections_from_ids_inner(
    backend: ExecutionPackBackend,
    literal_index: &[u8],
    regex_programs: &[u8],
    suppression_policy: &[u8],
    expected_detector_ir_digest: [u8; 32],
    detector_ids: &[&str],
    detector_pattern_counts: &[usize],
    trust: SectionDecodeTrust,
) -> Result<CompileState, ExecutionPackError> {
    let (literal, regex, _suppression) = decode_validated_compile_state_sections(
        backend,
        literal_index,
        regex_programs,
        suppression_policy,
        trust,
    )?;
    if literal.detector_ir_digest != expected_detector_ir_digest {
        return Err(ExecutionPackError::Incompatible(
            "compiled route matcher graph belongs to another detector IR".to_owned(),
        ));
    }
    if literal.detector_count as usize != detector_ids.len() {
        return Err(ExecutionPackError::Incompatible(format!(
            "compiled route owns {} detectors but runtime loaded {}",
            literal.detector_count,
            detector_ids.len()
        )));
    }
    if detector_pattern_counts.len() != detector_ids.len() {
        return Err(ExecutionPackError::Incompatible(format!(
            "compiled route owns {} detector pattern-count rows but runtime loaded {} detectors",
            detector_pattern_counts.len(),
            detector_ids.len()
        )));
    }
    let ac_map = regex
        .ac_patterns
        .into_iter()
        .enumerate()
        .map(|(index, pattern)| {
            unpack_pattern(
                pattern,
                detector_ids.len(),
                detector_pattern_counts,
                "ac_map",
                index,
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    let phase2_patterns = regex
        .phase2_patterns
        .into_iter()
        .enumerate()
        .map(|(index, packed)| {
            Ok((
                unpack_pattern(
                    packed.pattern,
                    detector_ids.len(),
                    detector_pattern_counts,
                    "phase2_patterns",
                    index,
                )?,
                packed.keywords,
            ))
        })
        .collect::<Result<Vec<_>, ExecutionPackError>>()?;
    let companions = regex
        .companions
        .into_iter()
        .enumerate()
        .map(|(detector_index, packed)| {
            packed
                .into_iter()
                .map(|companion| unpack_companion(companion, detector_ids[detector_index], trust))
                .collect()
        })
        .collect::<Result<Vec<_>, ExecutionPackError>>()?;
    Ok(CompileState {
        ac_literals: literal.ac_literals,
        ac_map,
        phase2_patterns,
        companions,
        quality_warnings: regex.quality_warnings,
        localization_hints: Some(regex.localization_hints),
    })
}

fn pack_pattern(pattern: &CompiledPattern) -> Result<PackedPattern, ExecutionPackError> {
    Ok(PackedPattern {
        detector_index: u32::try_from(pattern.detector_index).map_err(|_| {
            ExecutionPackError::InvalidCompilerInput(
                "compiled pattern detector index exceeds u32".to_owned(),
            )
        })?,
        pattern_index: pattern.pattern_index,
        regex: pattern.regex.as_str().to_owned(),
        case_insensitive: pattern.regex.is_case_insensitive(),
        group: pattern.group.map(u32::try_from).transpose().map_err(|_| {
            ExecutionPackError::InvalidCompilerInput(
                "compiled pattern capture group exceeds u32".to_owned(),
            )
        })?,
        client_safe: pattern.client_safe,
        weak_anchor: pattern.weak_anchor,
        structural_password_slot: pattern.structural_password_slot,
        match_proves_keyword_nearby: pattern.match_proves_keyword_nearby,
        allows_repeated_keyword_separator: pattern.allows_repeated_keyword_separator,
        homoglyph_variant: pattern.homoglyph_variant,
    })
}

fn unpack_pattern(
    packed: PackedPattern,
    detectors_len: usize,
    detector_pattern_counts: &[usize],
    table: &'static str,
    pattern_index: usize,
) -> Result<CompiledPattern, ExecutionPackError> {
    let detector_index = packed.detector_index as usize;
    if detector_index >= detectors_len {
        return Err(ExecutionPackError::InvalidPack(format!(
            "compiled route {table}[{pattern_index}] references detector index {} but only {detectors_len} detectors are loaded",
            packed.detector_index
        )));
    }
    let source_pattern_index = packed.pattern_index as usize;
    if source_pattern_index >= detector_pattern_counts[detector_index] {
        return Err(ExecutionPackError::InvalidPack(format!(
            "compiled route {table}[{pattern_index}] references source pattern index {} but detector {} owns only {} pattern(s)",
            packed.pattern_index,
            packed.detector_index,
            detector_pattern_counts[detector_index]
        )));
    }
    if packed.case_insensitive == packed.homoglyph_variant {
        return Err(ExecutionPackError::InvalidPack(format!(
            "compiled route {table}[{pattern_index}] has an invalid lazy-regex flavor"
        )));
    }
    let regex = if packed.case_insensitive {
        LazyRegex::detector(packed.regex)
    } else {
        LazyRegex::plain(packed.regex)
    };
    Ok(CompiledPattern {
        detector_index,
        pattern_index: packed.pattern_index,
        regex,
        group: packed.group.map(|group| group as usize),
        client_safe: packed.client_safe,
        weak_anchor: packed.weak_anchor,
        structural_password_slot: packed.structural_password_slot,
        match_proves_keyword_nearby: packed.match_proves_keyword_nearby,
        allows_repeated_keyword_separator: packed.allows_repeated_keyword_separator,
        homoglyph_variant: packed.homoglyph_variant,
    })
}

fn unpack_companion(
    packed: PackedCompanion,
    detector_id: &str,
    trust: SectionDecodeTrust,
) -> Result<crate::types::CompiledCompanion, ExecutionPackError> {
    if trust.skip_companion_validation() {
        return Ok(crate::types::CompiledCompanion {
            name: std::sync::Arc::<str>::from(packed.name),
            regex: LazyRegex::companion(packed.regex),
            capture_group: packed.capture_group.map(|group| group as usize),
            within_lines: packed.within_lines as usize,
            within_bytes: packed.within_bytes.map(|bytes| bytes as usize),
            direction: packed.direction,
            scope: packed.scope,
            requirement: packed.requirement,
            value_relation: packed.value_relation,
        });
    }
    RUNTIME_COMPANION_VALIDATIONS.set(RUNTIME_COMPANION_VALIDATIONS.get().saturating_add(1));
    let spec = CompanionSpec {
        name: packed.name,
        regex: packed.regex,
        within_lines: packed.within_lines as usize,
        within_bytes: packed.within_bytes.map(|bytes| bytes as usize),
        direction: packed.direction,
        scope: packed.scope,
        requirement: packed.requirement,
        capture_group: packed.capture_group.map(|group| group as usize),
        value_relation: packed.value_relation,
        required: false,
    };
    compile_companion(&spec, detector_id).map_err(|error| {
        ExecutionPackError::InvalidPack(format!(
            "compiled route companion for detector {detector_id:?} is invalid: {error}"
        ))
    })
}

fn decode_canonical<T>(
    name: &'static str,
    bytes: &[u8],
    backend: ExecutionPackBackend,
    trust: SectionDecodeTrust,
) -> Result<T, ExecutionPackError>
where
    T: serde::de::DeserializeOwned + Serialize + MatcherEnvelopeIdentity,
{
    let decoded: T = serde_json::from_slice(bytes).map_err(|error| {
        ExecutionPackError::InvalidPack(format!("compiled route {name} is invalid JSON: {error}"))
    })?;
    if decoded.version() != ROUTE_MATCHER_SECTION_VERSION
        || decoded.backend() != backend.pascal_name()
    {
        return Err(ExecutionPackError::Incompatible(format!(
            "compiled route {name} version or backend is incompatible"
        )));
    }
    if !trust.skip_canonical_reencode() {
        RUNTIME_CANONICAL_REENCODES.set(RUNTIME_CANONICAL_REENCODES.get().saturating_add(1));
        let canonical = serde_json::to_vec(&decoded).map_err(|error| {
            ExecutionPackError::InvalidPack(format!(
                "compiled route {name} cannot be canonicalized: {error}"
            ))
        })?;
        if canonical != bytes {
            return Err(ExecutionPackError::InvalidPack(format!(
                "compiled route {name} is not canonically encoded"
            )));
        }
    }
    Ok(decoded)
}

fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>, ExecutionPackError> {
    serde_json::to_vec(value).map_err(|error| {
        ExecutionPackError::InvalidCompilerInput(format!(
            "cannot serialize route matcher section: {error}"
        ))
    })
}

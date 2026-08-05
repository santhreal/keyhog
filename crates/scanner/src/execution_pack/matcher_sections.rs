use super::{CanonicalDetectorExecutionIr, ExecutionPackBackend, ExecutionPackError};
use crate::compiler::compiler_build::{
    build_compile_state, build_compile_state_invocations, CompileState,
};
use crate::compiler::compiler_compile::compile_companion;
use crate::types::{CompiledPattern, LazyRegex};
use keyhog_core::{
    CompanionSpec, EvidenceDirection, EvidenceRequirement, EvidenceScope, EvidenceValueRelation,
};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;

pub const ROUTE_MATCHER_SECTION_VERSION: u16 = 2;
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
}

#[derive(Deserialize, Serialize)]
struct PackedPattern {
    detector_index: u32,
    regex: String,
    case_insensitive: bool,
    group: Option<u32>,
    client_safe: bool,
    weak_anchor: bool,
    structural_password_slot: bool,
    match_proves_keyword_nearby: bool,
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
    detectors: Vec<keyhog_core::DetectorSpec>,
}

impl CompiledRouteMatcherSections {
    /// Serializes the canonical install-compiled matcher graph for one route.
    pub fn compile(
        ir: &CanonicalDetectorExecutionIr,
        backend: ExecutionPackBackend,
    ) -> Result<Self, ExecutionPackError> {
        let state = build_compile_state(ir.detectors()).map_err(|error| {
            ExecutionPackError::InvalidCompilerInput(format!(
                "cannot compile canonical route matcher graph: {error}"
            ))
        })?;
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
        let backend_name = backend_name(backend).to_owned();
        let literal_index = canonical_json(&LiteralEnvelope {
            version: ROUTE_MATCHER_SECTION_VERSION,
            backend: backend_name.clone(),
            detector_ir_digest: ir.digest(),
            detector_count,
            ac_literals: state.ac_literals,
        })?;
        let regex_programs = canonical_json(&RegexEnvelope {
            version: ROUTE_MATCHER_SECTION_VERSION,
            backend: backend_name.clone(),
            detector_ir_digest: ir.digest(),
            detector_count,
            ac_patterns,
            phase2_patterns,
            companions,
            quality_warnings: state.quality_warnings,
        })?;
        let suppression_policy = canonical_json(&SuppressionEnvelope {
            version: ROUTE_MATCHER_SECTION_VERSION,
            backend: backend_name,
            detector_ir_digest: ir.digest(),
            detectors: ir
                .detectors()
                .iter()
                .cloned()
                .map(|mut detector| {
                    detector.tests.clear();
                    detector.patterns.clear();
                    detector.keywords.clear();
                    detector.simdsieve_prefixes.clear();
                    detector
                })
                .collect(),
        })?;
        Ok(Self {
            backend,
            literal_index,
            regex_programs,
            suppression_policy,
        })
    }

    pub fn content_digest(&self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new();
        for bytes in [
            self.literal_index.as_slice(),
            self.regex_programs.as_slice(),
            self.suppression_policy.as_slice(),
        ] {
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
    let literal: LiteralEnvelope = decode_canonical("literal index", literal_index, backend)?;
    let regex: RegexEnvelope = decode_canonical("regex programs", regex_programs, backend)?;
    let suppression: SuppressionEnvelope =
        decode_canonical("suppression policy", suppression_policy, backend)?;
    if literal.detector_count != regex.detector_count {
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
    if suppression.detectors.len() != literal.detector_count as usize
        || regex.companions.len() != literal.detector_count as usize
    {
        return Err(ExecutionPackError::InvalidPack(
            "compiled route companion or suppression detector cardinality is invalid".to_owned(),
        ));
    }
    let mut seen = BTreeSet::new();
    for (name, bytes) in [
        ("literal index", literal_index),
        ("regex programs", regex_programs),
        ("suppression policy", suppression_policy),
    ] {
        if !seen.insert(*blake3::hash(bytes).as_bytes()) {
            return Err(ExecutionPackError::InvalidPack(format!(
                "compiled route {name} duplicates another matcher section"
            )));
        }
    }
    Ok(())
}

pub(crate) fn decode_compile_state_sections(
    backend: ExecutionPackBackend,
    literal_index: &[u8],
    regex_programs: &[u8],
    suppression_policy: &[u8],
    expected_detector_ir_digest: [u8; 32],
    detectors: &[keyhog_core::DetectorSpec],
) -> Result<CompileState, ExecutionPackError> {
    validate_compile_state_sections(
        backend,
        literal_index,
        regex_programs,
        suppression_policy,
    )?;
    let literal: LiteralEnvelope = decode_canonical("literal index", literal_index, backend)?;
    let regex: RegexEnvelope = decode_canonical("regex programs", regex_programs, backend)?;
    let suppression: SuppressionEnvelope =
        decode_canonical("suppression policy", suppression_policy, backend)?;
    if literal.detector_ir_digest != expected_detector_ir_digest {
        return Err(ExecutionPackError::Incompatible(
            "compiled route matcher graph belongs to another detector IR".to_owned(),
        ));
    }
    if literal.detector_count as usize != detectors.len() {
        return Err(ExecutionPackError::Incompatible(format!(
            "compiled route owns {} detectors but runtime loaded {}",
            literal.detector_count,
            detectors.len()
        )));
    }
    if !suppression
        .detectors
        .iter()
        .zip(detectors)
        .all(|(packed, detector)| packed.id == detector.id)
    {
        return Err(ExecutionPackError::Incompatible(
            "compiled route detector ordering does not match runtime detector ownership".to_owned(),
        ));
    }
    let ac_map = regex
        .ac_patterns
        .into_iter()
        .enumerate()
        .map(|(index, pattern)| unpack_pattern(pattern, detectors.len(), "ac_map", index))
        .collect::<Result<Vec<_>, _>>()?;
    let phase2_patterns = regex
        .phase2_patterns
        .into_iter()
        .enumerate()
        .map(|(index, packed)| {
            Ok((
                unpack_pattern(
                    packed.pattern,
                    detectors.len(),
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
                .map(|companion| unpack_companion(companion, &detectors[detector_index].id))
                .collect()
        })
        .collect::<Result<Vec<_>, ExecutionPackError>>()?;
    Ok(CompileState {
        ac_literals: literal.ac_literals,
        ac_map,
        phase2_patterns,
        companions,
        quality_warnings: regex.quality_warnings,
    })
}

fn pack_pattern(pattern: &CompiledPattern) -> Result<PackedPattern, ExecutionPackError> {
    Ok(PackedPattern {
        detector_index: u32::try_from(pattern.detector_index).map_err(|_| {
            ExecutionPackError::InvalidCompilerInput(
                "compiled pattern detector index exceeds u32".to_owned(),
            )
        })?,
        regex: pattern.regex.as_str().to_owned(),
        case_insensitive: pattern.regex.is_case_insensitive(),
        group: pattern
            .group
            .map(u32::try_from)
            .transpose()
            .map_err(|_| {
                ExecutionPackError::InvalidCompilerInput(
                    "compiled pattern capture group exceeds u32".to_owned(),
                )
            })?,
        client_safe: pattern.client_safe,
        weak_anchor: pattern.weak_anchor,
        structural_password_slot: pattern.structural_password_slot,
        match_proves_keyword_nearby: pattern.match_proves_keyword_nearby,
        homoglyph_variant: pattern.homoglyph_variant,
    })
}

fn unpack_pattern(
    packed: PackedPattern,
    detectors_len: usize,
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
        regex,
        group: packed.group.map(|group| group as usize),
        client_safe: packed.client_safe,
        weak_anchor: packed.weak_anchor,
        structural_password_slot: packed.structural_password_slot,
        match_proves_keyword_nearby: packed.match_proves_keyword_nearby,
        homoglyph_variant: packed.homoglyph_variant,
    })
}

fn unpack_companion(
    packed: PackedCompanion,
    detector_id: &str,
) -> Result<crate::types::CompiledCompanion, ExecutionPackError> {
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
) -> Result<T, ExecutionPackError>
where
    T: serde::de::DeserializeOwned + Serialize,
{
    let decoded: T = serde_json::from_slice(bytes).map_err(|error| {
        ExecutionPackError::InvalidPack(format!(
            "compiled route {name} is invalid JSON: {error}"
        ))
    })?;
    let value: serde_json::Value = serde_json::from_slice(bytes).map_err(|error| {
        ExecutionPackError::InvalidPack(format!(
            "compiled route {name} is invalid JSON: {error}"
        ))
    })?;
    if value.get("version").and_then(serde_json::Value::as_u64)
        != Some(u64::from(ROUTE_MATCHER_SECTION_VERSION))
        || value.get("backend").and_then(serde_json::Value::as_str)
            != Some(backend_name(backend))
    {
        return Err(ExecutionPackError::Incompatible(format!(
            "compiled route {name} version or backend is incompatible"
        )));
    }
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
    Ok(decoded)
}

fn canonical_json(value: &impl Serialize) -> Result<Vec<u8>, ExecutionPackError> {
    serde_json::to_vec(value).map_err(|error| {
        ExecutionPackError::InvalidCompilerInput(format!(
            "cannot serialize route matcher section: {error}"
        ))
    })
}

fn backend_name(backend: ExecutionPackBackend) -> &'static str {
    match backend {
        ExecutionPackBackend::Cpu => "Cpu",
        ExecutionPackBackend::Simd => "Simd",
        ExecutionPackBackend::GpuCuda => "GpuCuda",
        ExecutionPackBackend::GpuWgpu => "GpuWgpu",
        ExecutionPackBackend::GpuMetal => "GpuMetal",
    }
}

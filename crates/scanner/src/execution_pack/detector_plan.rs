use super::{CanonicalDetectorExecutionIr, ExecutionPackError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::sync::Arc;

pub const DETECTOR_PLAN_SECTION_VERSION: u16 = 1;
const MAX_DETECTORS: usize = 16_384;
const MAX_DECODERS: usize = 256;
const MAX_SECTION_BYTES: usize = 64 * 1024 * 1024;
static DETECTOR_SPEC_SCHEMA_RECONSTRUCTIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

#[doc(hidden)]
pub fn detector_spec_schema_reconstructions() -> usize {
    DETECTOR_SPEC_SCHEMA_RECONSTRUCTIONS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Explicit stable source facts required to rebuild one compiled detector plan.
/// Self-tests, verification configuration, and other non-runtime schema fields
/// are intentionally absent.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct DetectorPlanRecord {
    pub id: String,
    pub name: String,
    pub service: String,
    pub severity: keyhog_core::Severity,
    pub kind: keyhog_core::DetectorKind,
    pub ml: keyhog_core::DetectorMlPolicySpec,
    pub match_confidence: Option<keyhog_core::DetectorMatchConfidenceSpec>,
    pub validators: Vec<keyhog_core::DetectorValidatorSpec>,
    pub decode_transforms: keyhog_core::DetectorDecodeTransformSpec,
    pub patterns: Vec<keyhog_core::PatternSpec>,
    pub companion_names: Vec<String>,
    pub detector_relations: Vec<keyhog_core::DetectorRelationSpec>,
    pub source_admission: keyhog_core::SourceAdmissionSpec,
    pub keywords: Vec<String>,
    pub simdsieve_prefixes: Vec<String>,
    pub min_confidence: Option<f64>,
    pub entropy_floor: Vec<keyhog_core::EntropyFloorBucket>,
    pub entropy_high: Option<f64>,
    pub entropy_low: Option<f64>,
    pub entropy_very_high: Option<f64>,
    pub entropy_fallback: Option<keyhog_core::EntropyFallbackMetadata>,
    pub entropy_fallback_confidence: Option<keyhog_core::EntropyFallbackConfidenceSpec>,
    pub generic_assignment_confidence: Option<keyhog_core::GenericAssignmentConfidenceSpec>,
    pub entropy_roles: Vec<keyhog_core::EntropyDetectionRole>,
    pub sensitive_path_entropy_very_high: Option<f64>,
    pub entropy_shapes: Vec<keyhog_core::EntropyShapeSpec>,
    pub plausibility: Option<keyhog_core::DetectorPlausibilityPolicySpec>,
    pub entropy_policy_priority: Option<u16>,
    pub bpe_max_bytes_per_token: Option<f64>,
    pub bpe_enabled: Option<bool>,
    pub decoded_hex_key_material_lengths: Vec<usize>,
    pub canonical_hex_key_material: Vec<keyhog_core::CanonicalHexKeyMaterialSpec>,
    pub keyword_free_min_len: Option<usize>,
    pub min_len: Option<usize>,
    pub max_len: Option<usize>,
    pub generic_vendor_suffixes: Vec<String>,
    pub generic_assignment_tail_suffixes: Vec<String>,
    pub allowlist_paths: Vec<String>,
    pub allowlist_values: Vec<String>,
    pub stopwords: Vec<String>,
    pub public_identifier_assignment_markers: Vec<String>,
    pub structural_password_slot: bool,
    pub weak_anchor: bool,
    pub private_key_block: bool,
    pub resolution_priority: i16,
    pub credential_shape: Option<keyhog_core::CredentialShape>,
    pub live_verifier: bool,
    pub required_companion: bool,
}

impl DetectorPlanRecord {
    fn compile(spec: &keyhog_core::DetectorSpec) -> Self {
        Self {
            id: spec.id.clone(),
            name: spec.name.clone(),
            service: spec.service.clone(),
            severity: spec.severity,
            kind: spec.kind,
            ml: spec.ml,
            match_confidence: spec.match_confidence,
            validators: spec.validators.clone(),
            decode_transforms: spec.decode_transforms.clone(),
            patterns: spec.patterns.clone(),
            companion_names: spec.companions.iter().map(|row| row.name.clone()).collect(),
            detector_relations: spec.detector_relations.clone(),
            source_admission: spec.source_admission.clone(),
            keywords: spec.keywords.clone(),
            simdsieve_prefixes: spec.simdsieve_prefixes.clone(),
            min_confidence: spec.min_confidence,
            entropy_floor: spec.entropy_floor.clone(),
            entropy_high: spec.entropy_high,
            entropy_low: spec.entropy_low,
            entropy_very_high: spec.entropy_very_high,
            entropy_fallback: spec.entropy_fallback.clone(),
            entropy_fallback_confidence: spec.entropy_fallback_confidence,
            generic_assignment_confidence: spec.generic_assignment_confidence,
            entropy_roles: spec.entropy_roles.clone(),
            sensitive_path_entropy_very_high: spec.sensitive_path_entropy_very_high,
            entropy_shapes: spec.entropy_shapes.clone(),
            plausibility: spec.plausibility,
            entropy_policy_priority: spec.entropy_policy_priority,
            bpe_max_bytes_per_token: spec.bpe_max_bytes_per_token,
            bpe_enabled: spec.bpe_enabled,
            decoded_hex_key_material_lengths: spec.decoded_hex_key_material_lengths.clone(),
            canonical_hex_key_material: spec.canonical_hex_key_material.clone(),
            keyword_free_min_len: spec.keyword_free_min_len,
            min_len: spec.min_len,
            max_len: spec.max_len,
            generic_vendor_suffixes: spec.generic_vendor_suffixes.clone(),
            generic_assignment_tail_suffixes: spec.generic_assignment_tail_suffixes.clone(),
            allowlist_paths: spec.allowlist_paths.clone(),
            allowlist_values: spec.allowlist_values.clone(),
            stopwords: spec.stopwords.clone(),
            public_identifier_assignment_markers: spec.public_identifier_assignment_markers.clone(),
            structural_password_slot: spec.structural_password_slot,
            weak_anchor: spec.weak_anchor,
            private_key_block: spec.private_key_block,
            resolution_priority: spec.resolution_priority,
            credential_shape: spec.credential_shape.clone(),
            live_verifier: spec.verify.is_some(),
            required_companion: spec.companions.iter().any(|companion| {
                companion.effective_requirement() == keyhog_core::EvidenceRequirement::Required
            }),
        }
    }

    #[inline]
    pub(crate) fn owns_entropy_policy(&self) -> bool {
        self.kind == keyhog_core::DetectorKind::Phase2Generic
            || self.entropy_policy_priority.is_some()
    }

    pub(crate) fn into_detector_spec(self) -> keyhog_core::DetectorSpec {
        keyhog_core::DetectorSpec {
            id: self.id,
            name: self.name,
            service: self.service,
            severity: self.severity,
            kind: self.kind,
            ml: self.ml,
            match_confidence: self.match_confidence,
            validators: self.validators,
            decode_transforms: self.decode_transforms,
            patterns: self.patterns,
            companions: self
                .companion_names
                .into_iter()
                .map(|name| keyhog_core::CompanionSpec {
                    name,
                    ..Default::default()
                })
                .collect(),
            detector_relations: self.detector_relations,
            source_admission: self.source_admission,
            keywords: self.keywords,
            simdsieve_prefixes: self.simdsieve_prefixes,
            min_confidence: self.min_confidence,
            entropy_floor: self.entropy_floor,
            entropy_high: self.entropy_high,
            entropy_low: self.entropy_low,
            entropy_very_high: self.entropy_very_high,
            entropy_fallback: self.entropy_fallback,
            entropy_fallback_confidence: self.entropy_fallback_confidence,
            generic_assignment_confidence: self.generic_assignment_confidence,
            entropy_roles: self.entropy_roles,
            sensitive_path_entropy_very_high: self.sensitive_path_entropy_very_high,
            entropy_shapes: self.entropy_shapes,
            plausibility: self.plausibility,
            entropy_policy_priority: self.entropy_policy_priority,
            bpe_max_bytes_per_token: self.bpe_max_bytes_per_token,
            bpe_enabled: self.bpe_enabled,
            decoded_hex_key_material_lengths: self.decoded_hex_key_material_lengths,
            canonical_hex_key_material: self.canonical_hex_key_material,
            keyword_free_min_len: self.keyword_free_min_len,
            min_len: self.min_len,
            max_len: self.max_len,
            generic_vendor_suffixes: self.generic_vendor_suffixes,
            generic_assignment_tail_suffixes: self.generic_assignment_tail_suffixes,
            allowlist_paths: self.allowlist_paths,
            allowlist_values: self.allowlist_values,
            stopwords: self.stopwords,
            public_identifier_assignment_markers: self.public_identifier_assignment_markers,
            structural_password_slot: self.structural_password_slot,
            weak_anchor: self.weak_anchor,
            private_key_block: self.private_key_block,
            resolution_priority: self.resolution_priority,
            credential_shape: self.credential_shape,
            ..Default::default()
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetectorPlanEnvelope {
    version: u16,
    detector_ir_digest: [u8; 32],
    compiled_plan_digest: [u8; 32],
    detector_count: u32,
    detector_order_digest: [u8; 32],
    decoder_identities: Vec<String>,
    detectors: Vec<DetectorPlanRecord>,
}

#[derive(Clone, Debug)]
pub struct CompiledDetectorPlanSection {
    bytes: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct HydratedDetectorPlanSection {
    detectors: Arc<[DetectorPlanRecord]>,
    decoder_plan: Arc<crate::decode::CompiledDecoderPlan>,
    detector_ir_digest: [u8; 32],
    compiled_plan_digest: [u8; 32],
}

impl CompiledDetectorPlanSection {
    pub fn compile(ir: &CanonicalDetectorExecutionIr) -> Result<Self, ExecutionPackError> {
        if ir.detectors().len() > MAX_DETECTORS {
            return Err(ExecutionPackError::InvalidCompilerInput(format!(
                "detector plan has {} detectors; maximum is {MAX_DETECTORS}",
                ir.detectors().len()
            )));
        }
        let decoder_plan = crate::decode::CompiledDecoderPlan::snapshot().map_err(|error| {
            ExecutionPackError::InvalidCompilerInput(format!(
                "cannot snapshot detector-plan decoder identities: {error}"
            ))
        })?;
        let decoder_identities = decoder_plan.stable_identities();
        if decoder_identities.len() > MAX_DECODERS {
            return Err(ExecutionPackError::InvalidCompilerInput(format!(
                "detector plan has {} decoder identities; maximum is {MAX_DECODERS}",
                decoder_identities.len()
            )));
        }
        let detectors = ir
            .detectors()
            .iter()
            .map(DetectorPlanRecord::compile)
            .collect::<Vec<_>>();
        let detector_count = u32::try_from(detectors.len()).map_err(|_| {
            ExecutionPackError::InvalidCompilerInput("detector-plan count exceeds u32".to_owned())
        })?;
        let envelope = DetectorPlanEnvelope {
            version: DETECTOR_PLAN_SECTION_VERSION,
            detector_ir_digest: ir.digest(),
            compiled_plan_digest: crate::compiled_scanner::detector_digest::from_execution_plan(
                keyhog_core::compute_spec_hash(ir.detectors()),
                decoder_plan.identity(),
            ),
            detector_count,
            detector_order_digest: detector_order_digest(detectors.iter().map(|d| d.id.as_str())),
            decoder_identities,
            detectors,
        };
        let bytes = canonical_json(&envelope, "serialize")?;
        if bytes.len() > MAX_SECTION_BYTES {
            return Err(ExecutionPackError::InvalidCompilerInput(format!(
                "detector-plan section is {} bytes; maximum is {MAX_SECTION_BYTES}",
                bytes.len()
            )));
        }
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub(crate) fn decode(
        bytes: &[u8],
        expected_detector_ir_digest: [u8; 32],
    ) -> Result<HydratedDetectorPlanSection, ExecutionPackError> {
        if bytes.len() > MAX_SECTION_BYTES {
            return Err(ExecutionPackError::InvalidPack(format!(
                "detector-plan section is {} bytes; maximum is {MAX_SECTION_BYTES}",
                bytes.len()
            )));
        }
        let envelope: DetectorPlanEnvelope = serde_json::from_slice(bytes).map_err(|error| {
            ExecutionPackError::InvalidPack(format!(
                "detector-plan section is invalid or truncated: {error}"
            ))
        })?;
        if envelope.version != DETECTOR_PLAN_SECTION_VERSION {
            return Err(ExecutionPackError::Incompatible(format!(
                "detector-plan version {} is unsupported; this binary requires {}",
                envelope.version, DETECTOR_PLAN_SECTION_VERSION
            )));
        }
        if envelope.detector_ir_digest != expected_detector_ir_digest {
            return Err(ExecutionPackError::Incompatible(
                "detector plan belongs to another DetectorIr digest".to_owned(),
            ));
        }
        if envelope.detectors.len() > MAX_DETECTORS {
            return Err(ExecutionPackError::InvalidPack(format!(
                "detector plan has {} detectors; maximum is {MAX_DETECTORS}",
                envelope.detectors.len()
            )));
        }
        if envelope.detector_count as usize != envelope.detectors.len() {
            return Err(ExecutionPackError::InvalidPack(format!(
                "detector-plan count {} does not match its {} detector rows",
                envelope.detector_count,
                envelope.detectors.len()
            )));
        }
        if envelope.decoder_identities.len() > MAX_DECODERS {
            return Err(ExecutionPackError::InvalidPack(format!(
                "detector plan has {} decoder identities; maximum is {MAX_DECODERS}",
                envelope.decoder_identities.len()
            )));
        }
        let mut decoder_identities = BTreeSet::new();
        if envelope
            .decoder_identities
            .iter()
            .any(|identity| identity.is_empty() || !decoder_identities.insert(identity.as_str()))
        {
            return Err(ExecutionPackError::InvalidPack(
                "detector plan contains an empty or duplicate decoder identity".to_owned(),
            ));
        }
        let mut detector_ids = BTreeSet::new();
        let mut previous: Option<&str> = None;
        for detector in &envelope.detectors {
            if detector.id.is_empty() || !detector_ids.insert(detector.id.as_str()) {
                return Err(ExecutionPackError::InvalidPack(
                    "detector plan contains an empty or duplicate detector ID".to_owned(),
                ));
            }
            if previous.is_some_and(|id| id >= detector.id.as_str()) {
                return Err(ExecutionPackError::InvalidPack(
                    "detector-plan detector order is not canonical".to_owned(),
                ));
            }
            previous = Some(detector.id.as_str());
        }
        let order_digest = detector_order_digest(envelope.detectors.iter().map(|d| d.id.as_str()));
        if order_digest != envelope.detector_order_digest {
            return Err(ExecutionPackError::InvalidPack(
                "detector-plan detector order digest does not match its rows".to_owned(),
            ));
        }
        if canonical_json(&envelope, "re-serialize")? != bytes {
            return Err(ExecutionPackError::InvalidPack(
                "detector-plan section is not canonical JSON".to_owned(),
            ));
        }
        let decoder_plan = crate::decode::CompiledDecoderPlan::from_stable_identities(
            &envelope.decoder_identities,
        )
        .map_err(|error| ExecutionPackError::Incompatible(error.to_string()))?;
        Ok(HydratedDetectorPlanSection {
            detectors: envelope.detectors.into(),
            decoder_plan: Arc::new(decoder_plan),
            detector_ir_digest: envelope.detector_ir_digest,
            compiled_plan_digest: envelope.compiled_plan_digest,
        })
    }
}

impl HydratedDetectorPlanSection {
    pub(crate) fn into_direct_parts(
        self,
    ) -> (
        Arc<[DetectorPlanRecord]>,
        Arc<crate::decode::CompiledDecoderPlan>,
        [u8; 32],
    ) {
        (self.detectors, self.decoder_plan, self.compiled_plan_digest)
    }

    pub(crate) fn into_schema_parts(
        self,
    ) -> (
        Arc<[keyhog_core::DetectorSpec]>,
        Arc<crate::decode::CompiledDecoderPlan>,
    ) {
        DETECTOR_SPEC_SCHEMA_RECONSTRUCTIONS
            .fetch_add(self.detectors.len(), std::sync::atomic::Ordering::Relaxed);
        let detectors = self
            .detectors
            .iter()
            .cloned()
            .map(DetectorPlanRecord::into_detector_spec)
            .collect::<Vec<_>>()
            .into();
        (detectors, self.decoder_plan)
    }

    pub(crate) const fn detector_ir_digest(&self) -> [u8; 32] {
        self.detector_ir_digest
    }
}

fn detector_order_digest<'a>(ids: impl Iterator<Item = &'a str>) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"keyhog-detector-plan-order-v1\0");
    for id in ids {
        hasher.update(&(id.len() as u64).to_le_bytes());
        hasher.update(id.as_bytes());
    }
    *hasher.finalize().as_bytes()
}

fn canonical_json<T: Serialize>(value: &T, operation: &str) -> Result<Vec<u8>, ExecutionPackError> {
    serde_json::to_vec(value).map_err(|error| {
        ExecutionPackError::InvalidCompilerInput(format!(
            "cannot {operation} detector-plan section: {error}"
        ))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section() -> (CompiledDetectorPlanSection, [u8; 32]) {
        let detectors = ["a-plan", "b-plan"].map(|id| keyhog_core::DetectorSpec {
            id: id.to_owned(),
            name: format!("{id} fixture"),
            service: "detector-plan-fixture".to_owned(),
            ..keyhog_core::DetectorSpec::default()
        });
        let ir = CanonicalDetectorExecutionIr::compile(&detectors).expect("compile IR");
        (
            CompiledDetectorPlanSection::compile(&ir).expect("compile detector plan"),
            ir.digest(),
        )
    }

    fn replace_once(bytes: &mut [u8], old: &[u8], new: &[u8]) {
        assert_eq!(old.len(), new.len());
        let offset = bytes
            .windows(old.len())
            .position(|window| window == old)
            .expect("fixture contains field");
        bytes[offset..offset + old.len()].copy_from_slice(new);
    }

    #[test]
    fn detector_plan_round_trip_binds_count_order_and_digest() {
        let (section, digest) = section();
        let hydrated =
            CompiledDetectorPlanSection::decode(section.as_bytes(), digest).expect("decode");
        assert_eq!(hydrated.detector_ir_digest(), digest);
        assert_eq!(hydrated.detectors().len(), 2);
        assert_eq!(hydrated.detectors()[0].id, "a-plan");
        assert_eq!(hydrated.detectors()[1].id, "b-plan");

        let mut wrong_digest = digest;
        wrong_digest[0] ^= 0xff;
        assert!(
            CompiledDetectorPlanSection::decode(section.as_bytes(), wrong_digest)
                .expect_err("DetectorIr digest drift must fail")
                .to_string()
                .contains("another DetectorIr digest")
        );
    }

    #[test]
    fn detector_plan_rejects_version_count_order_and_truncation() {
        let (section, digest) = section();
        let mut version = section.as_bytes().to_vec();
        replace_once(&mut version, b"\"version\":1", b"\"version\":9");
        assert!(CompiledDetectorPlanSection::decode(&version, digest)
            .expect_err("version drift must fail")
            .to_string()
            .contains("version 9"));

        let mut count = section.as_bytes().to_vec();
        replace_once(&mut count, b"\"detector_count\":2", b"\"detector_count\":9");
        assert!(CompiledDetectorPlanSection::decode(&count, digest)
            .expect_err("count drift must fail")
            .to_string()
            .contains("does not match"));

        let mut order = section.as_bytes().to_vec();
        replace_once(&mut order, b"\"id\":\"a-plan\"", b"\"id\":\"z-plan\"");
        assert!(CompiledDetectorPlanSection::decode(&order, digest)
            .expect_err("order drift must fail")
            .to_string()
            .contains("order"));

        let truncated = &section.as_bytes()[..section.as_bytes().len() - 1];
        assert!(CompiledDetectorPlanSection::decode(truncated, digest)
            .expect_err("truncation must fail")
            .to_string()
            .contains("truncated"));
    }
}

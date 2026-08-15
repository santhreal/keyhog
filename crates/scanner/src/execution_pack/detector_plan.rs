use super::{CanonicalDetectorExecutionIr, ExecutionPackError};
use serde::de::{IgnoredAny, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::BTreeSet;
use std::sync::Arc;

pub const DETECTOR_PLAN_SECTION_VERSION: u16 = 2;
const DETECTOR_PLAN_MAGIC: [u8; 8] = *b"KHDPPLAN";
const DETECTOR_PLAN_HEADER_LEN: usize = 146;
const MAX_DETECTORS: usize = 16_384;
const MAX_DECODERS: usize = 256;
const MAX_DECODER_IDENTITY_BYTES: usize = 256;
const MAX_RECORD_BYTES: usize = 8 * 1024 * 1024;
const MAX_SECTION_BYTES: usize = 64 * 1024 * 1024;
static DETECTOR_SPEC_SCHEMA_RECONSTRUCTIONS: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);
thread_local! {
    static LIVE_WIRE_ROWS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
    static PEAK_LIVE_WIRE_ROWS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
}

#[doc(hidden)]
pub fn detector_spec_schema_reconstructions() -> usize {
    DETECTOR_SPEC_SCHEMA_RECONSTRUCTIONS.load(std::sync::atomic::Ordering::Relaxed)
}

#[doc(hidden)]
pub fn detector_plan_live_wire_rows() -> usize {
    LIVE_WIRE_ROWS.get()
}

#[doc(hidden)]
pub fn detector_plan_peak_live_wire_rows() -> usize {
    PEAK_LIVE_WIRE_ROWS.get()
}

pub(crate) fn reset_detector_plan_ownership_telemetry() {
    assert_eq!(detector_plan_live_wire_rows(), 0);
    PEAK_LIVE_WIRE_ROWS.set(0);
}

/// Explicit stable source facts required to rebuild one compiled detector plan.
/// Self-tests, verification configuration, and other non-runtime schema fields
/// are intentionally absent.
#[derive(Debug, Serialize, Deserialize)]
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

pub(crate) struct DetectorPlanPreludePatternCount(usize);

impl DetectorPlanPreludePatternCount {
    pub(crate) const fn len(&self) -> usize {
        self.0
    }
}

impl<'de> Deserialize<'de> for DetectorPlanPreludePatternCount {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct PatternCountVisitor;

        impl<'de> Visitor<'de> for PatternCountVisitor {
            type Value = DetectorPlanPreludePatternCount;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a detector pattern array")
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut count = 0usize;
                while sequence.next_element::<IgnoredAny>()?.is_some() {
                    count = count.saturating_add(1);
                }
                Ok(DetectorPlanPreludePatternCount(count))
            }
        }

        deserializer.deserialize_seq(PatternCountVisitor)
    }
}

#[derive(Deserialize)]
pub(crate) struct DetectorPlanPreludeRecord<'a> {
    pub(crate) id: &'a str,
    pub(crate) name: &'a str,
    pub(crate) service: &'a str,
    pub(crate) patterns: DetectorPlanPreludePatternCount,
    pub(crate) companion_names: Vec<&'a str>,
    #[serde(borrow)]
    pub(crate) entropy_fallback: Option<DetectorPlanPreludeEntropyFallback<'a>>,
}

#[derive(Deserialize)]
pub(crate) struct DetectorPlanPreludeEntropyFallback<'a> {
    pub(crate) id: &'a str,
    pub(crate) name: &'a str,
    pub(crate) service: &'a str,
}

impl DetectorPlanRecord {
    pub(crate) fn compile(spec: &keyhog_core::DetectorSpec) -> Self {
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

#[derive(Clone, Debug)]
pub struct CompiledDetectorPlanSection {
    bytes: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct HydratedDetectorPlanHeader {
    pub(crate) decoder_plan: Arc<crate::decode::CompiledDecoderPlan>,
    pub(crate) detector_ir_digest: [u8; 32],
    pub(crate) compiled_plan_digest: [u8; 32],
    pub(crate) detector_count: usize,
}

struct WireRowResidency;

impl WireRowResidency {
    fn enter() -> Self {
        LIVE_WIRE_ROWS.set(LIVE_WIRE_ROWS.get() + 1);
        PEAK_LIVE_WIRE_ROWS.set(PEAK_LIVE_WIRE_ROWS.get().max(LIVE_WIRE_ROWS.get()));
        Self
    }
}

impl Drop for WireRowResidency {
    fn drop(&mut self) {
        LIVE_WIRE_ROWS.set(LIVE_WIRE_ROWS.get() - 1);
    }
}

impl CompiledDetectorPlanSection {
    pub fn compile(ir: &CanonicalDetectorExecutionIr) -> Result<Self, ExecutionPackError> {
        let detector_count = ir.detectors().len();
        if detector_count > MAX_DETECTORS {
            return Err(ExecutionPackError::InvalidCompilerInput(format!(
                "detector plan has {detector_count} detectors; maximum is {MAX_DETECTORS}"
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
        let detector_count = u32::try_from(detector_count).map_err(|_| {
            ExecutionPackError::InvalidCompilerInput("detector-plan count exceeds u32".to_owned())
        })?;
        let compiled_plan_digest = crate::compiled_scanner::detector_digest::from_execution_plan(
            keyhog_core::compute_spec_hash(ir.detectors()),
            decoder_plan.identity(),
        );
        let order_digest =
            detector_order_digest(ir.detectors().iter().map(|detector| detector.id.as_str()));
        let decoder_count = decoder_identities.len() as u16;
        let mut payload_hasher = detector_payload_hasher(
            ir.digest(),
            compiled_plan_digest,
            order_digest,
            detector_count,
            decoder_count,
        );
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&DETECTOR_PLAN_MAGIC);
        bytes.extend_from_slice(&DETECTOR_PLAN_SECTION_VERSION.to_le_bytes());
        bytes.extend_from_slice(&0u16.to_le_bytes());
        bytes.extend_from_slice(&ir.digest());
        bytes.extend_from_slice(&compiled_plan_digest);
        bytes.extend_from_slice(&order_digest);
        bytes.extend_from_slice(&[0u8; 32]);
        bytes.extend_from_slice(&detector_count.to_le_bytes());
        bytes.extend_from_slice(&decoder_count.to_le_bytes());
        debug_assert_eq!(bytes.len(), DETECTOR_PLAN_HEADER_LEN);

        for identity in decoder_identities {
            let identity_bytes = identity.as_bytes();
            if identity_bytes.is_empty() || identity_bytes.len() > MAX_DECODER_IDENTITY_BYTES {
                return Err(ExecutionPackError::InvalidCompilerInput(format!(
                    "decoder identity has {} bytes; expected 1..={MAX_DECODER_IDENTITY_BYTES}",
                    identity_bytes.len()
                )));
            }
            let length = (identity_bytes.len() as u16).to_le_bytes();
            payload_hasher.update(&length);
            payload_hasher.update(identity_bytes);
            bytes.extend_from_slice(&length);
            bytes.extend_from_slice(identity_bytes);
        }
        for detector in ir.detectors() {
            let record = DetectorPlanRecord::compile(detector);
            let payload = canonical_json(&record, "serialize detector-plan record")?;
            if payload.len() > MAX_RECORD_BYTES {
                return Err(ExecutionPackError::InvalidCompilerInput(format!(
                    "detector-plan record {:?} is {} bytes; maximum is {MAX_RECORD_BYTES}",
                    detector.id,
                    payload.len()
                )));
            }
            let length = (payload.len() as u32).to_le_bytes();
            payload_hasher.update(&length);
            payload_hasher.update(&payload);
            bytes.extend_from_slice(&length);
            bytes.extend_from_slice(&payload);
            if bytes.len() > MAX_SECTION_BYTES {
                return Err(ExecutionPackError::InvalidCompilerInput(format!(
                    "detector-plan section is {} bytes; maximum is {MAX_SECTION_BYTES}",
                    bytes.len()
                )));
            }
        }
        bytes[108..140].copy_from_slice(payload_hasher.finalize().as_bytes());
        Ok(Self { bytes })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    fn stream_payloads<F>(
        bytes: &[u8],
        expected_detector_ir_digest: [u8; 32],
        mut visit: F,
    ) -> Result<HydratedDetectorPlanHeader, ExecutionPackError>
    where
        F: FnMut(usize, &[u8]) -> Result<Arc<str>, ExecutionPackError>,
    {
        if bytes.len() > MAX_SECTION_BYTES {
            return Err(ExecutionPackError::InvalidPack(format!(
                "detector-plan section is {} bytes; maximum is {MAX_SECTION_BYTES}",
                bytes.len()
            )));
        }
        if bytes.len() < DETECTOR_PLAN_HEADER_LEN {
            return Err(ExecutionPackError::InvalidPack(
                "detector-plan section is truncated before its fixed header".to_owned(),
            ));
        }
        if bytes[..8] != DETECTOR_PLAN_MAGIC {
            return Err(ExecutionPackError::InvalidPack(
                "detector-plan section has invalid magic".to_owned(),
            ));
        }
        let version = u16::from_le_bytes([bytes[8], bytes[9]]);
        if version != DETECTOR_PLAN_SECTION_VERSION {
            return Err(ExecutionPackError::Incompatible(format!(
                "detector-plan version {version} is unsupported; this binary requires {DETECTOR_PLAN_SECTION_VERSION}"
            )));
        }
        if bytes[10..12] != [0, 0] {
            return Err(ExecutionPackError::Incompatible(
                "detector-plan section uses unsupported flags".to_owned(),
            ));
        }
        let detector_ir_digest = read_digest(bytes, 12);
        if detector_ir_digest != expected_detector_ir_digest {
            return Err(ExecutionPackError::Incompatible(
                "detector plan belongs to another DetectorIr digest".to_owned(),
            ));
        }
        let compiled_plan_digest = read_digest(bytes, 44);
        let expected_order_digest = read_digest(bytes, 76);
        let expected_payload_digest = read_digest(bytes, 108);
        let detector_count = u32::from_le_bytes(
            bytes[140..144]
                .try_into()
                .expect("fixed detector-plan header bounds"),
        ) as usize;
        if detector_count > MAX_DETECTORS {
            return Err(ExecutionPackError::InvalidPack(format!(
                "detector plan has {detector_count} detectors; maximum is {MAX_DETECTORS}"
            )));
        }
        let decoder_count = u16::from_le_bytes([bytes[144], bytes[145]]) as usize;
        if decoder_count > MAX_DECODERS {
            return Err(ExecutionPackError::InvalidPack(format!(
                "detector plan has {decoder_count} decoder identities; maximum is {MAX_DECODERS}"
            )));
        }
        let mut cursor = DETECTOR_PLAN_HEADER_LEN;
        let mut decoder_identities = Vec::with_capacity(decoder_count);
        let mut unique_decoders = BTreeSet::new();
        let mut payload_hasher = detector_payload_hasher(
            detector_ir_digest,
            compiled_plan_digest,
            expected_order_digest,
            detector_count as u32,
            decoder_count as u16,
        );
        for _ in 0..decoder_count {
            let length_bytes = take(bytes, &mut cursor, 2, "decoder identity length")?;
            payload_hasher.update(length_bytes);
            let length = u16::from_le_bytes([length_bytes[0], length_bytes[1]]) as usize;
            if length == 0 || length > MAX_DECODER_IDENTITY_BYTES {
                return Err(ExecutionPackError::InvalidPack(format!(
                    "detector-plan decoder identity has {length} bytes; expected 1..={MAX_DECODER_IDENTITY_BYTES}"
                )));
            }
            let raw = take(bytes, &mut cursor, length, "decoder identity")?;
            payload_hasher.update(raw);
            let identity = std::str::from_utf8(raw).map_err(|error| {
                ExecutionPackError::InvalidPack(format!(
                    "detector-plan decoder identity is not UTF-8: {error}"
                ))
            })?;
            if !unique_decoders.insert(identity) {
                return Err(ExecutionPackError::InvalidPack(
                    "detector plan contains a duplicate decoder identity".to_owned(),
                ));
            }
            decoder_identities.push(identity.to_owned());
        }
        let decoder_plan =
            crate::decode::CompiledDecoderPlan::from_stable_identities(&decoder_identities)
                .map_err(|error| ExecutionPackError::Incompatible(error.to_string()))?;

        let mut order_hasher = detector_order_hasher();
        let mut previous_id: Option<Arc<str>> = None;
        for index in 0..detector_count {
            let length_bytes = take(bytes, &mut cursor, 4, "detector record length")?;
            payload_hasher.update(length_bytes);
            let payload_len = u32::from_le_bytes(
                length_bytes
                    .try_into()
                    .expect("four-byte detector record length"),
            ) as usize;
            if payload_len == 0 || payload_len > MAX_RECORD_BYTES {
                return Err(ExecutionPackError::InvalidPack(format!(
                    "detector-plan record {index} has {payload_len} bytes; expected 1..={MAX_RECORD_BYTES}"
                )));
            }
            let payload = take(bytes, &mut cursor, payload_len, "detector record payload")?;
            payload_hasher.update(payload);
            let record_id = visit(index, payload)?;
            if record_id.is_empty()
                || previous_id
                    .as_deref()
                    .is_some_and(|previous| previous >= record_id.as_ref())
            {
                return Err(ExecutionPackError::InvalidPack(format!(
                    "detector-plan record {index} has an empty, duplicate, or noncanonical detector ID"
                )));
            }
            update_detector_order_hasher(&mut order_hasher, record_id.as_ref());
            previous_id = Some(record_id);
        }
        if cursor != bytes.len() {
            return Err(ExecutionPackError::InvalidPack(format!(
                "detector-plan section has {} trailing bytes",
                bytes.len() - cursor
            )));
        }
        if *payload_hasher.finalize().as_bytes() != expected_payload_digest {
            return Err(ExecutionPackError::InvalidPack(
                "detector-plan payload digest does not match its framed rows".to_owned(),
            ));
        }
        if *order_hasher.finalize().as_bytes() != expected_order_digest {
            return Err(ExecutionPackError::InvalidPack(
                "detector-plan detector order digest does not match its rows".to_owned(),
            ));
        }
        Ok(HydratedDetectorPlanHeader {
            decoder_plan: Arc::new(decoder_plan),
            detector_ir_digest,
            compiled_plan_digest,
            detector_count,
        })
    }

    pub(crate) fn stream_prelude_records<F>(
        bytes: &[u8],
        expected_detector_ir_digest: [u8; 32],
        mut visit: F,
    ) -> Result<HydratedDetectorPlanHeader, ExecutionPackError>
    where
        F: for<'row> FnMut(
            usize,
            DetectorPlanPreludeRecord<'row>,
        ) -> Result<Arc<str>, ExecutionPackError>,
    {
        Self::stream_payloads(bytes, expected_detector_ir_digest, |index, payload| {
            let record: DetectorPlanPreludeRecord<'_> =
                serde_json::from_slice(payload).map_err(|error| {
                    ExecutionPackError::InvalidPack(format!(
                        "detector-plan prelude record {index} is invalid or truncated: {error}"
                    ))
                })?;
            let _residency = WireRowResidency::enter();
            visit(index, record)
        })
    }

    pub(crate) fn stream_records<F>(
        bytes: &[u8],
        expected_detector_ir_digest: [u8; 32],
        mut visit: F,
    ) -> Result<HydratedDetectorPlanHeader, ExecutionPackError>
    where
        F: FnMut(usize, DetectorPlanRecord) -> Result<(), ExecutionPackError>,
    {
        Self::stream_payloads(bytes, expected_detector_ir_digest, |index, payload| {
            let record: DetectorPlanRecord = serde_json::from_slice(payload).map_err(|error| {
                ExecutionPackError::InvalidPack(format!(
                    "detector-plan record {index} is invalid or truncated: {error}"
                ))
            })?;
            // Install-time compilation owns canonical JSON encoding. Runtime
            // authentication binds these exact framed bytes, so hydration only
            // needs the typed decode instead of serializing every row again.
            let record_id = Arc::<str>::from(record.id.as_str());
            let _residency = WireRowResidency::enter();
            visit(index, record)?;
            Ok(record_id)
        })
    }

    pub(crate) fn decode_schema(
        bytes: &[u8],
        expected_detector_ir_digest: [u8; 32],
    ) -> Result<(Arc<[keyhog_core::DetectorSpec]>, HydratedDetectorPlanHeader), ExecutionPackError>
    {
        let mut detectors = Vec::new();
        let header = Self::stream_records(bytes, expected_detector_ir_digest, |_, record| {
            DETECTOR_SPEC_SCHEMA_RECONSTRUCTIONS.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            detectors.push(record.into_detector_spec());
            Ok(())
        })?;
        if detectors.len() != header.detector_count {
            return Err(ExecutionPackError::InvalidPack(
                "detector-plan row count changed during schema reconstruction".to_owned(),
            ));
        }
        Ok((detectors.into(), header))
    }
}

fn read_digest(bytes: &[u8], offset: usize) -> [u8; 32] {
    bytes[offset..offset + 32]
        .try_into()
        .expect("fixed detector-plan header bounds")
}

fn take<'a>(
    bytes: &'a [u8],
    cursor: &mut usize,
    length: usize,
    field: &str,
) -> Result<&'a [u8], ExecutionPackError> {
    let end = cursor.checked_add(length).ok_or_else(|| {
        ExecutionPackError::InvalidPack(format!("detector-plan {field} length overflows"))
    })?;
    let value = bytes.get(*cursor..end).ok_or_else(|| {
        ExecutionPackError::InvalidPack(format!("detector-plan section is truncated in {field}"))
    })?;
    *cursor = end;
    Ok(value)
}

fn detector_payload_hasher(
    detector_ir_digest: [u8; 32],
    compiled_plan_digest: [u8; 32],
    detector_order_digest: [u8; 32],
    detector_count: u32,
    decoder_count: u16,
) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"keyhog-detector-plan-payload-v2\0");
    hasher.update(&detector_ir_digest);
    hasher.update(&compiled_plan_digest);
    hasher.update(&detector_order_digest);
    hasher.update(&detector_count.to_le_bytes());
    hasher.update(&decoder_count.to_le_bytes());
    hasher
}

fn detector_order_hasher() -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"keyhog-detector-plan-order-v1\0");
    hasher
}

fn update_detector_order_hasher(hasher: &mut blake3::Hasher, id: &str) {
    hasher.update(&(id.len() as u64).to_le_bytes());
    hasher.update(id.as_bytes());
}

fn detector_order_digest<'a>(ids: impl Iterator<Item = &'a str>) -> [u8; 32] {
    let mut hasher = detector_order_hasher();
    for id in ids {
        update_detector_order_hasher(&mut hasher, id);
    }
    *hasher.finalize().as_bytes()
}

fn canonical_json<T: Serialize>(value: &T, operation: &str) -> Result<Vec<u8>, ExecutionPackError> {
    serde_json::to_vec(value).map_err(|error| {
        ExecutionPackError::InvalidCompilerInput(format!("cannot {operation}: {error}"))
    })
}

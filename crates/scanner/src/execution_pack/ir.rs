use super::ExecutionPackError;
use keyhog_core::DetectorSpec;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;

static EMBEDDED_CANONICAL_IR: std::sync::LazyLock<
    Result<CanonicalDetectorExecutionIr, ExecutionPackError>,
> = std::sync::LazyLock::new(|| {
    let specs = keyhog_core::embedded_detector_specs();
    CanonicalDetectorExecutionIr::compile(specs)
});

pub const DETECTOR_EXECUTION_IR_VERSION: u16 = 1;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NormalizedDetectorMetadata {
    pub strings: Vec<String>,
    pub detectors: Vec<DetectorMetadataRecord>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DetectorMetadataRecord {
    pub id: u32,
    pub name: u32,
    pub service: u32,
    pub entropy_fallback: Option<EntropyFallbackMetadataRecord>,
    pub companion_names: Vec<u32>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EntropyFallbackMetadataRecord {
    pub id: u32,
    pub name: u32,
    pub service: u32,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DetectorExecutionIrEnvelope {
    version: u16,
    metadata: NormalizedDetectorMetadata,
    detectors: Vec<DetectorSpec>,
}

/// Canonical, validated detector execution input compiled during installation.
///
/// Detector order and self-test fixtures do not affect scanning. Compilation
/// sorts declarations by stable ID and removes tests before serialization, so
/// every backend program and pack identity consumes exactly one normalized IR.
#[derive(Clone, Debug)]
pub struct CanonicalDetectorExecutionIr {
    envelope: DetectorExecutionIrEnvelope,
    bytes: Vec<u8>,
    digest: [u8; 32],
}

/// Validated runtime detector IR without a second owned copy of its canonical
/// JSON bytes.
#[derive(Clone, Debug)]
pub struct DecodedDetectorExecutionIr {
    envelope: DetectorExecutionIrEnvelope,
    digest: [u8; 32],
}

impl CanonicalDetectorExecutionIr {
    pub fn compile(detectors: &[DetectorSpec]) -> Result<Self, ExecutionPackError> {
        if detectors.is_empty() {
            return Err(ExecutionPackError::InvalidCompilerInput(
                "detector execution IR has no detectors".to_owned(),
            ));
        }
        let mut normalized = detectors.to_vec();
        normalized.sort_unstable_by(|left, right| left.id.cmp(&right.id));
        let mut ids = BTreeSet::new();
        for detector in &mut normalized {
            if detector.id.is_empty() {
                return Err(ExecutionPackError::InvalidCompilerInput(
                    "detector execution IR contains an empty detector ID".to_owned(),
                ));
            }
            if !ids.insert(detector.id.clone()) {
                return Err(ExecutionPackError::InvalidCompilerInput(format!(
                    "detector execution IR repeats detector ID {:?}",
                    detector.id
                )));
            }
            detector.tests.clear();
        }
        let metadata = normalize_metadata(&normalized)?;
        let envelope = DetectorExecutionIrEnvelope {
            version: DETECTOR_EXECUTION_IR_VERSION,
            metadata,
            detectors: normalized,
        };
        Self::from_envelope(envelope)
    }
    /// Return the canonical execution IR compiled from the embedded detector corpus.
    ///
    /// Parsed and compiled at most once across the entire process lifetime.
    pub fn embedded() -> Result<&'static Self, ExecutionPackError> {
        EMBEDDED_CANONICAL_IR.as_ref().map_err(|err| err.clone())
    }

    /// Return the exact 32-byte BLAKE3 digest of the canonical embedded detector execution IR.
    pub fn embedded_digest() -> Result<[u8; 32], ExecutionPackError> {
        Self::embedded().map(|ir| ir.digest())
    }

    pub fn is_embedded_corpus(detectors: &[DetectorSpec]) -> bool {
        std::ptr::eq(detectors, keyhog_core::embedded_detector_specs())
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ExecutionPackError> {
        let decoded = DecodedDetectorExecutionIr::decode(bytes)?;
        Ok(Self {
            envelope: decoded.envelope,
            bytes: bytes.to_vec(),
            digest: decoded.digest,
        })
    }

    pub fn decode_runtime(bytes: &[u8]) -> Result<DecodedDetectorExecutionIr, ExecutionPackError> {
        DecodedDetectorExecutionIr::decode(bytes)
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }

    pub fn detectors(&self) -> &[DetectorSpec] {
        &self.envelope.detectors
    }

    pub fn into_detectors(self) -> Vec<DetectorSpec> {
        self.envelope.detectors
    }

    pub fn metadata(&self) -> &NormalizedDetectorMetadata {
        &self.envelope.metadata
    }

    fn from_envelope(
        mut envelope: DetectorExecutionIrEnvelope,
    ) -> Result<Self, ExecutionPackError> {
        envelope
            .detectors
            .sort_unstable_by(|left, right| left.id.cmp(&right.id));
        let mut ids = BTreeSet::new();
        for detector in &mut envelope.detectors {
            if detector.id.is_empty() || !ids.insert(detector.id.clone()) {
                return Err(ExecutionPackError::InvalidPack(
                    "detector execution IR contains an empty or duplicate detector ID".to_owned(),
                ));
            }
            detector.tests.clear();
        }
        let expected_metadata = normalize_metadata(&envelope.detectors)?;
        if envelope.metadata != expected_metadata {
            return Err(ExecutionPackError::InvalidPack(
                "detector execution IR normalized metadata does not match detector policy"
                    .to_owned(),
            ));
        }
        let bytes = serde_json::to_vec(&envelope).map_err(|error| {
            ExecutionPackError::InvalidCompilerInput(format!(
                "cannot serialize canonical detector execution IR: {error}"
            ))
        })?;
        let digest = *blake3::hash(&bytes).as_bytes();
        Ok(Self {
            envelope,
            bytes,
            digest,
        })
    }
}

impl DecodedDetectorExecutionIr {
    fn decode(bytes: &[u8]) -> Result<Self, ExecutionPackError> {
        let mut envelope: DetectorExecutionIrEnvelope =
            serde_json::from_slice(bytes).map_err(|error| {
                ExecutionPackError::InvalidPack(format!(
                    "canonical detector execution IR is invalid: {error}"
                ))
            })?;
        if envelope.version != DETECTOR_EXECUTION_IR_VERSION {
            return Err(ExecutionPackError::Incompatible(format!(
                "detector execution IR version {} is unsupported; this binary requires {}",
                envelope.version, DETECTOR_EXECUTION_IR_VERSION
            )));
        }
        envelope
            .detectors
            .sort_unstable_by(|left, right| left.id.cmp(&right.id));
        let mut ids = BTreeSet::new();
        for detector in &mut envelope.detectors {
            if detector.id.is_empty() || !ids.insert(detector.id.clone()) {
                return Err(ExecutionPackError::InvalidPack(
                    "detector execution IR contains an empty or duplicate detector ID".to_owned(),
                ));
            }
            detector.tests.clear();
        }
        let expected_metadata = normalize_metadata(&envelope.detectors)?;
        if envelope.metadata != expected_metadata {
            return Err(ExecutionPackError::InvalidPack(
                "detector execution IR normalized metadata does not match detector policy"
                    .to_owned(),
            ));
        }
        if !canonical_json_matches(&envelope, bytes)? {
            return Err(ExecutionPackError::InvalidPack(
                "detector execution IR is not in canonical byte order; reinstall this generation"
                    .to_owned(),
            ));
        }
        Ok(Self {
            envelope,
            digest: *blake3::hash(bytes).as_bytes(),
        })
    }

    pub fn detectors(&self) -> &[DetectorSpec] {
        &self.envelope.detectors
    }

    pub fn into_detectors(self) -> Vec<DetectorSpec> {
        self.envelope.detectors
    }

    pub const fn digest(&self) -> [u8; 32] {
        self.digest
    }
}

fn canonical_json_matches<T: Serialize>(
    value: &T,
    expected: &[u8],
) -> Result<bool, ExecutionPackError> {
    struct ExactWriter<'a> {
        expected: &'a [u8],
        position: usize,
        matches: bool,
    }

    impl Write for ExactWriter<'_> {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            let end = self.position.checked_add(bytes.len()).ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "canonical detector IR length overflow",
                )
            })?;
            if self.expected.get(self.position..end) != Some(bytes) {
                self.matches = false;
            }
            self.position = end;
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let mut writer = ExactWriter {
        expected,
        position: 0,
        matches: true,
    };
    serde_json::to_writer(&mut writer, value).map_err(|error| {
        ExecutionPackError::InvalidPack(format!(
            "cannot validate canonical detector execution IR bytes: {error}"
        ))
    })?;
    Ok(writer.matches && writer.position == expected.len())
}

fn normalize_metadata(
    detectors: &[DetectorSpec],
) -> Result<NormalizedDetectorMetadata, ExecutionPackError> {
    let mut unique = BTreeSet::<String>::new();
    for detector in detectors {
        for value in [&detector.id, &detector.name, &detector.service] {
            if value.is_empty() {
                return Err(ExecutionPackError::InvalidCompilerInput(
                    "detector metadata contains an empty identity string".to_owned(),
                ));
            }
            unique.insert(value.clone());
        }
        if let Some(fallback) = &detector.entropy_fallback {
            for value in [&fallback.id, &fallback.name, &fallback.service] {
                if value.is_empty() {
                    return Err(ExecutionPackError::InvalidCompilerInput(
                        "entropy fallback metadata contains an empty identity string".to_owned(),
                    ));
                }
                unique.insert(value.clone());
            }
        }
        for companion in &detector.companions {
            if companion.name.is_empty() {
                return Err(ExecutionPackError::InvalidCompilerInput(
                    "companion metadata contains an empty name".to_owned(),
                ));
            }
            unique.insert(companion.name.clone());
        }
    }
    let strings = unique.into_iter().collect::<Vec<_>>();
    let ids = strings
        .iter()
        .enumerate()
        .map(|(index, value)| {
            u32::try_from(index)
                .map(|index| (value.as_str(), index))
                .map_err(|_| {
                    ExecutionPackError::InvalidCompilerInput(
                        "normalized detector metadata exceeds u32 string IDs".to_owned(),
                    )
                })
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    let id = |value: &str| -> u32 { ids[value] };
    let records = detectors
        .iter()
        .map(|detector| DetectorMetadataRecord {
            id: id(&detector.id),
            name: id(&detector.name),
            service: id(&detector.service),
            entropy_fallback: detector.entropy_fallback.as_ref().map(|fallback| {
                EntropyFallbackMetadataRecord {
                    id: id(&fallback.id),
                    name: id(&fallback.name),
                    service: id(&fallback.service),
                }
            }),
            companion_names: detector
                .companions
                .iter()
                .map(|companion| id(&companion.name))
                .collect(),
        })
        .collect();
    Ok(NormalizedDetectorMetadata {
        strings,
        detectors: records,
    })
}

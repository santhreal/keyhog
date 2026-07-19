//! One compiled runtime plan per detector TOML.
//!
//! Global matchers and indices still span detectors, but every detector-local
//! execution decision is reached through this single detector-indexed owner.

use keyhog_core::DetectorSpec;
use std::collections::HashMap;
use std::sync::Arc;

pub(crate) type CompiledDetectorMetadata = (Arc<str>, Arc<str>, Arc<str>);

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum DetectorResolutionClass {
    Named,
    Generic,
    Entropy,
    PrivateKeyBlock,
}

/// Canonical detector and emitted-fallback classification compiled from the
/// active detector corpus. Resolution never infers semantics from an ID when
/// this index owns that identity.
#[derive(Debug)]
pub(crate) struct DetectorResolutionIndex {
    by_id: HashMap<Arc<str>, DetectorResolutionClass>,
}

impl DetectorResolutionIndex {
    pub(crate) fn compile(detectors: &[DetectorSpec]) -> Result<Self, String> {
        let mut by_id = HashMap::with_capacity(detectors.len() * 2);
        for detector in detectors {
            let class = if detector.private_key_block {
                DetectorResolutionClass::PrivateKeyBlock
            } else if detector.kind == keyhog_core::DetectorKind::Phase2Generic {
                DetectorResolutionClass::Generic
            } else {
                DetectorResolutionClass::Named
            };
            insert_resolution_class(&mut by_id, Arc::from(detector.id.as_str()), class)?;
            if let Some(metadata) = &detector.entropy_fallback {
                insert_resolution_class(
                    &mut by_id,
                    Arc::from(metadata.id.as_str()),
                    DetectorResolutionClass::Entropy,
                )?;
            }
        }
        Ok(Self { by_id })
    }

    #[inline]
    pub(crate) fn get(&self, detector_id: &str) -> Option<DetectorResolutionClass> {
        self.by_id.get(detector_id).copied()
    }
}

#[derive(Debug)]
pub(crate) struct CompiledDetectorPlan {
    pub(crate) metadata: CompiledDetectorMetadata,
    pub(crate) entropy_metadata: Option<CompiledDetectorMetadata>,
    pub(crate) execution: crate::detector_execution_policy::CompiledDetectorExecutionPolicy,
    pub(crate) key_material: crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy,
    pub(crate) entropy_floor: Option<crate::entropy::policy::CompiledEntropyFloorPolicy>,
    pub(crate) entropy: Option<crate::entropy::policy::CompiledEntropyPolicy>,
    pub(crate) credential_shape: Option<crate::credential_shapes::CredentialShapeRule>,
    pub(crate) suppression: Option<crate::suppression::DetectorSuppressionPolicy>,
    pub(crate) validators: crate::checksum::CompiledDetectorValidators,
    pub(crate) weak_anchor_base: crate::suppression::WeakAnchorBase,
    pub(crate) companions: Box<[crate::types::CompiledCompanion]>,
    #[cfg(feature = "ml")]
    pub(crate) ml: crate::detector_ml_policy::CompiledDetectorMlPolicy,
}

impl CompiledDetectorPlan {
    #[inline]
    pub(crate) fn cloned_metadata(&self) -> CompiledDetectorMetadata {
        (
            Arc::clone(&self.metadata.0),
            Arc::clone(&self.metadata.1),
            Arc::clone(&self.metadata.2),
        )
    }

    #[inline]
    pub(crate) fn pattern_weak_anchor(&self, pattern_weak_anchor: bool) -> bool {
        match self.weak_anchor_base {
            crate::suppression::WeakAnchorBase::Always => true,
            crate::suppression::WeakAnchorBase::Never => false,
            crate::suppression::WeakAnchorBase::PerPattern => pattern_weak_anchor,
        }
    }
}

#[derive(Debug)]
pub(crate) struct CompiledDetectorPlans {
    by_detector_index: Box<[CompiledDetectorPlan]>,
    resolution: DetectorResolutionIndex,
    validator_index: crate::checksum::CompiledValidatorIndex,
    decode_transforms: Arc<crate::decode::policy::CompiledDecodeTransformPolicy>,
    decoder_plan: Arc<crate::decode::CompiledDecoderPlan>,
}

impl CompiledDetectorPlans {
    pub(crate) fn compile(
        detectors: &[DetectorSpec],
        interner: &crate::static_intern::StaticInterner,
        companions: Vec<Vec<crate::types::CompiledCompanion>>,
    ) -> Result<Self, String> {
        let decoder_plan = Arc::new(
            crate::decode::CompiledDecoderPlan::snapshot()
                .map_err(|error| format!("invalid decoder registry: {error}"))?,
        );
        Self::compile_with_decoder_plan(detectors, interner, companions, decoder_plan)
    }

    pub(crate) fn compile_with_decoder_plan(
        detectors: &[DetectorSpec],
        interner: &crate::static_intern::StaticInterner,
        companions: Vec<Vec<crate::types::CompiledCompanion>>,
        decoder_plan: Arc<crate::decode::CompiledDecoderPlan>,
    ) -> Result<Self, String> {
        if companions.len() != detectors.len() {
            return Err(format!(
                "compiled companion rows ({}) do not match detector count ({})",
                companions.len(),
                detectors.len()
            ));
        }
        let by_detector_index = detectors
                .iter()
                .zip(companions)
                .map(|(detector, companions)| {
                    let execution = crate::detector_execution_policy::CompiledDetectorExecutionPolicy::compile(
                        detector,
                    );
                    let entropy = crate::entropy::policy::compile_entropy_policy_with_length(
                        detector,
                        execution.length,
                    )?;
                    Ok(CompiledDetectorPlan {
                        metadata: compile_metadata(
                            interner,
                            &detector.id,
                            "primary",
                            &detector.id,
                            &detector.name,
                            &detector.service,
                        )?,
                        entropy_metadata: detector
                            .entropy_fallback
                            .as_ref()
                            .map(|metadata| {
                                compile_metadata(
                                    interner,
                                    &detector.id,
                                    "entropy fallback",
                                    &metadata.id,
                                    &metadata.name,
                                    &metadata.service,
                                )
                            })
                            .transpose()?,
                        execution,
                        key_material:
                            crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy::compile(
                                detector,
                            )?,
                        entropy_floor:
                            crate::entropy::policy::CompiledEntropyFloorPolicy::compile(detector)?,
                        entropy,
                        credential_shape:
                            crate::credential_shapes::compile_detector_shape_rule(detector)?,
                        suppression:
                            crate::suppression::DetectorSuppressionPolicy::compile(detector)?,
                        validators: crate::checksum::CompiledDetectorValidators::compile(detector)?,
                        weak_anchor_base: crate::suppression::detector_weak_anchor_base(detector),
                        companions: companions.into_boxed_slice(),
                        #[cfg(feature = "ml")]
                        ml: crate::detector_ml_policy::CompiledDetectorMlPolicy::compile(detector),
                    })
                })
                .collect::<Result<Box<[_]>, String>>()?;
        let resolution = DetectorResolutionIndex::compile(detectors)?;
        let validator_index = crate::checksum::CompiledValidatorIndex::compile(
            by_detector_index.iter().map(|plan| &plan.validators),
        );
        let decode_transforms =
            Arc::new(crate::decode::policy::CompiledDecodeTransformPolicy::compile(detectors)?);
        Ok(Self {
            by_detector_index,
            resolution,
            validator_index,
            decode_transforms,
            decoder_plan,
        })
    }

    #[inline]
    pub(crate) fn get(&self, detector_index: usize) -> &CompiledDetectorPlan {
        &self.by_detector_index[detector_index]
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.by_detector_index.len()
    }

    #[inline]
    pub(crate) fn resolution_class(&self, detector_id: &str) -> Option<DetectorResolutionClass> {
        self.resolution.get(detector_id)
    }

    #[inline]
    pub(crate) fn is_entropy(&self, detector_id: &str) -> bool {
        matches!(
            self.resolution_class(detector_id),
            Some(DetectorResolutionClass::Entropy)
        )
    }

    #[inline]
    #[cfg(feature = "decode")]
    pub(crate) fn decode_transforms(
        &self,
    ) -> &crate::decode::policy::CompiledDecodeTransformPolicy {
        &self.decode_transforms
    }

    #[inline]
    pub(crate) fn decode_transforms_arc(
        &self,
    ) -> Arc<crate::decode::policy::CompiledDecodeTransformPolicy> {
        Arc::clone(&self.decode_transforms)
    }

    #[inline]
    #[cfg(feature = "decode")]
    pub(crate) fn decoder_plan(&self) -> &crate::decode::CompiledDecoderPlan {
        &self.decoder_plan
    }

    #[inline]
    pub(crate) fn decoder_plan_arc(&self) -> Arc<crate::decode::CompiledDecoderPlan> {
        Arc::clone(&self.decoder_plan)
    }

    /// Resolve a generic candidate against detector-declared validators. Named
    /// detector paths call their own plan directly and never pay this index
    /// lookup. The first-byte table reduces the generic path to the handful of
    /// validators that can claim the candidate's literal prefix.
    pub(crate) fn validate_any(
        &self,
        credential: &str,
    ) -> crate::checksum::ChecksumConfidenceDecision {
        self.validator_index.validate_any(
            credential,
            |detector_index, validator_index, candidate| {
                self.by_detector_index[detector_index]
                    .validators
                    .validate_indexed(validator_index, candidate)
            },
        )
    }
}

fn insert_resolution_class(
    classes: &mut HashMap<Arc<str>, DetectorResolutionClass>,
    detector_id: Arc<str>,
    class: DetectorResolutionClass,
) -> Result<(), String> {
    if let Some(existing) = classes.insert(detector_id.clone(), class) {
        return Err(format!(
            "compiled detector identity {detector_id:?} has conflicting resolution classes {existing:?} and {class:?}"
        ));
    }
    Ok(())
}

fn compile_metadata(
    interner: &crate::static_intern::StaticInterner,
    detector_id: &str,
    identity_kind: &str,
    id: &str,
    name: &str,
    service: &str,
) -> Result<CompiledDetectorMetadata, String> {
    let resolve = |field: &str, value: &str| {
        interner.lookup(value).ok_or_else(|| {
            format!(
                "detector {detector_id:?} {identity_kind} {field} {value:?} is missing from the scanner metadata interner"
            )
        })
    };
    Ok((
        resolve("id", id)?,
        resolve("name", name)?,
        resolve("service", service)?,
    ))
}

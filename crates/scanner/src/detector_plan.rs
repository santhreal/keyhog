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
    validator_refs: Box<[ValidatorRef]>,
    validator_ref_offsets: [usize; 257],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ValidatorRef {
    detector_index: usize,
    validator_index: usize,
}

impl CompiledDetectorPlans {
    pub(crate) fn compile(
        detectors: &[DetectorSpec],
        interner: &crate::static_intern::StaticInterner,
        companions: Vec<Vec<crate::types::CompiledCompanion>>,
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
        let mut validator_refs: [Vec<ValidatorRef>; 256] = std::array::from_fn(|_| Vec::new());
        for (detector_index, plan) in by_detector_index.iter().enumerate() {
            for (validator_index, prefix) in plan.validators.indexed_prefixes() {
                let Some(first) = prefix.as_bytes().first().copied() else {
                    continue;
                };
                let validator_ref = ValidatorRef {
                    detector_index,
                    validator_index,
                };
                if !validator_refs[first as usize].contains(&validator_ref) {
                    validator_refs[first as usize].push(validator_ref);
                }
            }
        }
        let mut flat_validator_refs = Vec::new();
        let mut validator_ref_offsets = [0usize; 257];
        for (first, bucket) in validator_refs.into_iter().enumerate() {
            validator_ref_offsets[first] = flat_validator_refs.len();
            flat_validator_refs.extend(bucket);
        }
        validator_ref_offsets[256] = flat_validator_refs.len();
        Ok(Self {
            by_detector_index,
            resolution,
            validator_refs: flat_validator_refs.into_boxed_slice(),
            validator_ref_offsets,
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

    /// Resolve a generic candidate against detector-declared validators. Named
    /// detector paths call their own plan directly and never pay this index
    /// lookup. The first-byte table reduces the generic path to the handful of
    /// validators that can claim the candidate's literal prefix.
    pub(crate) fn validate_any(
        &self,
        credential: &str,
    ) -> crate::checksum::ChecksumConfidenceDecision {
        let Some(first) = credential.as_bytes().first().copied() else {
            return crate::checksum::ChecksumConfidenceDecision::not_applicable();
        };
        let mut invalid = None;
        let mut unknown = None;
        let mut structural = None;
        let first = first as usize;
        for validator_ref in &self.validator_refs
            [self.validator_ref_offsets[first]..self.validator_ref_offsets[first + 1]]
        {
            let decision = self.by_detector_index[validator_ref.detector_index]
                .validators
                .validate_indexed(validator_ref.validator_index, credential);
            match decision.result() {
                crate::checksum::ChecksumResult::Valid => return decision,
                crate::checksum::ChecksumResult::StructurallyValid => structural = Some(decision),
                crate::checksum::ChecksumResult::Invalid => invalid = Some(decision),
                crate::checksum::ChecksumResult::NotApplicable if decision.claims_family() => {
                    unknown = Some(decision)
                }
                crate::checksum::ChecksumResult::NotApplicable => {}
            }
        }
        structural
            .or(unknown)
            .or(invalid)
            .unwrap_or_else(crate::checksum::ChecksumConfidenceDecision::not_applicable)
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

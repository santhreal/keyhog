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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct DetectorResolutionPolicy {
    class: DetectorResolutionClass,
    priority: i16,
}

/// Canonical detector and emitted-fallback classification compiled from the
/// active detector corpus. Resolution never infers semantics from an ID when
/// this index owns that identity.
#[derive(Debug)]
pub(crate) struct DetectorResolutionIndex {
    by_id: HashMap<Arc<str>, DetectorResolutionPolicy>,
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
            insert_resolution_policy(
                &mut by_id,
                Arc::from(detector.id.as_str()),
                DetectorResolutionPolicy {
                    class,
                    priority: detector.resolution_priority,
                },
            )?;
            if let Some(metadata) = &detector.entropy_fallback {
                insert_resolution_policy(
                    &mut by_id,
                    Arc::from(metadata.id.as_str()),
                    DetectorResolutionPolicy {
                        class: DetectorResolutionClass::Entropy,
                        priority: detector.resolution_priority,
                    },
                )?;
            }
        }
        Ok(Self { by_id })
    }

    #[inline]
    pub(crate) fn get(&self, detector_id: &str) -> Option<DetectorResolutionClass> {
        self.by_id.get(detector_id).map(|policy| policy.class)
    }

    #[inline]
    pub(crate) fn priority(&self, detector_id: &str) -> Option<i16> {
        self.by_id.get(detector_id).map(|policy| policy.priority)
    }
}

#[derive(Debug)]
pub(crate) struct CompiledDetectorPlan {
    pub(crate) metadata: CompiledDetectorMetadata,
    pub(crate) entropy_metadata: Option<CompiledDetectorMetadata>,
    pub(crate) execution: crate::detector_execution_policy::CompiledDetectorExecutionPolicy,
    pub(crate) match_confidence: crate::confidence::policy::CompiledMatchConfidencePolicy,
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
    generic_assignment:
        Option<crate::engine::phase2_generic::keywords::GenericAssignmentKeywordPlan>,
    generic_named_assignment_keywords: Box<[Arc<str>]>,
    generic_ownership: crate::generic_keyword_owner::GenericOwningDetectorIndex,
    public_identifier_assignment_markers: Box<[Box<[u8]>]>,
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
                    )?;
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
                        match_confidence:
                            crate::confidence::policy::CompiledMatchConfidencePolicy::compile(
                                detector,
                            )?,
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
        let generic_assignment = by_detector_index
            .iter()
            .any(|plan| plan.execution.is_generic)
            .then(|| {
                crate::engine::phase2_generic::keywords::GenericAssignmentKeywordPlan::compile(
                    detectors,
                )
            })
            .transpose()?;
        let generic_named_assignment_keywords =
            crate::generic_keyword_owner::build_generic_named_assignment_keywords(detectors)
                .into_boxed_slice();
        let generic_ownership =
            crate::generic_keyword_owner::GenericOwningDetectorIndex::build(detectors)?;
        let resolution = DetectorResolutionIndex::compile(detectors)?;
        let validator_index = crate::checksum::CompiledValidatorIndex::compile(
            by_detector_index.iter().map(|plan| &plan.validators),
        );
        let decode_transforms =
            Arc::new(crate::decode::policy::CompiledDecodeTransformPolicy::compile(detectors)?);
        let mut public_identifier_assignment_markers: Vec<Box<[u8]>> = Vec::new();
        for marker in detectors
            .iter()
            .flat_map(|detector| &detector.public_identifier_assignment_markers)
        {
            let bytes = marker.as_bytes();
            if !public_identifier_assignment_markers
                .iter()
                .any(|compiled| compiled.eq_ignore_ascii_case(bytes))
            {
                public_identifier_assignment_markers.push(bytes.into());
            }
        }
        Ok(Self {
            by_detector_index,
            resolution,
            validator_index,
            decode_transforms,
            decoder_plan,
            generic_assignment,
            generic_named_assignment_keywords,
            generic_ownership,
            public_identifier_assignment_markers: public_identifier_assignment_markers
                .into_boxed_slice(),
        })
    }

    #[inline]
    pub(crate) fn generic_assignment(
        &self,
    ) -> Option<&crate::engine::phase2_generic::keywords::GenericAssignmentKeywordPlan> {
        self.generic_assignment.as_ref()
    }

    /// True when any detector-declared public identifier marker owns the
    /// assignment whose value begins at `value_start`.
    pub(crate) fn assignment_has_public_identifier(&self, line: &[u8], value_start: usize) -> bool {
        let Some(prefix) = line.get(..value_start) else {
            return false;
        };
        self.public_identifier_assignment_markers
            .iter()
            .any(|marker| {
                let marker = marker.as_ref();
                let mut cursor = 0;
                while cursor < prefix.len() {
                    let Some(relative) = crate::ascii_ci::ci_find_at(&prefix[cursor..], marker)
                    else {
                        break;
                    };
                    let end = cursor + relative + marker.len();
                    if prefix[end..]
                        .iter()
                        .all(|byte| byte.is_ascii_whitespace() || matches!(byte, b'\'' | b'"'))
                    {
                        return true;
                    }
                    cursor += relative + 1;
                }
                false
            })
    }

    #[inline]
    pub(crate) fn generic_named_assignment_keywords(&self) -> &[Arc<str>] {
        &self.generic_named_assignment_keywords
    }

    #[inline]
    pub(crate) fn generic_ownership(
        &self,
    ) -> &crate::generic_keyword_owner::GenericOwningDetectorIndex {
        &self.generic_ownership
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
    pub(crate) fn resolution_priority(&self, detector_id: &str) -> Option<i16> {
        self.resolution.priority(detector_id)
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
    #[cfg(feature = "decode")]
    pub(crate) fn decoded_source_parent<'a>(&self, source: &'a str) -> Option<&'a str> {
        let (parent, decoder_name) = source.rsplit_once('/')?;
        self.decoder_plan
            .decoders()
            .iter()
            .any(|decoder| decoder.name() == decoder_name)
            .then_some(parent)
    }

    #[inline]
    #[cfg(not(feature = "decode"))]
    pub(crate) fn decoded_source_parent<'a>(&self, _source: &'a str) -> Option<&'a str> {
        None
    }

    pub(crate) fn decoded_source_depth(&self, source: &str) -> usize {
        let mut depth = 0;
        let mut current = source;
        while let Some(parent) = self.decoded_source_parent(current) {
            depth += 1;
            current = parent;
        }
        depth
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

fn insert_resolution_policy(
    policies: &mut HashMap<Arc<str>, DetectorResolutionPolicy>,
    detector_id: Arc<str>,
    policy: DetectorResolutionPolicy,
) -> Result<(), String> {
    if let Some(existing) = policies.insert(detector_id.clone(), policy) {
        return Err(format!(
            "compiled detector identity {detector_id:?} has conflicting resolution policies {existing:?} and {policy:?}"
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

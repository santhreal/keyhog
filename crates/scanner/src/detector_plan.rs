//! One compiled runtime plan per detector TOML.
//!
//! Global matchers and indices still span detectors, but every detector-local
//! execution decision is reached through this single detector-indexed owner.

use keyhog_core::DetectorSpec;
use std::sync::Arc;

pub(crate) type CompiledDetectorMetadata = (Arc<str>, Arc<str>, Arc<str>);

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
        Ok(Self {
            by_detector_index: detectors
                .iter()
                .zip(companions)
                .map(|(detector, companions)| {
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
                        execution:
                            crate::detector_execution_policy::CompiledDetectorExecutionPolicy::compile(
                                detector,
                            ),
                        key_material:
                            crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy::compile(
                                detector,
                            ),
                        entropy_floor:
                            crate::entropy::policy::CompiledEntropyFloorPolicy::compile(detector)?,
                        entropy: crate::entropy::policy::compile_entropy_policy(detector)?,
                        credential_shape:
                            crate::credential_shapes::compile_detector_shape_rule(detector)?,
                        suppression:
                            crate::suppression::DetectorSuppressionPolicy::compile(detector)?,
                        weak_anchor_base: crate::suppression::detector_weak_anchor_base(detector),
                        companions: companions.into_boxed_slice(),
                        #[cfg(feature = "ml")]
                        ml: crate::detector_ml_policy::CompiledDetectorMlPolicy::compile(detector),
                    })
                })
                .collect::<Result<Box<[_]>, String>>()?,
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

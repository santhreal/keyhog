//! One compiled runtime plan per detector TOML.
//!
//! Global matchers and indices still span detectors, but every detector-local
//! execution decision is reached through this single detector-indexed owner.

use keyhog_core::DetectorSpec;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Arc;

trait DetectorPlanSource {
    fn id(&self) -> &str;
    fn kind(&self) -> keyhog_core::DetectorKind;
    fn private_key_block(&self) -> bool;
    fn resolution_priority(&self) -> i16;
    fn entropy_fallback(&self) -> Option<&keyhog_core::EntropyFallbackMetadata>;
    fn detector_relations(&self) -> &[keyhog_core::DetectorRelationSpec];
}

impl DetectorPlanSource for DetectorSpec {
    fn id(&self) -> &str {
        &self.id
    }
    fn kind(&self) -> keyhog_core::DetectorKind {
        self.kind
    }
    fn private_key_block(&self) -> bool {
        self.private_key_block
    }
    fn resolution_priority(&self) -> i16 {
        self.resolution_priority
    }
    fn entropy_fallback(&self) -> Option<&keyhog_core::EntropyFallbackMetadata> {
        self.entropy_fallback.as_ref()
    }
    fn detector_relations(&self) -> &[keyhog_core::DetectorRelationSpec] {
        &self.detector_relations
    }
}

impl DetectorPlanSource for crate::execution_pack::detector_plan::DetectorPlanRecord {
    fn id(&self) -> &str {
        &self.id
    }
    fn kind(&self) -> keyhog_core::DetectorKind {
        self.kind
    }
    fn private_key_block(&self) -> bool {
        self.private_key_block
    }
    fn resolution_priority(&self) -> i16 {
        self.resolution_priority
    }
    fn entropy_fallback(&self) -> Option<&keyhog_core::EntropyFallbackMetadata> {
        self.entropy_fallback.as_ref()
    }
    fn detector_relations(&self) -> &[keyhog_core::DetectorRelationSpec] {
        &self.detector_relations
    }
}

#[derive(Debug)]
pub(crate) struct StreamingDetectorPlanSummary {
    pub(crate) id: Arc<str>,
    pub(crate) service: Arc<str>,
    pub(crate) kind: keyhog_core::DetectorKind,
    pub(crate) private_key_block: bool,
    pub(crate) resolution_priority: i16,
    pub(crate) entropy_fallback: Option<keyhog_core::EntropyFallbackMetadata>,
    pub(crate) detector_relations: Vec<keyhog_core::DetectorRelationSpec>,
    pub(crate) decode_transforms: keyhog_core::DetectorDecodeTransformSpec,
    pub(crate) keywords: Vec<String>,
    pub(crate) generic_vendor_suffixes: Vec<String>,
    pub(crate) generic_assignment_tail_suffixes: Vec<String>,
    pub(crate) max_len: Option<usize>,
    pub(crate) entropy_policy_priority: Option<u16>,
    pub(crate) entropy_roles: Vec<keyhog_core::EntropyDetectionRole>,
    pub(crate) canonical_hex_key_material: Vec<keyhog_core::CanonicalHexKeyMaterialSpec>,
    pub(crate) public_identifier_assignment_markers: Vec<String>,
}

impl StreamingDetectorPlanSummary {
    fn from_record(
        record: crate::execution_pack::detector_plan::DetectorPlanRecord,
        metadata: &CompiledDetectorMetadata,
    ) -> Self {
        Self {
            id: Arc::clone(&metadata.0),
            service: Arc::clone(&metadata.2),
            kind: record.kind,
            private_key_block: record.private_key_block,
            resolution_priority: record.resolution_priority,
            entropy_fallback: record.entropy_fallback,
            detector_relations: record.detector_relations,
            decode_transforms: record.decode_transforms,
            keywords: record.keywords,
            generic_vendor_suffixes: record.generic_vendor_suffixes,
            generic_assignment_tail_suffixes: record.generic_assignment_tail_suffixes,
            max_len: record.max_len,
            entropy_policy_priority: record.entropy_policy_priority,
            entropy_roles: record.entropy_roles,
            canonical_hex_key_material: record.canonical_hex_key_material,
            public_identifier_assignment_markers: record.public_identifier_assignment_markers,
        }
    }

    #[inline]
    pub(crate) fn owns_entropy_policy(&self) -> bool {
        self.kind == keyhog_core::DetectorKind::Phase2Generic
            || self.entropy_policy_priority.is_some()
    }
}

impl DetectorPlanSource for StreamingDetectorPlanSummary {
    fn id(&self) -> &str {
        &self.id
    }
    fn kind(&self) -> keyhog_core::DetectorKind {
        self.kind
    }
    fn private_key_block(&self) -> bool {
        self.private_key_block
    }
    fn resolution_priority(&self) -> i16 {
        self.resolution_priority
    }
    fn entropy_fallback(&self) -> Option<&keyhog_core::EntropyFallbackMetadata> {
        self.entropy_fallback.as_ref()
    }
    fn detector_relations(&self) -> &[keyhog_core::DetectorRelationSpec] {
        &self.detector_relations
    }
}

pub(crate) type CompiledDetectorMetadata = (Arc<str>, Arc<str>, Arc<str>);

fn intern_detector_identity(
    interner: &crate::static_intern::StaticInterner,
    detector_id: &str,
    role: &str,
) -> Result<Arc<str>, String> {
    interner.lookup(detector_id).ok_or_else(|| {
        format!(
            "detector identity {detector_id:?} for {role} is missing from the scanner metadata interner"
        )
    })
}

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
    pub(crate) fn compile(
        detectors: &[DetectorSpec],
        interner: &crate::static_intern::StaticInterner,
    ) -> Result<Self, String> {
        Self::compile_from(detectors, interner)
    }

    fn compile_from<T: DetectorPlanSource>(
        detectors: &[T],
        interner: &crate::static_intern::StaticInterner,
    ) -> Result<Self, String> {
        let expected_rows = detectors.len()
            + detectors
                .iter()
                .filter(|detector| detector.entropy_fallback().is_some())
                .count();
        let mut by_id = HashMap::with_capacity(expected_rows);
        for detector in detectors {
            let class = if detector.private_key_block() {
                DetectorResolutionClass::PrivateKeyBlock
            } else if detector.kind() == keyhog_core::DetectorKind::Phase2Generic {
                DetectorResolutionClass::Generic
            } else {
                DetectorResolutionClass::Named
            };
            insert_resolution_policy(
                &mut by_id,
                intern_detector_identity(interner, detector.id(), "resolution owner")?,
                DetectorResolutionPolicy {
                    class,
                    priority: detector.resolution_priority(),
                },
            )?;
            if let Some(metadata) = detector.entropy_fallback() {
                insert_resolution_policy(
                    &mut by_id,
                    intern_detector_identity(interner, &metadata.id, "entropy resolution owner")?,
                    DetectorResolutionPolicy {
                        class: DetectorResolutionClass::Entropy,
                        priority: detector.resolution_priority(),
                    },
                )?;
            }
        }
        by_id.shrink_to_fit();
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledDetectorRelation {
    pub(crate) detector_id: Arc<str>,
    pub(crate) kind: keyhog_core::DetectorRelationKind,
    pub(crate) within_lines: usize,
    pub(crate) within_bytes: Option<usize>,
    pub(crate) direction: keyhog_core::EvidenceDirection,
}

#[derive(Debug)]
pub(crate) struct CompiledDetectorRelationIndex {
    by_owner: HashMap<Arc<str>, Box<[CompiledDetectorRelation]>>,
}

impl CompiledDetectorRelationIndex {
    fn compile(
        detectors: &[DetectorSpec],
        interner: &crate::static_intern::StaticInterner,
    ) -> Result<Self, String> {
        Self::compile_from(detectors, interner)
    }

    fn compile_from<T: DetectorPlanSource>(
        detectors: &[T],
        interner: &crate::static_intern::StaticInterner,
    ) -> Result<Self, String> {
        let detector_ids = detectors
            .iter()
            .map(|detector| detector.id())
            .collect::<HashSet<_>>();
        let relation_owner_count = detectors
            .iter()
            .filter(|detector| !detector.detector_relations().is_empty())
            .count();
        let mut by_owner = HashMap::with_capacity(relation_owner_count);
        let mut graph = HashMap::<&str, Vec<&str>>::with_capacity(detectors.len());
        let mut declared = HashMap::<(&str, &str), keyhog_core::DetectorRelationKind>::new();
        let mut indegree = detector_ids
            .iter()
            .copied()
            .map(|detector_id| (detector_id, 0usize))
            .collect::<HashMap<_, _>>();

        for detector in detectors {
            let relations = detector.detector_relations();
            let mut targets = HashSet::with_capacity(relations.len());
            let mut compiled = Vec::with_capacity(relations.len());
            for relation in relations {
                let target = relation.detector_id.as_str();
                if !detector_ids.contains(target) {
                    return Err(format!(
                        "detector {:?} relation targets unknown detector {target:?}",
                        detector.id()
                    ));
                }
                if target == detector.id() {
                    return Err(format!(
                        "detector {:?} relation cannot target itself",
                        detector.id()
                    ));
                }
                if !targets.insert(target) {
                    return Err(format!(
                        "detector {:?} declares multiple relations to {target:?}; \
                         declare one operation per detector pair",
                        detector.id()
                    ));
                }
                if let Some(reverse_kind) = declared.get(&(target, detector.id())).copied() {
                    let contradictory = matches!(
                        (relation.kind, reverse_kind),
                        (
                            keyhog_core::DetectorRelationKind::Conflicts,
                            keyhog_core::DetectorRelationKind::Conflicts
                        ) | (
                            keyhog_core::DetectorRelationKind::Requires,
                            keyhog_core::DetectorRelationKind::Conflicts
                        ) | (
                            keyhog_core::DetectorRelationKind::Conflicts,
                            keyhog_core::DetectorRelationKind::Requires
                        )
                    );
                    if contradictory {
                        return Err(format!(
                            "detectors {:?} and {target:?} declare contradictory {} and {} relations",
                            detector.id(),
                            relation.kind.as_str(),
                            reverse_kind.as_str(),
                        ));
                    }
                }
                declared.insert((detector.id(), target), relation.kind);
                compiled.push(CompiledDetectorRelation {
                    detector_id: intern_detector_identity(interner, target, "relation target")?,
                    kind: relation.kind,
                    within_lines: relation.within_lines,
                    within_bytes: relation.within_bytes,
                    direction: relation.direction,
                });
                if matches!(
                    relation.kind,
                    keyhog_core::DetectorRelationKind::Requires
                        | keyhog_core::DetectorRelationKind::Subsumes
                ) {
                    graph.entry(detector.id()).or_default().push(target);
                    *indegree
                        .get_mut(target)
                        .expect("validated target has an indegree row") += 1;
                }
            }
            if !compiled.is_empty() {
                by_owner.insert(
                    intern_detector_identity(interner, detector.id(), "relation owner")?,
                    compiled.into_boxed_slice(),
                );
            }
        }

        let mut ready = indegree
            .iter()
            .filter_map(|(detector_id, degree)| (*degree == 0).then_some(*detector_id))
            .collect::<VecDeque<_>>();
        let mut visited = 0usize;
        while let Some(owner) = ready.pop_front() {
            visited += 1;
            for target in graph.get(owner).into_iter().flatten() {
                let degree = indegree
                    .get_mut(target)
                    .expect("validated target has an indegree row");
                *degree -= 1;
                if *degree == 0 {
                    ready.push_back(target);
                }
            }
        }
        if visited != detector_ids.len() {
            return Err(
                "detector requires/subsumes relations contain a cycle; remove one edge so \
                 resolution has a deterministic dependency order"
                    .into(),
            );
        }
        Ok(Self { by_owner })
    }

    pub(crate) fn get(&self, detector_id: &str) -> &[CompiledDetectorRelation] {
        self.by_owner
            .get(detector_id)
            .map_or(&[], |relations| relations.as_ref())
    }
}

#[derive(Debug)]
pub(crate) struct CompiledDetectorPlan {
    pub(crate) metadata: CompiledDetectorMetadata,
    pub(crate) entropy_metadata: Option<CompiledDetectorMetadata>,
    pub(crate) execution: crate::detector_execution_policy::CompiledDetectorExecutionPolicy,
    match_confidence_index: u16,
    pub(crate) key_material: crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy,
    sparse_policy_index: Option<std::num::NonZeroU16>,
    pub(crate) validators: crate::checksum::CompiledDetectorValidators,
    pub(crate) weak_anchor_base: crate::suppression::WeakAnchorBase,
    pub(crate) companions: Box<[crate::types::CompiledCompanion]>,
    #[cfg(feature = "ml")]
    pub(crate) ml: crate::detector_ml_policy::CompiledDetectorMlPolicy,
}

#[derive(Debug)]
struct CompiledSparseDetectorPolicies {
    entropy_floor: Option<crate::entropy::policy::CompiledEntropyFloorPolicy>,
    entropy: Option<crate::entropy::policy::CompiledEntropyPolicy>,
    credential_shape: Option<crate::credential_shapes::CredentialShapeRule>,
    suppression: Option<crate::suppression::DetectorSuppressionPolicy>,
}

impl CompiledSparseDetectorPolicies {
    #[inline]
    fn is_empty(&self) -> bool {
        self.entropy_floor.is_none()
            && self.entropy.is_none()
            && self.credential_shape.is_none()
            && self.suppression.is_none()
    }
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

fn intern_confidence_policy(
    policies: &mut Vec<crate::confidence::policy::CompiledMatchConfidencePolicy>,
    policy: crate::confidence::policy::CompiledMatchConfidencePolicy,
) -> Result<u16, String> {
    if let Some(index) = policies.iter().position(|shared| shared == &policy) {
        return u16::try_from(index)
            .map_err(|_| "compiled confidence policy index exceeds u16".to_string());
    }
    let index = u16::try_from(policies.len())
        .map_err(|_| "compiled confidence policy count exceeds u16".to_string())?;
    policies.push(policy);
    Ok(index)
}

fn store_sparse_policies(
    policies: &mut Vec<CompiledSparseDetectorPolicies>,
    policy: CompiledSparseDetectorPolicies,
) -> Result<Option<std::num::NonZeroU16>, String> {
    if policy.is_empty() {
        return Ok(None);
    }
    let one_based = policies
        .len()
        .checked_add(1)
        // LAW10: failed checked conversion reaches ok_or_else and rejects the plan; no sparse policy is dropped.
        .and_then(|index| u16::try_from(index).ok())
        .and_then(std::num::NonZeroU16::new)
        .ok_or_else(|| "compiled sparse detector policy count exceeds u16".to_string())?;
    policies.push(policy);
    Ok(Some(one_based))
}

#[inline]
fn sparse_policy_for<'a>(
    policies: &'a [CompiledSparseDetectorPolicies],
    plan: &CompiledDetectorPlan,
) -> Option<&'a CompiledSparseDetectorPolicies> {
    let index = usize::from(plan.sparse_policy_index?.get()) - 1;
    policies.get(index)
}

#[derive(Debug)]
pub(crate) struct CompiledDetectorPlans {
    by_detector_index: Box<[CompiledDetectorPlan]>,
    confidence_policies: Box<[crate::confidence::policy::CompiledMatchConfidencePolicy]>,
    sparse_policies: Box<[CompiledSparseDetectorPolicies]>,
    resolution: DetectorResolutionIndex,
    detector_relations: CompiledDetectorRelationIndex,
    validator_index: crate::checksum::CompiledValidatorIndex,
    decode_transforms: Arc<crate::decode::policy::CompiledDecodeTransformPolicy>,
    decoder_plan: Arc<crate::decode::CompiledDecoderPlan>,
    generic_assignment:
        Option<crate::engine::phase2_generic::keywords::GenericAssignmentKeywordPlan>,
    generic_named_assignment_keywords: Box<[Arc<str>]>,
    generic_ownership: crate::generic_keyword_owner::GenericOwningDetectorIndex,
    public_identifier_assignment_markers: Box<[Box<[u8]>]>,
}

pub(crate) struct StreamingCompiledDetectorPlansBuilder {
    by_detector_index: Vec<CompiledDetectorPlan>,
    summaries: Vec<StreamingDetectorPlanSummary>,
    confidence_policies: Vec<crate::confidence::policy::CompiledMatchConfidencePolicy>,
    sparse_policies: Vec<CompiledSparseDetectorPolicies>,
}

impl StreamingCompiledDetectorPlansBuilder {
    pub(crate) fn with_capacity(detector_count: usize) -> Self {
        Self {
            by_detector_index: Vec::with_capacity(detector_count),
            summaries: Vec::with_capacity(detector_count),
            confidence_policies: Vec::with_capacity(3),
            sparse_policies: Vec::new(),
        }
    }

    pub(crate) fn push(
        &mut self,
        record: crate::execution_pack::detector_plan::DetectorPlanRecord,
        companions: Vec<crate::types::CompiledCompanion>,
        interner: &crate::static_intern::StaticInterner,
    ) -> Result<(), String> {
        #[cfg(not(feature = "entropy"))]
        if record.owns_entropy_policy() {
            return Err(format!(
                "scanner was built without the `entropy` feature, but hydrated detector entropy policy is enabled for {}; reinstall with a compatible scanner",
                record.id
            ));
        }
        let plan = hydrate_detector_plan(
            &record,
            companions,
            interner,
            &mut self.confidence_policies,
            &mut self.sparse_policies,
        )?;
        let has_weak_pattern = match plan.weak_anchor_base {
            crate::suppression::WeakAnchorBase::Always => true,
            crate::suppression::WeakAnchorBase::PerPattern => {
                record.patterns.iter().any(|pattern| pattern.weak_anchor)
            }
            crate::suppression::WeakAnchorBase::Never => false,
        };
        if has_weak_pattern
            && sparse_policy_for(&self.sparse_policies, &plan)
                .and_then(|policy| policy.entropy_floor.as_ref())
                .is_none()
        {
            return Err(format!(
                "weak-anchor detector omits detector-local entropy_high/entropy_floor policy: {}",
                record.id
            ));
        }
        let summary = StreamingDetectorPlanSummary::from_record(record, &plan.metadata);
        self.by_detector_index.push(plan);
        self.summaries.push(summary);
        Ok(())
    }

    pub(crate) fn finish(
        self,
        interner: &crate::static_intern::StaticInterner,
        decoder_plan: Arc<crate::decode::CompiledDecoderPlan>,
    ) -> Result<CompiledDetectorPlans, String> {
        let by_detector_index = self.by_detector_index.into_boxed_slice();
        let summaries = self.summaries;
        let confidence_policies = self.confidence_policies.into_boxed_slice();
        let sparse_policies = self.sparse_policies.into_boxed_slice();
        let generic_assignment = by_detector_index
            .iter()
            .any(|plan| plan.execution.is_generic)
            .then(|| {
                crate::engine::phase2_generic::keywords::GenericAssignmentKeywordPlan::hydrate_from(
                    &summaries,
                )
            })
            .transpose()?;
        let generic_named_assignment_keywords =
            crate::generic_keyword_owner::build_named_assignment_keywords_from(&summaries)
                .into_boxed_slice();
        let generic_ownership =
            crate::generic_keyword_owner::GenericOwningDetectorIndex::build_from(&summaries)?;
        let resolution = DetectorResolutionIndex::compile_from(&summaries, interner)?;
        let detector_relations = CompiledDetectorRelationIndex::compile_from(&summaries, interner)?;
        let validator_index = crate::checksum::CompiledValidatorIndex::compile(
            by_detector_index.iter().map(|plan| &plan.validators),
        );
        let decode_transforms = Arc::new(
            crate::decode::policy::CompiledDecodeTransformPolicy::hydrate_summaries(&summaries)?,
        );
        let mut public_identifier_assignment_markers: Vec<Box<[u8]>> = Vec::new();
        for marker in summaries
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
        Ok(CompiledDetectorPlans {
            by_detector_index,
            confidence_policies,
            sparse_policies,
            resolution,
            detector_relations,
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
        let mut confidence_policies = Vec::with_capacity(3);
        let mut sparse_policies = Vec::new();
        let mut by_detector_index = Vec::with_capacity(detectors.len());
        for (detector, companions) in detectors.iter().zip(companions) {
            by_detector_index.push(compile_detector_plan(
                detector,
                companions,
                interner,
                &mut confidence_policies,
                &mut sparse_policies,
            )?);
        }
        let by_detector_index = by_detector_index.into_boxed_slice();
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
        let resolution = DetectorResolutionIndex::compile(detectors, interner)?;
        let detector_relations = CompiledDetectorRelationIndex::compile(detectors, interner)?;
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
            confidence_policies: confidence_policies.into_boxed_slice(),
            sparse_policies: sparse_policies.into_boxed_slice(),
            resolution,
            detector_relations,
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

    pub(crate) fn declared_min_confidence(&self) -> impl Iterator<Item = (&str, f64)> + '_ {
        self.by_detector_index.iter().filter_map(|plan| {
            plan.execution
                .min_confidence
                .map(|floor| (plan.metadata.0.as_ref(), floor))
        })
    }

    pub(crate) fn companion_signature_sources(&self) -> impl Iterator<Item = Arc<str>> + '_ {
        self.by_detector_index
            .iter()
            .flat_map(|plan| plan.companions.iter())
            .map(|companion| companion.regex.cloned_source())
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
    pub(crate) fn match_confidence(
        &self,
        detector_index: usize,
    ) -> &crate::confidence::policy::CompiledMatchConfidencePolicy {
        let policy_index = self.by_detector_index[detector_index].match_confidence_index;
        &self.confidence_policies[usize::from(policy_index)]
    }

    #[inline]
    fn sparse_policy(&self, detector_index: usize) -> Option<&CompiledSparseDetectorPolicies> {
        sparse_policy_for(
            &self.sparse_policies,
            &self.by_detector_index[detector_index],
        )
    }

    #[inline]
    pub(crate) fn entropy_floor(
        &self,
        detector_index: usize,
    ) -> Option<&crate::entropy::policy::CompiledEntropyFloorPolicy> {
        self.sparse_policy(detector_index)?.entropy_floor.as_ref()
    }

    #[inline]
    pub(crate) fn entropy(
        &self,
        detector_index: usize,
    ) -> Option<&crate::entropy::policy::CompiledEntropyPolicy> {
        self.sparse_policy(detector_index)?.entropy.as_ref()
    }

    #[inline]
    pub(crate) fn credential_shape(
        &self,
        detector_index: usize,
    ) -> Option<&crate::credential_shapes::CredentialShapeRule> {
        self.sparse_policy(detector_index)?
            .credential_shape
            .as_ref()
    }

    #[inline]
    pub(crate) fn suppression(
        &self,
        detector_index: usize,
    ) -> Option<&crate::suppression::DetectorSuppressionPolicy> {
        self.sparse_policy(detector_index)?.suppression.as_ref()
    }

    pub(crate) fn find_by_id(&self, detector_id: &str) -> Option<&CompiledDetectorPlan> {
        self.by_detector_index
            .iter()
            .find(|plan| plan.metadata.0.as_ref() == detector_id)
    }

    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.by_detector_index.len()
    }
    #[cfg(test)]
    pub(crate) fn resolution_identity_ptr(&self, detector_id: &str) -> Option<*const u8> {
        self.resolution
            .by_id
            .get_key_value(detector_id)
            .map(|(identity, _)| identity.as_ptr())
    }

    #[cfg(test)]
    pub(crate) fn relation_identity_ptrs(
        &self,
        owner: &str,
    ) -> Option<(*const u8, Vec<(&str, *const u8)>)> {
        self.detector_relations
            .by_owner
            .get_key_value(owner)
            .map(|(owner, relations)| {
                (
                    owner.as_ptr(),
                    relations
                        .iter()
                        .map(|relation| {
                            (relation.detector_id.as_ref(), relation.detector_id.as_ptr())
                        })
                        .collect(),
                )
            })
    }
    #[cfg(test)]
    pub(crate) fn retained_index_storage(&self) -> ((usize, usize), (usize, usize)) {
        (
            (
                self.resolution.by_id.len(),
                self.resolution.by_id.capacity(),
            ),
            (
                self.detector_relations.by_owner.len(),
                self.detector_relations.by_owner.capacity(),
            ),
        )
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
    pub(crate) fn detector_relations(&self, detector_id: &str) -> &[CompiledDetectorRelation] {
        self.detector_relations.get(detector_id)
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

    /// Strip only trailing decoder identities registered in this scanner's
    /// immutable decoder plan. Unknown slash suffixes remain part of the source
    /// type so detector source admission stays fail-closed.
    pub(crate) fn decoded_source_family<'a>(&self, source: &'a str) -> &'a str {
        let mut family = source;
        while let Some(parent) = self.decoded_source_parent(family) {
            family = parent;
        }
        family
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

fn compile_detector_plan(
    detector: &DetectorSpec,
    companions: Vec<crate::types::CompiledCompanion>,
    interner: &crate::static_intern::StaticInterner,
    confidence_policies: &mut Vec<crate::confidence::policy::CompiledMatchConfidencePolicy>,
    sparse_policies: &mut Vec<CompiledSparseDetectorPolicies>,
) -> Result<CompiledDetectorPlan, String> {
    let execution =
        crate::detector_execution_policy::CompiledDetectorExecutionPolicy::compile(detector)?;
    let entropy =
        crate::entropy::policy::compile_entropy_policy_with_length(detector, execution.length)?;
    let sparse_policy_index = store_sparse_policies(
        sparse_policies,
        CompiledSparseDetectorPolicies {
            entropy_floor: crate::entropy::policy::CompiledEntropyFloorPolicy::compile(detector)?,
            entropy,
            credential_shape: crate::credential_shapes::compile_detector_shape_rule(detector)?,
            suppression: crate::suppression::DetectorSuppressionPolicy::compile(detector)?,
        },
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
        match_confidence_index: intern_confidence_policy(
            confidence_policies,
            crate::confidence::policy::CompiledMatchConfidencePolicy::compile(detector)?,
        )?,
        key_material:
            crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy::compile(
                detector,
            )?,
        sparse_policy_index,
        validators: crate::checksum::CompiledDetectorValidators::compile(detector)?,
        weak_anchor_base: crate::suppression::detector_weak_anchor_base(detector),
        companions: companions.into_boxed_slice(),
        #[cfg(feature = "ml")]
        ml: crate::detector_ml_policy::CompiledDetectorMlPolicy::compile(detector),
    })
}

fn hydrate_detector_plan(
    detector: &crate::execution_pack::detector_plan::DetectorPlanRecord,
    companions: Vec<crate::types::CompiledCompanion>,
    interner: &crate::static_intern::StaticInterner,
    confidence_policies: &mut Vec<crate::confidence::policy::CompiledMatchConfidencePolicy>,
    sparse_policies: &mut Vec<CompiledSparseDetectorPolicies>,
) -> Result<CompiledDetectorPlan, String> {
    let execution = crate::detector_execution_policy::CompiledDetectorExecutionPolicy::hydrate(
        &detector.id,
        detector.owns_entropy_policy(),
        detector.min_len,
        detector.max_len,
        detector.min_confidence,
        detector.severity,
        detector.structural_password_slot,
        &detector.keywords,
        &detector.public_identifier_assignment_markers,
    )?;
    let entropy =
        crate::entropy::policy::hydrate_entropy_policy_with_length(detector, execution.length)?;
    let sparse_policy_index = store_sparse_policies(
        sparse_policies,
        CompiledSparseDetectorPolicies {
            entropy_floor: crate::entropy::policy::CompiledEntropyFloorPolicy::hydrate(detector)?,
            entropy,
            credential_shape: crate::credential_shapes::hydrate_detector_shape_rule(detector)?,
            suppression: crate::suppression::DetectorSuppressionPolicy::hydrate(detector)?,
        },
    )?;
    let weak_anchor_base = if detector.weak_anchor {
        crate::suppression::WeakAnchorBase::Always
    } else if detector.patterns.iter().any(|pattern| pattern.weak_anchor) {
        crate::suppression::WeakAnchorBase::PerPattern
    } else {
        crate::suppression::WeakAnchorBase::Never
    };
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
        match_confidence_index: intern_confidence_policy(
            confidence_policies,
            crate::confidence::policy::CompiledMatchConfidencePolicy::hydrate(
                &detector.id,
                detector.owns_entropy_policy(),
                detector.match_confidence,
            )?,
        )?,
        key_material:
            crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy::hydrate(
                &detector.id,
                detector.kind,
                &detector.decoded_hex_key_material_lengths,
                &detector.canonical_hex_key_material,
            )?,
        sparse_policy_index,
        validators: crate::checksum::CompiledDetectorValidators::hydrate(detector)?,
        weak_anchor_base,
        companions: companions.into_boxed_slice(),
        #[cfg(feature = "ml")]
        ml: crate::detector_ml_policy::CompiledDetectorMlPolicy::hydrate(detector),
    })
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

//! Detector-owned entropy policy resolution for active and embedded detector corpora.

use super::keywords::KeywordContext;
use super::scanner::KEYWORD_FREE_LABEL;

/// Borrowed view of the detector corpus that actually compiled for this scan.
/// Production phase-2 paths pass this view so custom detector directories and
/// operator-composed specs remain authoritative. Stable public convenience
/// APIs pass `None` and retain the embedded-corpus defaults they historically
/// exposed.
#[derive(Clone, Copy)]
pub(crate) struct ActiveDetectorPolicy<'a> {
    index: &'a crate::generic_keyword_owner::GenericOwningDetectorIndex,
    detector_plans: &'a crate::detector_plan::CompiledDetectorPlans,
}

impl<'a> ActiveDetectorPolicy<'a> {
    pub(crate) fn new(
        index: &'a crate::generic_keyword_owner::GenericOwningDetectorIndex,
        detector_plans: &'a crate::detector_plan::CompiledDetectorPlans,
    ) -> Self {
        Self {
            index,
            detector_plans,
        }
    }

    pub(super) fn compiled_for_keyword(
        self,
        keyword: &str,
    ) -> Option<&'a crate::entropy::policy::CompiledEntropyPolicy> {
        active_policy_detector_index(self.index, keyword)
            .and_then(|index| self.detector_plans.entropy(index))
    }

    pub(super) fn compiled_for_role(
        self,
        role: keyhog_core::EntropyDetectionRole,
    ) -> Option<&'a crate::entropy::policy::CompiledEntropyPolicy> {
        let index = match role {
            keyhog_core::EntropyDetectionRole::KeywordFree => self.index.keyword_free_owner_index(),
            keyhog_core::EntropyDetectionRole::IsolatedBare => {
                self.index.isolated_bare_owner_index()
            }
            keyhog_core::EntropyDetectionRole::UnclaimedKeyword => {
                self.index.unclaimed_keyword_owner_index()
            }
        }?;
        self.detector_plans.entropy(index)
    }

    pub(super) fn key_material_for_keyword(
        self,
        keyword: &str,
    ) -> Option<&'a crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy> {
        let index = self
            .index
            .canonical_index(keyword)
            .or_else(|| active_policy_detector_index(self.index, keyword))?;
        Some(&self.detector_plans.get(index).key_material)
    }

    pub(super) fn claims_keyword(self, keyword: &str) -> bool {
        self.index.claimed_policy_index(keyword).is_some()
    }
}

/// Resolve entropy policy from the compiled corpus. Synthetic paths have exact
/// owners, detector-declared keyword claims come next, and an unclaimed Tier-A
/// keyword resolves to the detector that explicitly owns the unclaimed-keyword
/// role. This is the single resolver shared by generation and emission.
pub(crate) fn active_policy_detector_index(
    index: &crate::generic_keyword_owner::GenericOwningDetectorIndex,
    keyword: &str,
) -> Option<usize> {
    if keyword == KEYWORD_FREE_LABEL {
        return index.keyword_free_owner_index();
    }
    if keyword == crate::entropy::ISOLATED_BARE_ENTROPY_LABEL {
        return index.isolated_bare_owner_index();
    }
    index
        .claimed_policy_index(keyword)
        .or_else(|| index.unclaimed_keyword_owner_index())
}

struct EmbeddedEntropyPolicies {
    index: crate::generic_keyword_owner::GenericOwningDetectorIndex,
    entropy: Box<[Option<crate::entropy::policy::CompiledEntropyPolicy>]>,
    key_material: Box<[crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy]>,
}

fn embedded_entropy_policies() -> &'static EmbeddedEntropyPolicies {
    static POLICIES: std::sync::LazyLock<EmbeddedEntropyPolicies> = std::sync::LazyLock::new(
        || {
            let detectors = keyhog_core::embedded_detector_specs();
            let index =
                match crate::generic_keyword_owner::GenericOwningDetectorIndex::build(detectors) {
                    Ok(index) => index,
                    Err(error) => {
                        panic!("embedded detector entropy ownership is invalid: {error}")
                    }
                };
            let entropy = detectors
                .iter()
                .map(
                    |detector| match crate::entropy::policy::compile_entropy_policy(detector) {
                        Ok(policy) => policy,
                        Err(error) => {
                            panic!("embedded detector entropy policy is invalid: {error}")
                        }
                    },
                )
                .collect();
            let key_material = detectors
                .iter()
                .map(|detector| {
                    match crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy::compile(
                        detector,
                    ) {
                        Ok(policy) => policy,
                        Err(error) => {
                            panic!("embedded detector key-material policy is invalid: {error}")
                        }
                    }
                })
                .collect();
            EmbeddedEntropyPolicies {
                index,
                entropy,
                key_material,
            }
        },
    );
    &POLICIES
}

pub(super) fn get_compiled_policy_for_keyword<'a>(
    active_policy: Option<ActiveDetectorPolicy<'a>>,
    keyword: &str,
) -> Option<&'a crate::entropy::policy::CompiledEntropyPolicy> {
    match active_policy {
        Some(policy) => policy.compiled_for_keyword(keyword),
        None => {
            let policies = embedded_entropy_policies();
            active_policy_detector_index(&policies.index, keyword)
                .and_then(|index| policies.entropy.get(index)?.as_ref())
        }
    }
}

pub(super) fn get_compiled_policy_for_role<'a>(
    active_policy: Option<ActiveDetectorPolicy<'a>>,
    role: keyhog_core::EntropyDetectionRole,
) -> Option<&'a crate::entropy::policy::CompiledEntropyPolicy> {
    match active_policy {
        Some(policy) => policy.compiled_for_role(role),
        None => {
            let policies = embedded_entropy_policies();
            let index = match role {
                keyhog_core::EntropyDetectionRole::KeywordFree => {
                    policies.index.keyword_free_owner_index()
                }
                keyhog_core::EntropyDetectionRole::IsolatedBare => {
                    policies.index.isolated_bare_owner_index()
                }
                keyhog_core::EntropyDetectionRole::UnclaimedKeyword => {
                    policies.index.unclaimed_keyword_owner_index()
                }
            }?;
            policies.entropy.get(index)?.as_ref()
        }
    }
}

pub(super) fn get_key_material_policy_for_keyword<'a>(
    active_policy: Option<ActiveDetectorPolicy<'a>>,
    keyword: &str,
) -> Option<&'a crate::detector_key_material_policy::CompiledDetectorKeyMaterialPolicy> {
    match active_policy {
        Some(policy) => policy.key_material_for_keyword(keyword),
        None => {
            let policies = embedded_entropy_policies();
            let index = policies
                .index
                .canonical_index(keyword)
                .or_else(|| active_policy_detector_index(&policies.index, keyword))?;
            policies.key_material.get(index)
        }
    }
}

#[doc(hidden)]
pub(crate) fn credential_keyword_context(keyword: &str) -> KeywordContext {
    let policy = match get_compiled_policy_for_keyword(None, keyword) {
        Some(policy) => policy,
        None => panic!(
            "embedded detector entropy policy is unavailable for keyword {keyword:?}; fix the owning detector TOML"
        ),
    };
    KeywordContext {
        keyword: keyword.to_string(),
        threshold: policy.entropy_low,
        min_len: policy.length.min_len,
        is_credential_context: true,
        plausibility_policy: *policy,
    }
}


use super::token_randomness::TokenRandomness;

#[derive(Debug)]
pub(crate) struct DetectorSuppressionPolicy {
    allowlist_paths: Vec<regex::Regex>,
    allowlist_values: Vec<regex::Regex>,
    stopwords: Vec<String>,
}

impl DetectorSuppressionPolicy {
    fn compile(spec: &keyhog_core::DetectorSpec) -> Result<Option<Self>, String> {
        if spec.allowlist_paths.is_empty()
            && spec.allowlist_values.is_empty()
            && spec.stopwords.is_empty()
        {
            return Ok(None);
        }
        let compile = |field: &str, patterns: &[String]| {
            patterns
                .iter()
                .map(|pattern| {
                    regex::Regex::new(pattern).map_err(|error| {
                        format!(
                            "detector {:?} {field} regex {pattern:?} failed to compile: {error}",
                            spec.id
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(Some(Self {
            allowlist_paths: compile("allowlist_paths", &spec.allowlist_paths)?,
            allowlist_values: compile("allowlist_values", &spec.allowlist_values)?,
            stopwords: spec.stopwords.clone(),
        }))
    }

    pub(crate) fn allowlist_stage(
        &self,
        path: Option<&str>,
        credential: &str,
    ) -> Option<crate::adjudicate::StageId> {
        if let Some(path) = path {
            if self
                .allowlist_paths
                .iter()
                .any(|regex| regex.is_match(path))
            {
                crate::adjudicate::record_example_suppression(
                    "pipeline",
                    Some(path),
                    credential,
                    "allowlist_paths",
                );
                return Some(crate::adjudicate::StageId::ShapeGate("allowlist_paths"));
            }
        }
        if self
            .allowlist_values
            .iter()
            .any(|regex| regex.is_match(credential))
        {
            crate::adjudicate::record_example_suppression(
                "pipeline",
                path,
                credential,
                "allowlist_values",
            );
            return Some(crate::adjudicate::StageId::ShapeGate("allowlist_values"));
        }
        None
    }

    pub(crate) fn stopword_stage(
        &self,
        path: Option<&str>,
        credential: &str,
        randomness: &TokenRandomness<'_>,
    ) -> Option<crate::adjudicate::StageId> {
        if self.stopwords.is_empty() || randomness.is_random_token(credential) {
            return None;
        }
        if self
            .stopwords
            .iter()
            .any(|word| keyhog_core::contains_ignore_ascii_case(credential, word))
        {
            crate::adjudicate::record_example_suppression(
                "pipeline",
                path,
                credential,
                "stopwords",
            );
            return Some(crate::adjudicate::StageId::ShapeGate("stopwords"));
        }
        None
    }

    pub(crate) fn full_stage(
        &self,
        path: Option<&str>,
        credential: &str,
    ) -> Option<crate::adjudicate::StageId> {
        self.allowlist_stage(path, credential).or_else(|| {
            let randomness = TokenRandomness::for_candidate(credential);
            self.stopword_stage(path, credential, &randomness)
        })
    }

    #[cfg(test)]
    pub(crate) fn test_fixture() -> Self {
        Self {
            allowlist_paths: vec![regex::Regex::new(".*allowlisted_path.*").unwrap()],
            allowlist_values: vec![regex::Regex::new("^allowlisted_value_.*").unwrap()],
            stopwords: vec!["stopword_here".to_string()],
        }
    }
}

pub(crate) struct CompiledDetectorSuppressions {
    slot_by_detector: Box<[u32]>,
    policies: Vec<DetectorSuppressionPolicy>,
}

impl CompiledDetectorSuppressions {
    pub(crate) fn compile(detectors: &[keyhog_core::DetectorSpec]) -> Result<Self, String> {
        let mut slot_by_detector = Vec::with_capacity(detectors.len());
        let mut policies = Vec::new();
        for spec in detectors {
            let Some(policy) = DetectorSuppressionPolicy::compile(spec)? else {
                slot_by_detector.push(0);
                continue;
            };
            policies.push(policy);
            let slot = u32::try_from(policies.len()).map_err(|_| {
                "detector suppression policy count exceeds the u32 index capacity".to_string()
            })?;
            slot_by_detector.push(slot);
        }
        Ok(Self {
            slot_by_detector: slot_by_detector.into_boxed_slice(),
            policies,
        })
    }

    pub(crate) fn get(&self, detector_index: usize) -> Option<&DetectorSuppressionPolicy> {
        let slot = *self.slot_by_detector.get(detector_index)?;
        self.policies.get(slot.checked_sub(1)? as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::CompiledDetectorSuppressions;

    #[test]
    fn dense_slots_follow_the_active_detector_order() {
        let detectors = [
            keyhog_core::DetectorSpec {
                id: "no-policy".into(),
                ..Default::default()
            },
            keyhog_core::DetectorSpec {
                id: "value-policy".into(),
                allowlist_values: vec!["^allowed$".into()],
                ..Default::default()
            },
            keyhog_core::DetectorSpec {
                id: "stopword-policy".into(),
                stopwords: vec!["example".into()],
                ..Default::default()
            },
        ];

        let policies = CompiledDetectorSuppressions::compile(&detectors).expect("compile policies");
        assert!(policies.get(0).is_none());
        assert!(policies.get(1).is_some());
        assert!(policies.get(2).is_some());
        assert!(policies.get(3).is_none());
    }

    #[test]
    fn invalid_programmatic_policy_regex_has_detector_and_field_context() {
        let detectors = [keyhog_core::DetectorSpec {
            id: "broken-policy".into(),
            allowlist_paths: vec!["[".into()],
            ..Default::default()
        }];

        let error = CompiledDetectorSuppressions::compile(&detectors)
            .err()
            .expect("invalid regex must fail compilation");
        assert!(error.contains("broken-policy"), "missing detector: {error}");
        assert!(error.contains("allowlist_paths"), "missing field: {error}");
        assert!(
            error.contains("failed to compile"),
            "missing cause: {error}"
        );
    }
}

use super::token_randomness::TokenRandomness;

#[derive(Debug)]
pub(crate) struct DetectorSuppressionPolicy {
    allowlist_paths: Vec<regex::Regex>,
    allowlist_values: Vec<regex::Regex>,
    stopwords: Vec<String>,
}

impl DetectorSuppressionPolicy {
    pub(crate) fn compile(spec: &keyhog_core::DetectorSpec) -> Result<Option<Self>, String> {
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

#[cfg(test)]
#[path = "../../tests/unit/suppression_detector_policy.rs"]
mod tests;

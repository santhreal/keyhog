use super::token_randomness::TokenRandomness;

#[derive(Debug)]
pub(crate) struct DetectorSuppressionPolicy {
    allowlist_paths: Vec<regex::Regex>,
    source_path_patterns: Vec<regex::Regex>,
    source_types: Vec<String>,
    file_extensions: Vec<String>,
    allowlist_values: Vec<regex::Regex>,
    stopwords: Vec<String>,
}

impl DetectorSuppressionPolicy {
    pub(crate) fn compile(spec: &keyhog_core::DetectorSpec) -> Result<Option<Self>, String> {
        if spec.allowlist_paths.is_empty()
            && spec.allowlist_values.is_empty()
            && spec.stopwords.is_empty()
            && spec.source_admission.path_patterns.is_empty()
            && spec.source_admission.source_types.is_empty()
            && spec.source_admission.file_extensions.is_empty()
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
            source_path_patterns: compile(
                "source_admission.path_patterns",
                &spec.source_admission.path_patterns,
            )?,
            source_types: spec.source_admission.source_types.clone(),
            file_extensions: spec.source_admission.file_extensions.clone(),
            allowlist_values: compile("allowlist_values", &spec.allowlist_values)?,
            stopwords: spec.stopwords.clone(),
        }))
    }

    pub(crate) fn allowlist_stage(
        &self,
        path: Option<&str>,
        source_type: Option<&str>,
        credential: &str,
    ) -> Option<crate::adjudicate::StageId> {
        if let Some(reason) = self.source_admission_rejection(path, source_type) {
            crate::adjudicate::record_example_suppression("pipeline", path, credential, reason);
            return Some(crate::adjudicate::StageId::ShapeGate(reason));
        }
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
        source_type: Option<&str>,
        credential: &str,
    ) -> Option<crate::adjudicate::StageId> {
        self.allowlist_stage(path, source_type, credential)
            .or_else(|| {
                let randomness = TokenRandomness::for_candidate(credential);
                self.stopword_stage(path, credential, &randomness)
            })
    }

    fn source_admission_rejection(
        &self,
        path: Option<&str>,
        source_type: Option<&str>,
    ) -> Option<&'static str> {
        if !self.source_path_patterns.is_empty()
            && !path.is_some_and(|path| {
                self.source_path_patterns
                    .iter()
                    .any(|pattern| pattern.is_match(path))
            })
        {
            return Some("source_admission_path");
        }
        if !self.source_types.is_empty()
            && !source_type.is_some_and(|source_type| {
                self.source_types
                    .iter()
                    .any(|admitted| admitted == source_type)
            })
        {
            return Some("source_admission_type");
        }
        if !self.file_extensions.is_empty()
            && !path
                .and_then(|path| path.rsplit('/').next())
                .and_then(|name| name.rsplit_once('.').map(|(_, extension)| extension))
                .is_some_and(|extension| {
                    self.file_extensions
                        .iter()
                        .any(|admitted| extension.eq_ignore_ascii_case(admitted))
                })
        {
            return Some("source_admission_extension");
        }
        None
    }

    #[cfg(test)]
    pub(crate) fn test_fixture() -> Self {
        Self {
            allowlist_paths: vec![regex::Regex::new(".*allowlisted_path.*").unwrap()],
            allowlist_values: vec![regex::Regex::new("^allowlisted_value_.*").unwrap()],
            stopwords: vec!["stopword_here".to_string()],
            source_path_patterns: Vec::new(),
            source_types: Vec::new(),
            file_extensions: Vec::new(),
        }
    }
}

#[cfg(test)]
#[path = "../../tests/unit/suppression_detector_policy.rs"]
mod tests;

use super::token_randomness::TokenRandomness;

/// Optimized compiled filter pattern for path and value suppression.
#[derive(Debug, Clone)]
pub(crate) enum FilterPattern {
    /// Exact string equality.
    Exact(String),
    /// String prefix match.
    Prefix(String),
    /// String suffix match.
    Suffix(String),
    /// Substring containment.
    Substring(String),
    /// General regular expression fallback.
    Regex(regex::Regex),
}

impl FilterPattern {
    /// Compile pattern string, optimizing exact literals to avoid regex allocations.
    pub(crate) fn compile(raw: &str) -> Result<Self, regex::Error> {
        let re = regex::Regex::new(raw)?;
        if let Some(optimized) = Self::try_optimize(raw) {
            return Ok(optimized);
        }
        Ok(Self::Regex(re))
    }

    fn is_regex_meta(c: char) -> bool {
        matches!(
            c,
            '\\' | '.' | '+' | '*' | '?' | '(' | ')' | '|' | '[' | ']' | '{' | '}' | '^' | '$'
        )
    }

    fn try_optimize(raw: &str) -> Option<Self> {
        if raw.starts_with('^') && raw.ends_with('$') && raw.len() >= 2 {
            let inner = &raw[1..raw.len() - 1];
            if !inner.chars().any(Self::is_regex_meta) {
                return Some(Self::Exact(inner.to_string()));
            }
        }
        if raw.starts_with('^') && raw.ends_with(".*") && raw.len() >= 3 {
            let inner = &raw[1..raw.len() - 2];
            if !inner.chars().any(Self::is_regex_meta) {
                return Some(Self::Prefix(inner.to_string()));
            }
        }
        if raw.starts_with('^') && !raw.is_empty() {
            let inner = &raw[1..];
            if !inner.chars().any(Self::is_regex_meta) {
                return Some(Self::Prefix(inner.to_string()));
            }
        }
        if raw.ends_with('$') && !raw.is_empty() {
            let inner = &raw[..raw.len() - 1];
            if !inner.chars().any(Self::is_regex_meta) {
                return Some(Self::Suffix(inner.to_string()));
            }
        }
        if raw.starts_with(".*") && raw.ends_with(".*") && raw.len() >= 4 {
            let inner = &raw[2..raw.len() - 2];
            if !inner.chars().any(Self::is_regex_meta) {
                return Some(Self::Substring(inner.to_string()));
            }
        }
        if !raw.chars().any(Self::is_regex_meta) {
            return Some(Self::Substring(raw.to_string()));
        }
        None
    }

    /// Check whether text matches this filter pattern.
    #[inline]
    pub(crate) fn is_match(&self, text: &str) -> bool {
        match self {
            Self::Exact(lit) => text == lit,
            Self::Prefix(p) => text.starts_with(p),
            Self::Suffix(s) => text.ends_with(s),
            Self::Substring(sub) => text.contains(sub),
            Self::Regex(re) => re.is_match(text),
        }
    }
}

#[derive(Debug)]
pub(crate) struct DetectorSuppressionPolicy {
    allowlist_paths: Vec<FilterPattern>,
    source_path_patterns: Vec<FilterPattern>,
    source_types: Vec<String>,
    file_extensions: Vec<String>,
    allowlist_values: Vec<FilterPattern>,
    stopwords: Vec<String>,
}

impl DetectorSuppressionPolicy {
    pub(crate) fn compile(spec: &keyhog_core::DetectorSpec) -> Result<Option<Self>, String> {
        keyhog_profile::record_compile_surface_invocation(
            keyhog_profile::CompileSurfaceId::DetectorPlan,
        );
        Self::hydrate_parts(
            &spec.id,
            &spec.allowlist_paths,
            &spec.allowlist_values,
            &spec.stopwords,
            &spec.source_admission,
        )
    }

    pub(crate) fn hydrate(
        spec: &crate::execution_pack::detector_plan::DetectorPlanRecord,
    ) -> Result<Option<Self>, String> {
        keyhog_profile::record_compile_surface_load(keyhog_profile::CompileSurfaceId::DetectorPlan);
        Self::hydrate_parts(
            &spec.id,
            &spec.allowlist_paths,
            &spec.allowlist_values,
            &spec.stopwords,
            &spec.source_admission,
        )
    }

    fn hydrate_parts(
        detector_id: &str,
        allowlist_paths: &[String],
        allowlist_values: &[String],
        stopwords: &[String],
        source_admission: &keyhog_core::SourceAdmissionSpec,
    ) -> Result<Option<Self>, String> {
        if allowlist_paths.is_empty()
            && allowlist_values.is_empty()
            && stopwords.is_empty()
            && source_admission.path_patterns.is_empty()
            && source_admission.source_types.is_empty()
            && source_admission.file_extensions.is_empty()
        {
            return Ok(None);
        }
        let compile = |field: &str, patterns: &[String]| {
            patterns
                .iter()
                .map(|pattern| {
                    FilterPattern::compile(pattern).map_err(|error| {
                        format!(
                            "detector {detector_id:?} {field} regex {pattern:?} failed to compile: {error}"
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()
        };
        Ok(Some(Self {
            allowlist_paths: compile("allowlist_paths", allowlist_paths)?,
            source_path_patterns: compile(
                "source_admission.path_patterns",
                &source_admission.path_patterns,
            )?,
            source_types: source_admission.source_types.clone(),
            file_extensions: source_admission.file_extensions.clone(),
            allowlist_values: compile("allowlist_values", allowlist_values)?,
            stopwords: stopwords.to_vec(),
        }))
    }

    pub(crate) fn allowlist_stage(
        &self,
        path: Option<&str>,
        source_family: Option<&str>,
        credential: &str,
    ) -> Option<crate::adjudicate::StageId> {
        if let Some(reason) = self.source_admission_rejection(path, source_family) {
            crate::adjudicate::record_example_suppression("pipeline", path, credential, reason);
            return Some(crate::adjudicate::StageId::ShapeGate(reason));
        }
        if let Some(path) = path {
            if self.allowlist_paths.iter().any(|pat| pat.is_match(path)) {
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
            .any(|pat| pat.is_match(credential))
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
        source_family: Option<&str>,
        credential: &str,
    ) -> Option<crate::adjudicate::StageId> {
        self.allowlist_stage(path, source_family, credential)
            .or_else(|| {
                let randomness = TokenRandomness::for_candidate(credential);
                self.stopword_stage(path, credential, &randomness)
            })
    }

    fn source_admission_rejection(
        &self,
        path: Option<&str>,
        source_family: Option<&str>,
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
            && !source_family.is_some_and(|source_family| {
                self.source_types
                    .iter()
                    .any(|admitted| admitted == source_family)
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
            allowlist_paths: vec![FilterPattern::Substring("allowlisted_path".to_string())],
            allowlist_values: vec![FilterPattern::Prefix("allowlisted_value_".to_string())],
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

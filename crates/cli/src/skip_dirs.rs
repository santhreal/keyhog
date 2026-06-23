//! Shared Tier-B directory skip policy for CLI filesystem surfaces.

use anyhow::{Context, Result};
use std::collections::BTreeSet;

const BUNDLED_SKIP_DIRS: &str = include_str!("../data/path_skip_dirs.toml");

#[derive(Debug, Clone)]
pub(crate) struct SkipDirPolicy {
    watch: Vec<String>,
    git_discovery: Vec<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct SkipDirFile {
    skip_dirs: SkipDirSection,
}

#[derive(Debug, Default, serde::Deserialize)]
struct SkipDirSection {
    #[serde(default)]
    base: Vec<String>,
    #[serde(default)]
    watch_extra: Vec<String>,
    #[serde(default)]
    git_discovery_extra: Vec<String>,
}

impl SkipDirPolicy {
    pub(crate) fn load() -> Result<Self> {
        let mut section = parse_section(BUNDLED_SKIP_DIRS)
            .map_err(|error| anyhow::anyhow!("invalid data/path_skip_dirs.toml: {error}"))?;
        if let Some(user_path) =
            dirs::config_dir().map(|dir| dir.join("keyhog/path_skip_dirs.toml"))
        {
            match std::fs::read_to_string(&user_path) {
                Ok(raw) => {
                    let user = parse_section(&raw)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| {
                            format!("parse path skip-dir policy {}", user_path.display())
                        })?;
                    section.base.extend(user.base);
                    section.watch_extra.extend(user.watch_extra);
                    section.git_discovery_extra.extend(user.git_discovery_extra);
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => {
                    return Err(anyhow::Error::new(error)).with_context(|| {
                        format!("read path skip-dir policy {}", user_path.display())
                    });
                }
            }
        }
        Self::from_section(section)
            .map_err(|error| anyhow::anyhow!("invalid path skip-dir policy: {error}"))
    }

    pub(crate) fn is_watch_component(&self, component: &str) -> bool {
        contains_component(&self.watch, component)
    }

    pub(crate) fn is_git_discovery_component(&self, component: &str) -> bool {
        contains_component(&self.git_discovery, component)
    }

    fn from_section(section: SkipDirSection) -> std::result::Result<Self, String> {
        validate_list("base", &section.base)?;
        validate_list("watch_extra", &section.watch_extra)?;
        validate_list("git_discovery_extra", &section.git_discovery_extra)?;

        let watch = merge_lists(&section.base, &section.watch_extra, "watch")?;
        let git_discovery =
            merge_lists(&section.base, &section.git_discovery_extra, "git_discovery")?;
        Ok(Self {
            watch,
            git_discovery,
        })
    }
}

fn parse_section(raw: &str) -> std::result::Result<SkipDirSection, String> {
    let parsed: SkipDirFile =
        toml::from_str(raw).map_err(|error| format!("invalid path_skip_dirs.toml: {error}"))?;
    Ok(parsed.skip_dirs)
}

fn contains_component(policy: &[String], component: &str) -> bool {
    policy
        .iter()
        .any(|skip| component.eq_ignore_ascii_case(skip))
}

fn merge_lists(
    base: &[String],
    extra: &[String],
    name: &str,
) -> std::result::Result<Vec<String>, String> {
    let mut merged = Vec::with_capacity(base.len() + extra.len());
    merged.extend(base.iter().cloned());
    merged.extend(extra.iter().cloned());
    reject_duplicates(name, &merged)?;
    Ok(merged)
}

fn validate_list(name: &str, values: &[String]) -> std::result::Result<(), String> {
    if values.is_empty() {
        return Err(format!("skip_dirs.{name} must contain at least one entry"));
    }
    for value in values {
        if value.is_empty() || value.trim() != value {
            return Err(format!(
                "skip_dirs.{name} entry {value:?} must be non-empty and trimmed"
            ));
        }
        if value.contains('/') || value.contains('\\') {
            return Err(format!(
                "skip_dirs.{name} entry {value:?} must be a single path component"
            ));
        }
        if value.chars().any(char::is_control) {
            return Err(format!(
                "skip_dirs.{name} entry {value:?} must not contain control characters"
            ));
        }
    }
    reject_duplicates(name, values)
}

fn reject_duplicates(name: &str, values: &[String]) -> std::result::Result<(), String> {
    let mut seen = BTreeSet::new();
    for value in values {
        let key = value.to_ascii_lowercase();
        if !seen.insert(key) {
            return Err(format!(
                "skip_dirs.{name} contains duplicate component {value:?}"
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{BUNDLED_SKIP_DIRS, SkipDirPolicy, parse_section};

    #[test]
    fn bundled_policy_contains_consumer_specific_components() {
        let section = parse_section(BUNDLED_SKIP_DIRS).expect("bundled TOML parses");
        let policy = SkipDirPolicy::from_section(section).expect("bundled skip-dir policy loads");

        assert!(policy.is_watch_component(".GIT"));
        assert!(policy.is_watch_component("NODE_MODULES"));
        assert!(policy.is_git_discovery_component("node_modules"));
        assert!(policy.is_git_discovery_component("system volume information"));
        assert!(!policy.is_git_discovery_component(".git"));
    }

    #[test]
    fn policy_validation_rejects_path_components_with_separators() {
        let raw = r#"
            [skip_dirs]
            base = ["node_modules/inner"]
            watch_extra = [".git"]
            git_discovery_extra = ["Library"]
        "#;

        let section = parse_section(raw).expect("TOML shape parses");
        let error = SkipDirPolicy::from_section(section).expect_err("separator must be rejected");
        assert!(
            error.contains("single path component"),
            "unexpected validation error: {error}"
        );
    }
}

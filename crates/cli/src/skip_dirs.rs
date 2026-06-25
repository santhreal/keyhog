//! Shared Tier-B directory skip policy for CLI filesystem surfaces.

use anyhow::{Context, Result};
use std::collections::BTreeSet;

const BUNDLED_SKIP_DIRS: &str = include_str!("../data/path_skip_dirs.toml");
const GIT_DISCOVERY_KEEP_COMPONENTS: &[&str] = &[".git"];

#[derive(Debug, Clone)]
pub(crate) struct SkipDirPolicy {
    watch: Vec<String>,
    git_discovery: Vec<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct SkipDirFile {
    #[serde(default)]
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
                    merge_user_section(&mut section, user)
                        .map_err(anyhow::Error::msg)
                        .with_context(|| {
                            format!("validate path skip-dir policy {}", user_path.display())
                        })?;
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

        let source_default_dirs = keyhog_sources::default_exclude_dir_components();
        let watch = merge_lists(
            "watch",
            &[
                ("source_default_dirs", source_default_dirs),
                ("base", &section.base),
                ("watch_extra", &section.watch_extra),
            ],
            &[],
        )?;
        let git_discovery = merge_lists(
            "git_discovery",
            &[
                ("source_default_dirs", source_default_dirs),
                ("base", &section.base),
                ("git_discovery_extra", &section.git_discovery_extra),
            ],
            GIT_DISCOVERY_KEEP_COMPONENTS,
        )?;
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

fn merge_user_section(
    bundled: &mut SkipDirSection,
    user: SkipDirSection,
) -> std::result::Result<(), String> {
    validate_optional_list("user.base", &user.base)?;
    validate_optional_list("user.watch_extra", &user.watch_extra)?;
    validate_optional_list("user.git_discovery_extra", &user.git_discovery_extra)?;

    extend_unique(&mut bundled.base, user.base);
    extend_unique(&mut bundled.watch_extra, user.watch_extra);
    extend_unique(&mut bundled.git_discovery_extra, user.git_discovery_extra);
    Ok(())
}

fn contains_component(policy: &[String], component: &str) -> bool {
    policy
        .iter()
        .any(|skip| component.eq_ignore_ascii_case(skip))
}

fn merge_lists(
    name: &str,
    lists: &[(&str, &[String])],
    keep_components: &[&str],
) -> std::result::Result<Vec<String>, String> {
    let capacity = lists.iter().map(|(_, list)| list.len()).sum();
    let mut merged = Vec::with_capacity(capacity);
    let mut seen = BTreeSet::new();
    for (_, list) in lists {
        for value in *list {
            if keep_components
                .iter()
                .any(|keep| value.eq_ignore_ascii_case(keep))
            {
                continue;
            }
            if !seen.insert(value.to_ascii_lowercase()) {
                continue;
            }
            merged.push(value.clone());
        }
    }
    if merged.is_empty() {
        return Err(format!("skip_dirs.{name} must contain at least one entry"));
    }
    Ok(merged)
}

fn validate_list(name: &str, values: &[String]) -> std::result::Result<(), String> {
    if values.is_empty() {
        return Err(format!("skip_dirs.{name} must contain at least one entry"));
    }
    validate_entries(name, values)
}

fn validate_optional_list(name: &str, values: &[String]) -> std::result::Result<(), String> {
    if values.is_empty() {
        return Ok(());
    }
    validate_entries(name, values)
}

fn validate_entries(name: &str, values: &[String]) -> std::result::Result<(), String> {
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

fn extend_unique(target: &mut Vec<String>, values: Vec<String>) {
    let mut seen: BTreeSet<String> = target
        .iter()
        .map(|value| value.to_ascii_lowercase())
        .collect();
    for value in values {
        if seen.insert(value.to_ascii_lowercase()) {
            target.push(value);
        }
    }
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

/// Test seam: the skip-dir policy parse/merge/validate path has unit tests
/// relocated to `crates/cli/tests/unit/` (the `no_inline_tests_in_src` gate
/// forbids inline `#[cfg(test)]`). These thin wrappers drive the otherwise
/// module-private `parse_section`/`merge_user_section`/`from_section` through
/// the `crate::testing` facade. Always compiled (referenced by `pub mod
/// testing`), so they never go stale.
pub(crate) mod testing {
    use super::{merge_user_section, parse_section, SkipDirPolicy, BUNDLED_SKIP_DIRS};

    pub(crate) fn policy_from_toml(toml: &str) -> std::result::Result<SkipDirPolicy, String> {
        SkipDirPolicy::from_section(parse_section(toml)?)
    }

    pub(crate) fn policy_from_bundled() -> std::result::Result<SkipDirPolicy, String> {
        SkipDirPolicy::from_section(parse_section(BUNDLED_SKIP_DIRS)?)
    }

    pub(crate) fn policy_from_bundled_plus_user(
        user_toml: &str,
    ) -> std::result::Result<SkipDirPolicy, String> {
        let mut bundled = parse_section(BUNDLED_SKIP_DIRS)?;
        let user = parse_section(user_toml)?;
        merge_user_section(&mut bundled, user)?;
        SkipDirPolicy::from_section(bundled)
    }

    /// `(base, watch_extra, git_discovery_extra)` element counts for a parsed
    /// section — proves an empty user TOML is a no-op section.
    pub(crate) fn section_counts(toml: &str) -> std::result::Result<(usize, usize, usize), String> {
        let section = parse_section(toml)?;
        Ok((
            section.base.len(),
            section.watch_extra.len(),
            section.git_discovery_extra.len(),
        ))
    }
}

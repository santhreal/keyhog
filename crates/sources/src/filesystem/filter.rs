use codewalk::WalkConfig;
use std::collections::{BTreeSet, HashSet};
use std::sync::LazyLock;

static DEFAULT_EXCLUDES: LazyLock<DefaultExcludeRules> = LazyLock::new(|| {
    match parse_default_excludes(include_str!("../../../../rules/default_excludes.toml")) {
        Ok(rules) => rules,
        Err(error) => {
            panic!(
                "rules/default_excludes.toml is invalid: {error}. Fix the bundled Tier-B \
                 default-exclude policy; refusing to run with unknown source exclusion truth."
            )
        }
    }
});

static SKIP_EXTENSIONS_SET: LazyLock<HashSet<&'static str>> = LazyLock::new(|| {
    default_excludes()
        .extensions
        .iter()
        .map(String::as_str)
        .collect()
});

pub(super) fn skip_extensions() -> &'static HashSet<&'static str> {
    &SKIP_EXTENSIONS_SET
}

pub(super) fn is_skip_extension(ext: &str) -> bool {
    skip_extensions()
        .iter()
        .any(|skip| ext.eq_ignore_ascii_case(skip))
}

fn default_excludes() -> &'static DefaultExcludeRules {
    &DEFAULT_EXCLUDES
}

pub(super) fn default_exclude_dirs() -> &'static [String] {
    &default_excludes().dirs
}

#[derive(Debug)]
struct DefaultExcludeRules {
    extensions: Vec<String>,
    dirs: Vec<String>,
    suffixes: Vec<String>,
    filenames: Vec<String>,
    filename_prefix_suffixes: Vec<PrefixSuffixRule>,
}

#[derive(Debug, serde::Deserialize)]
struct DefaultExcludeFile {
    default_excludes: DefaultExcludeSection,
}

#[derive(Debug, serde::Deserialize)]
struct DefaultExcludeSection {
    extensions: Vec<String>,
    dirs: Vec<String>,
    suffixes: Vec<String>,
    filenames: Vec<String>,
    filename_prefix_suffixes: Vec<PrefixSuffixRule>,
}

#[derive(Debug, serde::Deserialize)]
struct PrefixSuffixRule {
    prefix: String,
    suffix: String,
}

fn parse_default_excludes(raw: &str) -> Result<DefaultExcludeRules, String> {
    let parsed: DefaultExcludeFile =
        toml::from_str(raw).map_err(|error| format!("invalid default_excludes.toml: {error}"))?;
    let section = parsed.default_excludes;
    let extensions =
        normalize_rule_list("extensions", section.extensions, RuleListKind::Extension)?;
    let dirs = normalize_rule_list("dirs", section.dirs, RuleListKind::PathSegment)?;
    let suffixes = normalize_rule_list("suffixes", section.suffixes, RuleListKind::Suffix)?;
    let filenames = normalize_rule_list("filenames", section.filenames, RuleListKind::Filename)?;
    let filename_prefix_suffixes = normalize_prefix_suffix_rules(section.filename_prefix_suffixes)?;

    Ok(DefaultExcludeRules {
        extensions,
        dirs,
        suffixes,
        filenames,
        filename_prefix_suffixes,
    })
}

#[derive(Clone, Copy)]
enum RuleListKind {
    Extension,
    PathSegment,
    Suffix,
    Filename,
}

fn normalize_rule_list(
    name: &str,
    values: Vec<String>,
    kind: RuleListKind,
) -> Result<Vec<String>, String> {
    if values.is_empty() {
        return Err(format!(
            "default_excludes.{name} must contain at least one entry"
        ));
    }

    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(values.len());
    for raw in values {
        let value = raw.trim();
        validate_rule_value(name, value, kind)?;
        let value = value.to_string();
        if !seen.insert(value.clone()) {
            return Err(format!("duplicate default_excludes.{name} entry {value:?}"));
        }
        out.push(value);
    }
    Ok(out)
}

fn validate_rule_value(name: &str, value: &str, kind: RuleListKind) -> Result<(), String> {
    if value.is_empty() {
        return Err(format!("default_excludes.{name} entries must not be empty"));
    }
    if value != value.to_ascii_lowercase() {
        return Err(format!(
            "default_excludes.{name} entry {value:?} must be lowercase ASCII"
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(format!(
            "default_excludes.{name} entry {value:?} contains a control character"
        ));
    }
    match kind {
        RuleListKind::Extension => {
            if value.starts_with('.') || value.contains('/') || value.contains('\\') {
                return Err(format!(
                    "default_excludes.extensions entry {value:?} must be an extension without dot or path separators"
                ));
            }
        }
        RuleListKind::PathSegment | RuleListKind::Filename => {
            if value.contains('/') || value.contains('\\') {
                return Err(format!(
                    "default_excludes.{name} entry {value:?} must not contain path separators"
                ));
            }
        }
        RuleListKind::Suffix => {
            if !value.starts_with('.') || value.contains('/') || value.contains('\\') {
                return Err(format!(
                    "default_excludes.suffixes entry {value:?} must start with dot and contain no path separators"
                ));
            }
        }
    }
    Ok(())
}

fn normalize_prefix_suffix_rules(
    rules: Vec<PrefixSuffixRule>,
) -> Result<Vec<PrefixSuffixRule>, String> {
    if rules.is_empty() {
        return Err(
            "default_excludes.filename_prefix_suffixes must contain at least one entry".to_string(),
        );
    }

    let mut seen = BTreeSet::new();
    let mut out = Vec::with_capacity(rules.len());
    for mut rule in rules {
        rule.prefix = rule.prefix.trim().to_string();
        rule.suffix = rule.suffix.trim().to_string();
        validate_rule_value(
            "filename_prefix_suffixes.prefix",
            &rule.prefix,
            RuleListKind::Filename,
        )?;
        validate_rule_value(
            "filename_prefix_suffixes.suffix",
            &rule.suffix,
            RuleListKind::Suffix,
        )?;
        let key = (rule.prefix.clone(), rule.suffix.clone());
        if !seen.insert(key.clone()) {
            return Err(format!(
                "duplicate default_excludes.filename_prefix_suffixes entry {key:?}"
            ));
        }
        out.push(rule);
    }
    Ok(out)
}

/// Check if a path matches the built-in default exclusion patterns.
/// Mirrors the patterns in `crates/cli/src/sources.rs`.
///
/// ASCII case-insensitive byte comparisons; splits on both `/` and
/// `\` so Windows paths get the same treatment as POSIX. The previous
/// flow built a fully-lowercased copy of the entire path and ran
/// POSIX-only `.contains("/x/")` checks, which (a) allocated per
/// file on the walker hot path and (b) silently failed to exclude
/// `\node_modules\`, `\vendor\`, etc. on Windows checkouts.
pub(super) fn is_default_excluded(path: &str) -> bool {
    let rules = default_excludes();
    let bytes = path.as_bytes();
    let ends_ci = |suffix: &[u8]| -> bool {
        bytes.len() >= suffix.len()
            && bytes[bytes.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    };

    if rules
        .suffixes
        .iter()
        .any(|suffix| ends_ci(suffix.as_bytes()))
    {
        return true;
    }

    let mut filename: &[u8] = bytes;
    for segment in path.split(['/', '\\']) {
        let seg_bytes = segment.as_bytes();
        if is_default_excluded_segment(seg_bytes) {
            return true;
        }
        if !seg_bytes.is_empty() {
            filename = seg_bytes;
        }
    }

    if rules
        .filenames
        .iter()
        .any(|name| filename.eq_ignore_ascii_case(name.as_bytes()))
    {
        return true;
    }

    rules.filename_prefix_suffixes.iter().any(|rule| {
        let prefix = rule.prefix.as_bytes();
        let suffix = rule.suffix.as_bytes();
        filename.len() >= prefix.len() + suffix.len()
            && filename[..prefix.len()].eq_ignore_ascii_case(prefix)
            && filename[filename.len() - suffix.len()..].eq_ignore_ascii_case(suffix)
    })
}

fn is_default_excluded_segment(segment: &[u8]) -> bool {
    default_excludes()
        .dirs
        .iter()
        .any(|skip| segment.eq_ignore_ascii_case(skip.as_bytes()))
}

pub(super) fn walker_config(
    max_file_size: u64,
    ignore_paths: &[String],
    respect_default_excludes: bool,
) -> WalkConfig {
    let ignore_overrides = ignore_paths
        .iter()
        .map(|pattern| {
            if pattern.starts_with('!') {
                pattern.clone()
            } else {
                format!("!{pattern}")
            }
        })
        .collect();

    // Pass max_file_size=0 (unlimited) to codewalk so the cap is
    // enforced inside keyhog instead. That moves the silent walker
    // skip into `extract::process_entry` where we can warn + count it
    // (kimi-1 dogfood #130). codewalk's size filter runs before its
    // binary-detect read, so disabling it adds ~4 KiB of extra read
    // per over-size file - negligible at the scale where users hit
    // the cap.
    // Default excludes stay out of codewalk so every skipped file reaches
    // `extract::process_entry`, where it is counted through SourceSkipEvent.
    let _ = max_file_size; // LAW10: unused-binding marker; no runtime effect, not a fallback
    let _ = respect_default_excludes; // LAW10: walker does not own default-exclude decisions; process_entry owns visible skip accounting

    WalkConfig::default()
        .max_file_size(0)
        .follow_symlinks(false)
        .respect_gitignore(true)
        .skip_hidden(false)
        .skip_binary(false)
        .exclude_extensions(HashSet::new())
        .exclude_dirs(HashSet::new())
        .ignore_files(vec![".keyhogignore".to_string()])
        .ignore_patterns(ignore_overrides)
}

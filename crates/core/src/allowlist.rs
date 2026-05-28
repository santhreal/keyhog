//! Allowlist support: `.keyhogignore` file parsing for suppressing known false
//! positives by path glob, detector ID, or credential hash.

/// Allowlist: known false positives and ignored patterns.
///
/// Users can create a `.keyhogignore` file to suppress known FPs.
/// Format (one per line):
///   - `hash:<sha256>` - ignore a specific credential by hash
///   - `detector:<id>` - ignore all findings from a detector
///   - `path:<glob>` - ignore files matching a glob pattern
///   - `# comment` - comments
///   - blank lines are skipped
use std::collections::HashSet;
use std::path::Component;
use std::path::Path;

use crate::VerifiedFinding;

#[path = "allowlist_metadata.rs"]
mod allowlist_metadata;
use allowlist_metadata::*;

/// User-defined suppressions loaded from `.keyhogignore`: credential hashes, detector IDs, and path globs.
///
/// # Examples
///
/// ```rust
/// use keyhog_core::allowlist::Allowlist;
///
/// let allowlist = Allowlist::parse("detector:demo-token\npath:**/*.md\n");
/// assert!(allowlist.ignored_detectors.contains("demo-token"));
/// ```
#[derive(Debug, Clone, serde::Serialize)]
pub struct Allowlist {
    /// SHA-256 hashes of credentials to ignore.
    pub credential_hashes: HashSet<[u8; 32]>,
    /// Detector IDs to ignore entirely.
    pub ignored_detectors: HashSet<String>,
    /// Glob patterns for paths to ignore.
    pub ignored_paths: Vec<String>,
}

const MAX_GLOB_SEGMENTS: usize = 256;
const MAX_GLOB_SEGMENT_LEN: usize = 1024;

impl Allowlist {
    /// Create an empty allowlist with no suppressed hashes, detectors, or paths.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::allowlist::Allowlist;
    ///
    /// let allowlist = Allowlist::empty();
    /// assert!(allowlist.ignored_paths.is_empty());
    /// ```
    pub fn empty() -> Self {
        Self {
            credential_hashes: HashSet::new(),
            ignored_detectors: HashSet::new(),
            ignored_paths: Vec::new(),
        }
    }

    /// Load from a .keyhogignore file.
    ///
    /// # Examples
    ///
    /// ```rust,no_run
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use keyhog_core::allowlist::Allowlist;
    /// use std::path::Path;
    ///
    /// let _allowlist = Allowlist::load(Path::new(".keyhogignore"))?;
    /// # Ok(()) }
    /// ```
    pub fn load(path: &Path) -> Result<Self, std::io::Error> {
        let contents = std::fs::read_to_string(path)?;
        Ok(Self::parse(&contents))
    }

    /// Parse allowlist from string content.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::allowlist::Allowlist;
    ///
    /// let allowlist = Allowlist::parse("path:**/.env\ndetector:demo-token\n");
    /// assert!(allowlist.is_path_ignored("app/.env"));
    /// ```
    pub fn parse(content: &str) -> Self {
        let mut al = Self::empty();
        let today = today_yyyy_mm_dd();
        for (line_number, raw_line) in content.lines().enumerate() {
            let raw_line = raw_line.trim();
            if raw_line.is_empty() || raw_line.starts_with('#') {
                continue;
            }
            // Optional inline metadata: `entry; reason="..."; expires=YYYY-MM-DD; approved_by="..."`
            // Each `;`-separated token after the first is a key=value pair.
            let mut parts = raw_line.splitn(2, ';');
            let entry = parts.next().unwrap_or("").trim();
            let metadata = parts.next().unwrap_or("");
            let parsed_meta = parse_inline_metadata(metadata);

            // Drop entries whose `expires` is past - keeps `.keyhogignore`
            // self-cleaning for short-lived approvals (Tier-B #18 governance).
            if let Some(exp) = parsed_meta.expires.as_deref() {
                if exp < today.as_str() {
                    tracing::warn!(
                        "allowlist entry expired on {} (today is {}): '{}'",
                        exp,
                        today,
                        entry
                    );
                    continue;
                }
            }

            if let Some(hash) = entry.strip_prefix("hash:") {
                let trimmed = hash.trim();
                if let Some(valid_hash) = parse_sha256_hex(trimmed) {
                    al.credential_hashes.insert(valid_hash);
                    log_metadata_audit("hash", trimmed, &parsed_meta);
                } else {
                    tracing::warn!(
                        "invalid hash allowlist entry at line {}: '{}'",
                        line_number + 1,
                        trimmed
                    );
                }
            } else if let Some(detector) = entry.strip_prefix("detector:") {
                let detector = detector.trim();
                if detector.is_empty() {
                    tracing::warn!(
                        "invalid detector allowlist entry at line {}: detector id is empty",
                        line_number + 1
                    );
                } else {
                    al.ignored_detectors.insert(detector.to_string());
                    log_metadata_audit("detector", detector, &parsed_meta);
                }
            } else if let Some(path) = entry.strip_prefix("path:") {
                let path = path.trim();
                if path.is_empty() {
                    tracing::warn!(
                        "invalid path allowlist entry at line {}: glob is empty",
                        line_number + 1
                    );
                } else {
                    al.ignored_paths.push(path.to_string());
                    log_metadata_audit("path", path, &parsed_meta);
                }
            } else if let Some(bytes) = parse_sha256_hex(entry) {
                // Bare 64-char hex hash. Lets the obvious
                // `keyhog scan ... --format jsonl | jq -r '.credential_hash'
                // >> .keyhogignore` workflow Just Work without users
                // learning the `hash:` prefix.
                al.credential_hashes.insert(bytes);
                log_metadata_audit("hash", entry, &parsed_meta);
            } else {
                // Bare path glob (gitignore-style). Anything that didn't
                // match an explicit `hash:` / `detector:` / `path:` prefix
                // and isn't a bare hash is interpreted as a path glob,
                // matching `.gitignore` UX (`*.log`, `node_modules/`,
                // `vendor/**/*.json`). kimi-1 dogfood #129 - the prior
                // behavior emitted a warning and silently dropped the
                // line, which is the worst of both worlds: every
                // `.gitignore` users copied over was dead.
                al.ignored_paths.push(entry.to_string());
                log_metadata_audit("path", entry, &parsed_meta);
            }
        }
        al
    }

    /// Check whether detector or path rules suppress a verified finding.
    ///
    /// Hash-based suppression is evaluated earlier on [`crate::RawMatch`] values
    /// because [`VerifiedFinding`] stores only redacted credentials.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::allowlist::Allowlist;
    /// use keyhog_core::{MatchLocation, Severity, VerificationResult, VerifiedFinding};
    /// use std::collections::HashMap;
    ///
    /// let allowlist = Allowlist::parse("detector:demo-token\n");
    /// let finding = VerifiedFinding {
    ///     detector_id: "demo-token".into(),
    ///     detector_name: "Demo Token".into(),
    ///     service: "demo".into(),
    ///     severity: Severity::High,
    ///     credential_redacted: "demo_...1234".into(),
    ///     location: MatchLocation {
    ///         source: "fs".into(),
    ///         file_path: Some("src/main.rs".into()),
    ///         line: Some(1),
    ///         offset: 0,
    ///         commit: None,
    ///         author: None,
    ///         date: None,
    ///     },
    ///     verification: VerificationResult::Unverifiable,
    ///     metadata: std::collections::HashMap::new(),
    ///     additional_locations: Vec::new(),
    ///     confidence: None,
    ///     credential_hash: "hash".to_string(),
    /// };
    /// assert!(allowlist.is_allowed(&finding));
    /// ```
    pub fn is_allowed(&self, finding: &VerifiedFinding) -> bool {
        let detector_ignored = self.ignored_detectors.contains(&*finding.detector_id);

        let path_ignored = finding.location.file_path.as_ref().is_some_and(|path| {
            let normalized_path = normalize_path(path);
            self.ignored_paths
                .iter()
                .any(|pattern| glob_match_normalized(pattern, &normalized_path))
        });

        let hash_ignored = self.matches_ignored_hash(&finding.credential_hash);

        detector_ignored || path_ignored || hash_ignored
    }

    /// Check if a raw credential hash is allowlisted.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::allowlist::Allowlist;
    ///
    /// let allowlist = Allowlist::parse("");
    /// assert!(!allowlist.is_hash_allowed("demo_ABC12345"));
    /// ```
    pub fn is_hash_allowed(&self, credential: &str) -> bool {
        self.matches_ignored_hash(credential)
    }

    /// Check if a hex-encoded SHA-256 hash is allowlisted.
    pub fn is_raw_hash_ignored(&self, hash_hex: &str) -> bool {
        self.matches_ignored_hash(hash_hex)
    }

    /// Check whether a raw path matches an ignored-path glob.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::allowlist::Allowlist;
    ///
    /// let allowlist = Allowlist::parse("path:**/*.md\n");
    /// assert!(allowlist.is_path_ignored("docs/README.md"));
    /// ```
    pub fn is_path_ignored(&self, path: &str) -> bool {
        let normalized = normalize_path(path);
        self.ignored_paths
            .iter()
            .any(|pattern| glob_match_normalized(pattern, &normalized))
    }

    fn matches_ignored_hash(&self, input: &str) -> bool {
        // Only compare against the parsed-hex form. Earlier versions also
        // hashed the raw input as a fallback, which silently encouraged users
        // to put plaintext credentials in `.keyhogignore` (the file is often
        // committed by accident - see audit release-2026-04-26). The
        // `hash:` parser already rejects non-64-hex inputs at load time, so
        // every legitimate suppressing entry passes through `parse_sha256_hex`
        // here.
        if let Some(hash_bytes) = parse_sha256_hex(input) {
            return self.credential_hashes.contains(&hash_bytes);
        }
        false
    }
}

fn glob_match_normalized(pattern: &str, normalized_path: &str) -> bool {
    let normalized_pattern = normalize_path(pattern);
    let pattern_segments = split_segments(&normalized_pattern);
    let path_segments = split_segments(normalized_path);

    if pattern_segments.len() > MAX_GLOB_SEGMENTS
        || path_segments.len() > MAX_GLOB_SEGMENTS
        || pattern_segments
            .iter()
            .any(|segment| segment.len() > MAX_GLOB_SEGMENT_LEN)
        || path_segments
            .iter()
            .any(|segment| segment.len() > MAX_GLOB_SEGMENT_LEN)
    {
        tracing::warn!(
            "skipping oversized allowlist glob match (pattern segments: {}, path segments: {}). Fix: shorten the glob or path",
            pattern_segments.len(),
            path_segments.len()
        );
        return false;
    }

    glob_match_segments(&pattern_segments, &path_segments)
}

fn split_segments(path: &str) -> Vec<&str> {
    if path.is_empty() {
        Vec::new()
    } else {
        path.split(['/', '\\']).collect()
    }
}

fn glob_match_segments(pattern: &[&str], path: &[&str]) -> bool {
    let mut states = vec![false; path.len() + 1];
    states[0] = true;

    for segment in pattern {
        let mut next = vec![false; path.len() + 1];
        if *segment == "**" {
            let mut reachable = false;
            for idx in 0..=path.len() {
                reachable |= states[idx];
                next[idx] = reachable;
            }
        } else {
            for idx in 0..path.len() {
                if states[idx] && segment_match(segment, path[idx]) {
                    next[idx + 1] = true;
                }
            }
        }
        states = next;
    }

    states[path.len()]
}

fn segment_match(pattern: &str, text: &str) -> bool {
    if pattern.is_ascii() && text.is_ascii() {
        return segment_match_ascii(pattern.as_bytes(), text.as_bytes());
    }

    segment_match_chars(pattern, text)
}

#[allow(clippy::similar_names)] // star_pi / star_ti name the same Kleene-star state in two coordinate systems
fn segment_match_ascii(pattern: &[u8], text: &[u8]) -> bool {
    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star_pi = None;
    let mut star_ti = 0usize;

    while ti < text.len() {
        if pi < pattern.len() && pattern[pi] == b'*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
            continue;
        }

        if pi < pattern.len() && pattern[pi] == text[ti] {
            pi += 1;
            ti += 1;
            continue;
        }

        if let Some(star) = star_pi {
            star_ti += 1;
            ti = star_ti;
            pi = star + 1;
            continue;
        }

        return false;
    }

    while pi < pattern.len() && pattern[pi] == b'*' {
        pi += 1;
    }

    pi == pattern.len()
}

#[allow(clippy::similar_names)] // star_pi / star_ti name the same Kleene-star state in two coordinate systems
fn segment_match_chars(pattern: &str, text: &str) -> bool {
    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();

    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star_pi = None;
    let mut star_ti = 0usize;

    while ti < text_chars.len() {
        if pi < pattern_chars.len() && pattern_chars[pi] == '*' {
            star_pi = Some(pi);
            star_ti = ti;
            pi += 1;
            continue;
        }

        if pi < pattern_chars.len() && pattern_chars[pi] == text_chars[ti] {
            pi += 1;
            ti += 1;
            continue;
        }

        if let Some(star) = star_pi {
            star_ti += 1;
            ti = star_ti;
            pi = star + 1;
            continue;
        }

        return false;
    }

    while pi < pattern_chars.len() && pattern_chars[pi] == '*' {
        pi += 1;
    }

    pi == pattern_chars.len()
}

fn normalize_path(path: &str) -> String {
    let path = path.replace('\\', "/");
    let mut parts = Vec::new();
    for component in Path::new(&path).components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if !parts.is_empty() && parts.last().is_some_and(|part| part != "..") {
                    parts.pop();
                } else {
                    parts.push("..".to_string());
                }
            }
            Component::Normal(part) => parts.push(part.to_string_lossy().into_owned()),
            Component::RootDir => parts.clear(),
            Component::Prefix(prefix) => parts.push(prefix.as_os_str().to_string_lossy().into()),
        }
    }
    parts.join("/")
}

fn parse_sha256_hex(input: &str) -> Option<[u8; 32]> {
    let input = input.trim();
    if input.len() != 64 {
        return None;
    }

    let mut digest = [0u8; 32];
    for idx in 0..32 {
        let chunk = &input[idx * 2..idx * 2 + 2];
        digest[idx] = u8::from_str_radix(chunk, 16).ok()?;
    }
    Some(digest)
}

/// Inline metadata parsed from a `.keyhogignore` line trailer. Used to
/// implement enterprise governance fields (`reason`, `expires`,
/// `approved_by`) per audits/legendary-2026-04-26 Tier-B #18.
#[derive(Default, Debug)]
struct InlineMetadata {
    reason: Option<String>,
    expires: Option<String>,
    approved_by: Option<String>,
}

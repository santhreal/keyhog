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
use std::collections::HashMap;
use std::collections::HashSet;
use std::path::Component;
use std::path::Path;

use crate::merkle_spec_hash::hex_nibble;
use crate::VerifiedFinding;

// Submodule lives in `allowlist/` (native resolution), matching the
// `foo.rs` + `foo/` layout used across the workspace.
mod metadata;
use metadata::*;

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
    /// Glob patterns for paths to ignore (raw, as authored). Kept as the public
    /// contract + serialized form; the matcher consumes the precompiled
    /// [`PathGlobIndex`] built from these in [`Allowlist::parse`].
    pub ignored_paths: Vec<String>,
    /// Precompiled, first-segment-bucketed form of `ignored_paths`. Built once
    /// in `parse`/`empty` so per-finding path checks neither re-normalize +
    /// re-split each pattern nor sweep every rule. Skipped by `serde` (it is a
    /// pure function of `ignored_paths`; reconstructed via `Deserialize`/manual
    /// rebuild if ever needed) so the serialized shape is unchanged.
    #[serde(skip)]
    path_index: PathGlobIndex,
}

const MAX_GLOB_SEGMENTS: usize = 256;
const MAX_GLOB_SEGMENT_LEN: usize = 1024;

/// One precompiled ignored-path glob: its normalized segments computed ONCE at
/// parse time, plus the oversize verdict that `glob_match_normalized` used to
/// recompute per finding. `anchor` records how the pattern's first segment can
/// match a path's first segment, so the index can skip patterns that cannot
/// possibly match a given path without running the full automaton.
#[derive(Debug, Clone)]
struct CompiledGlob {
    /// Normalized pattern segments (the `normalize_path` + `split_segments`
    /// result, owned). Empty when the pattern normalized to nothing.
    segments: Vec<String>,
    /// True when the pattern (or, at match time, the path) is too large to
    /// match safely - preserves the original `glob_match_normalized` fail-safe.
    /// A path larger than the cap is rejected at match time; an oversize
    /// pattern is pre-marked here so it never matches anything.
    oversize: bool,
}

/// First-segment bucketed index over the compiled globs. A path can match a
/// glob only if the glob's first segment is `**` (matches any prefix), or it
/// matches the path's FIRST segment. Literal first segments key a hash bucket;
/// wildcard / `**` first segments (which can match many first segments) fall
/// into `wild_first`, always tested. This turns the per-finding O(rules) sweep
/// into O(wild_first + matching_literal_bucket), sub-linear in total rule count
/// for the realistic monorepo `.gitignore` shape (mostly literal-anchored dir
/// rules), while reproducing `glob_match_segments` bit-for-bit.
#[derive(Debug, Clone, Default)]
struct PathGlobIndex {
    /// Globs whose first segment is a pure literal, keyed by that literal. A
    /// path is tested only against the bucket for its own first segment.
    literal_first: HashMap<String, Vec<CompiledGlob>>,
    /// Globs whose first segment is `**` or contains a `*` wildcard (it can
    /// match more than one distinct first segment, so it cannot be bucketed by
    /// a literal). Always tested.
    wild_first: Vec<CompiledGlob>,
    /// Globs that normalized to ZERO segments (e.g. a pattern that was only
    /// `.` / `..` noise). `glob_match_segments(&[], path)` is true only for the
    /// empty path, so these are kept apart and only consulted for that case.
    empty_pattern: Vec<CompiledGlob>,
    /// Number of source patterns this index was compiled from. `ignored_paths`
    /// is a PUBLIC, mutable field: callers may push/extend/clear it directly
    /// after construction (the documented `.gitignore`-append workflow). The
    /// matcher compares this against the live `ignored_paths.len()` and rebuilds
    /// on mismatch, so a directly-mutated allowlist never silently under- or
    /// over-suppresses. Construction paths (`parse`/`load`/`empty`) keep it in
    /// sync, so the hot scanner path never pays the rebuild.
    source_len: usize,
}

impl PathGlobIndex {
    /// Build the index from raw ignored-path patterns. Runs `normalize_path` +
    /// `split_segments` + the oversize scan ONCE per pattern (the work
    /// `glob_match_normalized` previously repeated on every finding).
    fn build(patterns: &[String]) -> Self {
        let mut index = PathGlobIndex::default();
        index.source_len = patterns.len();
        for pattern in patterns {
            let normalized_pattern = normalize_path(pattern);
            let segments: Vec<String> = split_segments(&normalized_pattern)
                .into_iter()
                .map(str::to_string)
                .collect();
            // Mirror the pattern half of the original oversize fail-safe: an
            // oversize pattern can never match (it returned false before).
            let oversize = segments.len() > MAX_GLOB_SEGMENTS
                || segments.iter().any(|s| s.len() > MAX_GLOB_SEGMENT_LEN);
            let glob = CompiledGlob { segments, oversize };

            match glob.segments.first() {
                None => index.empty_pattern.push(glob),
                Some(first) if first == "**" || first.contains('*') => {
                    index.wild_first.push(glob);
                }
                Some(first) => {
                    index
                        .literal_first
                        .entry(first.clone())
                        .or_default()
                        .push(glob);
                }
            }
        }
        index
    }

    /// True when any compiled glob matches `normalized_path`. Tests only the
    /// candidate set for `normalized_path`'s first segment plus the always-on
    /// wildcard-anchored globs - never the full rule list.
    fn matches(&self, normalized_path: &str) -> bool {
        let path_segments = split_segments(normalized_path);

        // Path-side oversize fail-safe (was recomputed per pattern before).
        let path_oversize = path_segments.len() > MAX_GLOB_SEGMENTS
            || path_segments.iter().any(|s| s.len() > MAX_GLOB_SEGMENT_LEN);
        if path_oversize {
            tracing::warn!(
                "skipping oversized allowlist path match ({} segments). Fix: shorten the path",
                path_segments.len()
            );
            return false;
        }

        let test = |glob: &CompiledGlob| -> bool {
            !glob.oversize && glob_match_segments(&glob.segments, &path_segments)
        };

        // Empty path: only a zero-segment pattern (or a `**`-led one, which is
        // in wild_first) can match. Mirror `glob_match_segments(&[], &[])`.
        if path_segments.is_empty() {
            return self.empty_pattern.iter().any(test) || self.wild_first.iter().any(test);
        }

        let first = path_segments[0];
        if let Some(bucket) = self.literal_first.get(first) {
            if bucket.iter().any(test) {
                return true;
            }
        }
        self.wild_first.iter().any(test)
    }
}

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
            path_index: PathGlobIndex::default(),
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
        // Precompile the path globs ONCE: segments + oversize verdict + the
        // first-segment bucket index, so per-finding suppression neither
        // re-normalizes each pattern nor sweeps every rule.
        al.path_index = PathGlobIndex::build(&al.ignored_paths);
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
    ///     credential_hash: [0u8; 32],
    /// };
    /// assert!(allowlist.is_allowed(&finding));
    /// ```
    pub fn is_allowed(&self, finding: &VerifiedFinding) -> bool {
        let detector_ignored = self.ignored_detectors.contains(&*finding.detector_id);

        let path_ignored = finding.location.file_path.as_ref().is_some_and(|path| {
            let normalized_path = normalize_path(path);
            self.path_matches(&normalized_path)
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
        parse_sha256_hex(credential).is_some_and(|bytes| self.matches_ignored_hash(&bytes))
    }

    /// Check if a hex-encoded SHA-256 hash is allowlisted.
    pub fn is_raw_hash_ignored(&self, hash_hex: &str) -> bool {
        parse_sha256_hex(hash_hex).is_some_and(|bytes| self.matches_ignored_hash(&bytes))
    }

    /// Check if a finding's raw 32-byte SHA-256 hash is allowlisted - the
    /// scan-path entry that takes the `[u8; 32]` form directly (no hex
    /// round-trip). Siblings `is_hash_allowed` / `is_raw_hash_ignored` accept
    /// the hex-string form for `.keyhogignore` self-checks and CLI input.
    pub fn is_hash_ignored(&self, hash: &[u8; 32]) -> bool {
        self.matches_ignored_hash(hash)
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
        self.path_matches(&normalized)
    }

    /// Run the precompiled path-glob index against an already-normalized path,
    /// rebuilding the index first iff the public `ignored_paths` field was
    /// mutated directly since construction (detected by a length mismatch).
    /// The construction paths keep the index in sync, so the scanner hot path
    /// always takes the fast branch; only a hand-mutated allowlist pays the
    /// one-off rebuild, and it pays it for correctness, not silently skips it.
    fn path_matches(&self, normalized_path: &str) -> bool {
        if self.path_index.source_len == self.ignored_paths.len() {
            self.path_index.matches(normalized_path)
        } else {
            PathGlobIndex::build(&self.ignored_paths).matches(normalized_path)
        }
    }

    fn matches_ignored_hash(&self, hash: &[u8; 32]) -> bool {
        // Direct byte-set membership. Suppressing `hash:` entries are parsed
        // from 64-hex into this same `[u8; 32]` form at load time
        // (`parse_sha256_hex`), and findings carry the raw bytes, so no hex
        // round-trip happens here. (Earlier versions also hashed raw input as a
        // fallback, which silently encouraged plaintext in `.keyhogignore` - the
        // file is often committed by accident; that path is intentionally gone,
        // see audit release-2026-04-26.)
        self.credential_hashes.contains(hash)
    }
}

fn split_segments(path: &str) -> Vec<&str> {
    if path.is_empty() {
        Vec::new()
    } else {
        path.split(['/', '\\']).collect()
    }
}

/// Segment-automaton glob match. Pattern segments are accepted by reference
/// (`AsRef<str>`) so the precompiled `Vec<String>` index entries match WITHOUT
/// re-borrowing into a `Vec<&str>` per finding; the path segments stay
/// `&[&str]` (borrowed from the normalized path string). The matching logic is
/// byte-for-byte the original automaton - only the pattern element type was
/// generalized, so suppression decisions are identical.
fn glob_match_segments<S: AsRef<str>>(pattern: &[S], path: &[&str]) -> bool {
    let mut states = vec![false; path.len() + 1];
    states[0] = true;

    for segment in pattern {
        let segment = segment.as_ref();
        let mut next = vec![false; path.len() + 1];
        if segment == "**" {
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
    // A SHA-256 hex digest is 64 ASCII bytes. Operate on the byte slice, not
    // `&str[..]` slicing: a 64-*byte* input containing a multibyte UTF-8 char
    // at an odd offset (e.g. a stray `é` pasted into `.keyhogignore`) would
    // make `&input[idx*2..idx*2+2]` panic on a non-char boundary. Decode each
    // nibble directly so any non-hex byte just fails the parse.
    let bytes = input.as_bytes();
    if bytes.len() != 64 {
        return None;
    }
    let mut digest = [0u8; 32];
    for idx in 0..32 {
        let hi = hex_nibble(bytes[idx * 2])?;
        let lo = hex_nibble(bytes[idx * 2 + 1])?;
        digest[idx] = (hi << 4) | lo;
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

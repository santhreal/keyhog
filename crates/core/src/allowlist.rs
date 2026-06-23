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
use std::path::Path;

use crate::merkle_spec_hash::hex_to_array;
use crate::{CredentialHash, VerifiedFinding};

// Submodules live in `allowlist/` (native resolution), matching the
// `foo.rs` + `foo/` layout used across the workspace.
mod metadata;
use metadata::*;

// Path-glob matching (normalization, segment automaton, first-segment bucketed
// index) is its own subsystem; the `Allowlist` holds a precompiled index and
// delegates every path decision to it.
mod glob;
use glob::{normalize_path, PathGlobIndex};

/// User-defined suppressions loaded from `.keyhogignore`: credential hashes, detector IDs, and path globs.
///
/// # Examples
///
/// ```rust
/// # fn main() -> Result<(), Box<dyn std::error::Error>> {
/// use keyhog_core::Allowlist;
///
/// let path = std::env::temp_dir().join(format!(
///     "keyhog_allowlist_struct_{}.keyhogignore",
///     std::process::id()
/// ));
/// std::fs::write(&path, "detector:demo-token\npath:**/*.md\n")?;
/// let allowlist = Allowlist::load_with_metadata_policy(&path, false, false, None)?;
/// std::fs::remove_file(&path)?;
/// assert!(allowlist.ignored_detectors.contains("demo-token"));
/// # Ok(()) }
/// ```
#[derive(Debug, Clone, serde::Serialize)]
pub struct Allowlist {
    /// SHA-256 hashes of credentials to ignore.
    pub credential_hashes: HashSet<CredentialHash>,
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
    /// Expired policy lines found while parsing. They are never active
    /// suppressions; `load` turns them into a user-visible policy error.
    #[serde(skip)]
    expired_entries: Vec<ExpiredAllowlistEntry>,
    /// Governance-policy violations found while parsing. They are never active
    /// suppressions; `load_with_policy` turns them into a user-visible policy
    /// error.
    #[serde(skip)]
    policy_violations: Vec<AllowlistPolicyViolation>,
}

#[derive(Debug, Clone)]
struct ExpiredAllowlistEntry {
    line_number: usize,
    entry: String,
    expires: String,
}

#[derive(Debug, Clone, Copy, Default, serde::Serialize)]
struct AllowlistMetadataPolicy {
    require_reason: bool,
    require_approved_by: bool,
    max_expires_days: Option<u64>,
}

impl AllowlistMetadataPolicy {
    fn is_enforced(self) -> bool {
        self.require_reason || self.require_approved_by || self.max_expires_days.is_some()
    }
}

#[derive(Debug, Clone)]
struct AllowlistPolicyViolation {
    line_number: usize,
    entry: String,
    field: &'static str,
    detail: String,
}

impl Allowlist {
    /// Create an empty allowlist with no suppressed hashes, detectors, or paths.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_core::Allowlist;
    ///
    /// let allowlist = Allowlist::default();
    /// assert!(allowlist.ignored_paths.is_empty());
    /// ```
    pub(crate) fn empty() -> Self {
        Self {
            credential_hashes: HashSet::new(),
            ignored_detectors: HashSet::new(),
            ignored_paths: Vec::new(),
            path_index: PathGlobIndex::default(),
            expired_entries: Vec::new(),
            policy_violations: Vec::new(),
        }
    }

    /// Load from a `.keyhogignore` file and enforce metadata governance.
    pub fn load_with_metadata_policy(
        path: &Path,
        require_reason: bool,
        require_approved_by: bool,
        max_expires_days: Option<u64>,
    ) -> Result<Self, std::io::Error> {
        Self::load_with_policy(
            path,
            AllowlistMetadataPolicy {
                require_reason,
                require_approved_by,
                max_expires_days,
            },
        )
    }

    fn load_with_policy(
        path: &Path,
        policy: AllowlistMetadataPolicy,
    ) -> Result<Self, std::io::Error> {
        let contents = std::fs::read_to_string(path)?;
        let allowlist = Self::parse_with_policy(&contents, policy);
        if !allowlist.expired_entries.is_empty() {
            return Err(allowlist.expired_entries_error(path));
        }
        if !allowlist.policy_violations.is_empty() {
            return Err(allowlist.policy_violations_error(path));
        }
        Ok(allowlist)
    }

    /// Parse allowlist from string content.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use keyhog_core::Allowlist;
    ///
    /// let path = std::env::temp_dir().join(format!(
    ///     "keyhog_allowlist_parse_{}.keyhogignore",
    ///     std::process::id()
    /// ));
    /// std::fs::write(&path, "path:**/.env\ndetector:demo-token\n")?;
    /// let allowlist = Allowlist::load_with_metadata_policy(&path, false, false, None)?;
    /// std::fs::remove_file(&path)?;
    /// assert!(allowlist.is_path_ignored("app/.env"));
    /// # Ok(()) }
    /// ```
    pub(crate) fn parse(content: &str) -> Self {
        Self::parse_with_policy(content, AllowlistMetadataPolicy::default())
    }

    fn parse_with_policy(content: &str, policy: AllowlistMetadataPolicy) -> Self {
        let mut al = Self::empty();
        let today_days = today_days_since_epoch();
        let today = yyyy_mm_dd_from_days(today_days);
        for (line_number, raw_line) in content.lines().enumerate() {
            let raw_line = raw_line.trim();
            if raw_line.is_empty() || raw_line.starts_with('#') {
                continue;
            }
            // Optional inline metadata: `entry; reason="..."; expires=YYYY-MM-DD; approved_by="..."`
            // Each `;`-separated token after the first is a key=value pair.
            let mut parts = raw_line.splitn(2, ';');
            let entry = parts.next().unwrap_or("").trim(); // LAW10: missing/non-string field => empty/placeholder; recall-safe
            let metadata = parts.next().unwrap_or(""); // LAW10: missing/non-string field => empty/placeholder; recall-safe
            let parsed_meta = parse_inline_metadata(metadata);

            // Drop entries whose `expires` is past - keeps `.keyhogignore`
            // self-cleaning for short-lived approvals (Tier-B #18 governance).
            if let Some(exp) = parsed_meta.expires.as_deref() {
                match parse_yyyy_mm_dd_days(exp) {
                    Some(exp_days) if exp_days < today_days => {
                        al.expired_entries.push(ExpiredAllowlistEntry {
                            line_number: line_number + 1,
                            entry: entry.to_string(),
                            expires: exp.to_string(),
                        });
                        tracing::warn!(
                            "allowlist entry expired on {} (today is {}): '{}'",
                            exp,
                            today,
                            entry
                        );
                        continue;
                    }
                    Some(_) => {}
                    None => {
                        al.push_policy_violation(
                            line_number + 1,
                            entry,
                            "expires",
                            "must use YYYY-MM-DD".to_string(),
                        );
                        continue;
                    }
                }
            }

            if let Some(hash) = entry.strip_prefix("hash:") {
                let trimmed = hash.trim();
                if let Some(valid_hash) = parse_sha256_hex(trimmed) {
                    if !al.metadata_policy_allows(
                        line_number + 1,
                        entry,
                        &parsed_meta,
                        policy,
                        today_days,
                    ) {
                        continue;
                    }
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
                    if !al.metadata_policy_allows(
                        line_number + 1,
                        entry,
                        &parsed_meta,
                        policy,
                        today_days,
                    ) {
                        continue;
                    }
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
                    if !al.metadata_policy_allows(
                        line_number + 1,
                        entry,
                        &parsed_meta,
                        policy,
                        today_days,
                    ) {
                        continue;
                    }
                    al.ignored_paths.push(path.to_string());
                    log_metadata_audit("path", path, &parsed_meta);
                }
            } else if let Some(bytes) = parse_sha256_hex(entry) {
                // Bare 64-char hex hash. Lets the obvious
                // `keyhog scan ... --format jsonl | jq -r '.credential_hash'
                // >> .keyhogignore` workflow Just Work without users
                // learning the `hash:` prefix.
                if !al.metadata_policy_allows(
                    line_number + 1,
                    entry,
                    &parsed_meta,
                    policy,
                    today_days,
                ) {
                    continue;
                }
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
                if !al.metadata_policy_allows(
                    line_number + 1,
                    entry,
                    &parsed_meta,
                    policy,
                    today_days,
                ) {
                    continue;
                }
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

    fn metadata_policy_allows(
        &mut self,
        line_number: usize,
        entry: &str,
        metadata: &InlineMetadata,
        policy: AllowlistMetadataPolicy,
        today_days: i64,
    ) -> bool {
        if !policy.is_enforced() {
            return true;
        }
        let mut allowed = true;
        if policy.require_reason && metadata.reason.as_deref().is_none_or(str::is_empty) {
            self.push_policy_violation(
                line_number,
                entry,
                "reason",
                "required by [allowlist].require_reason".to_string(),
            );
            allowed = false;
        }
        if policy.require_approved_by && metadata.approved_by.as_deref().is_none_or(str::is_empty) {
            self.push_policy_violation(
                line_number,
                entry,
                "approved_by",
                "required by [allowlist].require_approved_by".to_string(),
            );
            allowed = false;
        }
        if let Some(max_expires_days) = policy.max_expires_days {
            match metadata.expires.as_deref() {
                Some(expires) if !expires.is_empty() => match parse_yyyy_mm_dd_days(expires) {
                    Some(expires_days) => {
                        let max_days = match i64::try_from(max_expires_days) {
                            Ok(days) => days,
                            Err(error) => {
                                self.push_policy_violation(
                                    line_number,
                                    entry,
                                    "expires",
                                    format!(
                                        "max_expires_days={max_expires_days} is too large to enforce ({error})"
                                    ),
                                );
                                allowed = false;
                                return allowed;
                            }
                        };
                        if expires_days.saturating_sub(today_days) > max_days {
                            self.push_policy_violation(
                                line_number,
                                entry,
                                "expires",
                                format!(
                                    "expires={expires} is more than {max_expires_days} days out"
                                ),
                            );
                            allowed = false;
                        }
                    }
                    None => {
                        self.push_policy_violation(
                            line_number,
                            entry,
                            "expires",
                            "must use YYYY-MM-DD when [allowlist].max_expires_days is set"
                                .to_string(),
                        );
                        allowed = false;
                    }
                },
                _ => {
                    self.push_policy_violation(
                        line_number,
                        entry,
                        "expires",
                        "required by [allowlist].max_expires_days".to_string(),
                    );
                    allowed = false;
                }
            }
        }
        allowed
    }

    fn push_policy_violation(
        &mut self,
        line_number: usize,
        entry: &str,
        field: &'static str,
        detail: String,
    ) {
        self.policy_violations.push(AllowlistPolicyViolation {
            line_number,
            entry: entry.to_string(),
            field,
            detail,
        });
    }

    fn expired_entries_error(&self, path: &Path) -> std::io::Error {
        let first = &self.expired_entries[0];
        let extra = self.expired_entries.len().saturating_sub(1);
        let suffix = if extra == 0 {
            String::new()
        } else if extra == 1 {
            " (+1 more expired entry)".to_string()
        } else {
            format!(" (+{extra} more expired entries)")
        };
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} contains expired allowlist policy at line {}: '{}' expired on {}{}. \
                 Remove the entry or renew its expires metadata; refusing to scan with stale suppressions.",
                path.display(),
                first.line_number,
                first.entry,
                first.expires,
                suffix
            ),
        )
    }

    fn policy_violations_error(&self, path: &Path) -> std::io::Error {
        let first = &self.policy_violations[0];
        let extra = self.policy_violations.len().saturating_sub(1);
        let suffix = if extra == 0 {
            String::new()
        } else if extra == 1 {
            " (+1 more policy violation)".to_string()
        } else {
            format!(" (+{extra} more policy violations)")
        };
        std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!(
                "{} violates allowlist governance at line {}: '{}' missing/invalid {} ({}){}. \
                 Add inline metadata like `; reason=\"...\"; approved_by=\"...\"; expires=YYYY-MM-DD` \
                 or relax the [allowlist] policy in .keyhog.toml; refusing to scan with unapproved suppressions.",
                path.display(),
                first.line_number,
                first.entry,
                first.field,
                first.detail,
                suffix
            ),
        )
    }

    /// Check whether detector or path rules suppress a verified finding.
    ///
    /// Hash-based suppression is evaluated earlier on [`crate::RawMatch`] values
    /// because [`VerifiedFinding`] stores only redacted credentials.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use keyhog_core::Allowlist;
    ///
    /// let path = std::env::temp_dir().join(format!(
    ///     "keyhog_allowlist_allowed_{}.keyhogignore",
    ///     std::process::id()
    /// ));
    /// std::fs::write(&path, "detector:demo-token\npath:src/*.rs\n")?;
    /// let allowlist = Allowlist::load_with_metadata_policy(&path, false, false, None)?;
    /// std::fs::remove_file(&path)?;
    /// assert!(allowlist.ignored_detectors.contains("demo-token"));
    /// assert!(allowlist.is_path_ignored("src/main.rs"));
    /// # Ok(()) }
    /// ```
    pub(crate) fn is_allowed(&self, finding: &VerifiedFinding) -> bool {
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
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use keyhog_core::Allowlist;
    ///
    /// let path = std::env::temp_dir().join(format!(
    ///     "keyhog_allowlist_hash_{}.keyhogignore",
    ///     std::process::id()
    /// ));
    /// std::fs::write(&path, "hash:0000000000000000000000000000000000000000000000000000000000000000\n")?;
    /// let allowlist = Allowlist::load_with_metadata_policy(&path, false, false, None)?;
    /// std::fs::remove_file(&path)?;
    /// assert!(allowlist.credential_hashes.contains(&[0u8; 32]));
    /// # Ok(()) }
    /// ```
    pub(crate) fn is_hash_allowed(&self, credential: &str) -> bool {
        self.matches_ignored_hash_hex(credential)
    }

    /// Check if a hex-encoded SHA-256 hash is allowlisted.
    pub(crate) fn is_raw_hash_ignored(&self, hash_hex: &str) -> bool {
        self.matches_ignored_hash_hex(hash_hex)
    }

    /// Check whether a raw path matches an ignored-path glob.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// use keyhog_core::Allowlist;
    ///
    /// let path = std::env::temp_dir().join(format!(
    ///     "keyhog_allowlist_path_{}.keyhogignore",
    ///     std::process::id()
    /// ));
    /// std::fs::write(&path, "path:**/*.md\n")?;
    /// let allowlist = Allowlist::load_with_metadata_policy(&path, false, false, None)?;
    /// std::fs::remove_file(&path)?;
    /// assert!(allowlist.is_path_ignored("docs/README.md"));
    /// # Ok(()) }
    /// ```
    pub fn is_path_ignored(&self, path: &str) -> bool {
        let normalized = normalize_path(path);
        self.path_matches(&normalized)
    }

    /// Run the precompiled path-glob index against an already-normalized path,
    /// rebuilding the index first iff the public `ignored_paths` field was
    /// mutated directly since construction. The construction paths keep the
    /// index in sync, so the scanner hot path always takes the fast branch;
    /// only a hand-mutated allowlist pays the one-off rebuild, and it pays it
    /// for correctness, not silently skips it.
    fn path_matches(&self, normalized_path: &str) -> bool {
        if self.path_index.matches_sources(&self.ignored_paths) {
            self.path_index.matches(normalized_path)
        } else {
            PathGlobIndex::build(&self.ignored_paths).matches(normalized_path)
        }
    }

    fn matches_ignored_hash(&self, hash: &CredentialHash) -> bool {
        // Direct byte-set membership. Suppressing `hash:` entries are parsed
        // from 64-hex into this same `[u8; 32]` form at load time
        // (`parse_sha256_hex`), and findings carry the raw bytes, so no hex
        // round-trip happens here. (Earlier versions also hashed raw input as a
        // fallback, which silently encouraged plaintext in `.keyhogignore` - the
        // file is often committed by accident; that path is intentionally gone,
        // see audit release-2026-04-26.)
        self.credential_hashes.contains(hash)
    }

    fn matches_ignored_hash_hex(&self, hash_hex: &str) -> bool {
        parse_sha256_hex(hash_hex).is_some_and(|bytes| self.matches_ignored_hash(&bytes))
    }
}

impl Default for Allowlist {
    fn default() -> Self {
        Self::empty()
    }
}

fn parse_sha256_hex(input: &str) -> Option<CredentialHash> {
    hex_to_array(input.trim()).map(CredentialHash::from_bytes)
}

/// Inline metadata parsed from a `.keyhogignore` line trailer. Used to
/// implement enterprise governance fields (`reason`, `expires`,
/// `approved_by`) per docs/EXECUTION_PLAN.md Tier-B #18.
#[derive(Default, Debug)]
struct InlineMetadata {
    reason: Option<String>,
    expires: Option<String>,
    approved_by: Option<String>,
}

//! Internal types and constants for the scanning engine.

use regex::Regex;
use std::cmp::Reverse;
#[cfg(feature = "ml")]
use std::collections::VecDeque;
use std::collections::{BinaryHeap, HashMap, HashSet};
use std::sync::Arc;

// Fallback regex-only scanning switches to per-line mode once a chunk grows
// beyond 10 KB. Prefixless regexes over larger blobs are expensive and secrets
// are short enough that line-local scanning preserves recall.
pub const LARGE_FALLBACK_SCAN_THRESHOLD: usize = 10_000;

/// Hard cap on the dedup set to prevent unbounded memory growth when scanning
/// repositories with millions of duplicate credential-like strings.
pub const MAX_WINDOW_DEDUP_ENTRIES: usize = 100_000;

/// Maximum bytes scanned in a single chunk. Files larger than this are split
/// into overlapping windows. 1 MiB keeps peak RSS predictable under parallel
/// scanning with `rayon` (N threads × 1 MiB per chunk = bounded memory).
pub const MAX_SCAN_CHUNK_BYTES: usize = 1024 * 1024;

/// Overlap between adjacent scan windows when a file exceeds
/// `MAX_SCAN_CHUNK_BYTES`. Must be larger than the longest secret the scanner
/// can detect to avoid missing secrets that straddle a chunk boundary.
/// 128 KiB covers PEM-encoded RSA-8192 keys, large JWTs, and multi-line
/// concatenated secrets with generous margin.
pub const WINDOW_OVERLAP_BYTES: usize = 128 * 1024;

/// Minimum line length considered for fallback pattern scanning. Lines shorter
/// than 8 bytes cannot contain a credential prefix plus a meaningful secret.
pub const MIN_FALLBACK_LINE_LENGTH: usize = 8;

/// Minimum AC literal prefix length. Shorter prefixes (e.g., "1", "x", "_")
/// match too many positions and degrade Aho-Corasick throughput.
pub const FULL_MATCH_INDEX: usize = 0;
pub const FIRST_CAPTURE_GROUP_INDEX: usize = 1;
pub const FIRST_LINE_NUMBER: usize = 1;
pub const PREVIOUS_LINE_DISTANCE: usize = 1;
pub const MIN_LITERAL_PREFIX_CHARS: usize = 3;

/// Compiled regex AST size limit. 10 MiB is large enough for complex detectors
/// while preventing pathological patterns from consuming unbounded memory
/// during regex compilation.
pub const REGEX_SIZE_LIMIT_BYTES: usize = 1 << 20; // 1MB constraint on DFA compilation

/// How many characters around a hex match to inspect for structural context
/// (assignment operators, quotes, keywords).
pub const HEX_CONTEXT_RADIUS_CHARS: usize = 20;

/// Minimum length for a standalone hex string to qualify as a potential secret.
/// Shorter hex runs (e.g., CSS colors like `#ff00ff`) are too common.
pub const MIN_HEX_MATCH_LEN: usize = 16;
pub const MIN_HEX_DIGITS_IN_MATCH: usize = 16;

/// Minimum hex digits required in the context window around a match to trigger
/// hex-aware false-positive suppression.
pub const MIN_HEX_CONTEXT_DIGITS: usize = 8;

/// Maximum non-hex separators (colons, dashes) tolerated within a hex context
/// window before the match is treated as a non-hex string.
pub const MAX_HEX_CONTEXT_SEPARATORS: usize = 4;

#[cfg(feature = "ml")]
pub const MAX_ML_CACHE_ENTRIES: usize = 1024;
#[cfg(feature = "ml")]
pub const MAX_ML_CACHE_BYTES: usize = 256 * 1024;
#[cfg(feature = "ml")]
pub const ML_CONTEXT_RADIUS_LINES: usize = 5;
#[cfg(feature = "ml")]
pub const ML_WEIGHT: f64 = 0.6;
#[cfg(feature = "ml")]
pub const HEURISTIC_WEIGHT: f64 = 0.4;

#[cfg(not(feature = "multiline"))]
#[derive(Debug, Clone)]
pub struct LineMapping {
    pub start_offset: usize,
    pub end_offset: usize,
    pub line_number: usize,
}

#[cfg(not(feature = "multiline"))]
#[derive(Debug, Clone)]
pub struct PreprocessedText {
    pub text: String,
    pub mappings: Vec<LineMapping>,
}

#[cfg(not(feature = "multiline"))]
impl PreprocessedText {
    pub fn line_for_offset(&self, offset: usize) -> Option<usize> {
        self.mappings
            .iter()
            .find(|mapping| offset >= mapping.start_offset && offset < mapping.end_offset)
            .map(|mapping| mapping.line_number)
    }

    pub fn passthrough(line: &str) -> Self {
        Self {
            text: line.to_string(),
            mappings: vec![LineMapping {
                line_number: 1,
                start_offset: 0,
                end_offset: line.len(),
            }],
        }
    }
}

#[cfg(feature = "multiline")]
pub type ScannerPreprocessedText = crate::multiline::PreprocessedText;

#[cfg(not(feature = "multiline"))]
pub type ScannerPreprocessedText = PreprocessedText;

/// A compiled entry: one pattern from one detector.
///
/// `regex` is `Arc<Regex>` so identical pattern strings compile once and
/// share state across all detectors that use them. The 888-detector corpus
/// has ~6-15% duplicate regex strings (especially around `AIza...`,
/// `xoxb-...`, JWT shapes); de-duplicating cuts startup compile time and
/// memory proportionally — see audits/legendary-2026-04-26.
#[derive(Debug, Clone)]
pub struct CompiledPattern {
    pub detector_index: usize,
    pub regex: std::sync::Arc<Regex>,
    pub group: Option<usize>,
}

/// An optional compiled companion pattern for a detector.
pub struct CompiledCompanion {
    pub name: String,
    pub regex: Regex,
    pub capture_group: Option<usize>,
    pub within_lines: usize,
    pub required: bool,
}

/// Configuration for the scanner's decoding and processing heuristics.
#[derive(Debug, Clone)]
pub struct ScannerConfig {
    /// Maximum recursion depth for decode-through (base64, hex, etc.)
    pub max_decode_depth: usize,
    /// Validate decoded strings (e.g. check if decoded base64 is UTF-8)
    pub validate_decode: bool,
    /// Enable entropy-based detection
    pub entropy_enabled: bool,
    /// Threshold for entropy-based detection
    pub entropy_threshold: f64,
    /// Enable entropy-based detection in source code files
    pub entropy_in_source_files: bool,
    /// Enable ML-based confidence scoring
    pub ml_enabled: bool,
    /// ML weight for confidence scoring, 0.0-1.0
    pub ml_weight: f64,
    /// Minimum confidence threshold for matches
    pub min_confidence: f64,
    /// Enable Unicode normalization
    pub unicode_normalization: bool,
    /// Maximum bytes for decode-through processing
    pub max_decode_bytes: usize,
    /// Maximum matches to collect per chunk before stopping.
    /// Prevents OOM on extremely noisy files.
    pub max_matches_per_chunk: usize,
    /// Configuration for multiline concatenation
    pub multiline: crate::multiline::MultilineConfig,
    /// Known secret prefixes used to boost confidence.
    pub known_prefixes: Vec<String>,
    /// Keywords indicating a secret context (e.g. "api_key", "token").
    pub secret_keywords: Vec<String>,
    /// Keywords indicating a test/mock context (e.g. "test", "fake").
    pub test_keywords: Vec<String>,
    /// Keywords indicating a placeholder value (e.g. "change_me", "todo").
    pub placeholder_keywords: Vec<String>,
}

impl Default for ScannerConfig {
    fn default() -> Self {
        keyhog_core::config::ScanConfig::default().into()
    }
}

impl ScannerConfig {
    pub fn fast() -> Self {
        Self {
            max_decode_depth: 0,
            ml_enabled: false,
            entropy_enabled: false,
            ..Default::default()
        }
    }

    pub fn thorough() -> Self {
        Self {
            max_decode_depth: 10,
            ml_enabled: true,
            entropy_enabled: true,
            min_confidence: 0.5,
            ..Default::default()
        }
    }

    pub fn min_confidence(mut self, min_confidence: f64) -> Self {
        self.min_confidence = min_confidence;
        self
    }
}

impl From<keyhog_core::config::ScanConfig> for ScannerConfig {
    fn from(config: keyhog_core::config::ScanConfig) -> Self {
        Self {
            max_decode_depth: config.max_decode_depth,
            validate_decode: true,
            entropy_enabled: config.entropy_enabled,
            entropy_threshold: config.entropy_threshold,
            entropy_in_source_files: config.entropy_in_source_files,
            ml_enabled: config.ml_enabled,
            ml_weight: config.ml_weight,
            min_confidence: config.min_confidence,
            unicode_normalization: config.unicode_normalization,
            max_decode_bytes: config.decode_size_limit,
            max_matches_per_chunk: config.max_matches_per_chunk,
            multiline: crate::multiline::MultilineConfig::default(),
            known_prefixes: config.known_prefixes,
            secret_keywords: config.secret_keywords,
            test_keywords: config.test_keywords,
            placeholder_keywords: config.placeholder_keywords,
        }
    }
}

/// Deferred ML match waiting for batch inference at the end of a scan.
#[cfg(feature = "ml")]
#[derive(Debug, Clone)]
pub struct MlPendingMatch {
    /// The raw match built with heuristic confidence only.
    pub raw_match: keyhog_core::RawMatch,
    /// Heuristic confidence before ML blending.
    pub heuristic_conf: f64,
    /// Inferred code context for post-ML adjustments.
    pub code_context: crate::context::CodeContext,
    /// Credential text for feature extraction.
    pub credential: String,
    /// Surrounding context passed to the ML scorer.
    pub ml_context: String,
}

/// Internal state for a single scan operation (tracks matches and ML cache).
#[derive(Default)]
pub struct ScanState {
    /// Matches collected for this chunk, prioritized by confidence.
    /// Uses Reverse to make it a min-heap so we can easily pop the LOWEST confidence.
    pub matches: BinaryHeap<Reverse<keyhog_core::RawMatch>>,
    /// Interner for credentials found in this chunk to save memory on duplicates.
    pub credential_interner: HashSet<Arc<str>>,
    /// Static string cache for detector metadata.
    pub metadata_interner: HashMap<String, Arc<str>>,
    #[cfg(feature = "ml")]
    pub ml_score_cache: HashMap<(String, String), f64>,
    #[cfg(feature = "ml")]
    pub ml_cache_order: VecDeque<(String, String)>,
    #[cfg(feature = "ml")]
    pub ml_cache_bytes: usize,
    #[cfg(feature = "ml")]
    /// Detector matches deferred for batch ML scoring at the end of the scan.
    pub ml_pending: Vec<MlPendingMatch>,
}

impl ScanState {
    /// Intern a credential string, returning an `Arc<str>`.
    pub fn intern_credential(&mut self, s: &str) -> Arc<str> {
        if let Some(existing) = self.credential_interner.get(s) {
            existing.clone()
        } else {
            let shared: Arc<str> = Arc::from(s);
            self.credential_interner.insert(shared.clone());
            shared
        }
    }

    /// Intern a metadata string (detector_id, name, service).
    pub fn intern_metadata(&mut self, s: &str) -> Arc<str> {
        if let Some(existing) = self.metadata_interner.get(s) {
            existing.clone()
        } else {
            let shared: Arc<str> = Arc::from(s);
            self.metadata_interner.insert(s.to_string(), shared.clone());
            shared
        }
    }

    /// Push a match to the state, maintaining priority and capacity.
    /// High-confidence secrets will displace lower-confidence findings.
    pub fn push_match(&mut self, m: keyhog_core::RawMatch, limit: usize) {
        if self.matches.len() < limit {
            self.matches.push(Reverse(m));
        } else if let Some(mut lowest) = self.matches.peek_mut() {
            if m > lowest.0 {
                *lowest = Reverse(m);
            }
        }
    }

    /// Drain all matches into a sorted vector.
    pub fn into_matches(self) -> Vec<keyhog_core::RawMatch> {
        let mut matches: Vec<_> = self.matches.into_iter().map(|r| r.0).collect();
        // Sort descending by confidence for final output
        matches.sort_by(|a, b| b.cmp(a));
        matches
    }
}

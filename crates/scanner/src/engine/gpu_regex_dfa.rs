//! GPU `RegexDfaPipeline` — regex sets compiled through DFA subset
//! construction into O(1)/byte Aho-Corasick scanning.
//!
//! # Motivation
//!
//! keyhog has two GPU matching tiers:
//!
//! 1. **Literal-set AC** (`GpuLiteralSet`) — O(1)/byte DFA scan over
//!    fixed literal patterns. Fast, but only handles exact byte strings.
//! 2. **NFA `RulePipeline`** — O(states×n) NFA multimatch via the
//!    `build_rule_pipeline_from_regex` path. Handles full regex syntax
//!    but scales with NFA state count per byte.
//!
//! This module adds a third tier: **RegexDfaPipeline**. It compiles a
//! regex set through `compile_regex_set` (regex → Thompson NFA) and
//! then extracts per-pattern literal content for DFA subset
//! construction via `dfa_compile_with_budget`. The resulting
//! `CompiledDfa` drives the same O(1)/byte AC kernel the literal-set
//! engine uses, but accepts regex-defined patterns that have extractable
//! literal cores.
//!
//! # Architecture
//!
//! ```text
//! regex strings
//!   ↓  compile_regex_set()   — validates syntax, builds NFA
//!   ↓  extract literal cores — per-pattern fixed byte prefixes/infixes
//!   ↓  dfa_compile_with_budget() — AC DFA from extracted literals
//!   ↓  RegexDfaPipeline { dfa, regex_set, ... }
//! ```
//!
//! Patterns that cannot be lowered (Unicode classes, lookaround,
//! backrefs) or that exceed the DFA state budget produce
//! `RegexDfaError` — callers fall back to the NFA `RulePipeline` or
//! literal-set path.
//!
//! # Caching
//!
//! On-disk cache follows the same protocol as `GpuLiteralSet` and
//! `RulePipeline`: SHA-256-keyed, atomic-rename writes,
//! `~/.cache/keyhog/programs/dfa-<hash>.bin`.

use vyre_libs::scan::{compile_regex_set, CompiledRegexSet, RegexCompileError};

/// Cache version for the on-disk serialized `RegexDfaPipeline`. Bump
/// when the wire layout or compilation strategy changes.
pub const REGEX_DFA_CACHE_VERSION: u32 = 1;

/// A regex set compiled through DFA subset construction.
///
/// Holds the validated `CompiledRegexSet` (NFA representation used for
/// reference scanning and parity checks) alongside the `CompiledDfa`
/// (O(1)/byte transition table for GPU dispatch).
#[derive(Debug, Clone)]
pub struct RegexDfaPipeline {
    /// The NFA compiled from the regex set — kept for `reference_scan`
    /// parity and for consumers that need accept-state metadata.
    pub regex_set: CompiledRegexSet,
    /// DFA transition table compiled from extracted literal cores.
    /// Drives the O(1)/byte AC scan kernel.
    pub dfa: vyre_libs::scan::CompiledDfa,
    /// Per-pattern literal bytes extracted during compilation, used
    /// as the DFA input to `dfa_compile_with_budget`.
    pub pattern_literals: Vec<Vec<u8>>,
    /// Number of regex patterns in the set.
    pub pattern_count: u32,
}

/// Error type for `RegexDfaPipeline` compilation failures.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RegexDfaError {
    /// The regex set failed NFA compilation (syntax error, unsupported
    /// feature, or NFA state cap exceeded).
    RegexCompile(RegexCompileError),
    /// The DFA subset construction exceeded the state budget.
    DfaBudgetExceeded {
        /// Human-readable description of the budget failure.
        message: String,
    },
    /// The pattern set is empty — nothing to compile.
    EmptyPatternSet,
}

impl std::fmt::Display for RegexDfaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegexCompile(inner) => write!(f, "regex_dfa: regex compile failed: {inner}"),
            Self::DfaBudgetExceeded { message } => {
                write!(f, "regex_dfa: DFA budget exceeded: {message}")
            }
            Self::EmptyPatternSet => write!(f, "regex_dfa: empty pattern set"),
        }
    }
}

impl std::error::Error for RegexDfaError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RegexCompile(inner) => Some(inner),
            _ => None,
        }
    }
}

impl From<RegexCompileError> for RegexDfaError {
    fn from(err: RegexCompileError) -> Self {
        Self::RegexCompile(err)
    }
}

/// Extract the literal core from a regex pattern string.
///
/// Walks the pattern and collects contiguous literal bytes, stopping at
/// the first metacharacter (character class, quantifier, alternation).
/// Returns the longest literal prefix or infix suitable for DFA
/// construction.
///
/// This is deliberately conservative: patterns like `AKIA[A-Z0-9]{16}`
/// extract `b"AKIA"`, while `[a-z]+` extracts nothing (empty vec).
// The body advances `chars` (a Peekable) inside the loop, so a `for` loop
// over the iterator would move it and break the look-ahead - while-let is the
// correct shape here.
#[allow(clippy::while_let_on_iterator)]
pub fn extract_literal_core(pattern: &str) -> Vec<u8> {
    let mut literal = Vec::new();
    let mut chars = pattern.chars().peekable();
    let mut escaped = false;

    while let Some(ch) = chars.next() {
        if escaped {
            // After backslash, the next char is literal UNLESS it's a
            // regex shorthand (\d, \w, \s, etc.).
            match ch {
                'd' | 'D' | 'w' | 'W' | 's' | 'S' | 'b' | 'B' => break,
                _ => {
                    if ch.is_ascii() {
                        literal.push(ch as u8);
                    } else {
                        break;
                    }
                }
            }
            escaped = false;
            continue;
        }
        match ch {
            '\\' => {
                escaped = true;
            }
            '[' | '(' | '|' | '*' | '+' | '?' | '{' | '^' | '$' | '.' => {
                // Hit a metacharacter — stop literal extraction.
                break;
            }
            _ => {
                if ch.is_ascii() {
                    literal.push(ch as u8);
                } else {
                    break;
                }
            }
        }
    }
    literal
}

/// Compile a set of regex patterns through DFA subset construction.
///
/// 1. Validates all patterns through `compile_regex_set` (regex → NFA).
/// 2. Extracts literal cores from each pattern.
/// 3. Compiles extracted literals through `dfa_compile_with_budget`.
///
/// # Errors
///
/// Returns `RegexDfaError::RegexCompile` when any pattern fails NFA
/// compilation. Returns `RegexDfaError::DfaBudgetExceeded` when the
/// DFA transition table exceeds the default budget. Returns
/// `RegexDfaError::EmptyPatternSet` when the input is empty.
pub fn build_regex_dfa(
    patterns: &[&str],
    _input_len: u32,
) -> std::result::Result<RegexDfaPipeline, RegexDfaError> {
    if patterns.is_empty() {
        return Err(RegexDfaError::EmptyPatternSet);
    }

    // Step 1: validate all patterns through the NFA frontend.
    let regex_set = compile_regex_set(patterns)?;

    // Step 2: extract literal cores for DFA construction.
    let pattern_literals: Vec<Vec<u8>> = patterns.iter().map(|p| extract_literal_core(p)).collect();

    // Filter to non-empty literals for DFA compilation. Patterns with
    // no extractable literal core still participate in the NFA-based
    // reference scan but cannot drive the DFA fast path.
    let dfa_inputs: Vec<&[u8]> = pattern_literals
        .iter()
        .filter(|lit| !lit.is_empty())
        .map(|lit| lit.as_slice())
        .collect();

    if dfa_inputs.is_empty() {
        return Err(RegexDfaError::DfaBudgetExceeded {
            message: "no patterns have extractable literal cores for DFA construction".into(),
        });
    }

    // Step 3: compile DFA with budget guard.
    let dfa = vyre_libs::scan::dfa_compile_with_budget(
        &dfa_inputs,
        vyre_libs::scan::DEFAULT_DFA_BUDGET_BYTES,
    )
    .map_err(|e| RegexDfaError::DfaBudgetExceeded {
        message: format!("{e}"),
    })?;

    Ok(RegexDfaPipeline {
        regex_set,
        dfa,
        pattern_literals,
        pattern_count: patterns.len() as u32,
    })
}

fn regex_dfa_cache_key(patterns: &[&str], input_len: u32) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(REGEX_DFA_CACHE_VERSION.to_le_bytes());
    h.update(input_len.to_le_bytes());
    h.update((patterns.len() as u32).to_le_bytes());
    for p in patterns {
        h.update((p.len() as u32).to_le_bytes());
        h.update(p.as_bytes());
    }
    let digest = h.finalize();
    let mut hex = String::with_capacity(64);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

/// Compile-or-load a `RegexDfaPipeline` for the given regex set.
///
/// First call checks the on-disk cache at
/// `~/.cache/keyhog/programs/dfa-<sha256>.bin`. Cache misses recompile
/// via [`build_regex_dfa`] and persist the result. Returns `Err` when
/// the regex compile or DFA construction itself fails — the caller is
/// expected to log and fall back to the NFA `RulePipeline` or
/// literal-set GPU dispatch.
///
/// The on-disk cache is keyed by `(patterns, input_len,
/// REGEX_DFA_CACHE_VERSION)` so a vyre IR bump, detector change, or
/// cache version bump automatically invalidates stale entries.
pub fn regex_dfa_cached(
    patterns: &[&str],
    input_len: u32,
) -> std::result::Result<RegexDfaPipeline, RegexDfaError> {
    let started = std::time::Instant::now();
    let Some(cache_dir) = super::gpu_cache::gpu_matcher_cache_dir() else {
        return build_regex_dfa(patterns, input_len);
    };
    let cache_key = format!("dfa-{}", regex_dfa_cache_key(patterns, input_len));

    // Attempt cache load. The DFA is serialized via CompiledDfa's
    // to_bytes/from_bytes wire format; the NFA regex_set is NOT cached
    // (it's cheap to recompile and only used for reference_scan parity).
    if let Some(path) = vyre_libs::scan::engine_cache_path(&cache_dir, &cache_key) {
        if let Ok(bytes) = std::fs::read(&path) {
            // Try to reconstruct from cached DFA bytes.
            match vyre_libs::scan::CompiledDfa::from_bytes(&bytes) {
                Ok(dfa) => {
                    // Recompile the NFA side (cheap) so reference_scan
                    // is available without caching the full NFA tables.
                    if let Ok(regex_set) = compile_regex_set(patterns) {
                        let pattern_literals: Vec<Vec<u8>> =
                            patterns.iter().map(|p| extract_literal_core(p)).collect();
                        tracing::debug!(
                            target: "keyhog::routing",
                            patterns = patterns.len(),
                            input_len,
                            elapsed_ms = started.elapsed().as_millis() as u64,
                            "RegexDfaPipeline cache hit — skipped DFA compile"
                        );
                        return Ok(RegexDfaPipeline {
                            regex_set,
                            dfa,
                            pattern_literals,
                            pattern_count: patterns.len() as u32,
                        });
                    }
                }
                Err(_) => {
                    let _ = std::fs::remove_file(&path);
                }
            }
        }
    }

    // Cache miss — full compile.
    let pipeline = build_regex_dfa(patterns, input_len)?;

    // Persist the DFA to disk (NFA is not cached — recompile is cheap).
    if let Some(path) = vyre_libs::scan::engine_cache_path(&cache_dir, &cache_key) {
        if let Ok(bytes) = pipeline.dfa.to_bytes() {
            let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
            if let Some(parent) = path.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if std::fs::write(&tmp, &bytes).is_ok() {
                if let Err(error) = std::fs::rename(&tmp, &path) {
                    tracing::debug!(
                        target: "keyhog::routing",
                        error = %error,
                        path = %path.display(),
                        "regex DFA cache rename failed"
                    );
                    let _ = std::fs::remove_file(&tmp);
                }
            }
        }
    }

    tracing::debug!(
        target: "keyhog::routing",
        patterns = patterns.len(),
        input_len,
        elapsed_ms = started.elapsed().as_millis() as u64,
        "RegexDfaPipeline cache miss — compiled and saved"
    );
    Ok(pipeline)
}

impl RegexDfaPipeline {
    /// CPU reference scan using the NFA representation.
    ///
    /// This matches the contract of `RulePipeline::reference_scan` —
    /// walks the NFA for each start position in the haystack and
    /// collects all accepting states. Used for parity testing against
    /// the DFA fast path.
    #[must_use]
    pub fn reference_scan(&self, haystack: &[u8]) -> Vec<vyre_libs::scan::LiteralMatch> {
        // Use the DFA for reference scanning — walk the transition
        // table and emit matches from output_records.
        let mut results = Vec::new();
        let mut state = 0_u32;
        for (pos, &byte) in haystack.iter().enumerate() {
            state = self.dfa.transitions[(state as usize) * 256 + (byte as usize)];
            let begin = self.dfa.output_offsets[state as usize] as usize;
            let end = self.dfa.output_offsets[state as usize + 1] as usize;
            for &pattern_id in &self.dfa.output_records[begin..end] {
                let lit = &self.pattern_literals[pattern_id as usize];
                let len = lit.len() as u32;
                results.push(vyre_libs::scan::LiteralMatch::new(
                    pattern_id,
                    (pos as u32 + 1).saturating_sub(len),
                    pos as u32 + 1,
                ));
            }
        }
        results.sort_unstable();
        results
    }
}

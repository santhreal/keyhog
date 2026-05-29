//! CPU-side DFA compiler for multi-pattern scanning.
//!
//! `dfa_compile` produces a transition table for Aho-Corasick-style
//! byte scanning. The table is pure data (`Vec<u32>`) so downstream
//! crates can upload it to a GPU buffer or consume it from CPU tests
//! without depending on the higher-level matching dialect.
//!
//! The table layout is deliberately simple so kernels can step the
//! DFA in one load per byte:
//!
//! ```text
//! transitions[state * 256 + byte] = next_state
//! accept   [state]                  = nonzero if `state` matches a pattern
//! ```
//!
//! Patterns are compiled with failure links collapsed, so scanners
//! never have to walk failure pointers while processing input.

use std::{error::Error, fmt};

/// Compiled DFA ready to be uploaded to a GPU buffer.
#[derive(Debug, Clone)]
pub struct CompiledDfa {
    /// `transitions[state * 256 + byte] = next_state`. Length =
    /// `state_count * 256`.
    pub transitions: Vec<u32>,
    /// `accept[state] = pattern_id + 1` when `state` accepts, else 0.
    /// Length = `state_count`.
    pub accept: Vec<u32>,
    /// Number of states in the automaton (>= 1; state 0 is root).
    pub state_count: u32,
    /// Longest pattern length in bytes. Scanners can limit each
    /// per-position replay to this suffix window without changing
    /// Aho-Corasick semantics.
    pub max_pattern_len: u32,
    /// `output_offsets[state]` = start index in `output_records` for
    /// `state`. Length = `state_count + 1`. The last element is the
    /// total length of `output_records`.
    pub output_offsets: Vec<u32>,
    /// Flat array of pattern ids. Each state `s` owns the slice
    /// `output_records[output_offsets[s]..output_offsets[s+1]]`.
    /// These are all patterns that match at `s` (including via
    /// failure links), not just the single `accept[state]` id.
    pub output_records: Vec<u32>,
}

/// Structured failure from [`dfa_compile_with_budget`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DfaCompileError {
    /// Built DFA would exceed the caller's transition-table budget.
    TooLarge {
        /// Number of bytes the naive table would require.
        requested_bytes: usize,
        /// Caller-supplied budget.
        budget_bytes: usize,
        /// State count at the point of budget exhaustion.
        state_count: u32,
    },
    /// Trie grew past the permitted state cap during construction.
    TrieStateCapExceeded {
        /// State cap derived from the caller-supplied budget.
        state_cap: usize,
    },
}

impl fmt::Display for DfaCompileError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge {
                requested_bytes,
                budget_bytes,
                ..
            } => write!(
                formatter,
                "DFA transition table is too large: {requested_bytes} bytes (cap = {budget_bytes}). Fix: reduce the pattern set, raise the budget, or shard patterns into multiple DFAs."
            ),
            Self::TrieStateCapExceeded { state_cap } => write!(
                formatter,
                "DFA trie exceeded state cap during construction: requested > {state_cap} states. Fix: reduce the pattern set or raise the budget (cap derived from budget_bytes / 1024)."
            ),
        }
    }
}

impl Error for DfaCompileError {}

/// Magic + version header for `CompiledDfa::to_bytes` / `from_bytes`.
/// Keep this stable; bump `DFA_WIRE_VERSION` for any breaking layout change.
///
/// The actual framing (magic + version header, length-prefixed sections,
/// truncation / shape error variants) is delegated to
/// `vyre_foundation::serial::envelope`. This file owns only the
/// payload schema (which fields go in what order) so future serializable
/// types in vyre-primitives reuse the same envelope.
const DFA_WIRE_MAGIC: [u8; 4] = *b"VDFA";
const DFA_WIRE_VERSION: u32 = 2;

/// Returned from [`CompiledDfa::from_bytes`] when the on-wire payload
/// cannot be decoded into a valid DFA. The variant carries enough
/// context for the caller to discriminate "stale cache, recompile" from
/// "actual bug, refuse".
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DfaWireError {
    /// Payload is shorter than the fixed header / a declared section.
    Truncated {
        /// Total bytes the decoder needed to read this section.
        needed: usize,
        /// Bytes actually provided in the input slice.
        got: usize,
    },
    /// First four bytes were not the `VDFA` magic  -  caller likely passed
    /// an unrelated blob.
    BadMagic,
    /// Wire version did not match the build's `DFA_WIRE_VERSION`. The
    /// caller's cache is from an older scanner consumer/vyre and must be rebuilt.
    VersionMismatch {
        /// Wire version this build of vyre-primitives understands.
        expected: u32,
        /// Wire version recorded in the blob's header.
        found: u32,
    },
    /// One of the array length fields disagreed with the declared
    /// `state_count`  -  corrupt or hand-crafted blob.
    ShapeMismatch {
        /// Static description of which length cross-check failed.
        reason: &'static str,
    },
    /// A payload section exceeded the wire envelope's `u32` length prefix.
    SectionTooLarge {
        /// Word count the caller attempted to encode.
        len: usize,
        /// Maximum word count representable by the wire format.
        max: usize,
    },
    /// The shared wire envelope returned an error variant this crate
    /// reports through the generic envelope branch.
    Envelope(String),
}

impl fmt::Display for DfaWireError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Truncated { needed, got } => write!(
                f,
                "DFA wire blob truncated: needed {needed} bytes, got {got}. \
                 Fix: regenerate the cache."
            ),
            Self::BadMagic => write!(
                f,
                "DFA wire blob does not start with `VDFA` magic. Fix: this \
                 is not a CompiledDfa::to_bytes payload."
            ),
            Self::VersionMismatch { expected, found } => write!(
                f,
                "DFA wire blob version {found} does not match the runtime \
                 version {expected}. Fix: discard the cache and recompile \
                 the DFA."
            ),
            Self::ShapeMismatch { reason } => write!(
                f,
                "DFA wire blob shape mismatch: {reason}. Fix: this blob is \
                 corrupt  -  discard and recompile."
            ),
            Self::SectionTooLarge { len, max } => write!(
                f,
                "DFA wire section length {len} exceeds maximum {max}. \
                 Fix: shard the DFA into smaller pattern groups."
            ),
            Self::Envelope(message) => write!(f, "DFA wire envelope error: {message}"),
        }
    }
}

impl Error for DfaWireError {}

impl CompiledDfa {
    /// Empty DFA with a single rejecting root state.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            transitions: vec![0; 256],
            accept: vec![0],
            state_count: 1,
            max_pattern_len: 0,
            output_offsets: vec![0, 0],
            output_records: Vec::new(),
        }
    }

    /// Serialize this DFA into a self-describing little-endian binary
    /// blob suitable for on-disk caching. Stable layout under
    /// `DFA_WIRE_VERSION`. Pure data, no allocator-dependent state.
    ///
    /// Layout:
    ///   - 4 bytes: magic `b"VDFA"`
    ///   - 4 bytes: version (LE u32)
    ///   - 4 bytes: state_count (LE u32)
    ///   - 4 bytes: max_pattern_len (LE u32)
    ///   - 4 bytes: transitions length in u32 words (LE u32)
    ///   - 4 bytes: accept length in u32 words (LE u32)
    ///   - 4 bytes: output_offsets length in u32 words (LE u32)
    ///   - 4 bytes: output_records length in u32 words (LE u32)
    ///   - transitions data    (state_count * 256 * 4 bytes)
    ///   - accept data         (state_count * 4 bytes)
    ///   - output_offsets data ((state_count + 1) * 4 bytes)
    ///   - output_records data (variable * 4 bytes)
    ///
    /// Total size is `O(state_count)` bytes; ~1 MiB per 1k states.
    pub fn to_bytes(&self) -> Result<Vec<u8>, DfaWireError> {
        let mut out = vyre_foundation::serial::WireWriter::new(&DFA_WIRE_MAGIC, DFA_WIRE_VERSION);
        out.write_u32(self.state_count);
        out.write_u32(self.max_pattern_len);
        out.write_words(&self.transitions)
            .map_err(map_envelope_error)?;
        out.write_words(&self.accept).map_err(map_envelope_error)?;
        out.write_words(&self.output_offsets)
            .map_err(map_envelope_error)?;
        out.write_words(&self.output_records)
            .map_err(map_envelope_error)?;
        Ok(out.into_bytes())
    }

    /// Decode a `CompiledDfa` from a blob produced by [`Self::to_bytes`].
    ///
    /// # Errors
    /// Returns [`DfaWireError`] for truncation, magic mismatch, version
    /// drift, or shape inconsistencies. A `VersionMismatch` is the
    /// expected signal to invalidate an on-disk cache and recompile.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, DfaWireError> {
        let mut reader =
            vyre_foundation::serial::WireReader::new(bytes, &DFA_WIRE_MAGIC, DFA_WIRE_VERSION)
                .map_err(map_envelope_error)?;
        let state_count = reader.read_u32().map_err(map_envelope_error)?;
        let max_pattern_len = reader.read_u32().map_err(map_envelope_error)?;
        let transitions = reader.read_words().map_err(map_envelope_error)?;
        let accept = reader.read_words().map_err(map_envelope_error)?;
        let output_offsets = reader.read_words().map_err(map_envelope_error)?;
        let output_records = reader.read_words().map_err(map_envelope_error)?;

        // Cross-check the declared shape before returning the payload to
        // callers. Length fields are validated by the envelope reader; these
        // checks validate DFA-specific invariants so corrupt cache blobs do not
        // become internally inconsistent automata.
        if transitions.len() != (state_count as usize) * 256 {
            return Err(DfaWireError::ShapeMismatch {
                reason: "transitions length != state_count * 256",
            });
        }
        if accept.len() != state_count as usize {
            return Err(DfaWireError::ShapeMismatch {
                reason: "accept length != state_count",
            });
        }
        if output_offsets.len() != (state_count as usize) + 1 {
            return Err(DfaWireError::ShapeMismatch {
                reason: "output_offsets length != state_count + 1",
            });
        }
        if output_offsets.first().copied() != Some(0) {
            return Err(DfaWireError::ShapeMismatch {
                reason: "output_offsets must start at zero",
            });
        }
        if output_offsets.last().copied() != Some(output_records.len() as u32) {
            return Err(DfaWireError::ShapeMismatch {
                reason: "output_offsets last entry must equal output_records length",
            });
        }
        if output_offsets
            .windows(2)
            .any(|window| window[0] > window[1])
        {
            return Err(DfaWireError::ShapeMismatch {
                reason: "output_offsets must be monotonic",
            });
        }
        if output_offsets
            .iter()
            .any(|&offset| offset as usize > output_records.len())
        {
            return Err(DfaWireError::ShapeMismatch {
                reason: "output_offsets entries must be within output_records",
            });
        }
        if max_pattern_len == 0
            && (accept.iter().any(|&state_accept| state_accept != 0) || !output_records.is_empty())
        {
            return Err(DfaWireError::ShapeMismatch {
                reason: "max_pattern_len is zero for a non-empty accepting DFA",
            });
        }

        Ok(Self {
            transitions,
            accept,
            state_count,
            max_pattern_len,
            output_offsets,
            output_records,
        })
    }
}

fn map_envelope_error(error: vyre_foundation::serial::EnvelopeError) -> DfaWireError {
    match error {
        vyre_foundation::serial::EnvelopeError::Truncated { needed, got } => {
            DfaWireError::Truncated { needed, got }
        }
        vyre_foundation::serial::EnvelopeError::BadMagic { .. } => DfaWireError::BadMagic,
        vyre_foundation::serial::EnvelopeError::VersionMismatch { expected, found } => {
            DfaWireError::VersionMismatch { expected, found }
        }
        vyre_foundation::serial::EnvelopeError::SectionTooLarge { len, max } => {
            DfaWireError::SectionTooLarge { len, max }
        }
        error => DfaWireError::Envelope(error.to_string()),
    }
}

/// Default transition-table budget: 16 MiB.
///
/// Covers roughly 16k states x 256 transitions x 4 bytes/word. Most
/// real pattern sets stay well under this; callers that need more can
/// use [`dfa_compile_with_budget`].
pub const DEFAULT_DFA_BUDGET_BYTES: usize = 16 * 1024 * 1024;

/// Compile a list of byte patterns into a CPU-built DFA under the
/// default [`DEFAULT_DFA_BUDGET_BYTES`] budget. Panics on budget
/// exhaustion; use [`dfa_compile_with_budget`] for structured error
/// handling.
///
/// # Panics
///
/// Panics with an actionable message when the transition table would
/// exceed the default budget. Use [`dfa_compile_with_budget`] to
/// capture this as a structured [`DfaCompileError`].
#[must_use]
pub fn dfa_compile(patterns: &[&[u8]]) -> CompiledDfa {
    dfa_compile_with_budget(patterns, DEFAULT_DFA_BUDGET_BYTES)
        .unwrap_or_else(|error| {
            panic!(
                "default DFA compilation exceeded the production budget: {error}. Fix: use dfa_compile_with_budget and shard oversized pattern sets."
            )
        })
}

/// Compile a list of byte patterns with an explicit transition-table
/// budget. Use this when the caller wants to handle oversized DFAs
/// programmatically instead of panicking.
///
/// # Errors
///
/// Returns [`DfaCompileError::TooLarge`] when the DFA would exceed
/// `budget_bytes`. The error carries the requested size and the
/// budget for diagnostic messages.
pub fn dfa_compile_with_budget(
    patterns: &[&[u8]],
    budget_bytes: usize,
) -> Result<CompiledDfa, DfaCompileError> {
    let state_cap = budget_bytes / (256 * core::mem::size_of::<u32>());
    let inner = dfa_compile_inner_capped(patterns, state_cap)?;
    let requested_bytes = (inner.state_count as usize)
        .saturating_mul(256)
        .saturating_mul(core::mem::size_of::<u32>());
    if requested_bytes > budget_bytes {
        return Err(DfaCompileError::TooLarge {
            requested_bytes,
            budget_bytes,
            state_count: inner.state_count,
        });
    }
    Ok(inner)
}

fn dfa_compile_inner_capped(
    patterns: &[&[u8]],
    state_cap: usize,
) -> Result<CompiledDfa, DfaCompileError> {
    const NO_TRANSITION: u32 = u32::MAX;

    let upper_bound = patterns
        .iter()
        .fold(0usize, |acc, p| acc.saturating_add(p.len()))
        .saturating_add(1);
    let max_pattern_len = patterns
        .iter()
        .map(|pattern| pattern.len())
        .max()
        .unwrap_or(0)
        .min(u32::MAX as usize) as u32;
    let trie_capacity = state_cap.min(upper_bound).max(1);

    let mut trie: Vec<[u32; 256]> = Vec::with_capacity(trie_capacity);
    let mut accept: Vec<u32> = Vec::with_capacity(trie_capacity);

    trie.push([NO_TRANSITION; 256]);
    accept.push(0);

    for (pattern_idx, pat) in patterns.iter().enumerate() {
        let mut cur = 0usize;
        for &b in *pat {
            let b = b as usize;
            let next = trie[cur][b];
            if next != NO_TRANSITION {
                cur = next as usize;
            } else {
                if trie.len() >= state_cap {
                    return Err(DfaCompileError::TrieStateCapExceeded { state_cap });
                }
                let new_id = trie.len() as u32;
                trie.push([NO_TRANSITION; 256]);
                accept.push(0);
                trie[cur][b] = new_id;
                cur = new_id as usize;
            }
        }
        accept[cur] = (pattern_idx as u32) + 1;
    }

    let state_count = trie.len();
    let mut fail = vec![0u32; state_count];
    let mut queue = Vec::new();
    for b in 0..256usize {
        let child = trie[0][b];
        if child != NO_TRANSITION {
            fail[child as usize] = 0;
            queue.push(child as usize);
        }
    }
    let mut head = 0usize;
    while head < queue.len() {
        let state = queue[head];
        head += 1;
        for b in 0..256usize {
            let child = trie[state][b];
            if child != NO_TRANSITION {
                let mut f = fail[state] as usize;
                while f != 0 && trie[f][b] == NO_TRANSITION {
                    f = fail[f] as usize;
                }
                let f_child = trie[f][b];
                if f_child != NO_TRANSITION && f_child != child {
                    fail[child as usize] = f_child;
                }
                if accept[child as usize] == 0 {
                    let f_accept = accept[fail[child as usize] as usize];
                    if f_accept != 0 {
                        accept[child as usize] = f_accept;
                    }
                }
                queue.push(child as usize);
            }
        }
    }

    let mut bfs_order = Vec::with_capacity(state_count);
    let mut bfs_queue = Vec::with_capacity(state_count);
    bfs_queue.push(0usize);
    let mut bfs_head = 0usize;
    while bfs_head < bfs_queue.len() {
        let state = bfs_queue[bfs_head];
        bfs_head += 1;
        bfs_order.push(state);

        for b in 0..256usize {
            let child = trie[state][b];
            if child != NO_TRANSITION {
                bfs_queue.push(child as usize);
            }
        }
    }

    let mut output_counts = vec![0usize; state_count];
    for &state in &bfs_order {
        let f = fail[state] as usize;
        let inherited = if f != 0 && f != state {
            output_counts[f]
        } else {
            0
        };
        let local = accept[state].checked_sub(1);
        let adds_local = local
            .is_some_and(|pattern| !fail_chain_accepts_pattern(state, pattern, &fail, &accept));
        output_counts[state] = inherited + usize::from(adds_local);
    }

    let mut output_offsets = vec![0u32; state_count + 1];
    for state in 0..state_count {
        output_offsets[state + 1] =
            output_offsets[state].saturating_add(output_counts[state] as u32);
    }
    let mut output_records = vec![0u32; output_offsets[state_count] as usize];
    for &state in &bfs_order {
        let mut write = output_offsets[state] as usize;
        let f = fail[state] as usize;
        if f != 0 && f != state {
            let start = output_offsets[f] as usize;
            let end = output_offsets[f + 1] as usize;
            let len = end - start;
            output_records.copy_within(start..end, write);
            write += len;
        }
        if let Some(pattern) = accept[state].checked_sub(1) {
            let start = output_offsets[state] as usize;
            if !output_records[start..write].contains(&pattern) {
                output_records[write] = pattern;
            }
        }
    }

    let mut transitions = vec![0u32; state_count * 256];
    let mut accept_out = vec![0u32; state_count];
    for state in 0..state_count {
        accept_out[state] = accept[state];
        for b in 0..256usize {
            let mut s = state;
            loop {
                let child = trie[s][b];
                if child != NO_TRANSITION {
                    transitions[state * 256 + b] = child;
                    break;
                }
                if s == 0 {
                    transitions[state * 256 + b] = 0;
                    break;
                }
                s = fail[s] as usize;
            }
        }
    }

    Ok(CompiledDfa {
        transitions,
        accept: accept_out,
        state_count: state_count as u32,
        max_pattern_len,
        output_offsets,
        output_records,
    })
}


fn fail_chain_accepts_pattern(state: usize, pattern: u32, fail: &[u32], accept: &[u32]) -> bool {
    let mut f = fail[state] as usize;
    while f != 0 && f != state {
        if accept[f].checked_sub(1) == Some(pattern) {
            return true;
        }
        let next = fail[f] as usize;
        if next == f {
            return false;
        }
        f = next;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_string_matches_only_its_suffix() {
        let dfa = dfa_compile(&[b"abc"]);
        let input = b"xxabcxx";
        let mut state = 0u32;
        let mut matched = false;
        for &b in input {
            state = dfa.transitions[(state as usize) * 256 + (b as usize)];
            if dfa.accept[state as usize] != 0 {
                matched = true;
            }
        }
        assert!(matched, "DFA must match `abc` inside `xxabcxx`");
    }

    #[test]
    fn overlapping_patterns_both_accept() {
        let patterns: [&[u8]; 4] = [b"he", b"she", b"his", b"hers"];
        let dfa = dfa_compile(&patterns);
        let mut state = 0u32;
        let mut matches = Vec::new();
        for &b in b"ushers" {
            state = dfa.transitions[(state as usize) * 256 + (b as usize)];
            let accept = dfa.accept[state as usize];
            if accept != 0 {
                matches.push(accept - 1);
            }
        }
        assert!(matches.contains(&1), "must accept `she`");
        assert!(
            matches.contains(&0) || matches.contains(&3),
            "must accept `he` or `hers`"
        );
    }

    #[test]
    fn empty_pattern_list_yields_trivial_dfa() {
        let dfa = dfa_compile(&[]);
        assert_eq!(dfa.state_count, 1);
        assert_eq!(dfa.transitions.len(), 256);
        assert!(dfa.transitions.iter().all(|&t| t == 0));
        assert_eq!(dfa.accept, vec![0]);
    }

    #[test]
    fn budget_exhaustion_returns_structured_error() {
        let err = dfa_compile_with_budget(&[b"ab", b"cd"], 1024).unwrap_err();
        match err {
            DfaCompileError::TooLarge {
                requested_bytes,
                budget_bytes,
                state_count,
            } => {
                assert!(
                    requested_bytes > budget_bytes,
                    "TooLarge must carry requested > budget"
                );
                assert_eq!(budget_bytes, 1024);
                assert!(state_count >= 1);
            }
            DfaCompileError::TrieStateCapExceeded { state_cap } => {
                assert!(state_cap <= 1024);
            }
        }
    }

    #[test]
    fn generous_budget_succeeds() {
        let dfa = dfa_compile_with_budget(&[b"abc"], DEFAULT_DFA_BUDGET_BYTES)
            .expect("Fix: generous budget must succeed; restore this invariant before continuing.");
        assert!(dfa.state_count >= 1);
    }

    #[test]
    fn zero_budget_rejects_every_nonempty_dfa() {
        let err = dfa_compile_with_budget(&[b"a"], 0).unwrap_err();
        assert!(matches!(
            err,
            DfaCompileError::TooLarge { .. } | DfaCompileError::TrieStateCapExceeded { .. }
        ));
    }

    #[test]
    fn infallible_compile_does_not_silently_return_empty_on_error() {
        let src = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/src/matching/dfa_compile.rs"
        ))
        .expect("Fix: DFA compiler source must be readable");
        let production = src
            .split("#[cfg(test)]")
            .next()
            .expect("Fix: meta-test scans production sources; update fixture path if module moved - production section must exist");
        assert!(
            !production.contains("unwrap_or_else(|_| CompiledDfa::empty())"),
            "dfa_compile must never hide a failed compile by returning the empty rejecting automaton"
        );
        assert!(
            production.contains("use dfa_compile_with_budget and shard oversized pattern sets"),
            "dfa_compile panic must explain the structured recovery path"
        );
    }
}


//! Regex AST → `NfaPlan` frontend.
//!
//! `nfa::compile` ships a literal-only NFA (one byte per state). This
//! module is its regex-aware counterpart: parse a regex string with
//! `regex-syntax`, lower the AST into a Thompson NFA over byte
//! transitions, emit the same `(NfaPlan, transition_table,
//! epsilon_table)` triple the literal compiler produces.
//!
//! # Why a separate module instead of widening `nfa::compile`
//!
//! The literal compiler is hot-path simple — every byte is a single
//! state. Bolting alternation / repetition / character classes onto it
//! would either bloat the literal path or fork the construction code.
//! The lego-block fix is a SECOND construction module that emits the
//! SAME output shape, so every downstream component (`nfa_scan`
//! Program, `mega_scan::build`, `RulePipeline`) works unmodified.
//!
//! # Supported regex subset
//!
//! Targets the ~85% of vyre's expected detector regex shapes:
//!
//!   - Concatenation (default)
//!   - Alternation `a|b`
//!   - Character classes `[abc]`, `[a-z]`, `[^abc]`
//!   - Builtin escapes `\d \D \w \W \s \S` (ASCII semantics)
//!   - Bounded repetition `*`, `+`, `?`, `{n}`, `{n,m}`
//!   - Escape literals `\.`, `\\`, `\(`, `\[`
//!
//! Explicitly NOT supported (returns `RegexCompileError::Unsupported`):
//!
//!   - Anchors `^` / `$` / `\b` (NFA always scans full haystack)
//!   - Backreferences `\1` (NFA cannot represent)
//!   - Lookarounds `(?=...)` (CPU regex-rs handles those)
//!   - Unicode character classes outside the ASCII range
//!
//! Consumers facing one of the unsupported features should keep the
//! relevant detector on the CPU regex backend — the cost of doing so
//! is well under the GPU roundtrip overhead anyway.

use std::collections::HashSet;

use regex_syntax::hir::{Class, Hir, HirKind, Repetition};

use crate::matching::nfa::NfaPlan;

const LANES: usize = vyre_primitives::nfa::subgroup_nfa::LANES_PER_SUBGROUP;

/// Failure modes for [`compile_regex_set`]. Variants are non-exhaustive
/// so future regex features can be added without a breaking change.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum RegexCompileError {
    /// `regex-syntax` rejected the pattern. Carries the parser's own
    /// diagnostic so callers can forward it.
    Parse {
        /// Index into the input slice that failed to parse.
        pattern_index: usize,
        /// `regex-syntax`'s error message.
        message: String,
    },
    /// The pattern uses a regex feature this NFA frontend does not
    /// support. Caller should fall back to a CPU regex backend for
    /// this single pattern.
    Unsupported {
        /// Index into the input slice that uses the unsupported feature.
        pattern_index: usize,
        /// One-line description of what isn't supported (e.g. "anchors").
        feature: &'static str,
    },
    /// The compiled NFA exceeds `LANES * 32` states (the lane-major
    /// transition table addresses states with one bit per lane).
    /// Mitigation: split the pattern set across multiple pipelines.
    TooManyStates {
        /// Number of states the AST would have produced.
        states: usize,
        /// Per-pipeline maximum.
        cap: usize,
    },
}

impl std::fmt::Display for RegexCompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Parse {
                pattern_index,
                message,
            } => write!(
                f,
                "regex_compile: pattern {pattern_index} parse error: {message}. \
                 Fix: review the regex syntax."
            ),
            Self::Unsupported {
                pattern_index,
                feature,
            } => write!(
                f,
                "regex_compile: pattern {pattern_index} uses unsupported feature `{feature}`. \
                 Fix: keep this detector on the CPU regex backend."
            ),
            Self::TooManyStates { states, cap } => write!(
                f,
                "regex_compile: NFA needs {states} states; per-pipeline cap is {cap}. \
                 Fix: split the pattern set across multiple pipelines."
            ),
        }
    }
}

impl std::error::Error for RegexCompileError {}

/// Output of [`compile_regex_set`] — same triple shape as the literal
/// `nfa::compile` returns plus the GPU side-tables `nfa::nfa_scan`
/// expects, so consumers can plug this into `RulePipeline` without
/// changing the dispatch path.
#[derive(Debug, Clone)]
pub struct CompiledRegexSet {
    /// State graph + accept-state metadata.
    pub plan: NfaPlan,
    /// Lane-major byte→bitset transition table:
    /// `[num_states × 256 × LANES_PER_SUBGROUP]` u32s.
    pub transition_table: Vec<u32>,
    /// Lane-major epsilon (free) transition table:
    /// `[num_states × LANES_PER_SUBGROUP]` u32s.
    pub epsilon_table: Vec<u32>,
}

const STATE_CAP: usize = LANES * 32;

/// Compile a list of regex strings into a single multimatch NFA.
///
/// # Errors
/// See [`RegexCompileError`].
pub fn compile_regex_set(patterns: &[&str]) -> Result<CompiledRegexSet, RegexCompileError> {
    let mut builder = NfaBuilder::new();
    let mut accept_states = Vec::with_capacity(patterns.len());
    let mut accept_state_ids = Vec::with_capacity(patterns.len());
    let entry = builder.fresh_state(); // shared entry state 0

    // Use the byte-oriented parser configuration: `unicode(false)` +
    // `utf8(false)` makes `\d` / `\w` / `\s` ASCII-only, which is what
    // this primitive's byte-state automaton can represent.
    // `regex_syntax::parse(pat)` defaults to Unicode classes that
    // explode into hundreds of byte ranges and trip our `> 0x7F` guard.
    for (pid, pat) in patterns.iter().enumerate() {
        let mut parser = regex_syntax::ParserBuilder::new()
            .unicode(false)
            .utf8(false)
            .build();
        let hir = parser.parse(pat).map_err(|e| RegexCompileError::Parse {
            pattern_index: pid,
            message: format!("{e}"),
        })?;
        let frag = build_hir(&mut builder, &hir, pid)?;
        // Connect the shared entry to this pattern's start via epsilon.
        builder.add_epsilon(entry, frag.start);
        accept_states.push((pid as u32, frag.match_len as u32));
        accept_state_ids.push(frag.end);
    }

    if builder.state_count() > STATE_CAP {
        return Err(RegexCompileError::TooManyStates {
            states: builder.state_count(),
            cap: STATE_CAP,
        });
    }

    let plan = NfaPlan {
        num_states: builder.state_count() as u32,
        input_len: 0,
        accept_states,
        accept_state_ids,
    };
    let (transition_table, epsilon_table) = builder.emit_lane_major_tables();
    Ok(CompiledRegexSet {
        plan,
        transition_table,
        epsilon_table,
    })
}

/// Build a [`crate::matching::RulePipeline`] directly from regex
/// sources. Convenience for consumers who don't need the
/// `CompiledRegexSet` intermediate. `input_len` matches the contract
/// of `mega_scan::build` (haystack byte count the dispatch will scan).
///
/// # Errors
/// Forwards [`RegexCompileError`].
pub fn build_rule_pipeline_from_regex(
    patterns: &[&str],
    input_buf: &str,
    hit_buf: &str,
    input_len: u32,
) -> Result<crate::matching::RulePipeline, RegexCompileError> {
    let compiled = compile_regex_set(patterns)?;
    // Reuse the literal nfa_scan Program shape — the buffer contracts
    // and lane-major table layouts are identical.
    let program = crate::matching::nfa::nfa_scan(patterns, input_buf, hit_buf, input_len);
    Ok(crate::matching::RulePipeline {
        program,
        transition_table: compiled.transition_table,
        epsilon_table: compiled.epsilon_table,
        plan: compiled.plan.for_input_len(input_len),
    })
}

// ---- Thompson NFA construction over byte transitions ----

#[derive(Debug)]
struct NfaBuilder {
    /// Per-state byte→[next-state-list] transitions.
    transitions: Vec<Vec<(ByteSet, u32)>>,
    /// Per-state list of epsilon (free) successors.
    epsilons: Vec<Vec<u32>>,
}

#[derive(Debug, Clone)]
struct ByteSet {
    bits: [u64; 4], // 256 bits → 4 u64s
}

impl ByteSet {
    fn new() -> Self {
        Self { bits: [0; 4] }
    }
    fn insert(&mut self, b: u8) {
        self.bits[(b / 64) as usize] |= 1u64 << (b % 64);
    }
    fn from_byte(b: u8) -> Self {
        let mut s = Self::new();
        s.insert(b);
        s
    }
    fn from_range(lo: u8, hi: u8) -> Self {
        let mut s = Self::new();
        for b in lo..=hi {
            s.insert(b);
        }
        s
    }
    fn contains(&self, b: u8) -> bool {
        (self.bits[(b / 64) as usize] >> (b % 64)) & 1 == 1
    }
}

#[derive(Debug, Clone, Copy)]
struct Fragment {
    start: u32,
    end: u32,
    /// Sum of byte-steps along the longest path. Used as the
    /// `pattern_len` reported in `NfaPlan::accept_states`.
    match_len: usize,
}

impl NfaBuilder {
    fn new() -> Self {
        Self {
            transitions: Vec::new(),
            epsilons: Vec::new(),
        }
    }

    fn state_count(&self) -> usize {
        self.transitions.len()
    }

    fn fresh_state(&mut self) -> u32 {
        self.transitions.push(Vec::new());
        self.epsilons.push(Vec::new());
        (self.transitions.len() - 1) as u32
    }

    fn add_byte_transition(&mut self, src: u32, set: ByteSet, dst: u32) {
        self.transitions[src as usize].push((set, dst));
    }

    fn add_epsilon(&mut self, src: u32, dst: u32) {
        self.epsilons[src as usize].push(dst);
    }

    /// Lane-major emission, matching the contract of
    /// `nfa::build_transition_table` + `build_epsilon_table`.
    fn emit_lane_major_tables(&self) -> (Vec<u32>, Vec<u32>) {
        let n = self.state_count();
        let mut transitions = vec![0u32; n * 256 * LANES];
        let mut epsilons = vec![0u32; n * LANES];

        for (src, edges) in self.transitions.iter().enumerate() {
            for (set, dst) in edges {
                let dst_lane = (*dst / 32) as usize;
                let dst_bit = 1u32 << (*dst % 32);
                for b in 0..=255u8 {
                    if set.contains(b) {
                        let idx = src * 256 * LANES + (b as usize) * LANES + dst_lane;
                        transitions[idx] |= dst_bit;
                    }
                }
            }
        }
        for (src, eps) in self.epsilons.iter().enumerate() {
            for dst in eps {
                let dst_lane = (*dst / 32) as usize;
                let dst_bit = 1u32 << (*dst % 32);
                let idx = src * LANES + dst_lane;
                epsilons[idx] |= dst_bit;
            }
        }
        (transitions, epsilons)
    }
}

fn build_hir(b: &mut NfaBuilder, hir: &Hir, pid: usize) -> Result<Fragment, RegexCompileError> {
    match hir.kind() {
        HirKind::Empty => {
            let s = b.fresh_state();
            Ok(Fragment {
                start: s,
                end: s,
                match_len: 0,
            })
        }
        HirKind::Literal(lit) => {
            // Each literal byte gets its own state.
            let start = b.fresh_state();
            let mut prev = start;
            for &byte in lit.0.iter() {
                let next = b.fresh_state();
                b.add_byte_transition(prev, ByteSet::from_byte(byte), next);
                prev = next;
            }
            Ok(Fragment {
                start,
                end: prev,
                match_len: lit.0.len(),
            })
        }
        HirKind::Class(cls) => {
            let set = byte_set_from_class(cls, pid)?;
            let start = b.fresh_state();
            let end = b.fresh_state();
            b.add_byte_transition(start, set, end);
            Ok(Fragment {
                start,
                end,
                match_len: 1,
            })
        }
        HirKind::Repetition(rep) => build_repetition(b, rep, pid),
        HirKind::Concat(parts) => {
            if parts.is_empty() {
                let s = b.fresh_state();
                return Ok(Fragment {
                    start: s,
                    end: s,
                    match_len: 0,
                });
            }
            let mut iter = parts.iter();
            let first = build_hir(b, iter.next().unwrap(), pid)?;
            let mut acc = first;
            for child in iter {
                let next = build_hir(b, child, pid)?;
                b.add_epsilon(acc.end, next.start);
                acc = Fragment {
                    start: acc.start,
                    end: next.end,
                    match_len: acc.match_len + next.match_len,
                };
            }
            Ok(acc)
        }
        HirKind::Alternation(alts) => {
            // Diamond: shared fork → each branch → shared join.
            let fork = b.fresh_state();
            let join = b.fresh_state();
            let mut max_len = 0usize;
            for child in alts {
                let frag = build_hir(b, child, pid)?;
                b.add_epsilon(fork, frag.start);
                b.add_epsilon(frag.end, join);
                if frag.match_len > max_len {
                    max_len = frag.match_len;
                }
            }
            Ok(Fragment {
                start: fork,
                end: join,
                match_len: max_len,
            })
        }
        HirKind::Look(_) => Err(RegexCompileError::Unsupported {
            pattern_index: pid,
            feature: "anchors / lookarounds",
        }),
        HirKind::Capture(c) => {
            // We don't expose capture groups (NFA scan is multimatch,
            // not capture). Strip and recurse.
            build_hir(b, &c.sub, pid)
        }
    }
}

fn build_repetition(
    b: &mut NfaBuilder,
    rep: &Repetition,
    pid: usize,
) -> Result<Fragment, RegexCompileError> {
    let min = rep.min;
    let max = rep.max;

    // Hard cap on `max` so a `{0,1000000}` doesn't blow up the state
    // table. The cap is conservative — bigger detectors fall back to
    // CPU regex.
    const MAX_REP: u32 = 64;
    if let Some(m) = max {
        if m > MAX_REP {
            return Err(RegexCompileError::Unsupported {
                pattern_index: pid,
                feature: "repetition with upper bound > 64",
            });
        }
    }
    if min > MAX_REP {
        return Err(RegexCompileError::Unsupported {
            pattern_index: pid,
            feature: "repetition with min > 64",
        });
    }

    // Build by unrolling: emit `min` copies, then either
    //   - a Kleene loop if max is None (`*` / `+`), OR
    //   - `max - min` optional copies if max is bounded.
    let start = b.fresh_state();
    let mut tail = start;
    let mut total_len = 0usize;

    for _ in 0..min {
        let frag = build_hir(b, &rep.sub, pid)?;
        b.add_epsilon(tail, frag.start);
        tail = frag.end;
        total_len += frag.match_len;
    }

    match max {
        None => {
            // Open-ended: insert a Kleene wrapper. tail → frag.start →
            // frag.end → tail (loop back) ; tail → join (skip).
            let join = b.fresh_state();
            let frag = build_hir(b, &rep.sub, pid)?;
            b.add_epsilon(tail, frag.start);
            b.add_epsilon(frag.end, frag.start); // loop
            b.add_epsilon(frag.end, join);
            b.add_epsilon(tail, join); // zero matches
            tail = join;
        }
        Some(m) => {
            for _ in min..m {
                let frag = build_hir(b, &rep.sub, pid)?;
                let join = b.fresh_state();
                b.add_epsilon(tail, frag.start);
                b.add_epsilon(frag.end, join);
                b.add_epsilon(tail, join); // skip this optional copy
                tail = join;
            }
        }
    }
    Ok(Fragment {
        start,
        end: tail,
        match_len: total_len,
    })
}

fn byte_set_from_class(cls: &Class, pid: usize) -> Result<ByteSet, RegexCompileError> {
    let mut out = ByteSet::new();
    match cls {
        Class::Bytes(byte_class) => {
            for r in byte_class.iter() {
                let lo = r.start();
                let hi = r.end();
                let merged = ByteSet::from_range(lo, hi);
                for w in 0..4 {
                    out.bits[w] |= merged.bits[w];
                }
            }
        }
        Class::Unicode(uni) => {
            // Only support ASCII subset of unicode classes — anything
            // outside 0..=127 escapes the byte-state automaton.
            for r in uni.iter() {
                let lo = r.start() as u32;
                let hi = r.end() as u32;
                if hi > 0x7F {
                    return Err(RegexCompileError::Unsupported {
                        pattern_index: pid,
                        feature: "unicode character classes outside ASCII",
                    });
                }
                let merged = ByteSet::from_range(lo as u8, hi as u8);
                for w in 0..4 {
                    out.bits[w] |= merged.bits[w];
                }
            }
        }
    }
    let _ = HashSet::<u8>::new(); // suppress unused-import warning if any
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn states_of(s: &str) -> u32 {
        compile_regex_set(&[s]).unwrap().plan.num_states
    }

    #[test]
    fn literal_compiles() {
        let r = compile_regex_set(&["abc"]).unwrap();
        // 1 entry + 1 literal-start + 3 letter states = 5
        assert_eq!(r.plan.num_states, 5);
        assert_eq!(r.plan.accept_states.len(), 1);
    }

    #[test]
    fn alternation_compiles() {
        let r = compile_regex_set(&["a|b"]).unwrap();
        // entry + fork + join + 2*(start + 1 byte) = 1+1+1+2+2 = 7
        // (exact count depends on builder; just sanity-check it's >0).
        assert!(r.plan.num_states > 0);
        assert_eq!(r.plan.accept_states.len(), 1);
    }

    #[test]
    fn class_compiles() {
        let r = compile_regex_set(&["[a-z]"]).unwrap();
        assert!(r.plan.num_states > 0);
        // Sanity: 26 lowercase bytes hit the same destination state.
        // We don't introspect the table here — just ensure it builds.
    }

    #[test]
    fn rejects_anchor() {
        let err = compile_regex_set(&["^foo"]).unwrap_err();
        assert!(matches!(err, RegexCompileError::Unsupported { .. }));
    }

    #[test]
    fn rejects_unbounded_max_rep() {
        let err = compile_regex_set(&["a{0,128}"]).unwrap_err();
        assert!(matches!(err, RegexCompileError::Unsupported { .. }));
    }

    #[test]
    fn states_count_grows_with_concat() {
        let one = states_of("a");
        let two = states_of("ab");
        let three = states_of("abc");
        assert!(two > one);
        assert!(three > two);
    }

    #[test]
    fn state_cap_enforced() {
        // Build a regex that would exceed the per-pipeline state cap.
        // A literal of LANES*32+1 = 1025 chars exceeds the cap.
        let huge: String = (0..(STATE_CAP + 4)).map(|_| 'a').collect();
        let err = compile_regex_set(&[&huge]).unwrap_err();
        assert!(matches!(err, RegexCompileError::TooManyStates { .. }));
    }
}

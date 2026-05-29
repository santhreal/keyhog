//! Regex set → dense DFA GPU pipeline.
//!
//! Composes three existing primitives end-to-end:
//!
//! 1. `compile_regex_set` (this crate) - regex sources → bit-vector NFA.
//! 2. `vyre_primitives::matching::nfa_to_dfa` - NFA → dense
//!    `CompiledDfa` via subset construction.
//! 3. `build_ac_bounded_ranges_program` (this crate) - `CompiledDfa`
//!    → GPU `Program` with O(1)-per-byte AC scan semantics.
//!
//! The output [`RegexDfaPipeline`] is the regex-aware counterpart of
//! the literal-pattern `ClassicAcAutomaton`: same `Program` shape, same
//! per-byte transition cost, same `(pid, start, end)` hit triple
//! output. Consumers that already dispatch
//! `classic_ac_bounded_ranges_program` can swap their literal pattern
//! source for a regex set and pay no extra per-byte cost on the GPU.
//!
//! # When this beats `RulePipeline`
//!
//! `RulePipeline` (the bit-vector NFA scan kernel) is O(LANES²) per
//! byte regardless of pattern set size - fine for short-buffer per-
//! anchor confirmation, catastrophic for whole-buffer scans at >1 MiB.
//! `RegexDfaPipeline` is O(1) per byte but pays a state-explosion risk
//! in the subset construction. Use it when:
//!
//! * The pattern set's subset-constructed DFA stays under
//!   `max_dfa_states` (typical for high-volume detector regexes:
//!   bounded character classes + bounded repetitions).
//! * The haystack is large enough that per-byte cost dominates per-
//!   dispatch overhead.
//!
//! Fall back to `RulePipeline` when the subset construction returns
//! [`vyre_primitives::matching::NfaToDfaError::StateExplosion`].

use std::error::Error;
use std::fmt;

use vyre_foundation::ir::Program;

use vyre_primitives::matching::{nfa_to_dfa, CompiledDfa, NfaTables, NfaToDfaError};

use crate::scan::classic_ac::try_build_ac_bounded_ranges_program_ext;
use crate::scan::regex_compile::{compile_regex_set, RegexCompileError};

/// Ready-to-dispatch regex DFA pipeline.
///
/// `program` is built by `build_ac_bounded_ranges_program` and has the
/// same buffer contract as a literal-AC dispatch: `haystack`,
/// `transitions`, `output_offsets`, `output_records`, `pattern_lengths`,
/// `haystack_len`, `match_count`, `matches`. Upload the corresponding
/// fields of [`RegexDfaPipeline::dfa`] and [`RegexDfaPipeline::pattern_lengths`]
/// to those buffers and dispatch.
#[derive(Debug, Clone)]
pub struct RegexDfaPipeline {
    /// Dispatchable GPU program. Same shape as
    /// `classic_ac_bounded_ranges_program` output - caller wires the
    /// existing AC kernel host-side, no new dispatch path needed.
    pub program: Program,
    /// Dense DFA produced by NFA → DFA subset construction. Owns the
    /// transition / accept / output_offsets / output_records buffers
    /// the GPU program reads from.
    pub dfa: CompiledDfa,
    /// One entry per input regex; `pattern_lengths[pid]` is the longest
    /// possible match length for that pattern. Uploaded to the
    /// `pattern_lengths` buffer the AC kernel uses to derive each
    /// match's `start` offset from the accepting `end` offset.
    pub pattern_lengths: Vec<u32>,
}

/// Failures from [`build_regex_dfa_pipeline`].
#[derive(Debug)]
#[non_exhaustive]
pub enum RegexDfaError {
    /// Regex parsing or NFA construction rejected a pattern.
    Compile(RegexCompileError),
    /// Subset construction couldn't lower the NFA - typically state
    /// explosion. The caller should either raise `max_dfa_states`,
    /// shard the pattern set, or fall back to `RulePipeline`.
    Lower(NfaToDfaError),
    /// Regex/DFA metadata exceeded the GPU program's u32 ABI or host-side
    /// staging allocation budget.
    Size {
        /// Actionable sizing diagnostic.
        message: String,
    },
}

impl fmt::Display for RegexDfaError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Compile(error) => write!(formatter, "regex NFA compile failed: {error}"),
            Self::Lower(error) => {
                write!(formatter, "NFA → DFA subset construction failed: {error}")
            }
            Self::Size { message } => write!(formatter, "regex DFA sizing failed: {message}"),
        }
    }
}

impl Error for RegexDfaError {}

impl From<RegexCompileError> for RegexDfaError {
    fn from(error: RegexCompileError) -> Self {
        Self::Compile(error)
    }
}

impl From<NfaToDfaError> for RegexDfaError {
    fn from(error: NfaToDfaError) -> Self {
        Self::Lower(error)
    }
}

/// Build a [`RegexDfaPipeline`] from a list of regex sources.
///
/// `max_matches` is the per-dispatch hit-buffer cap (passed through to
/// `build_ac_bounded_ranges_program`). `max_dfa_states` is the subset-
/// construction state cap (see
/// [`vyre_primitives::matching::nfa_to_dfa`]). The default of 16k
/// states matches `DEFAULT_DFA_BUDGET_BYTES = 16 MiB` (16k × 256 × 4 B).
///
/// The match-append strategy is the default `append_match_subgroup`
/// (I.17 - one atomic per subgroup leader). On backends that can't
/// lower `subgroup_ballot` / `subgroup_shuffle` yet (currently
/// `vyre-driver-cuda`) use [`build_regex_dfa_pipeline_ext`] with
/// `use_subgroup_coalesce = false`.
///
/// # Errors
/// See [`RegexDfaError`].
pub fn build_regex_dfa_pipeline(
    patterns: &[&str],
    max_matches: u32,
    max_dfa_states: usize,
) -> Result<RegexDfaPipeline, RegexDfaError> {
    build_regex_dfa_pipeline_ext(patterns, max_matches, max_dfa_states, true)
}

/// [`build_regex_dfa_pipeline`] with explicit `use_subgroup_coalesce`
/// control. Pass `false` on backends whose IR lowering cannot yet emit
/// `subgroup_ballot` + `subgroup_shuffle` - currently `vyre-driver-cuda`
/// rejects the subgroup form during canonical pre-emit lowering. Either
/// flag produces bit-identical match output; the difference is purely
/// the atomic-coalescing strategy at hit-buffer append time.
///
/// # Errors
/// See [`RegexDfaError`].
pub fn build_regex_dfa_pipeline_ext(
    patterns: &[&str],
    max_matches: u32,
    max_dfa_states: usize,
    use_subgroup_coalesce: bool,
) -> Result<RegexDfaPipeline, RegexDfaError> {
    let regex_set = compile_regex_set(patterns)?;

    // The NFA `plan` carries accept_states as `(pattern_id, match_len)`
    // tuples. nfa_to_dfa wants the pattern ids and the max len
    // separately; max_pattern_len doubles as the AC kernel's per-
    // position replay window cap.
    let mut accept_pattern_ids: Vec<u32> = Vec::new();
    reserve_regex_vec(
        &mut accept_pattern_ids,
        regex_set.plan.accept_states.len(),
        "accept pattern id table",
    )?;
    accept_pattern_ids.extend(regex_set.plan.accept_states.iter().map(|(pid, _)| *pid));
    let max_pattern_len = regex_set
        .plan
        .accept_states
        .iter()
        .map(|(_, len)| *len)
        .max()
        .unwrap_or(0);
    // pattern_lengths is per-pattern indexed; build it from the accept
    // table. A pattern with multiple accept states (alternation) takes
    // the longest match length - same convention `dfa_compile` uses.
    let pattern_count = u32::try_from(patterns.len()).map_err(|source| RegexDfaError::Size {
        message: format!(
            "pattern count {} exceeds u32 GPU buffer metadata: {source}. Fix: shard the regex set before building a DFA dispatch.",
            patterns.len()
        ),
    })?;
    let mut pattern_lengths = Vec::new();
    reserve_regex_vec(&mut pattern_lengths, patterns.len(), "pattern length table")?;
    pattern_lengths.resize(patterns.len(), 0);
    for (pid, len) in &regex_set.plan.accept_states {
        let idx = usize::try_from(*pid).map_err(|source| RegexDfaError::Size {
            message: format!(
                "accept pattern id {pid} cannot fit usize for pattern-length indexing: {source}. Fix: shard the regex set before building a DFA dispatch."
            ),
        })?;
        if idx < pattern_lengths.len() && *len > pattern_lengths[idx] {
            pattern_lengths[idx] = *len;
        }
    }

    let tables = NfaTables {
        num_states: regex_set.plan.num_states,
        transition_table: &regex_set.transition_table,
        epsilon_table: &regex_set.epsilon_table,
        accept_state_ids: &regex_set.plan.accept_state_ids,
        accept_pattern_ids: &accept_pattern_ids,
        max_pattern_len,
    };
    let dfa = nfa_to_dfa(&tables, max_dfa_states)?;

    let program = try_build_ac_bounded_ranges_program_ext(
        &dfa,
        pattern_count,
        max_matches,
        use_subgroup_coalesce,
    )
    .map_err(|message| RegexDfaError::Size { message })?;

    Ok(RegexDfaPipeline {
        program,
        dfa,
        pattern_lengths,
    })
}

fn reserve_regex_vec<T>(
    vec: &mut Vec<T>,
    requested: usize,
    label: &'static str,
) -> Result<(), RegexDfaError> {
    vyre_foundation::allocation::try_reserve_vec_to_capacity(vec, requested).map_err(|source| {
        RegexDfaError::Size {
            message: format!(
                "regex DFA {label} reservation failed for {requested} item(s): {source}. Fix: shard the regex set or lower the DFA budget before dispatch."
            ),
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// End-to-end: a literal regex set should produce a Program whose
    /// CompiledDfa accepts the literal at the expected end offset. The
    /// CompiledDfa accept table is the load-bearing assertion - if it's
    /// empty, the composition didn't propagate accept metadata through
    /// the subset construction.
    #[test]
    fn literal_pattern_set_lowers_through_to_dfa_program() {
        let pipeline =
            build_regex_dfa_pipeline(&["abc"], 1024, 1024).expect("Fix: literal must compile");
        assert!(
            pipeline.dfa.state_count >= 4,
            "literal 'abc' DFA must have at least 4 states (entry + 3 progress); got {}",
            pipeline.dfa.state_count
        );
        assert_eq!(
            pipeline.pattern_lengths,
            vec![3],
            "single literal 'abc' must have pattern_lengths = [3]"
        );
        assert!(
            pipeline
                .dfa
                .accept
                .iter()
                .any(|&pid_plus_one| pid_plus_one == 1),
            "at least one DFA state must accept pattern 0 (encoded as accept = 1)"
        );
        // Program buffer surface matches the AC kernel's contract:
        // haystack, transitions, output_offsets, output_records,
        // pattern_lengths, haystack_len, match_count, matches.
        let names: Vec<&str> = pipeline.program.buffers.iter().map(|b| b.name()).collect();
        for expected in [
            "haystack",
            "transitions",
            "output_offsets",
            "output_records",
            "pattern_lengths",
            "haystack_len",
            "match_count",
            "matches",
        ] {
            assert!(
                names.contains(&expected),
                "RegexDfaPipeline program must declare buffer `{expected}` for AC dispatch; got {names:?}"
            );
        }
    }

    /// Multi-pattern union: two literals must end up in two distinct
    /// accept states (each tied to its own pattern id), not collapsed
    /// into one.
    #[test]
    fn multi_literal_set_emits_distinct_accept_pids() {
        let pipeline = build_regex_dfa_pipeline(&["abc", "xyz"], 1024, 1024)
            .expect("Fix: two literals must compile");
        assert_eq!(pipeline.pattern_lengths, vec![3, 3]);
        // accept[s] = pid + 1, so a multi-pattern set should produce
        // both `1` (pid 0) and `2` (pid 1) somewhere in the accept
        // table. If either is missing, the subset construction lost
        // an accept's pattern_id.
        let has_pid0 = pipeline.dfa.accept.iter().any(|&value| value == 1);
        let has_pid1 = pipeline.dfa.accept.iter().any(|&value| value == 2);
        assert!(has_pid0, "no DFA state accepts pid 0 - 'abc' lost in lower");
        assert!(has_pid1, "no DFA state accepts pid 1 - 'xyz' lost in lower");
    }

    /// State-explosion path: setting `max_dfa_states` to 1 must surface
    /// as a structured error, not a panic.
    #[test]
    fn state_explosion_surfaces_as_error_not_panic() {
        let err = build_regex_dfa_pipeline(&["abc"], 1024, 1)
            .expect_err("max_dfa_states=1 must trip state explosion");
        match err {
            RegexDfaError::Lower(NfaToDfaError::StateExplosion { .. }) => {}
            other => panic!("expected Lower(StateExplosion), got {other:?}"),
        }
    }

    /// A regex with a character class should also lower - this is the
    /// case `RulePipeline` would scan via NFA bit-vector. The DFA path
    /// must produce an accept somewhere so the consumer gets a hit.
    #[test]
    fn character_class_pattern_lowers_to_acceptor_dfa() {
        let pipeline = build_regex_dfa_pipeline(&["[ab]c"], 1024, 1024)
            .expect("Fix: character class must compile");
        assert!(
            pipeline.dfa.accept.iter().any(|&value| value != 0),
            "DFA for '[ab]c' must accept at least one state"
        );
    }

    #[test]
    fn regex_dfa_pipeline_uses_checked_size_conversions() {
        let production = include_str!("regex_dfa.rs")
            .split("\n#[cfg(test)]\nmod tests")
            .next()
            .expect("Fix: regex DFA production section should precede tests");

        assert!(
            production.contains("RegexDfaError::Size"),
            "Fix: regex DFA sizing failures must be structured errors, not panics or unchecked casts."
        );
        assert!(
            production.contains("u32::try_from(patterns.len())"),
            "Fix: regex DFA pattern count must use checked conversion for GPU ABI metadata."
        );
        assert!(
            production.contains("usize::try_from(*pid)"),
            "Fix: regex DFA accept pattern ids must use checked host indexing conversion."
        );
        assert!(
            production.contains("try_build_ac_bounded_ranges_program_ext"),
            "Fix: regex DFA must call the fallible AC program builder."
        );
        assert!(
            !production.contains("patterns.len() as u32"),
            "Fix: regex DFA must not narrow pattern counts with unchecked casts."
        );
    }
}

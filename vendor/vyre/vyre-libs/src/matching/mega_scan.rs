//! Mega-scan integrator.
//!
//! Fuses the G-stack innovations into one `RulePipeline` that surgec
//! dispatches. Right now the integrator wires G1 (subgroup-cooperative
//! NFA scan) end-to-end. As G2-G10 land their composition hooks here,
//! keeping one authoritative entry point for every scan configuration.
//!
//! # Why a single entry point
//!
//! Each innovation has its own buffer contracts (lane-major NFA
//! transition tables, CHD perfect-hash buckets, persistent-engine
//! work queues, etc.). Attempting to wire those inside surgec would
//! push backend-specific knowledge into the language compiler —
//! exactly the coupling vyre's layer boundaries exist to prevent.
//! `RulePipeline::new` holds the composition rules; callers hand in
//! patterns + input, the integrator returns a ready-to-dispatch
//! `Program` plus the host-side bit-tables the Program expects to
//! find at its declared storage buffers.

use vyre::VyreBackend;
use vyre_foundation::ir::Program;
use vyre_foundation::match_result::Match;

use super::nfa;

/// A ready-to-dispatch pipeline produced by the integrator.
#[derive(Debug, Clone)]
pub struct RulePipeline {
    /// GPU-resident Program. Dispatch with the pattern plan's
    /// workgroup configuration.
    pub program: Program,
    /// Lane-major transition table, sized
    /// `num_states × 256 × LANES_PER_SUBGROUP` u32s. Upload to the
    /// `nfa_transition` storage buffer.
    pub transition_table: Vec<u32>,
    /// Lane-major epsilon table, sized
    /// `num_states × LANES_PER_SUBGROUP` u32s. Upload to the
    /// `nfa_epsilon` storage buffer.
    pub epsilon_table: Vec<u32>,
    /// Compiled NFA plan (accept states, num_states, input length).
    pub plan: nfa::NfaPlan,
}

impl RulePipeline {
    /// Dispatch this pipeline against `haystack` using the provided
    /// `backend`, returning up to `max_matches` matches.
    ///
    /// This is the regex-multimatch counterpart of
    /// [`crate::matching::GpuLiteralSet::scan`] — same backend trait,
    /// same hit-buffer encoding (slot 0 = atomic counter, then triples
    /// of `(pattern_id, start, end)`), so callers can swap the two
    /// matchers without changing post-processing code.
    ///
    /// # Errors
    /// Returns [`vyre::BackendError`] on dispatch or readback failure.
    /// Returns an error wrapping the message
    /// `"haystack length exceeds u32 capacity"` when `haystack.len()`
    /// cannot be encoded as `u32` — split the input first.
    pub fn scan<B: VyreBackend + ?Sized>(
        &self,
        backend: &B,
        haystack: &[u8],
        max_matches: u32,
    ) -> Result<Vec<Match>, vyre::BackendError> {
        use crate::matching::dispatch_io;

        let haystack_len = dispatch_io::scan_guard(
            haystack,
            "RulePipeline::scan",
            dispatch_io::DEFAULT_MAX_SCAN_BYTES,
        )?;

        // Buffer order matches the BufferDecl declarations in
        // `nfa::nfa_scan`: input, nfa_transition, nfa_epsilon, hits.
        // The hit buffer pre-allocates `max_matches * 3 + 1` u32 slots
        // (slot 0 = atomic counter, then triples).
        let hit_buf_words = (max_matches as usize) * 3 + 1;
        let inputs = vec![
            dispatch_io::pack_haystack_u32(haystack),
            dispatch_io::pack_u32_slice(&self.transition_table),
            dispatch_io::pack_u32_slice(&self.epsilon_table),
            vec![0u8; hit_buf_words * 4],
        ];

        let config = dispatch_io::candidate_start_dispatch_config(haystack_len);

        let outputs = backend.dispatch(&self.program, &inputs, &config)?;

        // The hit buffer is the only ReadWrite storage in the program;
        // backends return outputs in declaration order, so it lives at
        // index 0 of `outputs`.
        let hit_bytes = &outputs[0];
        if hit_bytes.len() < 4 {
            return Err(vyre::BackendError::new(
                "RulePipeline::scan: hit buffer truncated. \
                 Fix: this is a backend bug; report it.",
            ));
        }
        let count = u32::from_le_bytes(hit_bytes[0..4].try_into().unwrap());
        // Triples start at byte 4 (after the atomic counter).
        Ok(dispatch_io::unpack_match_triples(
            &hit_bytes[4..],
            count.min(max_matches),
        ))
    }

    /// Compute matches against `haystack` on the CPU using the same NFA
    /// the GPU program runs. Mirrors [`super::GpuLiteralSet::scan_cpu`]
    /// — same `Match` type, same sort, so any consumer can write a
    /// single parity test that swaps backends and asserts equality.
    ///
    /// This is intentionally O(n × patterns) — it is only meant for
    /// parity / debugging, not production scanning.
    #[must_use]
    pub fn scan_cpu(&self, haystack: &[u8]) -> Vec<Match> {
        let mut results = Vec::new();
        for start in 0..haystack.len() {
            let mut state = vec![0_u32; vyre_primitives::nfa::subgroup_nfa::LANES_PER_SUBGROUP];
            state[0] = 1;
            for (cursor, &byte) in haystack.iter().enumerate().skip(start) {
                let mut next = vec![0_u32; vyre_primitives::nfa::subgroup_nfa::LANES_PER_SUBGROUP];
                for (lane, &peer) in state.iter().enumerate() {
                    for bit in 0..32 {
                        if (peer >> bit) & 1 == 0 {
                            continue;
                        }
                        let src_state = lane * 32 + bit;
                        if src_state >= self.plan.num_states as usize {
                            continue;
                        }
                        let base = src_state
                            * 256
                            * vyre_primitives::nfa::subgroup_nfa::LANES_PER_SUBGROUP
                            + (byte as usize)
                                * vyre_primitives::nfa::subgroup_nfa::LANES_PER_SUBGROUP;
                        for (dst_lane, slot) in next.iter_mut().enumerate() {
                            *slot |= self.transition_table[base + dst_lane];
                        }
                    }
                }
                state = next;
                for (&accept_state, &(pattern_id, _pattern_len)) in self
                    .plan
                    .accept_state_ids
                    .iter()
                    .zip(&self.plan.accept_states)
                {
                    let lane = (accept_state / 32) as usize;
                    let bit = accept_state % 32;
                    if lane < state.len() && (state[lane] & (1_u32 << bit)) != 0 {
                        results.push(Match::new(pattern_id, start as u32, cursor as u32 + 1));
                    }
                }
            }
        }
        results.sort_unstable();
        results
    }
}

/// Integrator entry point. Takes a pattern set + the input length the
/// pipeline will be dispatched against and returns everything surgec
/// needs to issue a single dispatch.
///
/// Additional G-stack options land here as optional parameters —
/// callers that don't opt in keep the current behaviour.
#[must_use]
pub fn build(patterns: &[&str], input_buf: &str, hit_buf: &str, input_len: u32) -> RulePipeline {
    let plan = nfa::compile(patterns).for_input_len(input_len);
    let program = nfa::nfa_scan(patterns, input_buf, hit_buf, input_len);
    let transition_table = nfa::build_transition_table(patterns);
    let epsilon_table = nfa::build_epsilon_table(patterns);
    RulePipeline {
        program,
        transition_table,
        epsilon_table,
        plan,
    }
}

const PIPELINE_WIRE_MAGIC: &[u8; 4] = b"VRPL";
const PIPELINE_WIRE_VERSION: u32 = 1;

/// Errors returned by [`RulePipeline::from_bytes`]. Mirrors the layered
/// error pattern of `LiteralSetWireError` — outer envelope failures
/// forward to `WireFraming`, inner failures keep typed variants.
#[derive(Debug)]
#[non_exhaustive]
pub enum PipelineWireError {
    /// Outer envelope (magic / version / section length) was rejected.
    WireFraming(vyre_foundation::serial::envelope::EnvelopeError),
    /// Nested vyre IR `Program` blob was rejected.
    InvalidProgram(String),
    /// One of the four `u32`-array sections had the wrong length to be
    /// consistent with the recorded `num_states` header field. Stale
    /// blob — recompile.
    ShapeMismatch {
        /// Static description of which section's length cross-check
        /// failed.
        reason: &'static str,
    },
}

impl std::fmt::Display for PipelineWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WireFraming(e) => write!(f, "RulePipeline wire envelope: {e}"),
            Self::InvalidProgram(msg) => {
                write!(f, "RulePipeline wire blob has invalid Program: {msg}")
            }
            Self::ShapeMismatch { reason } => {
                write!(f, "RulePipeline wire blob shape mismatch: {reason}")
            }
        }
    }
}

impl std::error::Error for PipelineWireError {}

impl RulePipeline {
    /// Serialize this pipeline into a self-describing binary blob
    /// suitable for on-disk caching. Built on the shared
    /// `vyre_foundation::serial::envelope` primitive — any future cache
    /// consumer reuses the same framing without re-implementing
    /// magic / version / truncation handling.
    ///
    /// Sections, in order:
    ///   - `u32`     : `plan.num_states`
    ///   - `u32`     : `plan.input_len`
    ///   - section 0 : vyre `Program::to_bytes` payload
    ///   - words 1   : `transition_table` (lane-major)
    ///   - words 2   : `epsilon_table` (lane-major)
    ///   - words 3   : `plan.accept_states` flattened as
    ///                 `[pid_0, len_0, pid_1, len_1, …]`
    ///   - words 4   : `plan.accept_state_ids`
    ///
    /// # Errors
    /// Returns [`PipelineWireError::WireFraming`] if any section
    /// exceeds the envelope's `u32` length-prefix capacity.
    pub fn to_bytes(&self) -> Result<Vec<u8>, PipelineWireError> {
        let mut w = vyre_foundation::serial::envelope::WireWriter::new(
            PIPELINE_WIRE_MAGIC,
            PIPELINE_WIRE_VERSION,
        );
        w.write_u32(self.plan.num_states);
        w.write_u32(self.plan.input_len);
        w.write_section(&self.program.to_bytes())
            .map_err(PipelineWireError::WireFraming)?;
        w.write_words(&self.transition_table)
            .map_err(PipelineWireError::WireFraming)?;
        w.write_words(&self.epsilon_table)
            .map_err(PipelineWireError::WireFraming)?;
        // Flatten accept_states tuples into a flat u32 array; each
        // accept-state contributes two consecutive words.
        let mut accept_flat: Vec<u32> = Vec::with_capacity(self.plan.accept_states.len() * 2);
        for &(pid, len) in &self.plan.accept_states {
            accept_flat.push(pid);
            accept_flat.push(len);
        }
        w.write_words(&accept_flat)
            .map_err(PipelineWireError::WireFraming)?;
        w.write_words(&self.plan.accept_state_ids)
            .map_err(PipelineWireError::WireFraming)?;
        Ok(w.into_bytes())
    }

    /// Decode a `RulePipeline` from a blob produced by
    /// [`Self::to_bytes`].
    ///
    /// # Errors
    /// Returns [`PipelineWireError`] when the envelope rejects the
    /// outer header, the nested `Program` is invalid, or the section
    /// shapes don't match the recorded `num_states`.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, PipelineWireError> {
        let mut r = vyre_foundation::serial::envelope::WireReader::new(
            bytes,
            PIPELINE_WIRE_MAGIC,
            PIPELINE_WIRE_VERSION,
        )
        .map_err(PipelineWireError::WireFraming)?;

        let num_states = r.read_u32().map_err(PipelineWireError::WireFraming)?;
        let input_len = r.read_u32().map_err(PipelineWireError::WireFraming)?;

        let program_bytes = r.read_section().map_err(PipelineWireError::WireFraming)?;
        let program = vyre_foundation::ir::Program::from_bytes(program_bytes)
            .map_err(|e| PipelineWireError::InvalidProgram(format!("{e}")))?;

        let transition_table = r.read_words().map_err(PipelineWireError::WireFraming)?;
        let epsilon_table = r.read_words().map_err(PipelineWireError::WireFraming)?;
        let accept_flat = r.read_words().map_err(PipelineWireError::WireFraming)?;
        let accept_state_ids = r.read_words().map_err(PipelineWireError::WireFraming)?;

        if accept_flat.len() % 2 != 0 {
            return Err(PipelineWireError::ShapeMismatch {
                reason: "accept_states array length is not even",
            });
        }
        let accept_states: Vec<(u32, u32)> =
            accept_flat.chunks_exact(2).map(|w| (w[0], w[1])).collect();
        if accept_state_ids.len() != accept_states.len() {
            return Err(PipelineWireError::ShapeMismatch {
                reason: "accept_state_ids length disagrees with accept_states length",
            });
        }

        Ok(RulePipeline {
            program,
            transition_table,
            epsilon_table,
            plan: nfa::NfaPlan {
                num_states,
                input_len,
                accept_states,
                accept_state_ids,
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn integrator_returns_primitive_compatible_tables() {
        let pipe = build(&["abc"], "input", "hits", 16);
        let plan = nfa::compile(&["abc"]);
        let expected_trans_len = (plan.num_states as usize)
            * 256
            * vyre_primitives::nfa::subgroup_nfa::LANES_PER_SUBGROUP;
        let expected_eps_len =
            (plan.num_states as usize) * vyre_primitives::nfa::subgroup_nfa::LANES_PER_SUBGROUP;
        assert_eq!(pipe.transition_table.len(), expected_trans_len);
        assert_eq!(pipe.epsilon_table.len(), expected_eps_len);
    }

    #[test]
    fn integrator_plan_matches_compile() {
        let pipe = build(&["ab", "cd"], "input", "hits", 8);
        assert_eq!(pipe.plan.num_states, 5);
        assert_eq!(pipe.plan.input_len, 8);
        assert_eq!(pipe.plan.accept_states.len(), 2);
    }
}

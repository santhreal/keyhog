use crate::{primitives::common, workgroup::Memory};
use vyre_primitives::PatternMatchDfa;

const HEADER_LEN: usize = 16;
const MAGIC: &[u8; 4] = b"VDFA";

impl common::ReferenceEvaluator for PatternMatchDfa {
    fn evaluate(&self, inputs: &[Memory]) -> Result<Memory, common::EvalError> {
        let haystack = common::one_input(inputs, "scan_dfa")?;
        let dfa = ParsedDfa::parse(&self.dfa)?;
        let mut state = dfa.start;
        let mut offsets = Vec::new();
        for (offset, byte) in haystack.iter().copied().enumerate() {
            state = dfa.step(state, byte)?;
            if dfa.accepts[state] {
                offsets.push(u32::try_from(offset).map_err(|_| {
                    common::EvalError::new(
                        "primitive `scan_dfa` offset exceeds u32. Fix: split haystacks before 4 GiB.",
                    )
                })?);
            }
        }
        Ok(common::write_u32s(offsets))
    }
}

struct ParsedDfa {
    start: usize,
    accepts: Vec<bool>,
    transitions: Vec<u32>,
}

impl ParsedDfa {
    fn parse(bytes: &[u8]) -> Result<Self, common::EvalError> {
        if bytes.len() < HEADER_LEN || &bytes[..4] != MAGIC {
            return Err(common::EvalError::new(
                "primitive `scan_dfa` expected VDFA header. Fix: encode magic, state_count, start, and accept_count.",
            ));
        }
        let state_count = read_u32_at(bytes, 4)? as usize;
        let start = read_u32_at(bytes, 8)? as usize;
        let accept_count = read_u32_at(bytes, 12)? as usize;
        if state_count == 0 || start >= state_count {
            return Err(common::EvalError::new(
                "primitive `scan_dfa` has invalid state count/start. Fix: provide at least one state and a valid start state.",
            ));
        }
        let accept_bytes = accept_count.checked_mul(4).ok_or_else(|| {
            common::EvalError::new(
                "primitive `scan_dfa` accept table size overflow. Fix: bound DFA state metadata.",
            )
        })?;
        let transition_start = HEADER_LEN + accept_bytes;
        let transition_words = state_count.checked_mul(256).ok_or_else(|| {
            common::EvalError::new(
                "primitive `scan_dfa` transition table size overflow. Fix: bound DFA state count.",
            )
        })?;
        let transition_bytes = transition_words.checked_mul(4).ok_or_else(|| {
            common::EvalError::new(
                "primitive `scan_dfa` transition byte size overflow. Fix: bound DFA state count.",
            )
        })?;
        if bytes.len() != transition_start + transition_bytes {
            return Err(common::EvalError::new(format!(
                "primitive `scan_dfa` byte length mismatch: got {}, expected {}. Fix: encode accept states followed by state_count*256 u32 transitions.",
                bytes.len(),
                transition_start + transition_bytes
            )));
        }
        let mut accepts = vec![false; state_count];
        for accept in 0..accept_count {
            let state = read_u32_at(bytes, HEADER_LEN + accept * 4)? as usize;
            if state >= state_count {
                return Err(common::EvalError::new(
                    "primitive `scan_dfa` accept state is out of range. Fix: keep accept states below state_count.",
                ));
            }
            accepts[state] = true;
        }
        let transitions = common::u32_words(&bytes[transition_start..], "scan_dfa")?;
        Ok(Self {
            start,
            accepts,
            transitions,
        })
    }

    fn step(&self, state: usize, byte: u8) -> Result<usize, common::EvalError> {
        let offset = state * 256 + usize::from(byte);
        let next = self.transitions[offset] as usize;
        if next >= self.accepts.len() {
            Err(common::EvalError::new(
                "primitive `scan_dfa` transition targets an out-of-range state. Fix: validate every transition target.",
            ))
        } else {
            Ok(next)
        }
    }
}

fn read_u32_at(bytes: &[u8], offset: usize) -> Result<u32, common::EvalError> {
    if offset + 4 > bytes.len() {
        return Err(common::EvalError::new(
            "primitive `scan_dfa` truncated u32 field. Fix: encode all header fields.",
        ));
    }
    Ok(u32::from_le_bytes([
        bytes[offset],
        bytes[offset + 1],
        bytes[offset + 2],
        bytes[offset + 3],
    ]))
}

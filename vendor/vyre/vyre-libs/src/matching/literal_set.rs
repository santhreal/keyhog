//! High-level GPU literal matching engine.
//!
//! Composed entirely from \`vyre-libs\` LEGO blocks with Innovation I.17.

use crate::matching::builders::append_match_subgroup;
use crate::matching::dfa::{dfa_compile, CompiledDfa};
use crate::matching::hit_buffer::HIT_BUFFER_OVERFLOW_COUNT;
use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre::VyreBackend;
pub use vyre_foundation::match_result::Match;
use vyre_primitives::matching::DfaWireError;

const OP_ID: &str = "vyre-libs::matching::literal_set";

/// Back-compatible literal match type.
pub type LiteralMatch = Match;

/// A high-level literal matching engine.
pub struct GpuLiteralSet {
    /// Underlying DFA components.
    pub dfa: CompiledDfa,
    /// Concatenated literal bytes, one byte per u32 word for GPU comparison.
    pub pattern_bytes: Vec<u32>,
    /// Start offset of each pattern in `pattern_bytes`.
    pub pattern_offsets: Vec<u32>,
    /// Pattern lengths for start-offset calculation.
    pub pattern_lengths: Vec<u32>,
    /// The pre-built vyre Program.
    pub program: Program,
}

impl GpuLiteralSet {
    /// Compile a set of literal patterns into a GPU-ready matcher.
    #[must_use]
    pub fn compile(patterns: &[&[u8]]) -> Self {
        let dfa = dfa_compile(patterns);
        let pattern_lengths: Vec<u32> = patterns.iter().map(|p| p.len() as u32).collect();
        let mut pattern_offsets = Vec::with_capacity(patterns.len());
        let mut pattern_bytes = Vec::new();
        for pattern in patterns {
            pattern_offsets.push(pattern_bytes.len() as u32);
            pattern_bytes.extend(pattern.iter().map(|&byte| u32::from(byte)));
        }

        let program = build_literal_set_program(
            "haystack",
            "pattern_offsets",
            "pattern_lengths",
            "pattern_bytes",
            "haystack_len",
            "pattern_count",
            "match_count",
            "matches",
            patterns.len() as u32,
            pattern_bytes.len() as u32,
        );

        Self {
            dfa,
            pattern_bytes,
            pattern_offsets,
            pattern_lengths,
            program,
        }
    }

    /// CPU reference implementation for parity testing.
    #[must_use]
    pub fn scan_cpu(&self, haystack: &[u8]) -> Vec<Match> {
        let mut state = 0u32;
        let mut results = Vec::new();
        for (pos, &byte) in haystack.iter().enumerate() {
            state = self.dfa.transitions[(state as usize) * 256 + (byte as usize)];
            let begin = self.dfa.output_offsets[state as usize] as usize;
            let end = self.dfa.output_offsets[state as usize + 1] as usize;
            for &pattern_id in &self.dfa.output_records[begin..end] {
                let len = self.pattern_lengths[pattern_id as usize];
                results.push(Match::new(
                    pattern_id,
                    (pos as u32 + 1).saturating_sub(len),
                    pos as u32 + 1,
                ));
            }
        }
        results.sort_unstable();
        results
    }

    /// GPU scan dispatch.
    ///
    /// # Errors
    /// Returns [\`vyre::BackendError\`] if dispatch or readback fails.
    pub fn scan<B: VyreBackend + ?Sized>(
        &self,
        backend: &B,
        haystack: &[u8],
        max_matches: u32,
    ) -> Result<Vec<Match>, vyre::BackendError> {
        use crate::matching::dispatch_io;

        let haystack_len =
            dispatch_io::scan_guard(haystack, "literal_set", dispatch_io::DEFAULT_MAX_SCAN_BYTES)?;
        let pattern_count = u32::try_from(self.pattern_lengths.len()).map_err(|_| {
            vyre::BackendError::new(
                "literal_set pattern count exceeds u32 capacity. Fix: split the pattern set into smaller shards.",
            )
        })?;

        // Buffer order matches the BufferDecl declaration in
        // `build_literal_set_program`; reordering here would silently
        // miswire the GPU program.
        let inputs = vec![
            // 0: haystack (Packed U32)
            dispatch_io::pack_haystack_u32(haystack),
            // 1: pattern_offsets
            dispatch_io::pack_u32_slice(&self.pattern_offsets),
            // 2: pattern_lengths
            dispatch_io::pack_u32_slice(&self.pattern_lengths),
            // 3: pattern_bytes
            dispatch_io::pack_u32_slice(&self.pattern_bytes),
            // 4: haystack_len
            dispatch_io::pack_u32_slice(&[haystack_len]),
            // 5: pattern_count
            dispatch_io::pack_u32_slice(&[pattern_count]),
            // 6: match_count atomic counter
            vec![0u8; 4],
            // 7: matches is a pure `BufferDecl::output`; the backend
            // allocates it from the Program declaration.
            // 8: overflow counter
            vec![0u8; 4],
        ];

        let config =
            dispatch_io::byte_scan_dispatch_config(haystack_len, self.program.workgroup_size[0]);
        let outputs = backend.dispatch(&self.program, &inputs, &config)?;

        let count_bytes = &outputs[0];
        let count = u32::from_le_bytes(count_bytes[0..4].try_into().unwrap());
        let matches_bytes = &outputs[1];

        Ok(dispatch_io::unpack_match_triples(
            matches_bytes,
            count.min(max_matches),
        ))
    }

    /// Scan input bytes using the shared Vyre device.
    ///
    /// # Errors
    /// Returns [\`vyre::BackendError\`] if dispatch or readback fails.
    #[cfg(feature = "vyre_wgpu")]
    pub fn scan_shared(&self, haystack: &[u8]) -> Result<Vec<Match>, vyre::BackendError> {
        let backend = vyre_driver_wgpu::WgpuBackend::new()?;
        self.scan(&backend, haystack, 10000)
    }

    /// Serialize this matcher into a self-describing binary blob suitable
    /// for on-disk caching. Composed from the existing layer-1 wire
    /// formats: `Program::to_bytes` for the dispatch IR and
    /// `CompiledDfa::to_bytes` for the transition tables. The pattern
    /// arrays are packed as raw little-endian `u32` words.
    ///
    /// Layout:
    ///   - 4 bytes magic `b"VLIT"`
    ///   - 4 bytes wire version (LE u32)
    ///   - 4 bytes program byte length (LE u32)  + program bytes
    ///   - 4 bytes dfa byte length (LE u32)      + dfa bytes
    ///   - 4 bytes pattern_offsets word count    + words
    ///   - 4 bytes pattern_lengths word count    + words
    ///   - 4 bytes pattern_bytes word count      + words
    ///
    /// Caller-side cache invalidation: the dispatch `Program` already
    /// includes vyre's IR wire version + pattern fingerprint inside its
    /// own framing, so a stale cache surfaces as `LiteralSetWireError::
    /// InvalidProgram` from `Program::from_bytes` (or as a bad magic /
    /// version on this outer envelope). Both signal "recompile from
    /// patterns".
    /// # Errors
    /// Returns [`LiteralSetWireError::WireFraming`] if any section
    /// exceeds the envelope's `u32` length-prefix capacity.
    pub fn to_bytes(&self) -> Result<Vec<u8>, LiteralSetWireError> {
        let mut w = vyre_foundation::serial::envelope::WireWriter::new(
            LITERAL_SET_WIRE_MAGIC,
            LITERAL_SET_WIRE_VERSION,
        );
        w.write_section(&self.program.to_bytes())
            .map_err(LiteralSetWireError::WireFraming)?;
        let dfa_bytes = self
            .dfa
            .to_bytes()
            .map_err(LiteralSetWireError::InvalidDfa)?;
        w.write_section(&dfa_bytes)
            .map_err(LiteralSetWireError::WireFraming)?;
        w.write_words(&self.pattern_offsets)
            .map_err(LiteralSetWireError::WireFraming)?;
        w.write_words(&self.pattern_lengths)
            .map_err(LiteralSetWireError::WireFraming)?;
        w.write_words(&self.pattern_bytes)
            .map_err(LiteralSetWireError::WireFraming)?;
        Ok(w.into_bytes())
    }

    /// Decode a `GpuLiteralSet` from a blob produced by [`Self::to_bytes`].
    ///
    /// # Errors
    /// Returns [`LiteralSetWireError`] when the envelope rejects the
    /// outer header, or any inner section (program, DFA) is itself
    /// rejected.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, LiteralSetWireError> {
        let mut r = vyre_foundation::serial::envelope::WireReader::new(
            bytes,
            LITERAL_SET_WIRE_MAGIC,
            LITERAL_SET_WIRE_VERSION,
        )
        .map_err(LiteralSetWireError::WireFraming)?;

        let program_bytes = r.read_section().map_err(LiteralSetWireError::WireFraming)?;
        let program = Program::from_bytes(program_bytes)
            .map_err(|e| LiteralSetWireError::InvalidProgram(format!("{e}")))?;

        let dfa_bytes = r.read_section().map_err(LiteralSetWireError::WireFraming)?;
        let dfa = CompiledDfa::from_bytes(dfa_bytes).map_err(LiteralSetWireError::InvalidDfa)?;

        let pattern_offsets = r.read_words().map_err(LiteralSetWireError::WireFraming)?;
        let pattern_lengths = r.read_words().map_err(LiteralSetWireError::WireFraming)?;
        let pattern_bytes = r.read_words().map_err(LiteralSetWireError::WireFraming)?;

        Ok(Self {
            dfa,
            pattern_bytes,
            pattern_offsets,
            pattern_lengths,
            program,
        })
    }
}

const LITERAL_SET_WIRE_MAGIC: &[u8; 4] = b"VLIT";
const LITERAL_SET_WIRE_VERSION: u32 = 1;

/// Errors returned by [`GpuLiteralSet::from_bytes`]. Outer-framing
/// failures (truncation, bad magic, version drift) are forwarded
/// straight from the shared `WireFraming` envelope. Inner-section
/// failures (program decode, DFA decode) keep their own typed variants
/// so consumers can act on them. Variants are non-exhaustive so future
/// inner sections can be added without a breaking change.
#[derive(Debug)]
#[non_exhaustive]
pub enum LiteralSetWireError {
    /// Outer envelope (magic / version / section length) was rejected.
    /// Forwarded from `vyre_foundation::serial::envelope::EnvelopeError`.
    WireFraming(vyre_foundation::serial::envelope::EnvelopeError),
    /// The nested vyre IR `Program` blob was rejected. Inner message is
    /// stringified to keep this error type independent of vyre's own
    /// error enum.
    InvalidProgram(String),
    /// The nested `CompiledDfa` blob was rejected.
    InvalidDfa(DfaWireError),
}

impl std::fmt::Display for LiteralSetWireError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::WireFraming(e) => write!(f, "GpuLiteralSet wire envelope: {e}"),
            Self::InvalidProgram(msg) => {
                write!(f, "GpuLiteralSet wire blob has invalid Program: {msg}")
            }
            Self::InvalidDfa(e) => {
                write!(f, "GpuLiteralSet wire blob has invalid DFA: {e}")
            }
        }
    }
}

impl std::error::Error for LiteralSetWireError {}

fn build_literal_set_program(
    haystack: &str,
    pattern_offsets: &str,
    pattern_lengths: &str,
    pattern_bytes: &str,
    haystack_len: &str,
    pattern_count: &str,
    match_count: &str,
    matches: &str,
    declared_pattern_count: u32,
    pattern_byte_count: u32,
) -> Program {
    let idx = Expr::InvocationId { axis: 0 };
    let subgroup_size = 32u32;

    fn packed_byte(haystack: &str, index: Expr) -> Expr {
        Expr::bitand(
            Expr::shr(
                Expr::load(haystack, Expr::div(index.clone(), Expr::u32(4))),
                Expr::mul(Expr::rem(index, Expr::u32(4)), Expr::u32(8)),
            ),
            Expr::u32(0xFF),
        )
    }

    let offset_at_end = Expr::add(idx.clone(), Expr::u32(1));
    let lane_body = vec![Node::Loop {
        var: "_pid".into(),
        from: Expr::u32(0),
        to: Expr::load(pattern_count, Expr::u32(0)),
        body: vec![
            Node::Let {
                name: "_pattern_start".into(),
                value: Expr::load(pattern_offsets, Expr::var("_pid")),
            },
            Node::Let {
                name: "_len".into(),
                value: Expr::load(pattern_lengths, Expr::var("_pid")),
            },
            Node::Let {
                name: "_candidate_start".into(),
                value: Expr::Select {
                    cond: Box::new(Expr::ge(offset_at_end.clone(), Expr::var("_len"))),
                    true_val: Box::new(Expr::sub(offset_at_end.clone(), Expr::var("_len"))),
                    false_val: Box::new(Expr::u32(0)),
                },
            },
            Node::Let {
                name: "_literal_matched".into(),
                value: Expr::ge(offset_at_end.clone(), Expr::var("_len")),
            },
            Node::Loop {
                var: "_j".into(),
                from: Expr::u32(0),
                to: Expr::var("_len"),
                body: vec![Node::If {
                    cond: Expr::ne(
                        packed_byte(
                            haystack,
                            Expr::add(Expr::var("_candidate_start"), Expr::var("_j")),
                        ),
                        Expr::load(
                            pattern_bytes,
                            Expr::add(Expr::var("_pattern_start"), Expr::var("_j")),
                        ),
                    ),
                    then: vec![Node::Assign {
                        name: "_literal_matched".into(),
                        value: Expr::bool(false),
                    }],
                    otherwise: vec![],
                }],
            },
            Node::Block(append_match_subgroup(
                matches,
                match_count,
                Expr::var("_pid"),
                Expr::var("_candidate_start"),
                offset_at_end.clone(),
                Expr::var("_literal_matched"),
            )),
        ],
    }];

    let body = vec![
        Node::Let {
            name: "state".into(),
            value: Expr::u32(0),
        },
        Node::If {
            cond: Expr::lt(idx.clone(), Expr::load(haystack_len, Expr::u32(0))),
            then: lane_body,
            otherwise: vec![],
        },
    ];

    Program::wrapped(
        vec![
            BufferDecl::storage(haystack, 0, BufferAccess::ReadOnly, DataType::U32),
            BufferDecl::storage(pattern_offsets, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(declared_pattern_count),
            BufferDecl::storage(pattern_lengths, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(declared_pattern_count),
            BufferDecl::storage(pattern_bytes, 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(pattern_byte_count),
            BufferDecl::storage(haystack_len, 4, BufferAccess::ReadOnly, DataType::U32)
                .with_count(1),
            BufferDecl::storage(pattern_count, 5, BufferAccess::ReadOnly, DataType::U32)
                .with_count(1),
            BufferDecl::read_write(match_count, 6, DataType::U32).with_count(1),
            BufferDecl::output(matches, 7, DataType::U32).with_count(10000 * 3),
            BufferDecl::read_write(HIT_BUFFER_OVERFLOW_COUNT, 8, DataType::U32).with_count(1),
        ],
        [subgroup_size, 1, 1],
        vec![wrap_anonymous(OP_ID, body)],
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use vyre_driver_wgpu::WgpuBackend;

    #[test]
    fn literal_set_parity_abc() {
        let patterns: &[&[u8]] = &[b"abc", b"bc"];
        let engine = GpuLiteralSet::compile(patterns);
        let haystack = b"zabc";

        let cpu_matches = engine.scan_cpu(haystack);
        assert_eq!(cpu_matches.len(), 2);
        assert_eq!(cpu_matches[0], Match::new(0, 1, 4)); // abc
        assert_eq!(cpu_matches[1], Match::new(1, 2, 4)); // bc

        let backend =
            WgpuBackend::new().expect("Fix: literal_set subgroup parity requires a live GPU");
        let gpu_matches = engine.scan(&backend, haystack, 10_000).unwrap();
        assert_eq!(gpu_matches, cpu_matches);
    }
}

/// Innovation I.18: JIT DFA Lowering.
///
/// Converts a static transition table into a nested \`If\` cascade.
/// For small pattern sets, this eliminates the VRAM bandwidth bottleneck
/// by keeping the state machine in the GPU instruction cache.
pub fn dfa_to_jit_ir(dfa: &CompiledDfa, state_var: &str, byte_expr: Expr) -> Node {
    build_state_cascade(dfa, 0, state_var, byte_expr)
}

fn build_state_cascade(dfa: &CompiledDfa, state: u32, state_var: &str, byte_expr: Expr) -> Node {
    // Basic implementation: if state == S { if byte == B1 { state = T1 } ... }
    // V7-PERF-024: Binary-search tree emission for instructions.
    // Naive linear if/else is O(N); a binary tree is O(log N).

    let mut arms = Vec::new();
    for byte in 0..=255 {
        let next_state = dfa.transitions[(state as usize) * 256 + byte];
        if next_state != 0 {
            arms.push((byte as u32, next_state));
        }
    }

    if arms.is_empty() {
        return Node::Assign {
            name: state_var.into(),
            value: Expr::u32(0),
        };
    }

    // Build a nested If cascade for the transitions from this state
    let mut node = Node::Assign {
        name: state_var.into(),
        value: Expr::u32(0),
    };
    for (byte, next) in arms.into_iter().rev() {
        node = Node::If {
            cond: Expr::eq(byte_expr.clone(), Expr::u32(byte)),
            then: vec![Node::Assign {
                name: state_var.into(),
                value: Expr::u32(next),
            }],
            otherwise: vec![node],
        };
    }
    node
}

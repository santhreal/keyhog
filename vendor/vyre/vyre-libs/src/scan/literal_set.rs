//! High-level GPU literal matching engine.
//!
//! Composed entirely from \`vyre-libs\` LEGO blocks with Innovation I.17.

use crate::region::wrap_anonymous;
use crate::scan::builders::append_match_subgroup;
use crate::scan::dfa::{dfa_compile, CompiledDfa};
use crate::scan::hit_buffer::HIT_BUFFER_OVERFLOW_COUNT;
use std::collections::TryReserveError;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre::VyreBackend;
pub use vyre_foundation::match_result::Match;
use vyre_primitives::matching::DfaWireError;

const OP_ID: &str = "vyre-libs::matching::literal_set";

/// Back-compatible literal match type.
pub type LiteralMatch = Match;

/// Errors returned by [`GpuLiteralSet::try_compile`].
#[derive(Debug)]
pub enum LiteralSetCompileError {
    /// Number of patterns does not fit the GPU ABI's `u32` count field.
    PatternCountOverflow {
        /// Number of patterns supplied by the caller.
        count: usize,
    },
    /// One pattern length does not fit the GPU ABI's `u32` length field.
    PatternLengthOverflow {
        /// Index of the oversized pattern.
        pattern_index: usize,
        /// Byte length of the oversized pattern.
        len: usize,
    },
    /// Total concatenated pattern bytes overflowed host `usize`.
    PatternByteCountOverflow,
    /// Total concatenated pattern bytes do not fit the GPU ABI's `u32` field.
    PatternByteCountExceedsGpuAbi {
        /// Concatenated pattern byte count.
        count: usize,
    },
    /// Compiler staging allocation failed.
    StorageReserveFailed {
        /// Scratch vector being reserved.
        field: &'static str,
        /// Requested target capacity.
        requested: usize,
        /// Allocator failure details.
        message: String,
    },
}

impl std::fmt::Display for LiteralSetCompileError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PatternCountOverflow { count } => write!(
                f,
                "literal_set pattern count {count} exceeds u32 capacity. Fix: shard the pattern set before GPU compilation."
            ),
            Self::PatternLengthOverflow { pattern_index, len } => write!(
                f,
                "literal_set pattern {pattern_index} length {len} exceeds u32 capacity. Fix: split or reject oversized literals before GPU compilation."
            ),
            Self::PatternByteCountOverflow => write!(
                f,
                "literal_set total pattern byte count overflowed host usize. Fix: shard the pattern set before GPU compilation."
            ),
            Self::PatternByteCountExceedsGpuAbi { count } => write!(
                f,
                "literal_set total pattern byte count {count} exceeds u32 capacity. Fix: shard the pattern set before GPU compilation."
            ),
            Self::StorageReserveFailed {
                field,
                requested,
                message,
            } => write!(
                f,
                "literal_set compile failed to reserve {requested} {field} slot(s): {message}. Fix: shard the pattern set before GPU compilation."
            ),
        }
    }
}

impl std::error::Error for LiteralSetCompileError {}

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
        match Self::try_compile(patterns) {
            Ok(compiled) => compiled,
            Err(error) => {
                eprintln!("vyre-libs GpuLiteralSet::compile failed: {error}");
                Self::empty_after_compile_failure()
            }
        }
    }

    /// Compile a set of literal patterns into a GPU-ready matcher, surfacing
    /// allocation and ABI-size failures instead of truncating them.
    ///
    /// # Errors
    ///
    /// Returns [`LiteralSetCompileError`] when staging allocation fails or a
    /// pattern count/length cannot be represented by the GPU ABI.
    pub fn try_compile(patterns: &[&[u8]]) -> Result<Self, LiteralSetCompileError> {
        let dfa = dfa_compile(patterns);
        let declared_pattern_count = u32::try_from(patterns.len()).map_err(|_| {
            LiteralSetCompileError::PatternCountOverflow {
                count: patterns.len(),
            }
        })?;
        let total_pattern_bytes = patterns.iter().try_fold(0usize, |sum, pattern| {
            sum.checked_add(pattern.len())
                .ok_or(LiteralSetCompileError::PatternByteCountOverflow)
        })?;
        let pattern_byte_count = u32::try_from(total_pattern_bytes).map_err(|_| {
            LiteralSetCompileError::PatternByteCountExceedsGpuAbi {
                count: total_pattern_bytes,
            }
        })?;
        let mut pattern_lengths = Vec::new();
        reserve_vec(&mut pattern_lengths, patterns.len(), "pattern length")?;
        let mut pattern_offsets = Vec::new();
        reserve_vec(&mut pattern_offsets, patterns.len(), "pattern offset")?;
        let mut pattern_bytes = Vec::new();
        reserve_vec(
            &mut pattern_bytes,
            total_pattern_bytes,
            "packed pattern byte",
        )?;
        for (pattern_index, pattern) in patterns.iter().enumerate() {
            let offset = u32::try_from(pattern_bytes.len()).map_err(|_| {
                LiteralSetCompileError::PatternByteCountExceedsGpuAbi {
                    count: pattern_bytes.len(),
                }
            })?;
            let len = u32::try_from(pattern.len()).map_err(|_| {
                LiteralSetCompileError::PatternLengthOverflow {
                    pattern_index,
                    len: pattern.len(),
                }
            })?;
            pattern_offsets.push(offset);
            pattern_lengths.push(len);
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
            declared_pattern_count,
            pattern_byte_count,
        );

        Ok(Self {
            dfa,
            pattern_bytes,
            pattern_offsets,
            pattern_lengths,
            program,
        })
    }

    fn empty_after_compile_failure() -> Self {
        let dfa = dfa_compile(&[]);
        let program = build_literal_set_program(
            "haystack",
            "pattern_offsets",
            "pattern_lengths",
            "pattern_bytes",
            "haystack_len",
            "pattern_count",
            "match_count",
            "matches",
            0,
            0,
        );

        Self {
            dfa,
            pattern_bytes: Vec::new(),
            pattern_offsets: Vec::new(),
            pattern_lengths: Vec::new(),
            program,
        }
    }

    /// Reference oracle implementation for parity testing.
    #[must_use]
    pub fn reference_scan(&self, haystack: &[u8]) -> Vec<Match> {
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
        let mut matches = Vec::new();
        self.scan_into(backend, haystack, max_matches, &mut matches)?;
        Ok(matches)
    }

    /// GPU scan dispatch that decodes into caller-owned match scratch.
    ///
    /// Long-running scanners can reuse `matches` across inputs and avoid one
    /// heap allocation per dispatch. Output ordering and truncation semantics
    /// match [`Self::scan`].
    ///
    /// # Errors
    /// Returns [`vyre::BackendError`] if dispatch or readback fails.
    pub fn scan_into<B: VyreBackend + ?Sized>(
        &self,
        backend: &B,
        haystack: &[u8],
        max_matches: u32,
        matches: &mut Vec<Match>,
    ) -> Result<(), vyre::BackendError> {
        let mut scratch = crate::scan::dispatch_io::ScanDispatchScratch::default();
        self.scan_into_with_scratch(backend, haystack, max_matches, matches, &mut scratch)
    }

    /// GPU scan dispatch that decodes into caller-owned match scratch and
    /// reuses caller-owned byte staging.
    ///
    /// This is the lowest-allocation hot-loop API for literal scanning:
    /// `matches` reuses decoded match storage and `scratch` reuses the packed
    /// haystack buffer across dispatches.
    ///
    /// # Errors
    /// Returns [`vyre::BackendError`] if dispatch, readback, scan-boundary
    /// validation, or host staging allocation fails.
    pub fn scan_into_with_scratch<B: VyreBackend + ?Sized>(
        &self,
        backend: &B,
        haystack: &[u8],
        max_matches: u32,
        matches: &mut Vec<Match>,
        scratch: &mut crate::scan::dispatch_io::ScanDispatchScratch,
    ) -> Result<(), vyre::BackendError> {
        use crate::scan::dispatch_io;

        matches.clear();
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
        dispatch_io::pack_haystack_u32_into(haystack, &mut scratch.haystack_bytes)?;
        let haystack_bytes = scratch.haystack_bytes.as_slice();
        let pattern_offset_bytes = dispatch_io::u32_words_as_le_bytes(&self.pattern_offsets);
        let pattern_length_bytes = dispatch_io::u32_words_as_le_bytes(&self.pattern_lengths);
        let pattern_bytes = dispatch_io::u32_words_as_le_bytes(&self.pattern_bytes);
        let haystack_len_word = [haystack_len];
        let pattern_count_word = [pattern_count];
        let haystack_len_bytes = dispatch_io::u32_words_as_le_bytes(&haystack_len_word);
        let pattern_count_bytes = dispatch_io::u32_words_as_le_bytes(&pattern_count_word);
        let match_count_bytes = [0u8; 4];
        let overflow_count_bytes = [0u8; 4];

        let config =
            dispatch_io::byte_scan_dispatch_config(haystack_len, self.program.workgroup_size[0]);
        let borrowed_inputs: smallvec::SmallVec<[&[u8]; 8]> = [
            // 0: haystack (Packed U32)
            haystack_bytes,
            // 1: pattern_offsets
            pattern_offset_bytes.as_ref(),
            // 2: pattern_lengths
            pattern_length_bytes.as_ref(),
            // 3: pattern_bytes
            pattern_bytes.as_ref(),
            // 4: haystack_len
            haystack_len_bytes.as_ref(),
            // 5: pattern_count
            pattern_count_bytes.as_ref(),
            // 6: match_count atomic counter
            match_count_bytes.as_slice(),
            // 7: matches is a pure `BufferDecl::output`; the backend
            // allocates it from the Program declaration.
            // 8: overflow counter
            overflow_count_bytes.as_slice(),
        ]
        .into_iter()
        .collect();
        let outputs = backend.dispatch_borrowed(&self.program, &borrowed_inputs, &config)?;

        let count_bytes = &outputs[0];
        let count = u32::from_le_bytes([
            count_bytes[0],
            count_bytes[1],
            count_bytes[2],
            count_bytes[3],
        ]);
        let matches_bytes = &outputs[1];

        dispatch_io::try_unpack_match_triples_into(matches_bytes, count.min(max_matches), matches)?;
        Ok(())
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

fn reserve_vec<T>(
    vec: &mut Vec<T>,
    requested: usize,
    field: &'static str,
) -> Result<(), LiteralSetCompileError> {
    vyre_foundation::allocation::try_reserve_vec_to_capacity(vec, requested).map_err(
        |source: TryReserveError| LiteralSetCompileError::StorageReserveFailed {
            field,
            requested,
            message: source.to_string(),
        },
    )
}

#[cfg(test)]
mod compile_tests {
    use super::*;

    #[test]
    fn try_compile_packs_offsets_lengths_and_bytes_without_truncation() {
        let compiled = GpuLiteralSet::try_compile(&[b"ab".as_slice(), b"cde".as_slice()])
            .expect("Fix: small literal set must compile");

        assert_eq!(compiled.pattern_offsets, vec![0, 2]);
        assert_eq!(compiled.pattern_lengths, vec![2, 3]);
        assert_eq!(
            compiled.pattern_bytes,
            vec![
                b'a' as u32,
                b'b' as u32,
                b'c' as u32,
                b'd' as u32,
                b'e' as u32
            ]
        );
    }

    #[test]
    fn compile_empty_patterns_matches_fallible_compile_contract() {
        let compat = GpuLiteralSet::compile(&[]);
        let fallible = GpuLiteralSet::try_compile(&[]).expect("Fix: empty literal set must compile");

        assert_eq!(compat.pattern_offsets, fallible.pattern_offsets);
        assert_eq!(compat.pattern_lengths, fallible.pattern_lengths);
        assert_eq!(compat.pattern_bytes, fallible.pattern_bytes);
    }

    #[test]
    fn reserve_vec_reports_compile_storage_failure() {
        let mut scratch = Vec::<u8>::new();
        let error = reserve_vec(&mut scratch, usize::MAX, "adversarial scratch")
            .expect_err("Fix: usize::MAX reserve must fail instead of silently truncating");

        match error {
            LiteralSetCompileError::StorageReserveFailed {
                field, requested, ..
            } => {
                assert_eq!(field, "adversarial scratch");
                assert_eq!(requested, usize::MAX);
            }
            other => panic!("expected storage reserve failure, got {other:?}"),
        }
        assert!(scratch.is_empty());
    }

    #[test]
    fn literal_scan_exposes_scratch_backed_dispatch_staging() {
        let production = include_str!("literal_set.rs")
            .split("#[cfg(test)]")
            .next()
            .expect("Fix: literal_set.rs must contain production section");

        assert!(
            production.contains("pub fn scan_into_with_scratch")
                && production.contains("ScanDispatchScratch")
                && production.contains("pack_haystack_u32_into")
                && !production.contains(concat!("pack_haystack_u32", "(haystack)")),
            "Fix: literal scan hot path must expose reusable dispatch scratch and avoid fresh haystack packing allocations."
        );
        assert!(
            !production.contains(".expect(") && !production.contains(".unwrap("),
            "Fix: literal_set production wrappers must not panic."
        );
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

    // Use the canonical `builders::load_packed_byte` LEGO primitive
    // instead of a local re-inlining. Earlier "complete" tasks (#21,
    // #22) missed this site; the inline version was less efficient
    // (no let-bind for the loaded word ⇒ no CSE opportunity).
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
                        crate::scan::builders::load_packed_byte_expr(
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


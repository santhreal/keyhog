//! GPU-resident preprocessor pipeline orchestration.
//!
//! Replaces the CPU helpers in `vyre-frontend-c::tu_host` with a chain
//! of GPU dispatches. Host-side responsibilities are limited to:
//!
//! - File I/O initiation (`fs::read`) — the kernel-mode VFS work that
//!   has no GPU equivalent.
//! - Recursive include scheduling — graph-traversal state-management
//!   over file paths.
//! - Macro / conditional-frame state held between dispatches in plain
//!   Rust data structures.
//!
//! All actual byte-level / token-level / expression-level computation
//! runs on GPU via the kernels in
//! `vyre_libs::parsing::c::preprocess::*`.
//!
//! ## Phase split (this module ships in chunks)
//!
//! - **18a (this commit):** `gpu_filter_source_bytes` — runs
//!   `line_splice_classify` + `comment_strip_mask` + element-wise AND
//!   + prefix-scan + scatter-compact to produce the post-phase-2,
//!   comment-free byte stream that the lexer consumes. Foundational
//!   brick that every later stage builds on.
//! - **18b:** Lex + directive-classify + ifdef/if value evaluation
//!   batch.
//! - **18c:** `#define` / `#include` row parsing + macro-table
//!   maintenance.
//! - **18d:** Recursive include graph driver + macro expansion.
//! - **18e (after all of the above is green):** delete the CPU
//!   preprocessor helpers (`tu_host/preprocess.rs`).

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre::{DispatchConfig, VyreBackend};

use crate::parsing::c::lex::lexer::c11_lexer;
use crate::parsing::c::preprocess::gpu_comment_strip_mask::gpu_comment_strip_mask;
use crate::parsing::c::preprocess::gpu_define_parse::gpu_define_parse;
use crate::parsing::c::preprocess::gpu_directive_metadata::gpu_directive_metadata;
use crate::parsing::c::preprocess::gpu_if_expression::gpu_if_expression;
use crate::parsing::c::preprocess::gpu_ifdef_value::gpu_ifdef_value;
use crate::parsing::c::preprocess::gpu_include_parse::gpu_include_parse;
use crate::parsing::c::preprocess::gpu_undef_parse::gpu_undef_parse;
use vyre::execution_plan::fusion::fuse_programs;
// use vyre_primitives::math::prefix_scan::{prefix_scan, ScanKind};
// ROADMAP: prefix_scan integration for multi-pass conditional nesting depth.
// Currently unused but reserved for future conditional-stack depth analysis.
use vyre_primitives::parsing::line_splice_classify::line_splice_classify;

/// Dispatcher abstraction: anything that can take a `Program` and
/// input buffers and return output buffers. Lets the orchestrator be
/// driven by either a real `VyreBackend` (production) or a closure
/// over `vyre_reference::reference_eval` (tests). The closure form
/// matters because `VyreBackend` is sealed — third-party impls aren't
/// allowed — and because the reference path needs none of the GPU
/// driver's transitive dependencies.
pub trait GpuDispatcher {
    /// Run `program` with `inputs`; return one `Vec<u8>` per output buffer.
    fn dispatch(&self, program: &Program, inputs: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String>;
}

/// Adapter so any `&dyn VyreBackend` plugs into the orchestrator
/// without callers wrapping it manually.
pub struct BackendDispatcher<'a>(pub &'a dyn VyreBackend);

impl GpuDispatcher for BackendDispatcher<'_> {
    fn dispatch(&self, program: &Program, inputs: &[Vec<u8>]) -> Result<Vec<Vec<u8>>, String> {
        self.0
            .dispatch(program, inputs, &DispatchConfig::default())
            .map_err(|e| format!("backend dispatch: {e}"))
    }
}

/// Output of the byte-filter stage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FilteredBytes {
    /// The post-phase-2, comment-free byte stream ready to feed the
    /// lexer. Length is the number of survivor bytes, not the input
    /// length.
    pub bytes: Vec<u8>,
}

/// Run the GPU byte-filter pipeline (line splice + comment strip)
/// over `raw` source bytes via the given dispatcher.
///
/// Dispatches:
///   1. `line_splice_classify` → splice-keep mask (1 = keep).
///   2. `gpu_comment_strip_mask` → comment mask (1 = comment).
///   3. `combine_keep_mask` (built inline) → `splice_keep & ~comment`.
///   4. `inclusive_prefix_scan_u32` (built inline) → output offsets.
///   5. `byte_compact` (built inline) → final byte stream.
///
/// Buffers round-trip through host memory between dispatches; a future
/// commit can `fuse_programs` the adjacent stages to avoid the
/// round-trips. All five Programs are valid GPU IR; the dispatcher
/// chooses how to execute them (production: real backend, tests:
/// reference interpreter).
///
/// # Errors
///
/// Returns the dispatcher error verbatim if any stage fails.
pub fn gpu_filter_source_bytes(
    dispatcher: &dyn GpuDispatcher,
    raw: &[u8],
) -> Result<FilteredBytes, String> {
    if raw.is_empty() {
        return Ok(FilteredBytes { bytes: Vec::new() });
    }
    let n = raw.len() as u32;
    let cap = n.max(1) as usize;
    // line_splice_classify, gpu_comment_strip_mask, and the byte-compact
    // program below all declare their byte-storage buffers as packed
    // U32 words (so reference-eval and naga-emitted real GPU agree on
    // word-indexed access). Pad input + output byte buffers up to a
    // multiple of 4 bytes; the kernels do byte extraction inline.
    let byte_buf_pad = (cap.div_ceil(4) * 4).max(4);

    // ---- Stages 1+2+3 fused: line_splice + comment_strip + combine ----
    // line_splice writes `kept_mask_out`, comment_strip writes
    // `comment_mask_out`; combine reads both and writes `final_keep`.
    // Buffer names match across the three kernels so fuse_programs
    // wires the dataflow automatically with barriers between
    // producers and consumer. 3 dispatches → 1.
    let splice_prog = line_splice_classify(n);
    let comment_prog = gpu_comment_strip_mask(n);
    let combine_prog = combine_keep_mask_program(n);
    let filter_fused = fuse_programs(&[splice_prog, comment_prog, combine_prog])
        .map_err(|e| format!("fuse line_splice+comment_strip+combine: {e}"))?;
    let mut splice_input = raw.to_vec();
    splice_input.resize(byte_buf_pad, 0);
    // Buffer order in the fused program: bytes_in (shared input),
    // kept_mask_out (line_splice output, combine input),
    // comment_mask_out (comment_strip output, combine input),
    // final_keep (combine output).
    let filter_inputs = vec![
        splice_input,
        vec![0u8; cap * 4], // kept_mask_out
        vec![0u8; cap * 4], // comment_mask_out
        vec![0u8; cap * 4], // final_keep
    ];
    let filter_out = dispatcher
        .dispatch(&filter_fused, &filter_inputs)
        .map_err(|e| format!("filter pipeline fused: {e}"))?;
    let final_mask_bytes = filter_out
        .into_iter()
        .nth(2)
        .ok_or_else(|| "filter pipeline fused: missing final_keep output".to_string())?;

    // ---- Stage 4: exclusive prefix scan over keep mask (CPU) ----
    //
    // The earlier GPU `prefix_scan` (Hillis-Steele in a single
    // workgroup) hard-rejects `n > 1024` by returning an
    // `invalid_output_program`, which then causes a dispatch
    // input-count mismatch on every real Linux file (post-include-
    // expansion, n is tens to hundreds of KB). The mask is one u32
    // per input byte, so the scan is O(n) trivial work. Doing it on
    // the host costs microseconds for any real source size — far
    // less than even one GPU dispatch's pipeline-create overhead —
    // and removes the 1024-element scaling cliff entirely. The
    // multi-block GPU prefix scan is open work; until it lands the
    // CPU path is the production-correct choice.
    let mask_words: Vec<u32> = final_mask_bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect();
    let mut offsets_words: Vec<u32> = Vec::with_capacity(mask_words.len());
    let mut acc: u32 = 0;
    for m in &mask_words {
        offsets_words.push(acc);
        acc = acc.wrapping_add(*m);
    }
    let mut offsets_bytes: Vec<u8> = Vec::with_capacity(offsets_words.len() * 4);
    for o in &offsets_words {
        offsets_bytes.extend_from_slice(&o.to_le_bytes());
    }
    // Pad up to the storage size byte_compact will see.
    if offsets_bytes.len() < cap * 4 {
        offsets_bytes.resize(cap * 4, 0);
    }

    // ---- Stage 5: scatter-compact bytes by offsets ----
    let compact_prog = byte_compact_program(n);
    // byte_compact dispatches one thread per *output word* (the
    // kernel iterates `w = InvocationId.x` over `0..ceil(n/4)`,
    // unrolling 4 input bytes per thread). compacted_out is sized
    // at `ceil(n/4)` u32 words = `byte_buf_pad` bytes — no over-
    // allocation, and the inferred grid (output_word_count =
    // ceil(n/4)) matches the kernel's logical extent exactly. The
    // host MUST zero-init compacted_out because the kernel
    // accumulates via `atomic_or`.
    let compact_init = vec![0u8; byte_buf_pad];
    let live_init = vec![0u8; 4];
    // bytes_in for byte_compact is also packed U32; pad to multiple
    // of 4 bytes.
    let mut input_padded = raw.to_vec();
    input_padded.resize(byte_buf_pad, 0);
    let compact_out = dispatcher
        .dispatch(
            &compact_prog,
            &[
                input_padded,
                final_mask_bytes,
                offsets_bytes,
                compact_init,
                live_init,
            ],
        )
        .map_err(|e| format!("byte_compact: {e}"))?;
    let mut iter = compact_out.into_iter();
    let mut compacted = iter
        .next()
        .ok_or_else(|| "byte_compact: missing compacted output".to_string())?;
    let live_buf = iter
        .next()
        .ok_or_else(|| "byte_compact: missing live_count output".to_string())?;
    let live = u32::from_le_bytes([live_buf[0], live_buf[1], live_buf[2], live_buf[3]]) as usize;
    compacted.truncate(live.min(compacted.len()));
    Ok(FilteredBytes { bytes: compacted })
}

// ---------- inline helper Programs ----------

/// Element-wise `kept_mask_out & ~comment_mask_out` over u32 buffers.
///
/// Input buffer names match the producing kernels' output names
/// (`kept_mask_out` from `line_splice_classify` and
/// `comment_mask_out` from `gpu_comment_strip_mask`) so that
/// `fuse_programs` can wire the three stages into a single dispatch
/// without renaming. Output is `final_keep`.
fn combine_keep_mask_program(n: u32) -> Program {
    let i = Expr::var("i");
    let body = vec![
        Node::let_bind("i", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(i.clone(), Expr::u32(n)),
            vec![
                Node::let_bind("sk", Expr::load("kept_mask_out", i.clone())),
                Node::let_bind("ck", Expr::load("comment_mask_out", i.clone())),
                Node::let_bind(
                    "out",
                    Expr::select(
                        Expr::and(
                            Expr::eq(Expr::var("sk"), Expr::u32(1)),
                            Expr::eq(Expr::var("ck"), Expr::u32(0)),
                        ),
                        Expr::u32(1),
                        Expr::u32(0),
                    ),
                ),
                Node::store("final_keep", i.clone(), Expr::var("out")),
            ],
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage(
                "kept_mask_out",
                0,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(n.max(1)),
            BufferDecl::storage(
                "comment_mask_out",
                1,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(n.max(1)),
            BufferDecl::storage(
                "final_keep",
                2,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(n.max(1)),
        ],
        [256, 1, 1],
        body,
    )
    .with_entry_op_id("vyre-frontend-c::tu_host::gpu_pipeline::combine_keep_mask")
}

/// Single-thread inclusive prefix scan over a u32 keep-mask. Outputs
/// Per-byte compact: if `mask[i] == 1`, write `bytes_in[i]` to
/// `compacted_out[offsets[i]]`. Last lane writes the survivor count.
///
/// Real-GPU note: both `bytes_in` and `compacted_out` are declared as
/// packed U32 words (see module-level lowering note); each thread
/// reads its source byte by extracting from the containing word, and
/// scatters its byte into the output via `atomic_or` to safely
/// combine concurrent writes from neighboring threads that target the
/// same output u32 word. Output buffer must be zero-initialized by
/// the host so the OR accumulates correctly.
fn byte_compact_program(n: u32) -> Program {
    // One thread per *output word* (not per input byte). Each thread
    // handles up to 4 input bytes at indices [4w, 4w+1, 4w+2, 4w+3],
    // checks each one's mask, and atomic-or's its byte into the
    // packed output word at the prefix-scan offset. The thread that
    // covers the last input byte (`w == (n-1)/4`) computes the live
    // count from its in-window slot.
    //
    // This shape was chosen over the simpler "one thread per input
    // byte" because the dispatcher infers the launch grid from the
    // primary output buffer's `count`. `compacted_out` is naturally
    // sized at `ceil(n/4)` u32 words, so a per-input-byte kernel
    // under-dispatched whenever n > workgroup_size (256 threads ran
    // but the loop indexed 0..n; bytes past 256 were silently
    // skipped, the last-thread `live_count_out` store never fired,
    // and the host saw `live=0`). A per-word kernel makes the kernel's
    // logical extent match the inferred grid exactly with no over-
    // allocation, no DispatchConfig override needed, and no false
    // dependency between primary-output word count and input length.
    let words = n.div_ceil(4).max(1);
    let w = Expr::var("w");
    fn process_byte_arm(k: u32, n: u32) -> Vec<Node> {
        let i = Expr::add(Expr::mul(Expr::var("w"), Expr::u32(4)), Expr::u32(k));
        vec![Node::if_then(
            Expr::lt(i.clone(), Expr::u32(n)),
            vec![
                Node::let_bind(format!("m_{k}"), Expr::load("mask", i.clone())),
                Node::let_bind(format!("off_{k}"), Expr::load("offsets", i.clone())),
                Node::let_bind(
                    format!("in_word_{k}"),
                    Expr::cast(
                        DataType::U32,
                        Expr::load("bytes_in", Expr::div(i.clone(), Expr::u32(4))),
                    ),
                ),
                Node::let_bind(
                    format!("in_byte_{k}"),
                    Expr::bitand(
                        Expr::shr(
                            Expr::var(format!("in_word_{k}")),
                            Expr::mul(Expr::rem(i.clone(), Expr::u32(4)), Expr::u32(8)),
                        ),
                        Expr::u32(0xFF),
                    ),
                ),
                Node::if_then(
                    Expr::eq(Expr::var(format!("m_{k}")), Expr::u32(1)),
                    vec![
                        Node::let_bind(
                            format!("out_word_idx_{k}"),
                            Expr::div(Expr::var(format!("off_{k}")), Expr::u32(4)),
                        ),
                        Node::let_bind(
                            format!("out_shift_{k}"),
                            Expr::mul(
                                Expr::rem(Expr::var(format!("off_{k}")), Expr::u32(4)),
                                Expr::u32(8),
                            ),
                        ),
                        Node::let_bind(
                            format!("shifted_byte_{k}"),
                            Expr::shl(
                                Expr::var(format!("in_byte_{k}")),
                                Expr::var(format!("out_shift_{k}")),
                            ),
                        ),
                        Node::let_bind(
                            format!("_prev_{k}"),
                            Expr::atomic_or(
                                "compacted_out",
                                Expr::var(format!("out_word_idx_{k}")),
                                Expr::var(format!("shifted_byte_{k}")),
                            ),
                        ),
                    ],
                ),
                // The thread covering the last input byte commits the
                // live count: live = offsets[n-1] + mask[n-1] (an
                // exclusive-prefix-sum + the tail mask = total kept).
                Node::if_then(
                    Expr::eq(i.clone(), Expr::u32(n - 1)),
                    vec![Node::store(
                        "live_count_out",
                        Expr::u32(0),
                        Expr::add(
                            Expr::var(format!("off_{k}")),
                            Expr::var(format!("m_{k}")),
                        ),
                    )],
                ),
            ],
        )]
    }
    let body = vec![
        Node::let_bind("w", Expr::InvocationId { axis: 0 }),
        Node::if_then(
            Expr::lt(w.clone(), Expr::u32(words)),
            {
                let mut arms = Vec::new();
                for k in 0..4u32 {
                    arms.extend(process_byte_arm(k, n));
                }
                arms
            },
        ),
    ];
    Program::wrapped(
        vec![
            BufferDecl::storage("bytes_in", 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(words),
            BufferDecl::storage("mask", 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.max(1)),
            BufferDecl::storage("offsets", 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.max(1)),
            BufferDecl::storage(
                "compacted_out",
                3,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(words),
            BufferDecl::storage(
                "live_count_out",
                4,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(1),
        ],
        [256, 1, 1],
        body,
    )
    .with_entry_op_id("vyre-frontend-c::tu_host::gpu_pipeline::byte_compact")
}

// GPU-roundtrip tests live in `tests/gpu_pipeline_filter_roundtrip.rs`
// because they drive the real dispatch backend.

// =================================================================
// Phase 18b: gpu_tokenize_and_classify
// =================================================================

/// Output of the lex+classify stage.
///
/// All four columns are dense (one entry per emitted token, length =
/// `n_tokens`). `directive_kinds[i]` is `0` for any token whose type
/// is not `TOK_PREPROC`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClassifiedTokens {
    /// Token kind id per token (TOK_* constants from `parsing::c::lex::tokens`).
    pub tok_types: Vec<u32>,
    /// Per-token byte offset into the source buffer.
    pub tok_starts: Vec<u32>,
    /// Per-token byte length in the source buffer.
    pub tok_lens: Vec<u32>,
    /// Per-token directive kind (TOK_PP_* constants); `0` for non-PREPROC.
    pub directive_kinds: Vec<u32>,
    /// The source bytes the tokens index into. Held alongside the
    /// columns so downstream stages don't have to re-pass it.
    pub source: Vec<u8>,
}

impl ClassifiedTokens {
    /// Iterate `(index, kind)` over directive rows whose kind is non-zero.
    pub fn directive_rows(&self) -> impl Iterator<Item = (usize, u32)> + '_ {
        self.directive_kinds
            .iter()
            .enumerate()
            .filter_map(|(i, &k)| if k == 0 { None } else { Some((i, k)) })
    }
}

/// Run lex + directive classify on `raw` source bytes.
///
/// Dispatches:
///   1. `c11_lexer` (existing GPU kernel) → `(types, starts, lens, n_tokens)`.
///      One output entry per byte position; first `n_tokens` slots are
///      the dense token list, the remainder are zero-padded.
///   2. `gpu_directive_metadata` (17a) → directive kinds per token.
///
/// `raw` should be the post-byte-filter stream (output of
/// `gpu_filter_source_bytes`), but the function works on any byte
/// slice — no preprocessing is required for the lexer to produce a
/// valid token list.
///
/// # Errors
/// Returns the dispatcher error verbatim if any stage fails.
pub fn gpu_tokenize_and_classify(
    dispatcher: &dyn GpuDispatcher,
    raw: &[u8],
) -> Result<ClassifiedTokens, String> {
    if raw.is_empty() {
        return Ok(ClassifiedTokens {
            tok_types: Vec::new(),
            tok_starts: Vec::new(),
            tok_lens: Vec::new(),
            directive_kinds: Vec::new(),
            source: Vec::new(),
        });
    }
    let n_bytes = raw.len() as u32;

    // ---- Stage 1: lex ----
    // c11_lexer expects `haystack` as one u32 per byte (zero-extended).
    let mut haystack_u32 = Vec::with_capacity(raw.len() * 4);
    for b in raw {
        haystack_u32.extend_from_slice(&u32::from(*b).to_le_bytes());
    }
    let lex_prog = c11_lexer(
        "haystack",
        "out_tok_types",
        "out_tok_starts",
        "out_tok_lens",
        "out_counts",
        n_bytes,
    );
    let lex_inputs = vec![
        haystack_u32,
        vec![0u8; raw.len() * 4],
        vec![0u8; raw.len() * 4],
        vec![0u8; raw.len() * 4],
        vec![0u8; 4],
    ];
    let lex_out = dispatcher
        .dispatch(&lex_prog, &lex_inputs)
        .map_err(|e| format!("c11_lexer: {e}"))?;
    if lex_out.len() < 4 {
        return Err("c11_lexer: expected 4 output buffers".to_string());
    }
    let types_full = unpack_u32_words(&lex_out[0]);
    let starts_full = unpack_u32_words(&lex_out[1]);
    let lens_full = unpack_u32_words(&lex_out[2]);
    let count_buf = &lex_out[3];
    let n_tokens = u32::from_le_bytes([
        count_buf[0],
        count_buf[1],
        count_buf[2],
        count_buf[3],
    ]) as usize;
    let n_tokens = n_tokens.min(types_full.len());
    let tok_types: Vec<u32> = types_full[..n_tokens].to_vec();
    let tok_starts: Vec<u32> = starts_full[..n_tokens].to_vec();
    let tok_lens: Vec<u32> = lens_full[..n_tokens].to_vec();

    // ---- Stage 2: directive classify ----
    if n_tokens == 0 {
        return Ok(ClassifiedTokens {
            tok_types,
            tok_starts,
            tok_lens,
            directive_kinds: Vec::new(),
            source: raw.to_vec(),
        });
    }
    let dm_prog = gpu_directive_metadata(n_tokens as u32, n_bytes);
    let n_pad = n_tokens.max(1);
    // gpu_directive_metadata's `source` buffer is declared as packed
    // U32 words; pad raw bytes up to a multiple of 4.
    let mut raw_padded = raw.to_vec();
    let raw_pad_len = (raw.len().div_ceil(4) * 4).max(4);
    raw_padded.resize(raw_pad_len, 0);
    let dm_inputs = vec![
        pack_u32_words(&tok_types, n_pad),
        pack_u32_words(&tok_starts, n_pad),
        pack_u32_words(&tok_lens, n_pad),
        raw_padded,
        vec![0u8; n_pad * 4],
        vec![0u8; n_pad * 4],
    ];
    let dm_out = dispatcher
        .dispatch(&dm_prog, &dm_inputs)
        .map_err(|e| format!("gpu_directive_metadata: {e}"))?;
    let directive_kinds_full = unpack_u32_words(&dm_out[0]);
    let directive_kinds = directive_kinds_full[..n_tokens].to_vec();

    Ok(ClassifiedTokens {
        tok_types,
        tok_starts,
        tok_lens,
        directive_kinds,
        source: raw.to_vec(),
    })
}

fn unpack_u32_words(bytes: &[u8]) -> Vec<u32> {
    bytes
        .chunks_exact(4)
        .map(|c| u32::from_le_bytes([c[0], c[1], c[2], c[3]]))
        .collect()
}

fn pack_u32_words(words: &[u32], pad_len: usize) -> Vec<u8> {
    let mut out = Vec::with_capacity(pad_len * 4);
    for w in words {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.resize(pad_len * 4, 0);
    out
}

// =================================================================
// Phase 18c: gpu_extract_directive_payloads
// =================================================================

/// Parsed payload for one directive row.
///
/// Indexed by token position in the source-order token stream. Rows
/// whose `directive_kinds[i] == 0` (not a directive) get
/// [`DirectivePayload::None`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DirectivePayload {
    /// Not a directive row.
    None,
    /// `#define name [(args)] body`.
    Define {
        /// Macro name bytes.
        name: Vec<u8>,
        /// Comma-separated args (function-like macros only). Empty for object-like.
        args: Vec<u8>,
        /// Replacement body bytes (trailing whitespace already trimmed).
        body: Vec<u8>,
        /// `true` if the directive used the `name(args)` form.
        is_function_like: bool,
    },
    /// `#undef name`. Currently classified by directive kind only —
    /// the name extraction reuses the define-parse name span shape
    /// (treats `#undef` as `#define`-shaped for the parse).
    Undef {
        /// Macro name to undefine.
        name: Vec<u8>,
    },
    /// `#include <…>` or `#include "…"` (and `#include_next`).
    Include {
        /// The path bytes between the delimiters.
        path: Vec<u8>,
        /// `true` for `<…>`, `false` for `"…"`.
        is_system: bool,
        /// `true` only for `#include_next`.
        is_next: bool,
    },
    /// `#ifdef name` / `#ifndef name`. The kernel's value column gives
    /// 1/0 against the supplied macro table.
    Ifdef {
        /// `1` if `name` is defined, else `0`.
        value: u32,
        /// `true` if the directive was `#ifndef` (value semantics inverted).
        negated: bool,
    },
    /// `#if expr` / `#elif expr`. Value evaluated against the supplied
    /// macro table.
    IfExpr {
        /// The truth value of the expression (1 or 0).
        value: u32,
        /// `true` for `#elif`, `false` for `#if`.
        is_elif: bool,
    },
    /// `#else`. No payload — caller flips the conditional frame.
    Else,
    /// `#endif`. No payload — caller pops the conditional frame.
    Endif,
    /// `#pragma`, `#line`, `#error`, `#warning`, `#ident`, `#sccs`,
    /// `#null` (empty `#`). Carried by kind only; payload is opaque.
    Other,
}

/// Extract per-directive payloads for every directive row in
/// `classified`, against the supplied `defined_macros` snapshot.
///
/// Dispatches each per-directive kernel once over the FULL token
/// stream (every kernel is per-thread parallel internally). Then host
/// walks the directive_kinds column to assemble payloads.
///
/// **Note on macro accuracy:** `#if` / `#ifdef` / `#ifndef` values are
/// evaluated against the SAME `defined_macros` snapshot for every
/// directive row. This is correct when no `#define` row above a `#if`
/// row alters its evaluation. Real C files often have such patterns;
/// the recursive driver in 18d handles this by iterating
/// extract → walk → re-extract until the macro table stabilises.
///
/// # Errors
/// Returns the dispatcher error verbatim if any stage fails.
pub fn gpu_extract_directive_payloads(
    dispatcher: &dyn GpuDispatcher,
    classified: &ClassifiedTokens,
    defined_macros: &[&[u8]],
) -> Result<Vec<DirectivePayload>, String> {
    use crate::parsing::c::lex::tokens::{
        TOK_PP_DEFINE, TOK_PP_ELIF, TOK_PP_ELSE, TOK_PP_ENDIF, TOK_PP_IF, TOK_PP_IFDEF,
        TOK_PP_IFNDEF, TOK_PP_INCLUDE, TOK_PP_INCLUDE_NEXT, TOK_PP_UNDEF,
    };
    let n = classified.tok_types.len();
    if n == 0 {
        return Ok(Vec::new());
    }
    // Fast path: if there are no directive rows at all (no `#define`,
    // `#include`, `#ifdef`, `#if`, etc.), every payload is `None`.
    // Skip the parse-kernel dispatches entirely. For fixtures that
    // arrive at this stage already preprocessor-clean (the common case
    // after the host has expanded includes / inlined defines upstream),
    // this avoids 3 cold native-compiles of the directive parse
    // kernels — each of which is ~MB-scale WGSL and ~20s cold-compile
    // on the wgpu Vulkan path. The kernels still dispatch when
    // directives are present.
    if classified.directive_rows().next().is_none() {
        return Ok(vec![DirectivePayload::None; n]);
    }
    let n_pad = n.max(1);
    let source_len = classified.source.len() as u32;
    let starts_b = pack_u32_words(&classified.tok_starts, n_pad);
    let lens_b = pack_u32_words(&classified.tok_lens, n_pad);
    let kinds_b = pack_u32_words(&classified.directive_kinds, n_pad);
    // gpu_directive_metadata and gpu_include_parse declare `source` as
    // packed U32 words (so reference-eval and naga-emitted real GPU
    // agree on word-indexed access; the kernels do byte extraction in
    // their `load_byte_u32` helpers). Pad source bytes up to a multiple
    // of 4 so the last word is fully covered.
    // Pre-allocate the padded buffer at exact target size so we get
    // one allocation + one memcpy + one zero-fill, rather than
    // clone() (allocates `len` capacity) followed by resize() to a
    // larger size (potentially reallocates, copying the just-cloned
    // bytes a second time). For MB-scale Linux source bytes this
    // avoids one source-sized memcpy per file.
    let padded_src_len = classified.source.len().div_ceil(4) * 4;
    let target = padded_src_len.max(4);
    let mut src_pad = Vec::with_capacity(target);
    src_pad.extend_from_slice(&classified.source);
    src_pad.resize(target, 0);

    // Pack defined_macros into the (names_packed, offsets) layout the
    // ifdef/if-expr kernels expect.
    let mut macro_names: Vec<u8> = Vec::new();
    let mut macro_offsets: Vec<u32> = Vec::with_capacity(defined_macros.len() + 1);
    macro_offsets.push(0);
    for name in defined_macros {
        macro_names.extend_from_slice(name);
        macro_offsets.push(macro_names.len() as u32);
    }
    // gpu_ifdef_value declares macro_names_packed as packed U32 words
    // (matching how `source` is declared, so reference-eval and naga-
    // emitted real GPU agree on word-indexed access). Pad the byte
    // buffer up to a multiple of 4 to fill the last word.
    let macro_names_pad = {
        let mut v = macro_names.clone();
        let padded = macro_names.len().div_ceil(4) * 4;
        v.resize(padded.max(4), 0);
        v
    };
    let macro_offsets_b = pack_u32_words(&macro_offsets, macro_offsets.len());

    // ---- Dispatch 1: define + include + undef parsers fused ----
    // All three kernels share the (tok_starts, tok_lens,
    // directive_kinds, source) inputs and have NO overlapping output
    // buffer names (undef_parse's outputs were renamed to
    // `undef_name_*` so they don't collide with define_parse's
    // `name_*`). Fusing reduces 3 separate dispatches to 1, cutting
    // host-side Vec<u8> round-trips substantially. Buffer order in
    // the fused program is set by `fuse_programs` iteration:
    //   shared:     tok_starts, tok_lens, directive_kinds, source
    //   define out: name_start, name_len, args_start, args_len,
    //               body_start, body_len, is_function_like
    //   include out: path_start, path_len, is_system
    //   undef out:  undef_name_start, undef_name_len
    let dp = gpu_define_parse(n as u32, source_len);
    let ip = gpu_include_parse(n as u32, source_len);
    let up = gpu_undef_parse(n as u32, source_len);
    let parse_fused = fuse_programs(&[dp, ip, up])
        .map_err(|e| format!("fuse define+include+undef parse: {e}"))?;
    let parse_inputs = vec![
        starts_b.clone(),
        lens_b.clone(),
        kinds_b.clone(),
        src_pad.clone(),
        vec![0u8; n_pad * 4], // name_start_out (define)
        vec![0u8; n_pad * 4], // name_len_out (define)
        vec![0u8; n_pad * 4], // args_start_out (define)
        vec![0u8; n_pad * 4], // args_len_out (define)
        vec![0u8; n_pad * 4], // body_start_out (define)
        vec![0u8; n_pad * 4], // body_len_out (define)
        vec![0u8; n_pad * 4], // is_function_like_out (define)
        vec![0u8; n_pad * 4], // path_start_out (include)
        vec![0u8; n_pad * 4], // path_len_out (include)
        vec![0u8; n_pad * 4], // is_system_out (include)
        vec![0u8; n_pad * 4], // undef_name_start_out (undef)
        vec![0u8; n_pad * 4], // undef_name_len_out (undef)
    ];
    let parse_out = dispatcher
        .dispatch(&parse_fused, &parse_inputs)
        .map_err(|e| format!("gpu_define+include+undef_parse fused: {e}"))?;
    let name_s = unpack_u32_words(&parse_out[0]);
    let name_l = unpack_u32_words(&parse_out[1]);
    let args_s = unpack_u32_words(&parse_out[2]);
    let args_l = unpack_u32_words(&parse_out[3]);
    let body_s = unpack_u32_words(&parse_out[4]);
    let body_l = unpack_u32_words(&parse_out[5]);
    let is_func = unpack_u32_words(&parse_out[6]);
    let path_s = unpack_u32_words(&parse_out[7]);
    let path_l = unpack_u32_words(&parse_out[8]);
    let is_system = unpack_u32_words(&parse_out[9]);
    let undef_name_s = unpack_u32_words(&parse_out[10]);
    let undef_name_l = unpack_u32_words(&parse_out[11]);

    // ---- Dispatch 2: gpu_ifdef_value ----
    // Both gpu_ifdef_value and gpu_if_expression are kind-gated to
    // disjoint rows of `directive_values`, so they can be fused safely
    // (verified under reference-eval). Real-GPU cold-pipeline evidence
    // showed the merged shader compiles substantially slower, so the
    // release path keeps them as separate dispatches until compile-cache
    // telemetry proves fusion wins end-to-end.
    let num_macros = defined_macros.len() as u32;
    let macro_names_len = macro_names.len() as u32;
    let iv = gpu_ifdef_value(n as u32, source_len, macro_names_len, num_macros);
    let iv_inputs = vec![
        starts_b.clone(),
        lens_b.clone(),
        kinds_b.clone(),
        src_pad.clone(),
        macro_names_pad.clone(),
        macro_offsets_b.clone(),
        vec![0u8; n_pad * 4],
    ];
    let iv_out = dispatcher
        .dispatch(&iv, &iv_inputs)
        .map_err(|e| format!("gpu_ifdef_value: {e}"))?;
    let ifdef_values = unpack_u32_words(&iv_out[0]);

    // ---- Dispatch 3: gpu_if_expression ----
    // This is the last consumer of `starts_b`, `lens_b`, `kinds_b`,
    // and `src_pad` — move them in instead of cloning. Each is
    // tokens*4 / source*1 bytes respectively, MB-scale on real
    // Linux files. Cloning before the last use was tens-of-MB of
    // wasted memcpy per file.
    let ie = gpu_if_expression(n as u32, source_len, macro_names_len, num_macros);
    let ie_inputs = vec![
        starts_b,
        lens_b,
        kinds_b,
        src_pad,
        macro_names_pad,
        macro_offsets_b,
        vec![0u8; n_pad * 4],
    ];
    let ie_out = dispatcher
        .dispatch(&ie, &ie_inputs)
        .map_err(|e| format!("gpu_if_expression: {e}"))?;
    let if_values = unpack_u32_words(&ie_out[0]);

    // (define + include + undef fused above into one dispatch.
    // Total: 5 dispatches → 3.)

    // ---- Walk and assemble payloads ----
    let mut out = Vec::with_capacity(n);
    for i in 0..n {
        let kind = classified.directive_kinds[i];
        let payload = match kind {
            0 => DirectivePayload::None,
            k if k == TOK_PP_DEFINE => {
                let nb = name_s[i] as usize;
                let nl = name_l[i] as usize;
                let ab = args_s[i] as usize;
                let al = args_l[i] as usize;
                let bb = body_s[i] as usize;
                let bl = body_l[i] as usize;
                DirectivePayload::Define {
                    name: classified.source[nb..nb + nl].to_vec(),
                    args: if al == 0 { Vec::new() } else { classified.source[ab..ab + al].to_vec() },
                    body: if bl == 0 { Vec::new() } else { classified.source[bb..bb + bl].to_vec() },
                    is_function_like: is_func[i] == 1,
                }
            }
            k if k == TOK_PP_UNDEF => {
                // Dedicated `gpu_undef_parse` kernel (5-byte keyword
                // step, single ident scan). Replaces the prior workaround
                // that routed `#undef` through `gpu_define_parse` which
                // bakes in a 6-byte `#define` keyword length.
                let nb = undef_name_s[i] as usize;
                let nl = undef_name_l[i] as usize;
                if nl == 0 || nb + nl > classified.source.len() {
                    DirectivePayload::Undef { name: Vec::new() }
                } else {
                    DirectivePayload::Undef {
                        name: classified.source[nb..nb + nl].to_vec(),
                    }
                }
            }
            k if k == TOK_PP_INCLUDE || k == TOK_PP_INCLUDE_NEXT => {
                let pb = path_s[i] as usize;
                let pl = path_l[i] as usize;
                if pl == 0 {
                    DirectivePayload::Other
                } else {
                    DirectivePayload::Include {
                        path: classified.source[pb..pb + pl].to_vec(),
                        is_system: is_system[i] == 1,
                        is_next: k == TOK_PP_INCLUDE_NEXT,
                    }
                }
            }
            k if k == TOK_PP_IFDEF => DirectivePayload::Ifdef {
                value: ifdef_values[i],
                negated: false,
            },
            k if k == TOK_PP_IFNDEF => DirectivePayload::Ifdef {
                value: ifdef_values[i],
                negated: true,
            },
            k if k == TOK_PP_IF => DirectivePayload::IfExpr {
                value: if_values[i],
                is_elif: false,
            },
            k if k == TOK_PP_ELIF => DirectivePayload::IfExpr {
                value: if_values[i],
                is_elif: true,
            },
            k if k == TOK_PP_ELSE => DirectivePayload::Else,
            k if k == TOK_PP_ENDIF => DirectivePayload::Endif,
            _ => DirectivePayload::Other,
        };
        out.push(payload);
    }
    Ok(out)
}

// =================================================================
// Phase 18d: gpu_preprocess_translation_unit (recursive include driver)
// =================================================================

/// Loader for `#include` resolution. The driver calls this once per
/// `#include` directive with `(path, is_system)` and the path of the
/// file currently being processed; the impl returns the file's raw
/// bytes plus the canonical path of the loaded file (used for recursion
/// scheduling and cycle detection).
///
/// Lives as a trait so the driver itself stays GPU-pure: the CPU
/// kernel-mode VFS work (file open / path resolution) is pushed to the
/// caller. `vyre-frontend-c::tu_host` will provide the production impl
/// that walks `-I` dirs and reads from disk.
pub trait IncludeLoader {
    /// Resolve and load `#include <path>` (system) or `#include "path"`
    /// (local). `from` is the canonical path of the file currently
    /// being preprocessed; the impl uses it as the search base for
    /// local includes.
    ///
    /// Returns `(canonical_path, file_bytes)`. Returns `Ok(None)` only
    /// when the caller's include policy has explicitly classified the
    /// include as non-fatal for this preprocessing run. Returns `Err` for
    /// strict missing-include failures and fatal I/O errors.
    fn load(
        &self,
        path: &[u8],
        is_system: bool,
        from: &std::path::Path,
    ) -> Result<Option<(std::path::PathBuf, Vec<u8>)>, String>;
}

/// Output of the driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PreprocessedSource {
    /// Concatenated active bytes — line-spliced, comment-stripped,
    /// conditional-masked, include-expanded. Macro expansion is
    /// deliberately NOT performed here (mirrors the v0.4
    /// `prepare_resident_translation_unit_source` contract).
    pub bytes: Vec<u8>,
    /// Macros accumulated during the walk (CLI macros + every
    /// `#define` in active branches). Downstream macro-expansion
    /// kernels consume this.
    pub macros: Vec<MacroDef>,
}

/// A `#define`'d macro encountered during preprocessing.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MacroDef {
    /// Macro identifier bytes.
    pub name: Vec<u8>,
    /// Comma-separated argument-list bytes for function-like macros;
    /// empty for object-like.
    pub args: Vec<u8>,
    /// Replacement body bytes.
    pub body: Vec<u8>,
    /// `true` for function-like (`#define M(a) …`).
    pub is_function_like: bool,
}

/// Maximum recursive `#include` depth before the driver bails out.
/// Mirrors the CPU helper's `MAX_INCLUDE_DEPTH`.
pub const MAX_INCLUDE_DEPTH: u32 = 64;

/// Drive the GPU preprocessor over `(tu_path, source)`, recursively
/// expanding `#include` directives via `loader`.
///
/// Stages per file:
///   1. `gpu_filter_source_bytes` — line splice + comment strip.
///   2. `gpu_tokenize_and_classify` — lex + directive classify.
///   3. `gpu_extract_directive_payloads` — per-directive parse against
///      the current macro table snapshot.
///   4. Host walk: thread a conditional-frame stack, copy active code
///      bytes to the output, accumulate `#define`s, recurse on active
///      `#include`s.
///
/// Live macro semantics:
///   - `#if` / `#ifdef` / `#ifndef` rows are re-evaluated during the
///     host walk against the current macro table, so an earlier active
///     `#define` in the same file affects later conditionals.
///   - `#undef` rows remove matching macros from the live table before
///     subsequent conditionals and includes are processed.
///
/// # Errors
///
/// Returns `Err` on dispatcher failure, depth-exceeded, or loader I/O
/// failure. Loader-returned `Ok(None)` is treated as an explicit
/// non-fatal include-policy decision by the caller.
pub fn gpu_preprocess_translation_unit(
    dispatcher: &dyn GpuDispatcher,
    loader: &dyn IncludeLoader,
    tu_path: &std::path::Path,
    source: &[u8],
    cli_macros: &[MacroDef],
) -> Result<PreprocessedSource, String> {
    let mut macros = cli_macros.to_vec();
    let mut output = Vec::new();
    let mut stack: Vec<std::path::PathBuf> = Vec::new();
    preprocess_one_file(
        dispatcher,
        loader,
        tu_path,
        source,
        &mut macros,
        &mut output,
        &mut stack,
        0,
    )?;
    Ok(PreprocessedSource {
        bytes: output,
        macros,
    })
}

#[derive(Debug, Clone, Copy)]
struct ConditionalFrame {
    /// `true` if the parent stack frame was active at the time this
    /// frame was pushed.
    parent_active: bool,
    /// `true` if any branch in this `#if/#elif/#else` chain has been
    /// taken. Suppresses subsequent `#elif`/`#else` from activating.
    branch_taken: bool,
    /// Computed: `parent_active && current_branch_truth`.
    current_active: bool,
}

#[allow(clippy::too_many_arguments)]
fn preprocess_one_file(
    dispatcher: &dyn GpuDispatcher,
    loader: &dyn IncludeLoader,
    file_path: &std::path::Path,
    source: &[u8],
    macros: &mut Vec<MacroDef>,
    output: &mut Vec<u8>,
    stack: &mut Vec<std::path::PathBuf>,
    depth: u32,
) -> Result<(), String> {
    if depth > MAX_INCLUDE_DEPTH {
        return Err(format!(
            "vyre-libs::gpu_pipeline: include depth exceeded {MAX_INCLUDE_DEPTH}"
        ));
    }
    // Stage 1: filter (line splice + comment strip).
    let filtered = gpu_filter_source_bytes(dispatcher, source)?;
    // Stage 2: lex + classify.
    let classified = gpu_tokenize_and_classify(dispatcher, &filtered.bytes)?;
    // Stage 3: extract directive payloads against the current macro snapshot.
    let macro_refs: Vec<&[u8]> = macros.iter().map(|m| m.name.as_slice()).collect();
    let payloads =
        gpu_extract_directive_payloads(dispatcher, &classified, &macro_refs)?;
    // Stage 4: host walk.
    //
    // Whitespace preservation: the GPU tokenizer emits one row per
    // *token* and the per-row byte range covers only the token bytes,
    // not the inter-token whitespace. Copying token bytes alone
    // produced a whitespace-stripped output ("int main(void)" →
    // "intmain(void)"), which the downstream `c11_lexer` then
    // re-tokenized as a single concatenated identifier. The fix is to
    // also copy the inter-token byte run BEFORE each non-directive
    // token: that's the original source's whitespace (and any other
    // bytes that the tokenizer didn't classify as part of a token).
    // For directive rows the inter-token bytes BEFORE the directive
    // are part of the directive's line — strip them with the directive.
    // Track `last_emit_end` (an index into `classified.source`) as the
    // upper-bound of the last emitted byte range. After a directive
    // line we advance `last_emit_end` to the directive token's end so
    // the leading whitespace of the directive line is also dropped.
    let mut conditionals: Vec<ConditionalFrame> = Vec::new();
    let active = |conds: &[ConditionalFrame]| {
        conds.last().map(|f| f.current_active).unwrap_or(true)
    };
    let mut last_emit_end: usize = 0;
    for (i, payload) in payloads.iter().enumerate() {
        let row_active = active(&conditionals);
        let tok_start = classified.tok_starts[i] as usize;
        let tok_len = classified.tok_lens[i] as usize;
        let tok_end = tok_start + tok_len;
        match payload {
            DirectivePayload::None => {
                // Non-directive token: copy inter-token bytes
                // (whitespace) since the last emit, then the token
                // bytes themselves. Together this preserves the
                // original source verbatim except for stripped
                // directive lines.
                if row_active {
                    if tok_start > last_emit_end {
                        output.extend_from_slice(
                            &classified.source[last_emit_end..tok_start],
                        );
                    }
                    output.extend_from_slice(&classified.source[tok_start..tok_end]);
                    last_emit_end = tok_end;
                }
            }
            DirectivePayload::Define { name, args, body, is_function_like } => {
                if row_active {
                    macros.push(MacroDef {
                        name: name.clone(),
                        args: args.clone(),
                        body: body.clone(),
                        is_function_like: *is_function_like,
                    });
                }
                // Skip the entire directive line in the byte-emit
                // stream: advance last_emit_end past this row's bytes
                // so the next non-directive token doesn't pick up the
                // directive's leading whitespace as inter-token bytes.
                last_emit_end = tok_end;
            }
            DirectivePayload::Undef { name } => {
                if row_active && !name.is_empty() {
                    macros.retain(|m| m.name.as_slice() != name.as_slice());
                }
                last_emit_end = tok_end;
            }
            DirectivePayload::Include { path, is_system, .. } => {
                if row_active {
                    if let Some((canon, bytes)) = loader.load(path, *is_system, file_path)?
                    {
                        // Cycle guard.
                        if !stack.contains(&canon) {
                            stack.push(canon.clone());
                            let res = preprocess_one_file(
                                dispatcher,
                                loader,
                                &canon,
                                &bytes,
                                macros,
                                output,
                                stack,
                                depth + 1,
                            );
                            stack.pop();
                            res?;
                        }
                    }
                }
                last_emit_end = tok_end;
            }
            DirectivePayload::Ifdef { value: _, negated } => {
                // Re-evaluate against the LIVE macro table here on the
                // host. The kernel's `value` was computed against the
                // macro snapshot at `gpu_extract_directive_payloads`
                // time, which doesn't see `#define` rows that appear
                // earlier in the same file (they're applied during the
                // walk below). Real Linux headers depend on this.
                let s = classified.tok_starts[i] as usize;
                let l = classified.tok_lens[i] as usize;
                let row_bytes = &classified.source[s..s + l];
                let truth = recompute_ifdef_truth(row_bytes, *negated, macros);
                let parent = row_active;
                conditionals.push(ConditionalFrame {
                    parent_active: parent,
                    branch_taken: truth,
                    current_active: parent && truth,
                });
                last_emit_end = tok_end;
            }
            DirectivePayload::IfExpr { value: _, is_elif } => {
                let s = classified.tok_starts[i] as usize;
                let l = classified.tok_lens[i] as usize;
                let row_bytes = &classified.source[s..s + l];
                let truth = recompute_if_expr_truth(row_bytes, macros);
                if *is_elif {
                    if let Some(frame) = conditionals.last_mut() {
                        let take = !frame.branch_taken && truth;
                        frame.current_active = frame.parent_active && take;
                        frame.branch_taken |= take;
                    }
                } else {
                    let parent = row_active;
                    conditionals.push(ConditionalFrame {
                        parent_active: parent,
                        branch_taken: truth,
                        current_active: parent && truth,
                    });
                }
                last_emit_end = tok_end;
            }
            DirectivePayload::Else => {
                if let Some(frame) = conditionals.last_mut() {
                    let take = !frame.branch_taken;
                    frame.current_active = frame.parent_active && take;
                    frame.branch_taken = true;
                }
                last_emit_end = tok_end;
            }
            DirectivePayload::Endif => {
                conditionals.pop();
                last_emit_end = tok_end;
            }
            DirectivePayload::Other => {
                // #pragma / #line / #error / #warning / #ident / #sccs /
                // empty `#`. Pass through to output if active. Match
                // the non-directive branch's whitespace-preserving
                // copy (inter-token bytes + token bytes), so a
                // `#pragma` line doesn't fuse with the surrounding
                // tokens.
                if row_active {
                    if tok_start > last_emit_end {
                        output.extend_from_slice(
                            &classified.source[last_emit_end..tok_start],
                        );
                    }
                    output.extend_from_slice(&classified.source[tok_start..tok_end]);
                    last_emit_end = tok_end;
                } else {
                    last_emit_end = tok_end;
                }
            }
        }
    }
    Ok(())
}

/// Re-evaluate an `#ifdef` / `#ifndef` row against the live macro
/// table. Used during the host walk to override the kernel's
/// snapshot-frozen value when an earlier `#define` in the same file
/// adds to the macro set.
fn recompute_ifdef_truth(row_bytes: &[u8], negated: bool, macros: &[MacroDef]) -> bool {
    use super::{
        c_logical_directive_len, c_translation_phase_line_splice,
        first_payload_ident, macro_is_defined,
    };
    let logical_end = c_logical_directive_len(row_bytes, 0);
    let phys = row_bytes.get(..logical_end).unwrap_or(row_bytes);
    let spliced = c_translation_phase_line_splice(phys);
    // Walk past `#`, the keyword, and into the payload to extract the
    // macro name. Use the same phase-2 classification helper as the
    // CPU reference path; falling back to an empty payload when the
    // row doesn't classify (kernel already classified it as ifdef so
    // this is defensive).
    let Ok(directive) = super::try_classify_preprocessor_directive(&spliced.bytes) else {
        return false;
    };
    let payload = spliced
        .bytes
        .get(directive.payload_start..directive.logical_end)
        .unwrap_or_default();
    let Some(name) = first_payload_ident(payload) else {
        return false;
    };
    let macro_refs: Vec<&[u8]> = macros.iter().map(|m| m.name.as_slice()).collect();
    let defined = macro_is_defined(&macro_refs, name);
    if negated { !defined } else { defined }
}

/// Re-evaluate an `#if` / `#elif` row against the live macro table.
/// Falls back to `false` if the expression doesn't parse cleanly
/// (matches the CPU reference's "treat as 0" convention for
/// unparseable conditional payloads).
fn recompute_if_expr_truth(row_bytes: &[u8], macros: &[MacroDef]) -> bool {
    let macro_refs: Vec<&[u8]> = macros.iter().map(|m| m.name.as_slice()).collect();
    match super::reference_c_preprocessor_directive_metadata(
        &[crate::parsing::c::lex::tokens::TOK_PREPROC],
        &[0u32],
        &[row_bytes.len() as u32],
        row_bytes,
        &macro_refs,
    ) {
        Ok((_, values)) => values.first().copied().unwrap_or(0) == 1,
        Err(_) => false,
    }
}

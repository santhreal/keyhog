use std::cell::RefCell;
use std::mem;

use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre::{DispatchConfig, VyreBackend};

use vyre_libs::compiler::object_writer::opt_lower_elf;
use vyre_libs::parsing::c::lex::tokens::{TOK_LBRACE, TOK_LPAREN, TOK_RBRACE, TOK_RPAREN};

#[cfg(test)]
use super::buffers::read_u32_stream;
const MATCH_NONE: u32 = u32::MAX;
const ELF_OUT_BYTES: usize = 4096 * 4;

#[derive(Default)]
struct DispatchScratch {
    tok_bytes: Vec<u8>,
    outputs: Vec<Vec<u8>>,
    paren_pairs: Vec<u32>,
    brace_pairs: Vec<u32>,
}

thread_local! {
    static DISPATCH_SCRATCH: RefCell<DispatchScratch> =
        RefCell::new(DispatchScratch::default());
}

fn elf_out_zeroes() -> &'static [u8] {
    static ZEROES: std::sync::OnceLock<Vec<u8>> = std::sync::OnceLock::new();
    ZEROES.get_or_init(|| vec![0u8; ELF_OUT_BYTES]).as_slice()
}

pub(super) fn dispatch_c11_bracket_pairs(
    backend: &dyn VyreBackend,
    tok_types: &[u32],
    label: &str,
) -> Result<(Vec<u32>, Vec<u32>), String> {
    DISPATCH_SCRATCH.with(|scratch| {
        let mut scratch = scratch.try_borrow_mut().map_err(|_| {
            "C11 bracket-pair dispatch scratch was re-entered on the same thread. Fix: call bracket matching from a non-nested parser context or add explicit caller-owned scratch.".to_string()
        })?;
        dispatch_c11_bracket_pairs_with_scratch(backend, tok_types, label, &mut scratch)
    })
}

fn dispatch_c11_bracket_pairs_with_scratch(
    backend: &dyn VyreBackend,
    tok_types: &[u32],
    label: &str,
    scratch: &mut DispatchScratch,
) -> Result<(Vec<u32>, Vec<u32>), String> {
    let n_u32 = u32::try_from(tok_types.len()).map_err(|_| {
        format!(
            "c11_dual_bracket_match token count {} exceeds the u32 GPU index space. Fix: shard the translation unit before bracket-pair dispatch.",
            tok_types.len()
        )
    })?.max(1);
    let max_depth = n_u32.min(4096);
    pack_u32_le_bytes_min_words_into(tok_types, n_u32, &mut scratch.tok_bytes)?;
    let mut cfg = DispatchConfig::default();
    cfg.label = Some(label.to_string());
    cfg.grid_override = Some([1, 1, 1]);
    let key = super::stage_pipeline_cache_key(
        "c11_dual_bracket_match",
        &[n_u32 as u64, max_depth as u64],
    );
    let inputs = [scratch.tok_bytes.as_slice()];
    super::dispatch_borrowed_stage_cached_into(
        backend,
        key,
        || {
            let prog = c11_dual_bracket_match(
                "tok_types",
                "paren_stack",
                "brace_stack",
                "paren_pairs",
                "brace_pairs",
                n_u32,
                max_depth,
            );
            super::validate_internal_stage(&prog, "c11_dual_bracket_match")?;
            Ok(prog)
        },
        &inputs,
        &cfg,
        &mut scratch.outputs,
    )
    .map_err(|e| e.to_string())?;
    if scratch.outputs.len() != 2 {
        return Err(format!(
            "c11_dual_bracket_match returned {} output buffer(s), expected exactly 2. Fix: backend must return paren_pairs and brace_pairs.",
            scratch.outputs.len()
        ));
    }
    read_u32_stream_into(
        &scratch.outputs[0],
        tok_types.len(),
        "c11 paren pairs",
        &mut scratch.paren_pairs,
    )?;
    read_u32_stream_into(
        &scratch.outputs[1],
        tok_types.len(),
        "c11 brace pairs",
        &mut scratch.brace_pairs,
    )?;
    let mut paren_pairs = Vec::new();
    let mut brace_pairs = Vec::new();
    mem::swap(&mut paren_pairs, &mut scratch.paren_pairs);
    mem::swap(&mut brace_pairs, &mut scratch.brace_pairs);
    Ok((paren_pairs, brace_pairs))
}

fn c11_dual_bracket_match(
    tok_types: &str,
    paren_stack: &str,
    brace_stack: &str,
    paren_pairs: &str,
    brace_pairs: &str,
    n: u32,
    max_depth: u32,
) -> Program {
    Program::wrapped(
        vec![
            BufferDecl::storage(tok_types, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::workgroup(paren_stack, max_depth, DataType::U32),
            BufferDecl::workgroup(brace_stack, max_depth, DataType::U32),
            BufferDecl {
                is_output: true,
                ..BufferDecl::storage(paren_pairs, 3, BufferAccess::ReadWrite, DataType::U32)
                    .with_count(n)
                    .with_pipeline_live_out(true)
            },
            BufferDecl::storage(brace_pairs, 4, BufferAccess::ReadWrite, DataType::U32)
                .with_count(n)
                .with_pipeline_live_out(true),
        ],
        [1, 1, 1],
        vec![Node::if_then(
            Expr::eq(Expr::InvocationId { axis: 0 }, Expr::u32(0)),
            vec![
                Node::let_bind("paren_depth", Expr::u32(0)),
                Node::let_bind("brace_depth", Expr::u32(0)),
                Node::loop_for(
                    "i",
                    Expr::u32(0),
                    Expr::u32(n),
                    vec![
                        Node::store(paren_pairs, Expr::var("i"), Expr::u32(MATCH_NONE)),
                        Node::store(brace_pairs, Expr::var("i"), Expr::u32(MATCH_NONE)),
                        Node::let_bind("tok", Expr::load(tok_types, Expr::var("i"))),
                        Node::if_then(
                            Expr::eq(Expr::var("tok"), Expr::u32(TOK_LPAREN)),
                            vec![Node::if_then(
                                Expr::lt(Expr::var("paren_depth"), Expr::u32(max_depth)),
                                vec![
                                    Node::store(
                                        paren_stack,
                                        Expr::var("paren_depth"),
                                        Expr::var("i"),
                                    ),
                                    Node::assign(
                                        "paren_depth",
                                        Expr::add(Expr::var("paren_depth"), Expr::u32(1)),
                                    ),
                                ],
                            )],
                        ),
                        Node::if_then(
                            Expr::eq(Expr::var("tok"), Expr::u32(TOK_RPAREN)),
                            vec![Node::if_then(
                                Expr::lt(Expr::u32(0), Expr::var("paren_depth")),
                                vec![
                                    Node::assign(
                                        "paren_depth",
                                        Expr::sub(Expr::var("paren_depth"), Expr::u32(1)),
                                    ),
                                    Node::let_bind(
                                        "open_paren",
                                        Expr::load(paren_stack, Expr::var("paren_depth")),
                                    ),
                                    Node::store(
                                        paren_pairs,
                                        Expr::var("open_paren"),
                                        Expr::var("i"),
                                    ),
                                    Node::store(
                                        paren_pairs,
                                        Expr::var("i"),
                                        Expr::var("open_paren"),
                                    ),
                                ],
                            )],
                        ),
                        Node::if_then(
                            Expr::eq(Expr::var("tok"), Expr::u32(TOK_LBRACE)),
                            vec![Node::if_then(
                                Expr::lt(Expr::var("brace_depth"), Expr::u32(max_depth)),
                                vec![
                                    Node::store(
                                        brace_stack,
                                        Expr::var("brace_depth"),
                                        Expr::var("i"),
                                    ),
                                    Node::assign(
                                        "brace_depth",
                                        Expr::add(Expr::var("brace_depth"), Expr::u32(1)),
                                    ),
                                ],
                            )],
                        ),
                        Node::if_then(
                            Expr::eq(Expr::var("tok"), Expr::u32(TOK_RBRACE)),
                            vec![Node::if_then(
                                Expr::lt(Expr::u32(0), Expr::var("brace_depth")),
                                vec![
                                    Node::assign(
                                        "brace_depth",
                                        Expr::sub(Expr::var("brace_depth"), Expr::u32(1)),
                                    ),
                                    Node::let_bind(
                                        "open_brace",
                                        Expr::load(brace_stack, Expr::var("brace_depth")),
                                    ),
                                    Node::store(
                                        brace_pairs,
                                        Expr::var("open_brace"),
                                        Expr::var("i"),
                                    ),
                                    Node::store(
                                        brace_pairs,
                                        Expr::var("i"),
                                        Expr::var("open_brace"),
                                    ),
                                ],
                            )],
                        ),
                    ],
                ),
            ],
        )],
    )
}

pub(super) fn try_dispatch_elf(
    backend: &dyn VyreBackend,
    compiler_bytes: &[u8],
    node_count: u32,
) -> Result<Vec<u8>, String> {
    DISPATCH_SCRATCH.with(|scratch| {
        let mut scratch = scratch.try_borrow_mut().map_err(|_| {
            "ELF lowering dispatch scratch was re-entered on the same thread. Fix: call ELF lowering from a non-nested compile path or add explicit caller-owned scratch.".to_string()
        })?;
        try_dispatch_elf_with_scratch(backend, compiler_bytes, node_count, &mut scratch)
    })
}

fn try_dispatch_elf_with_scratch(
    backend: &dyn VyreBackend,
    compiler_bytes: &[u8],
    node_count: u32,
    scratch: &mut DispatchScratch,
) -> Result<Vec<u8>, String> {
    let node_count = node_count.max(1);
    let mut cfg = DispatchConfig::default();
    cfg.label = Some("vyre-frontend-c opt_lower_elf".to_string());
    let key = super::stage_pipeline_cache_key("opt_lower_elf", &[node_count as u64]);
    let inputs = [compiler_bytes, elf_out_zeroes()];
    super::dispatch_borrowed_stage_cached_into(
        backend,
        key,
        || {
            let prog = opt_lower_elf("ssa_nodes", "elf_out", Expr::u32(node_count));
            super::validate_internal_stage(&prog, "opt_lower_elf")?;
            Ok(prog)
        },
        &inputs,
        &cfg,
        &mut scratch.outputs,
    )
    .map_err(|e| e.to_string())?;
    if scratch.outputs.is_empty() {
        return Err("ELF lowering: missing output buffer".to_string());
    }
    let mut elf = Vec::new();
    mem::swap(&mut elf, &mut scratch.outputs[0]);
    Ok(elf)
}

fn pack_u32_le_bytes_min_words_into(
    words: &[u32],
    min_words: u32,
    out: &mut Vec<u8>,
) -> Result<(), String> {
    vyre_primitives::wire::pack_u32_slice_min_words_into(words, min_words, out)
}

fn read_u32_stream_into(
    buf: &[u8],
    words: usize,
    label: &str,
    out: &mut Vec<u32>,
) -> Result<(), String> {
    vyre_primitives::wire::unpack_u32_slice_into(buf, words, label, out)
}

#[cfg(test)]
mod gpu_bracket_tests {
    use super::*;
    use vyre_libs::parsing::c::lex::tokens::TOK_IDENTIFIER;
    use vyre_reference::value::Value;

    fn bracket_pairs_gpu_reference(tokens: &[u32]) -> (Vec<u32>, Vec<u32>) {
        if tokens.is_empty() {
            return (Vec::new(), Vec::new());
        }
        let n = tokens.len() as u32;
        let program = c11_dual_bracket_match(
            "tok_types",
            "paren_stack",
            "brace_stack",
            "paren_pairs",
            "brace_pairs",
            n,
            n,
        );
        let outputs = vyre_reference::reference_eval(
            &program,
            &[Value::from(super::super::buffers::vec_u32_le_bytes(tokens))],
        )
        .expect("Fix: GPU bracket-pair program must execute under reference evaluator");
        assert_eq!(outputs.len(), 2);
        (
            read_u32_stream(&outputs[0].to_bytes(), tokens.len(), "paren test pairs")
                .expect("Fix: paren pairs must decode"),
            read_u32_stream(&outputs[1].to_bytes(), tokens.len(), "brace test pairs")
                .expect("Fix: brace pairs must decode"),
        )
    }

    #[test]
    fn matches_balanced_parens_and_braces() {
        let tokens = vec![
            TOK_IDENTIFIER,
            TOK_IDENTIFIER,
            TOK_LPAREN,
            TOK_IDENTIFIER,
            TOK_RPAREN,
            TOK_LBRACE,
            TOK_IDENTIFIER,
            TOK_IDENTIFIER,
            TOK_IDENTIFIER,
            TOK_RBRACE,
        ];
        let (paren, brace) = bracket_pairs_gpu_reference(&tokens);
        assert_eq!(paren[2], 4);
        assert_eq!(paren[4], 2);
        assert_eq!(brace[5], 9);
        assert_eq!(brace[9], 5);
        assert_eq!(paren[0], MATCH_NONE);
        assert_eq!(brace[2], MATCH_NONE);
    }

    #[test]
    fn bracket_match_handles_windows_larger_than_legacy_fixed_depth_cap() {
        let tokens = vec![TOK_IDENTIFIER; 4097];
        let (paren, brace) = bracket_pairs_gpu_reference(&tokens);
        assert_eq!(paren.len(), tokens.len());
        assert_eq!(brace.len(), tokens.len());
        assert!(paren.iter().all(|word| *word == MATCH_NONE));
        assert!(brace.iter().all(|word| *word == MATCH_NONE));
    }

    #[test]
    fn nested_brackets_pair_innermost_first() {
        let tokens = vec![TOK_LPAREN, TOK_LPAREN, TOK_RPAREN, TOK_RPAREN];
        let (paren, _) = bracket_pairs_gpu_reference(&tokens);
        assert_eq!(paren[1], 2);
        assert_eq!(paren[2], 1);
        assert_eq!(paren[0], 3);
        assert_eq!(paren[3], 0);
    }

    #[test]
    fn unmatched_close_is_ignored_not_panic() {
        let tokens = vec![TOK_RPAREN, TOK_LPAREN, TOK_RPAREN];
        let (paren, _) = bracket_pairs_gpu_reference(&tokens);
        assert_eq!(paren[0], MATCH_NONE);
        assert_eq!(paren[1], 2);
        assert_eq!(paren[2], 1);
    }

    #[test]
    fn empty_token_stream_returns_empty_pairs() {
        let (paren, brace) = bracket_pairs_gpu_reference(&[]);
        assert!(paren.is_empty());
        assert!(brace.is_empty());
    }
}

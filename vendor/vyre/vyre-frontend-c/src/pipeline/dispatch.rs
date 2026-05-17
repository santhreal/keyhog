use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre::{DispatchConfig, VyreBackend};

use vyre_libs::compiler::object_writer::opt_lower_elf;
use vyre_libs::parsing::c::lex::tokens::{TOK_LBRACE, TOK_LPAREN, TOK_RBRACE, TOK_RPAREN};

use super::buffers::{fast_pack_u32_le, read_u32_stream, vec_u32_le_bytes};
use super::BRACKET_MAX_DEPTH;

const MATCH_NONE: u32 = u32::MAX;

pub(super) fn dispatch_c11_bracket_pairs(
    backend: &dyn VyreBackend,
    tok_types: &[u32],
    label: &str,
) -> Result<(Vec<u32>, Vec<u32>), String> {
    let n_u32 = u32::try_from(tok_types.len()).unwrap_or(u32::MAX).max(1);
    let max_depth = n_u32.clamp(1, BRACKET_MAX_DEPTH);
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
    let tok_bytes = vec_u32_le_bytes(tok_types);
    let paren_stack = vec![0u8; max_depth as usize * 4];
    let brace_stack = vec![0u8; max_depth as usize * 4];
    let paren_pairs_init = vec![0u8; n_u32 as usize * 4];
    let mut cfg = DispatchConfig::default();
    cfg.label = Some(label.to_string());
    let outs = backend
        .dispatch(&prog, &[tok_bytes, paren_stack, brace_stack, paren_pairs_init], &cfg)
        .map_err(|e| e.to_string())?;
    let paren_pairs = outs
        .get(2)
        .ok_or_else(|| "c11_dual_bracket_match: missing paren_pairs output".to_string())?;
    let brace_pairs = outs
        .get(3)
        .ok_or_else(|| "c11_dual_bracket_match: missing brace_pairs output".to_string())?;
    Ok((
        read_u32_stream(paren_pairs, tok_types.len(), "c11 paren pairs")?,
        read_u32_stream(brace_pairs, tok_types.len(), "c11 brace pairs")?,
    ))
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
            BufferDecl::read_write(paren_stack, 1, DataType::U32).with_count(max_depth),
            BufferDecl::read_write(brace_stack, 2, DataType::U32).with_count(max_depth),
            BufferDecl::read_write(paren_pairs, 3, DataType::U32).with_count(n),
            BufferDecl::output(brace_pairs, 4, DataType::U32).with_count(n),
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
    compiler_words: &[u32],
) -> Result<Vec<u8>, String> {
    let node_count = u32::try_from(compiler_words.len())
        .map_err(|_| "ELF lowering input exceeds u32 word count".to_string())?
        .max(1);
    let prog = opt_lower_elf("ssa_nodes", "elf_out", Expr::u32(node_count));
    super::validate_internal_stage(&prog, "opt_lower_elf")?;
    let ssa = fast_pack_u32_le(compiler_words);
    let elf_init = vec![0u8; 4096 * 4];
    let offsets_init = vec![0u8; 16 * 4];
    let mut cfg = DispatchConfig::default();
    cfg.label = Some("vyre-frontend-c opt_lower_elf".to_string());
    let outs = backend
        .dispatch(&prog, &[ssa, elf_init, offsets_init], &cfg)
        .map_err(|e| e.to_string())?;
    outs.into_iter()
        .next()
        .ok_or_else(|| "ELF lowering: missing output buffer".to_string())
}

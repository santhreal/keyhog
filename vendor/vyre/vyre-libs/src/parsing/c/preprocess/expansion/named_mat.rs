//! Materialized named macro-expansion dispatch builder.

#![allow(missing_docs)] // Internal macro-expansion helpers are documented at the owning module boundary.
use crate::parsing::c::lex::tokens::*;
use crate::parsing::c::preprocess::materialization::*;
use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};

use super::fnlike_mat::*;
use super::helpers::*;
use super::objlike_mat::*;
use super::*;

pub fn opt_named_macro_expansion_materialized(
    in_tok_types: &str,
    in_tok_starts: &str,
    in_tok_lens: &str,
    source_words: &str,
    macro_name_hashes: &str,
    macro_name_starts: &str,
    macro_name_lens: &str,
    macro_name_words: &str,
    macro_vals: &str,
    macro_sizes: &str,
    macro_kinds: &str,
    macro_param_counts: &str,
    macro_replacement_params: &str,
    macro_replacement_starts: &str,
    macro_replacement_lens: &str,
    macro_replacement_words: &str,
    runtime_counts: &str,
    out_tok_types: &str,
    out_tok_starts: &str,
    out_tok_lens: &str,
    out_source_words: &str,
    out_tok_counts: &str,
    out_source_counts: &str,
    num_tokens: Expr,
    source_len: Expr,
    macro_replacement_source_len: Expr,
    max_input_tokens: u32,
    max_source_words: u32,
    max_replacement_source_words: u32,
    max_out_tokens: u32,
    max_out_source_bytes: u32,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let tok_buffer_count = max_input_tokens.max(1);
    let source_count = max_source_words.max(1);
    let replacement_source_count = max_replacement_source_words.max(1);
    let out_buffer_count = max_out_tokens.max(1);
    let out_source_count = max_out_source_bytes.max(1);

    let mut process_current = vec![
        Node::let_bind("named_tok", Expr::load(in_tok_types, Expr::var("named_i"))),
        Node::let_bind("named_macro_slot", Expr::u32(EMPTY_MACRO_SLOT)),
        Node::let_bind("named_macro_idx", Expr::u32(EMPTY_MACRO_SLOT)),
        Node::let_bind("named_macro_kind", Expr::u32(C_MACRO_KIND_OBJECT_LIKE)),
        Node::let_bind("named_param_count", Expr::u32(0)),
        Node::let_bind("named_is_variadic", Expr::u32(0)),
        Node::let_bind("named_required_param_count", Expr::u32(0)),
    ];
    process_current.push(Node::if_then(
        Expr::eq(Expr::var("named_tok"), Expr::u32(TOK_IDENTIFIER)),
        {
            let mut ident = emit_source_span_hash(
                "named",
                Expr::var("named_i"),
                in_tok_starts,
                in_tok_lens,
                source_words,
                source_len.clone(),
                "named_name_hash",
            );
            ident.extend(emit_macro_hash_lookup(
                "named_lookup",
                Expr::var("named_name_hash"),
                Expr::var("named_start"),
                Expr::var("named_len"),
                source_words,
                macro_name_hashes,
                macro_name_starts,
                macro_name_lens,
                macro_name_words,
                "named_macro_slot",
            ));
            ident
        },
    ));
    process_current.push(Node::if_then(
        Expr::ne(Expr::var("named_macro_slot"), Expr::u32(EMPTY_MACRO_SLOT)),
        vec![
            Node::assign(
                "named_macro_idx",
                Expr::load(macro_vals, Expr::var("named_macro_slot")),
            ),
            Node::assign(
                "named_macro_kind",
                Expr::load(macro_kinds, Expr::var("named_macro_slot")),
            ),
            Node::let_bind(
                "named_param_count_raw",
                Expr::load(macro_param_counts, Expr::var("named_macro_slot")),
            ),
            Node::assign(
                "named_param_count",
                Expr::bitand(Expr::var("named_param_count_raw"), Expr::u32(0x7fff_ffff)),
            ),
            Node::assign(
                "named_is_variadic",
                Expr::shr(Expr::var("named_param_count_raw"), Expr::u32(31)),
            ),
            Node::assign(
                "named_required_param_count",
                Expr::saturating_sub(
                    Expr::var("named_param_count"),
                    Expr::var("named_is_variadic"),
                ),
            ),
            Node::if_then(
                Expr::and(
                    Expr::ne(
                        Expr::var("named_macro_kind"),
                        Expr::u32(C_MACRO_KIND_OBJECT_LIKE),
                    ),
                    Expr::ne(
                        Expr::var("named_macro_kind"),
                        Expr::u32(C_MACRO_KIND_FUNCTION_LIKE),
                    ),
                ),
                vec![Node::trap(
                    Expr::var("named_macro_kind"),
                    "named-macro-kind-invalid",
                )],
            ),
        ],
    ));
    process_current.push(Node::if_then_else(
        Expr::eq(Expr::var("named_macro_slot"), Expr::u32(EMPTY_MACRO_SLOT)),
        {
            let mut passthrough = emit_materialized_output_token(
                "passthrough",
                Expr::var("named_tok"),
                source_words,
                Expr::load(in_tok_starts, Expr::var("named_i")),
                Expr::load(in_tok_lens, Expr::var("named_i")),
                source_len.clone(),
                out_tok_types,
                out_tok_starts,
                out_tok_lens,
                out_source_words,
                max_out_tokens,
                max_out_source_bytes,
                "passthrough-token-source-span-out-of-bounds",
            );
            passthrough.push(Node::assign(
                "named_i",
                Expr::add(Expr::var("named_i"), Expr::u32(1)),
            ));
            passthrough
        },
        {
            let mut expanded = vec![
                Node::let_bind(
                    "named_repl_size",
                    Expr::load(macro_sizes, Expr::var("named_macro_idx")),
                ),
                Node::if_then(
                    Expr::gt(
                        Expr::add(Expr::var("named_macro_idx"), Expr::var("named_repl_size")),
                        Expr::u32(MACRO_TABLE_SLOTS),
                    ),
                    vec![Node::trap(
                        Expr::add(Expr::var("named_macro_idx"), Expr::var("named_repl_size")),
                        "named-macro-replacement-range-out-of-bounds",
                    )],
                ),
                Node::let_bind("named_has_open_paren", Expr::u32(0)),
                Node::if_then(
                    Expr::lt(
                        Expr::add(Expr::var("named_i"), Expr::u32(1)),
                        num_tokens.clone(),
                    ),
                    vec![Node::if_then(
                        Expr::eq(
                            Expr::load(in_tok_types, Expr::add(Expr::var("named_i"), Expr::u32(1))),
                            Expr::u32(TOK_LPAREN),
                        ),
                        vec![Node::assign("named_has_open_paren", Expr::u32(1))],
                    )],
                ),
            ];
            expanded.push(Node::if_then_else(
                Expr::eq(
                    Expr::var("named_macro_kind"),
                    Expr::u32(C_MACRO_KIND_OBJECT_LIKE),
                ),
                emit_materialized_object_like_replacement(
                    macro_vals,
                    macro_replacement_params,
                    macro_replacement_starts,
                    macro_replacement_lens,
                    macro_replacement_words,
                    out_tok_types,
                    out_tok_starts,
                    out_tok_lens,
                    out_source_words,
                    macro_replacement_source_len.clone(),
                    max_out_tokens,
                    max_out_source_bytes,
                ),
                vec![Node::if_then_else(
                    Expr::eq(Expr::var("named_has_open_paren"), Expr::u32(0)),
                    {
                        let mut passthrough = emit_materialized_output_token(
                            "function_name_passthrough",
                            Expr::var("named_tok"),
                            source_words,
                            Expr::load(in_tok_starts, Expr::var("named_i")),
                            Expr::load(in_tok_lens, Expr::var("named_i")),
                            source_len.clone(),
                            out_tok_types,
                            out_tok_starts,
                            out_tok_lens,
                            out_source_words,
                            max_out_tokens,
                            max_out_source_bytes,
                            "function-name-passthrough-source-span-out-of-bounds",
                        );
                        passthrough.push(Node::assign(
                            "named_i",
                            Expr::add(Expr::var("named_i"), Expr::u32(1)),
                        ));
                        passthrough
                    },
                    emit_materialized_function_like_replacement(
                        in_tok_types,
                        in_tok_starts,
                        in_tok_lens,
                        source_words,
                        macro_vals,
                        macro_replacement_params,
                        macro_replacement_starts,
                        macro_replacement_lens,
                        macro_replacement_words,
                        out_tok_types,
                        out_tok_starts,
                        out_tok_lens,
                        out_source_words,
                        "macro_arg_starts",
                        "macro_arg_ends",
                        num_tokens.clone(),
                        source_len.clone(),
                        macro_replacement_source_len.clone(),
                        max_out_tokens,
                        max_out_source_bytes,
                    ),
                )],
            ));
            expanded
        },
    ));

    Program::wrapped(
        vec![
            BufferDecl::storage(in_tok_types, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_buffer_count),
            BufferDecl::storage(in_tok_starts, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_buffer_count),
            BufferDecl::storage(in_tok_lens, 2, BufferAccess::ReadOnly, DataType::U32)
                .with_count(tok_buffer_count),
            BufferDecl::storage(source_words, 3, BufferAccess::ReadOnly, DataType::U32)
                .with_count(source_count),
            BufferDecl::storage(macro_name_hashes, 4, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(macro_name_starts, 5, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(macro_name_lens, 6, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(macro_name_words, 7, BufferAccess::ReadOnly, DataType::U32)
                .with_count(0),
            BufferDecl::storage(macro_vals, 8, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(macro_sizes, 9, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(macro_kinds, 10, BufferAccess::ReadOnly, DataType::U32)
                .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(
                macro_param_counts,
                11,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(
                macro_replacement_params,
                12,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(
                macro_replacement_starts,
                13,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(
                macro_replacement_lens,
                14,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(MACRO_TABLE_SLOTS),
            BufferDecl::storage(
                macro_replacement_words,
                15,
                BufferAccess::ReadOnly,
                DataType::U32,
            )
            .with_count(replacement_source_count),
            BufferDecl::storage(runtime_counts, 16, BufferAccess::ReadOnly, DataType::U32)
                .with_count(3),
            BufferDecl::storage(out_tok_types, 17, BufferAccess::ReadWrite, DataType::U32)
                .with_count(out_buffer_count),
            BufferDecl::storage(out_tok_starts, 18, BufferAccess::ReadWrite, DataType::U32)
                .with_count(out_buffer_count),
            BufferDecl::storage(out_tok_lens, 19, BufferAccess::ReadWrite, DataType::U32)
                .with_count(out_buffer_count),
            BufferDecl::storage(out_source_words, 20, BufferAccess::ReadWrite, DataType::U32)
                .with_count(out_source_count),
            BufferDecl::storage(out_tok_counts, 21, BufferAccess::ReadWrite, DataType::U32)
                .with_count(1),
            BufferDecl::storage(
                out_source_counts,
                22,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(1),
            BufferDecl::storage(
                "macro_arg_starts",
                23,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(tok_buffer_count),
            BufferDecl::storage("macro_arg_ends", 24, BufferAccess::ReadWrite, DataType::U32)
                .with_count(tok_buffer_count),
        ],
        [1, 1, 1],
        vec![wrap_anonymous(
            "vyre-libs::parsing::opt_named_macro_expansion_materialized",
            vec![Node::if_then(
                Expr::eq(t, Expr::u32(0)),
                vec![
                    Node::let_bind("named_i", Expr::u32(0)),
                    Node::let_bind("named_out_idx", Expr::u32(0)),
                    Node::let_bind("named_source_out_idx", Expr::u32(0)),
                    Node::loop_for(
                        "named_cursor",
                        Expr::u32(0),
                        num_tokens,
                        vec![Node::if_then(
                            Expr::eq(Expr::var("named_cursor"), Expr::var("named_i")),
                            process_current,
                        )],
                    ),
                    Node::store(out_tok_counts, Expr::u32(0), Expr::var("named_out_idx")),
                    Node::store(
                        out_source_counts,
                        Expr::u32(C_MACRO_SOURCE_COUNT_BYTES),
                        Expr::var("named_source_out_idx"),
                    ),
                ],
            )],
        )],
    )
    .with_entry_op_id("vyre-libs::parsing::opt_named_macro_expansion_materialized_v5")
    .with_non_composable_with_self(true)
}

use crate::harness::OpEntry;
use crate::parsing::c::lex::tokens::{
    TOK_ALIGNAS, TOK_ALIGNOF, TOK_AMP, TOK_AMP_EQ, TOK_AND, TOK_ARROW, TOK_ASSIGN, TOK_ATOMIC,
    TOK_BANG, TOK_BOOL, TOK_BREAK, TOK_BUILTIN_CHOOSE_EXPR, TOK_BUILTIN_CONSTANT_P,
    TOK_BUILTIN_TYPES_COMPATIBLE_P, TOK_CARET, TOK_CARET_EQ, TOK_CASE, TOK_CHAR, TOK_CHAR_KW,
    TOK_COLON, TOK_COMMA, TOK_COMPLEX, TOK_CONST, TOK_CONTINUE, TOK_DEC, TOK_DEFAULT, TOK_DO,
    TOK_DOT, TOK_DOUBLE, TOK_ELLIPSIS, TOK_ELSE, TOK_ENUM, TOK_EQ, TOK_EXTERN, TOK_FLOAT,
    TOK_FLOAT_KW, TOK_FOR, TOK_GE, TOK_GENERIC, TOK_GNU_ADDRESS_SPACE, TOK_GNU_ASM,
    TOK_GNU_ATTRIBUTE, TOK_GNU_AUTO_TYPE, TOK_GNU_BUILTIN_VA_LIST, TOK_GNU_EXTENSION, TOK_GNU_IMAG,
    TOK_GNU_INT128, TOK_GNU_LABEL, TOK_GNU_REAL, TOK_GNU_TYPEOF, TOK_GNU_TYPEOF_UNQUAL, TOK_GOTO,
    TOK_GT, TOK_IDENTIFIER, TOK_IF, TOK_IMAGINARY, TOK_INC, TOK_INLINE, TOK_INT, TOK_INTEGER,
    TOK_LBRACE, TOK_LBRACKET, TOK_LE, TOK_LONG, TOK_LPAREN, TOK_LSHIFT, TOK_LSHIFT_EQ, TOK_LT,
    TOK_MINUS, TOK_MINUS_EQ, TOK_NE, TOK_NORETURN, TOK_OR, TOK_PERCENT, TOK_PERCENT_EQ, TOK_PIPE,
    TOK_PIPE_EQ, TOK_PLUS, TOK_PLUS_EQ, TOK_QUESTION, TOK_RBRACE, TOK_RBRACKET, TOK_RESTRICT,
    TOK_RETURN, TOK_RPAREN, TOK_RSHIFT, TOK_RSHIFT_EQ, TOK_SEMICOLON, TOK_SHORT, TOK_SIGNED,
    TOK_SIZEOF, TOK_SLASH, TOK_SLASH_EQ, TOK_STAR, TOK_STAR_EQ, TOK_STATIC, TOK_STATIC_ASSERT,
    TOK_STRING, TOK_STRUCT, TOK_SWITCH, TOK_THREAD_LOCAL, TOK_TILDE, TOK_TYPEDEF, TOK_UNION,
    TOK_UNSIGNED, TOK_VOID, TOK_VOLATILE, TOK_WHILE,
};
use crate::region::wrap_anonymous;
use vyre::ir::{BufferAccess, BufferDecl, DataType, Expr, Node, Program};
use vyre_primitives::predicate::node_kind;

pub use super::vast_kinds::{
    C_AST_KIND_ALIGNOF_EXPR, C_AST_KIND_ARRAY_DECL, C_AST_KIND_ARRAY_SUBSCRIPT_EXPR,
    C_AST_KIND_ASM_CLOBBERS_LIST, C_AST_KIND_ASM_GOTO_LABELS, C_AST_KIND_ASM_INPUT_OPERAND,
    C_AST_KIND_ASM_OUTPUT_OPERAND, C_AST_KIND_ASM_QUALIFIER, C_AST_KIND_ASM_TEMPLATE,
    C_AST_KIND_ASSIGN_EXPR, C_AST_KIND_ATTRIBUTE_ALIAS, C_AST_KIND_ATTRIBUTE_ALIGNED,
    C_AST_KIND_ATTRIBUTE_ALWAYS_INLINE, C_AST_KIND_ATTRIBUTE_CLEANUP, C_AST_KIND_ATTRIBUTE_COLD,
    C_AST_KIND_ATTRIBUTE_CONST, C_AST_KIND_ATTRIBUTE_CONSTRUCTOR, C_AST_KIND_ATTRIBUTE_DESTRUCTOR,
    C_AST_KIND_ATTRIBUTE_FALLTHROUGH, C_AST_KIND_ATTRIBUTE_FORMAT, C_AST_KIND_ATTRIBUTE_HOT,
    C_AST_KIND_ATTRIBUTE_MODE, C_AST_KIND_ATTRIBUTE_NAKED, C_AST_KIND_ATTRIBUTE_NOINLINE,
    C_AST_KIND_ATTRIBUTE_PACKED, C_AST_KIND_ATTRIBUTE_PURE, C_AST_KIND_ATTRIBUTE_SECTION,
    C_AST_KIND_ATTRIBUTE_UNUSED, C_AST_KIND_ATTRIBUTE_USED, C_AST_KIND_ATTRIBUTE_VISIBILITY,
    C_AST_KIND_ATTRIBUTE_WEAK, C_AST_KIND_BIT_FIELD_DECL, C_AST_KIND_BREAK_STMT,
    C_AST_KIND_BUILTIN_CHOOSE_EXPR, C_AST_KIND_BUILTIN_CLASSIFY_TYPE_EXPR,
    C_AST_KIND_BUILTIN_CONSTANT_P_EXPR, C_AST_KIND_BUILTIN_EXPECT_EXPR,
    C_AST_KIND_BUILTIN_OBJECT_SIZE_EXPR, C_AST_KIND_BUILTIN_OFFSETOF_EXPR,
    C_AST_KIND_BUILTIN_OVERFLOW_EXPR, C_AST_KIND_BUILTIN_PREFETCH_EXPR,
    C_AST_KIND_BUILTIN_TYPES_COMPATIBLE_P_EXPR, C_AST_KIND_BUILTIN_UNREACHABLE_STMT,
    C_AST_KIND_CASE_STMT, C_AST_KIND_CAST_EXPR, C_AST_KIND_COMPOUND_LITERAL_EXPR,
    C_AST_KIND_CONDITIONAL_EXPR, C_AST_KIND_CONTINUE_STMT, C_AST_KIND_DEFAULT_STMT,
    C_AST_KIND_DO_STMT, C_AST_KIND_ELSE_STMT, C_AST_KIND_ENUMERATOR_DECL, C_AST_KIND_ENUM_DECL,
    C_AST_KIND_FIELD_DECL, C_AST_KIND_FOR_STMT, C_AST_KIND_FUNCTION_DECLARATOR,
    C_AST_KIND_FUNCTION_DEFINITION, C_AST_KIND_GENERIC_SELECTION_EXPR, C_AST_KIND_GNU_ATTRIBUTE,
    C_AST_KIND_GNU_LABEL_ADDRESS_EXPR, C_AST_KIND_GNU_LOCAL_LABEL_DECL,
    C_AST_KIND_GNU_STATEMENT_EXPR, C_AST_KIND_GOTO_STMT, C_AST_KIND_IF_STMT,
    C_AST_KIND_INITIALIZER_LIST, C_AST_KIND_INLINE_ASM, C_AST_KIND_LABEL_STMT,
    C_AST_KIND_MEMBER_ACCESS_EXPR, C_AST_KIND_POINTER_DECL, C_AST_KIND_RANGE_DESIGNATOR_EXPR,
    C_AST_KIND_RETURN_STMT, C_AST_KIND_SIZEOF_EXPR, C_AST_KIND_STATIC_ASSERT_DECL,
    C_AST_KIND_STRUCT_DECL, C_AST_KIND_SWITCH_STMT, C_AST_KIND_TYPEDEF_DECL, C_AST_KIND_UNARY_EXPR,
    C_AST_KIND_UNION_DECL, C_AST_KIND_WHILE_STMT, C_EXPR_ASSOC_LEFT, C_EXPR_ASSOC_NONE,
    C_EXPR_ASSOC_RIGHT, C_EXPR_SHAPE_BINARY, C_EXPR_SHAPE_CONDITIONAL, C_EXPR_SHAPE_NONE,
    C_EXPR_SHAPE_STRIDE_U32,
};

const BUILD_VAST_OP_ID: &str = "vyre-libs::parsing::c11_build_vast_nodes";
const CLASSIFY_VAST_OP_ID: &str = "vyre-libs::parsing::c11_classify_vast_node_kinds";
const ANNOTATE_TYPEDEF_OP_ID: &str = "vyre-libs::parsing::c11_annotate_typedef_names";
const EXPR_SHAPE_OP_ID: &str = "vyre-libs::parsing::c11_build_expression_shape_nodes";
const VAST_NODE_STRIDE_U32: u32 = 10;
const SENTINEL: u32 = u32::MAX;
const VAST_TYPEDEF_FLAGS_FIELD: u32 = 7;
const VAST_TYPEDEF_SCOPE_FIELD: u32 = 8;
const VAST_TYPEDEF_SYMBOL_FIELD: u32 = 9;
const C_TYPEDEF_FLAG_VISIBLE_TYPEDEF_NAME: u32 = 1;
const C_TYPEDEF_FLAG_TYPEDEF_DECLARATOR: u32 = 1 << 1;
const C_TYPEDEF_FLAG_ORDINARY_DECLARATOR: u32 = 1 << 2;

const C_GNU_TYPEOF_HASHES: &[u32] = &[
    0x9a90_a8a0, // typeof
    0xff65_c714, // __typeof__
    0xee15_bd69, // typeof_unqual
    0x812b_41f1, // __typeof_unqual__
];
const C_GNU_AUTO_TYPE_HASH: u32 = 0x572b_7b0d;

const C_ATTRIBUTE_KIND_HASHES: &[(u32, u32)] = &[
    (0xfcdd_0ccc, C_AST_KIND_ATTRIBUTE_SECTION),
    (0x2a13_825c, C_AST_KIND_ATTRIBUTE_SECTION),
    (0xedbc_2ec9, C_AST_KIND_ATTRIBUTE_WEAK),
    (0xa67d_9bad, C_AST_KIND_ATTRIBUTE_WEAK),
    (0x7d26_8157, C_AST_KIND_ATTRIBUTE_ALIAS),
    (0xa79d_c33b, C_AST_KIND_ATTRIBUTE_ALIAS),
    (0xc731_74df, C_AST_KIND_ATTRIBUTE_ALIGNED),
    (0x45b0_1e27, C_AST_KIND_ATTRIBUTE_ALIGNED),
    (0x6a78_6eb0, C_AST_KIND_ATTRIBUTE_USED),
    (0xbc04_7928, C_AST_KIND_ATTRIBUTE_USED),
    (0x85cf_281b, C_AST_KIND_ATTRIBUTE_UNUSED),
    (0xc6de_fd0f, C_AST_KIND_ATTRIBUTE_UNUSED),
    (0x06ca_5a98, C_AST_KIND_ATTRIBUTE_NAKED),
    (0x7d09_0c10, C_AST_KIND_ATTRIBUTE_NAKED),
    (0x7f37_f5e5, C_AST_KIND_ATTRIBUTE_VISIBILITY),
    (0x643d_c155, C_AST_KIND_ATTRIBUTE_VISIBILITY),
    (0x7d7f_64e1, C_AST_KIND_ATTRIBUTE_PACKED),
    (0x2c44_2d6d, C_AST_KIND_ATTRIBUTE_PACKED),
    (0xd95d_f1b3, C_AST_KIND_ATTRIBUTE_CLEANUP),
    (0xac5f_fe13, C_AST_KIND_ATTRIBUTE_CLEANUP),
    (0xf25d_9f4f, C_AST_KIND_ATTRIBUTE_CONSTRUCTOR),
    (0x963c_e7ef, C_AST_KIND_ATTRIBUTE_CONSTRUCTOR),
    (0xb856_15de, C_AST_KIND_ATTRIBUTE_DESTRUCTOR),
    (0xee92_8ba6, C_AST_KIND_ATTRIBUTE_DESTRUCTOR),
    (0xec6e_e012, C_AST_KIND_ATTRIBUTE_MODE),
    (0x1cd7_9962, C_AST_KIND_ATTRIBUTE_MODE),
    (0xb0a7_e467, C_AST_KIND_ATTRIBUTE_NOINLINE),
    (0x268f_f2d3, C_AST_KIND_ATTRIBUTE_NOINLINE),
    (0xe368_4d30, C_AST_KIND_ATTRIBUTE_ALWAYS_INLINE),
    (0x9190_71f4, C_AST_KIND_ATTRIBUTE_ALWAYS_INLINE),
    (0xea44_dd0f, C_AST_KIND_ATTRIBUTE_COLD),
    (0x057f_7b43, C_AST_KIND_ATTRIBUTE_COLD),
    (0xfec3_a7d4, C_AST_KIND_ATTRIBUTE_HOT),
    (0x9b27_4c90, C_AST_KIND_ATTRIBUTE_HOT),
    (0x966d_d8e3, C_AST_KIND_ATTRIBUTE_PURE),
    (0x4edb_a0f3, C_AST_KIND_ATTRIBUTE_PURE),
    (0x664f_d1d4, C_AST_KIND_ATTRIBUTE_CONST),
    (0xc53a_deb4, C_AST_KIND_ATTRIBUTE_CONST),
    (0xb99d_8552, C_AST_KIND_ATTRIBUTE_FORMAT),
    (0x5299_0142, C_AST_KIND_ATTRIBUTE_FORMAT),
    (0x8034_7b09, C_AST_KIND_ATTRIBUTE_FALLTHROUGH),
    (0xc373_7bd1, C_AST_KIND_ATTRIBUTE_FALLTHROUGH),
];

fn node_count(num_tokens: &Expr) -> u32 {
    match num_tokens {
        Expr::LitU32(n) => *n,
        _ => 1,
    }
}

fn is_open_token(token: Expr) -> Expr {
    Expr::or(
        Expr::or(
            Expr::eq(token.clone(), Expr::u32(TOK_LPAREN)),
            Expr::eq(token.clone(), Expr::u32(TOK_LBRACE)),
        ),
        Expr::eq(token, Expr::u32(TOK_LBRACKET)),
    )
}

fn is_matching_close(current: Expr, candidate: Expr) -> Expr {
    Expr::or(
        Expr::or(
            Expr::and(
                Expr::eq(current.clone(), Expr::u32(TOK_LPAREN)),
                Expr::eq(candidate.clone(), Expr::u32(TOK_RPAREN)),
            ),
            Expr::and(
                Expr::eq(current.clone(), Expr::u32(TOK_LBRACE)),
                Expr::eq(candidate.clone(), Expr::u32(TOK_RBRACE)),
            ),
        ),
        Expr::and(
            Expr::eq(current, Expr::u32(TOK_LBRACKET)),
            Expr::eq(candidate, Expr::u32(TOK_RBRACKET)),
        ),
    )
}

fn is_c_literal_token(token: Expr) -> Expr {
    Expr::or(
        Expr::or(
            Expr::eq(token.clone(), Expr::u32(TOK_INTEGER)),
            Expr::eq(token.clone(), Expr::u32(TOK_FLOAT)),
        ),
        Expr::or(
            Expr::eq(token.clone(), Expr::u32(TOK_STRING)),
            Expr::eq(token, Expr::u32(TOK_CHAR)),
        ),
    )
}

fn c_statement_kind(token: Expr) -> Expr {
    Expr::select(
        Expr::eq(token.clone(), Expr::u32(TOK_IF)),
        Expr::u32(C_AST_KIND_IF_STMT),
        Expr::select(
            Expr::eq(token.clone(), Expr::u32(TOK_ELSE)),
            Expr::u32(C_AST_KIND_ELSE_STMT),
            Expr::select(
                Expr::eq(token.clone(), Expr::u32(TOK_SWITCH)),
                Expr::u32(C_AST_KIND_SWITCH_STMT),
                Expr::select(
                    Expr::eq(token.clone(), Expr::u32(TOK_CASE)),
                    Expr::u32(C_AST_KIND_CASE_STMT),
                    Expr::select(
                        Expr::eq(token.clone(), Expr::u32(TOK_DEFAULT)),
                        Expr::u32(C_AST_KIND_DEFAULT_STMT),
                        Expr::select(
                            Expr::eq(token.clone(), Expr::u32(TOK_FOR)),
                            Expr::u32(C_AST_KIND_FOR_STMT),
                            Expr::select(
                                Expr::eq(token.clone(), Expr::u32(TOK_WHILE)),
                                Expr::u32(C_AST_KIND_WHILE_STMT),
                                Expr::select(
                                    Expr::eq(token.clone(), Expr::u32(TOK_DO)),
                                    Expr::u32(C_AST_KIND_DO_STMT),
                                    Expr::select(
                                        Expr::eq(token.clone(), Expr::u32(TOK_RETURN)),
                                        Expr::u32(C_AST_KIND_RETURN_STMT),
                                        Expr::select(
                                            Expr::eq(token.clone(), Expr::u32(TOK_BREAK)),
                                            Expr::u32(C_AST_KIND_BREAK_STMT),
                                            Expr::select(
                                                Expr::eq(token.clone(), Expr::u32(TOK_CONTINUE)),
                                                Expr::u32(C_AST_KIND_CONTINUE_STMT),
                                                Expr::select(
                                                    Expr::eq(token, Expr::u32(TOK_GOTO)),
                                                    Expr::u32(C_AST_KIND_GOTO_STMT),
                                                    Expr::u32(0),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
}

fn c_effective_expression_prev_kind(prev_kind: Expr, prev_prev_kind: Expr) -> Expr {
    let parenthesized_type_operand = Expr::and(
        Expr::eq(prev_kind.clone(), Expr::u32(TOK_LPAREN)),
        any_token_eq(
            prev_prev_kind,
            &[
                TOK_SIZEOF,
                TOK_ALIGNOF,
                TOK_GNU_TYPEOF,
                TOK_GNU_TYPEOF_UNQUAL,
            ],
        ),
    );
    Expr::select(parenthesized_type_operand, Expr::u32(TOK_RPAREN), prev_kind)
}

fn c_expression_operator_kind(token: Expr, prev_kind: Expr, prev_prev_kind: Expr) -> Expr {
    let effective_prev_kind = c_effective_expression_prev_kind(prev_kind, prev_prev_kind);
    let is_assignment_operator = any_token_eq(
        token.clone(),
        &[
            TOK_ASSIGN,
            TOK_PLUS_EQ,
            TOK_MINUS_EQ,
            TOK_STAR_EQ,
            TOK_SLASH_EQ,
            TOK_PERCENT_EQ,
            TOK_AMP_EQ,
            TOK_PIPE_EQ,
            TOK_CARET_EQ,
            TOK_LSHIFT_EQ,
            TOK_RSHIFT_EQ,
        ],
    );
    let unary_context = c_unary_context(effective_prev_kind.clone());
    let is_unary_operator = Expr::or(
        Expr::and(
            unary_context.clone(),
            Expr::or(
                Expr::eq(token.clone(), Expr::u32(TOK_INC)),
                Expr::eq(token.clone(), Expr::u32(TOK_DEC)),
            ),
        ),
        Expr::and(
            unary_context.clone(),
            any_token_eq(
                token.clone(),
                &[
                    TOK_STAR,
                    TOK_AMP,
                    TOK_PLUS,
                    TOK_MINUS,
                    TOK_BANG,
                    TOK_TILDE,
                    TOK_GNU_REAL,
                    TOK_GNU_IMAG,
                ],
            ),
        ),
    );
    let is_array_subscript = Expr::and(
        Expr::eq(token.clone(), Expr::u32(TOK_LBRACKET)),
        c_can_end_expression(effective_prev_kind.clone()),
    );

    Expr::select(
        is_assignment_operator,
        Expr::u32(C_AST_KIND_ASSIGN_EXPR),
        Expr::select(
            Expr::or(
                Expr::eq(token.clone(), Expr::u32(TOK_DOT)),
                Expr::eq(token.clone(), Expr::u32(TOK_ARROW)),
            ),
            Expr::u32(C_AST_KIND_MEMBER_ACCESS_EXPR),
            Expr::select(
                is_array_subscript,
                Expr::u32(C_AST_KIND_ARRAY_SUBSCRIPT_EXPR),
                Expr::select(
                    Expr::or(
                        Expr::eq(token.clone(), Expr::u32(TOK_SIZEOF)),
                        Expr::or(
                            Expr::eq(token.clone(), Expr::u32(TOK_GNU_TYPEOF)),
                            Expr::eq(token.clone(), Expr::u32(TOK_GNU_TYPEOF_UNQUAL)),
                        ),
                    ),
                    Expr::u32(C_AST_KIND_SIZEOF_EXPR),
                    Expr::select(
                        Expr::eq(token.clone(), Expr::u32(TOK_ALIGNOF)),
                        Expr::u32(C_AST_KIND_ALIGNOF_EXPR),
                        Expr::select(
                            Expr::eq(token.clone(), Expr::u32(TOK_QUESTION)),
                            Expr::u32(C_AST_KIND_CONDITIONAL_EXPR),
                            Expr::select(
                                is_unary_operator,
                                Expr::u32(C_AST_KIND_UNARY_EXPR),
                                Expr::select(
                                    Expr::and(
                                        Expr::not(unary_context),
                                        any_token_eq(
                                            token,
                                            &[
                                                TOK_PLUS,
                                                TOK_MINUS,
                                                TOK_STAR,
                                                TOK_SLASH,
                                                TOK_PERCENT,
                                                TOK_AMP,
                                                TOK_PIPE,
                                                TOK_CARET,
                                                TOK_EQ,
                                                TOK_NE,
                                                TOK_LE,
                                                TOK_GE,
                                                TOK_AND,
                                                TOK_OR,
                                                TOK_LSHIFT,
                                                TOK_RSHIFT,
                                                TOK_LT,
                                                TOK_GT,
                                            ],
                                        ),
                                    ),
                                    Expr::u32(node_kind::BINARY),
                                    Expr::u32(0),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
}

fn c_builtin_expression_kind(token: Expr) -> Expr {
    Expr::select(
        Expr::eq(token.clone(), Expr::u32(TOK_BUILTIN_CONSTANT_P)),
        Expr::u32(C_AST_KIND_BUILTIN_CONSTANT_P_EXPR),
        Expr::select(
            Expr::eq(token.clone(), Expr::u32(TOK_BUILTIN_CHOOSE_EXPR)),
            Expr::u32(C_AST_KIND_BUILTIN_CHOOSE_EXPR),
            Expr::select(
                Expr::eq(token.clone(), Expr::u32(TOK_BUILTIN_TYPES_COMPATIBLE_P)),
                Expr::u32(C_AST_KIND_BUILTIN_TYPES_COMPATIBLE_P_EXPR),
                Expr::select(
                    Expr::eq(token.clone(), Expr::u32(TOK_GENERIC)),
                    Expr::u32(C_AST_KIND_GENERIC_SELECTION_EXPR),
                    Expr::select(
                        Expr::eq(token, Expr::u32(TOK_ELLIPSIS)),
                        Expr::u32(C_AST_KIND_RANGE_DESIGNATOR_EXPR),
                        Expr::u32(0),
                    ),
                ),
            ),
        ),
    )
}

fn c_builtin_identifier_expression_kind(
    raw_kind: Expr,
    symbol_hash: Expr,
    next_kind: Expr,
) -> Expr {
    let hash_kind = |hash: u32, kind: u32, fallback: Expr| {
        Expr::select(
            Expr::eq(symbol_hash.clone(), Expr::u32(hash)),
            Expr::u32(kind),
            fallback,
        )
    };
    Expr::select(
        Expr::and(
            Expr::eq(raw_kind, Expr::u32(TOK_IDENTIFIER)),
            Expr::eq(next_kind, Expr::u32(TOK_LPAREN)),
        ),
        Expr::select(
            is_gnu_typeof_symbol_hash(symbol_hash.clone()),
            Expr::u32(C_AST_KIND_SIZEOF_EXPR),
            hash_kind(
                0x749d_f71e,
                C_AST_KIND_BUILTIN_EXPECT_EXPR,
                hash_kind(
                    0xdcec_13f5,
                    C_AST_KIND_BUILTIN_OFFSETOF_EXPR,
                    hash_kind(
                        0x7900_03c8,
                        C_AST_KIND_BUILTIN_OBJECT_SIZE_EXPR,
                        hash_kind(
                            0x21a7_53f0,
                            C_AST_KIND_BUILTIN_PREFETCH_EXPR,
                            hash_kind(
                                0x4a9a_c967,
                                C_AST_KIND_BUILTIN_UNREACHABLE_STMT,
                                hash_kind(
                                    0x7f55_6bd5,
                                    C_AST_KIND_BUILTIN_OVERFLOW_EXPR,
                                    hash_kind(
                                        0xb0bc_f282,
                                        C_AST_KIND_BUILTIN_OVERFLOW_EXPR,
                                        hash_kind(
                                            0x8cc7_b276,
                                            C_AST_KIND_BUILTIN_OVERFLOW_EXPR,
                                            hash_kind(
                                                0x3909_1622,
                                                C_AST_KIND_BUILTIN_CLASSIFY_TYPE_EXPR,
                                                Expr::u32(0),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
        Expr::u32(0),
    )
}

fn c_unary_context(prev_kind: Expr) -> Expr {
    Expr::or(
        Expr::eq(prev_kind.clone(), Expr::u32(SENTINEL)),
        any_token_eq(
            prev_kind,
            &[
                TOK_LPAREN,
                TOK_LBRACKET,
                TOK_LBRACE,
                TOK_SEMICOLON,
                TOK_COMMA,
                TOK_ASSIGN,
                TOK_PLUS_EQ,
                TOK_MINUS_EQ,
                TOK_STAR_EQ,
                TOK_SLASH_EQ,
                TOK_PERCENT_EQ,
                TOK_AMP_EQ,
                TOK_PIPE_EQ,
                TOK_CARET_EQ,
                TOK_LSHIFT_EQ,
                TOK_RSHIFT_EQ,
                TOK_QUESTION,
                TOK_COLON,
                TOK_RETURN,
                TOK_CASE,
                TOK_SIZEOF,
                TOK_GNU_TYPEOF,
                TOK_GNU_TYPEOF_UNQUAL,
                TOK_ALIGNOF,
                TOK_PLUS,
                TOK_MINUS,
                TOK_STAR,
                TOK_SLASH,
                TOK_PERCENT,
                TOK_AMP,
                TOK_PIPE,
                TOK_CARET,
                TOK_BANG,
                TOK_TILDE,
                TOK_EQ,
                TOK_NE,
                TOK_LE,
                TOK_GE,
                TOK_AND,
                TOK_OR,
                TOK_LSHIFT,
                TOK_RSHIFT,
                TOK_LT,
                TOK_GT,
            ],
        ),
    )
}

fn c_can_end_expression(prev_kind: Expr) -> Expr {
    Expr::or(
        Expr::or(
            Expr::eq(prev_kind.clone(), Expr::u32(TOK_IDENTIFIER)),
            is_c_literal_token(prev_kind.clone()),
        ),
        any_token_eq(prev_kind, &[TOK_RPAREN, TOK_RBRACKET, TOK_INC, TOK_DEC]),
    )
}

fn c_expr_shape_kind(raw_kind: Expr, typed_kind: Expr) -> Expr {
    Expr::select(
        Expr::eq(typed_kind.clone(), Expr::u32(C_AST_KIND_CONDITIONAL_EXPR)),
        Expr::u32(C_EXPR_SHAPE_CONDITIONAL),
        Expr::select(
            Expr::or(
                Expr::eq(typed_kind.clone(), Expr::u32(node_kind::BINARY)),
                Expr::eq(typed_kind, Expr::u32(C_AST_KIND_ASSIGN_EXPR)),
            ),
            Expr::u32(C_EXPR_SHAPE_BINARY),
            Expr::select(
                Expr::eq(raw_kind, Expr::u32(TOK_QUESTION)),
                Expr::u32(C_EXPR_SHAPE_CONDITIONAL),
                Expr::u32(C_EXPR_SHAPE_NONE),
            ),
        ),
    )
}

fn c_expr_operator_precedence(raw_kind: Expr, typed_kind: Expr) -> Expr {
    Expr::select(
        Expr::and(
            Expr::ne(typed_kind.clone(), Expr::u32(node_kind::BINARY)),
            Expr::and(
                Expr::ne(typed_kind.clone(), Expr::u32(C_AST_KIND_ASSIGN_EXPR)),
                Expr::and(
                    Expr::ne(typed_kind.clone(), Expr::u32(C_AST_KIND_CONDITIONAL_EXPR)),
                    Expr::ne(raw_kind.clone(), Expr::u32(TOK_QUESTION)),
                ),
            ),
        ),
        Expr::u32(0),
        Expr::select(
            Expr::eq(typed_kind.clone(), Expr::u32(C_AST_KIND_ASSIGN_EXPR)),
            Expr::u32(2),
            Expr::select(
                Expr::eq(typed_kind.clone(), Expr::u32(C_AST_KIND_CONDITIONAL_EXPR)),
                Expr::u32(3),
                Expr::select(
                    Expr::eq(raw_kind.clone(), Expr::u32(TOK_OR)),
                    Expr::u32(4),
                    Expr::select(
                        Expr::eq(raw_kind.clone(), Expr::u32(TOK_AND)),
                        Expr::u32(5),
                        Expr::select(
                            Expr::eq(raw_kind.clone(), Expr::u32(TOK_PIPE)),
                            Expr::u32(6),
                            Expr::select(
                                Expr::eq(raw_kind.clone(), Expr::u32(TOK_CARET)),
                                Expr::u32(7),
                                Expr::select(
                                    Expr::eq(raw_kind.clone(), Expr::u32(TOK_AMP)),
                                    Expr::u32(8),
                                    Expr::select(
                                        Expr::or(
                                            Expr::eq(raw_kind.clone(), Expr::u32(TOK_EQ)),
                                            Expr::eq(raw_kind.clone(), Expr::u32(TOK_NE)),
                                        ),
                                        Expr::u32(9),
                                        Expr::select(
                                            any_token_eq(
                                                raw_kind.clone(),
                                                &[TOK_LT, TOK_GT, TOK_LE, TOK_GE],
                                            ),
                                            Expr::u32(10),
                                            Expr::select(
                                                Expr::or(
                                                    Expr::eq(
                                                        raw_kind.clone(),
                                                        Expr::u32(TOK_LSHIFT),
                                                    ),
                                                    Expr::eq(
                                                        raw_kind.clone(),
                                                        Expr::u32(TOK_RSHIFT),
                                                    ),
                                                ),
                                                Expr::u32(11),
                                                Expr::select(
                                                    Expr::or(
                                                        Expr::eq(
                                                            raw_kind.clone(),
                                                            Expr::u32(TOK_PLUS),
                                                        ),
                                                        Expr::eq(
                                                            raw_kind.clone(),
                                                            Expr::u32(TOK_MINUS),
                                                        ),
                                                    ),
                                                    Expr::u32(12),
                                                    Expr::select(
                                                        any_token_eq(
                                                            raw_kind,
                                                            &[TOK_STAR, TOK_SLASH, TOK_PERCENT],
                                                        ),
                                                        Expr::u32(13),
                                                        Expr::u32(0),
                                                    ),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
}

fn c_expr_operator_associativity(typed_kind: Expr) -> Expr {
    Expr::select(
        Expr::or(
            Expr::eq(typed_kind.clone(), Expr::u32(C_AST_KIND_ASSIGN_EXPR)),
            Expr::eq(typed_kind.clone(), Expr::u32(C_AST_KIND_CONDITIONAL_EXPR)),
        ),
        Expr::u32(C_EXPR_ASSOC_RIGHT),
        Expr::select(
            Expr::eq(typed_kind, Expr::u32(node_kind::BINARY)),
            Expr::u32(C_EXPR_ASSOC_LEFT),
            Expr::u32(C_EXPR_ASSOC_NONE),
        ),
    )
}

fn is_expr_shape_boundary(raw_kind: Expr, include_ternary_parts: bool) -> Expr {
    let common = Expr::or(
        Expr::eq(raw_kind.clone(), Expr::u32(TOK_SEMICOLON)),
        Expr::eq(raw_kind.clone(), Expr::u32(TOK_COMMA)),
    );
    if include_ternary_parts {
        Expr::or(
            common,
            Expr::or(
                Expr::eq(raw_kind.clone(), Expr::u32(TOK_QUESTION)),
                Expr::eq(raw_kind, Expr::u32(TOK_COLON)),
            ),
        )
    } else {
        common
    }
}

fn emit_prior_ternary_boundary_flag(
    raw_vast_nodes: &str,
    parent_expr: Expr,
    target: Expr,
    prefix: &str,
) -> Vec<Node> {
    let flag = format!("{prefix}_use_ternary_boundaries");
    let stop = format!("{prefix}_ternary_boundary_stop");
    let scan = format!("{prefix}_ternary_boundary_scan");
    let rev = format!("{prefix}_ternary_boundary_rev");
    let base = format!("{prefix}_ternary_boundary_base");
    let raw = format!("{prefix}_ternary_boundary_raw");
    let parent = format!("{prefix}_ternary_boundary_parent");
    let is_prior_ternary = format!("{prefix}_is_prior_ternary_boundary");

    vec![
        Node::let_bind(&flag, Expr::u32(0)),
        Node::let_bind(&stop, Expr::u32(0)),
        Node::loop_for(
            &scan,
            Expr::u32(0),
            target.clone(),
            vec![Node::if_then(
                Expr::eq(Expr::var(&stop), Expr::u32(0)),
                vec![
                    Node::let_bind(
                        &rev,
                        Expr::sub(Expr::sub(target.clone(), Expr::var(&scan)), Expr::u32(1)),
                    ),
                    Node::let_bind(
                        &base,
                        Expr::mul(Expr::var(&rev), Expr::u32(VAST_NODE_STRIDE_U32)),
                    ),
                    Node::let_bind(&raw, Expr::load(raw_vast_nodes, Expr::var(&base))),
                    Node::let_bind(
                        &parent,
                        Expr::load(raw_vast_nodes, Expr::add(Expr::var(&base), Expr::u32(1))),
                    ),
                    Node::if_then(
                        Expr::and(
                            Expr::eq(Expr::var(&parent), parent_expr.clone()),
                            is_expr_shape_boundary(Expr::var(&raw), true),
                        ),
                        vec![
                            Node::let_bind(
                                &is_prior_ternary,
                                Expr::or(
                                    Expr::eq(Expr::var(&raw), Expr::u32(TOK_QUESTION)),
                                    Expr::eq(Expr::var(&raw), Expr::u32(TOK_COLON)),
                                ),
                            ),
                            Node::if_then(
                                Expr::var(&is_prior_ternary),
                                vec![Node::assign(&flag, Expr::u32(1))],
                            ),
                            Node::assign(&stop, Expr::u32(1)),
                        ],
                    ),
                ],
            )],
        ),
    ]
}

fn emit_expr_segment_bounds(
    raw_vast_nodes: &str,
    parent_expr: Expr,
    target: Expr,
    num_nodes: Expr,
    prefix: &str,
    include_ternary_parts: bool,
) -> Vec<Node> {
    let start = format!("{prefix}_seg_start");
    let end = format!("{prefix}_seg_end");
    let scan = format!("{prefix}_seg_scan");
    let rev = format!("{prefix}_seg_rev");
    let base = format!("{prefix}_seg_base");
    let raw = format!("{prefix}_seg_raw");
    let parent = format!("{prefix}_seg_parent");
    let seen_left_boundary = format!("{prefix}_seen_left_boundary");
    let seen_right_boundary = format!("{prefix}_seen_right_boundary");

    vec![
        Node::let_bind(&start, Expr::u32(0)),
        Node::let_bind(&end, num_nodes.clone()),
        Node::let_bind(&seen_left_boundary, Expr::u32(0)),
        Node::loop_for(
            &scan,
            Expr::u32(0),
            target.clone(),
            vec![Node::if_then(
                Expr::eq(Expr::var(&seen_left_boundary), Expr::u32(0)),
                vec![
                    Node::let_bind(
                        &rev,
                        Expr::sub(Expr::sub(target.clone(), Expr::var(&scan)), Expr::u32(1)),
                    ),
                    Node::let_bind(
                        &base,
                        Expr::mul(Expr::var(&rev), Expr::u32(VAST_NODE_STRIDE_U32)),
                    ),
                    Node::let_bind(&raw, Expr::load(raw_vast_nodes, Expr::var(&base))),
                    Node::let_bind(
                        &parent,
                        Expr::load(raw_vast_nodes, Expr::add(Expr::var(&base), Expr::u32(1))),
                    ),
                    Node::if_then(
                        Expr::and(
                            Expr::eq(Expr::var(&parent), parent_expr.clone()),
                            is_expr_shape_boundary(Expr::var(&raw), include_ternary_parts),
                        ),
                        vec![
                            Node::assign(&start, Expr::add(Expr::var(&rev), Expr::u32(1))),
                            Node::assign(&seen_left_boundary, Expr::u32(1)),
                        ],
                    ),
                ],
            )],
        ),
        Node::let_bind(&seen_right_boundary, Expr::u32(0)),
        Node::loop_for(
            &scan,
            Expr::add(target, Expr::u32(1)),
            num_nodes,
            vec![Node::if_then(
                Expr::eq(Expr::var(&seen_right_boundary), Expr::u32(0)),
                vec![
                    Node::let_bind(
                        &base,
                        Expr::mul(Expr::var(&scan), Expr::u32(VAST_NODE_STRIDE_U32)),
                    ),
                    Node::let_bind(&raw, Expr::load(raw_vast_nodes, Expr::var(&base))),
                    Node::let_bind(
                        &parent,
                        Expr::load(raw_vast_nodes, Expr::add(Expr::var(&base), Expr::u32(1))),
                    ),
                    Node::if_then(
                        Expr::and(
                            Expr::eq(Expr::var(&parent), parent_expr),
                            is_expr_shape_boundary(Expr::var(&raw), include_ternary_parts),
                        ),
                        vec![
                            Node::assign(&end, Expr::var(&scan)),
                            Node::assign(&seen_right_boundary, Expr::u32(1)),
                        ],
                    ),
                ],
            )],
        ),
    ]
}

fn emit_expr_root_scan(
    raw_vast_nodes: &str,
    typed_vast_nodes: &str,
    lo: Expr,
    hi: Expr,
    parent_expr: Expr,
    prefix: &str,
) -> Vec<Node> {
    let root = format!("{prefix}_root");
    let root_prec = format!("{prefix}_root_prec");
    let operand = format!("{prefix}_operand");
    let scan = format!("{prefix}_scan");
    let base = format!("{prefix}_base");
    let raw = format!("{prefix}_raw");
    let typed = format!("{prefix}_typed");
    let parent = format!("{prefix}_parent");
    let shape = format!("{prefix}_shape");
    let prec = format!("{prefix}_prec");
    let assoc = format!("{prefix}_assoc");
    let is_operator = format!("{prefix}_is_operator");
    let replace_root = format!("{prefix}_replace_root");

    vec![
        Node::let_bind(&root, Expr::u32(SENTINEL)),
        Node::let_bind(&root_prec, Expr::u32(u32::MAX)),
        Node::let_bind(&operand, Expr::u32(SENTINEL)),
        Node::loop_for(
            &scan,
            lo,
            hi,
            vec![
                Node::let_bind(
                    &base,
                    Expr::mul(Expr::var(&scan), Expr::u32(VAST_NODE_STRIDE_U32)),
                ),
                Node::let_bind(&raw, Expr::load(raw_vast_nodes, Expr::var(&base))),
                Node::let_bind(&typed, Expr::load(typed_vast_nodes, Expr::var(&base))),
                Node::let_bind(
                    &parent,
                    Expr::load(raw_vast_nodes, Expr::add(Expr::var(&base), Expr::u32(1))),
                ),
                Node::let_bind(
                    &shape,
                    c_expr_shape_kind(Expr::var(&raw), Expr::var(&typed)),
                ),
                Node::let_bind(
                    &prec,
                    c_expr_operator_precedence(Expr::var(&raw), Expr::var(&typed)),
                ),
                Node::let_bind(&assoc, c_expr_operator_associativity(Expr::var(&typed))),
                Node::let_bind(
                    &is_operator,
                    Expr::ne(Expr::var(&shape), Expr::u32(C_EXPR_SHAPE_NONE)),
                ),
                Node::if_then(
                    Expr::or(
                        Expr::eq(Expr::var(&parent), parent_expr.clone()),
                        Expr::var(&is_operator),
                    ),
                    vec![
                        Node::if_then(
                            Expr::and(
                                Expr::eq(Expr::var(&operand), Expr::u32(SENTINEL)),
                                Expr::and(
                                    Expr::eq(Expr::var(&parent), parent_expr.clone()),
                                    Expr::and(
                                        Expr::not(Expr::var(&is_operator)),
                                        Expr::not(is_expr_shape_boundary(Expr::var(&raw), true)),
                                    ),
                                ),
                            ),
                            vec![Node::assign(&operand, Expr::var(&scan))],
                        ),
                        Node::let_bind(
                            &replace_root,
                            Expr::or(
                                Expr::eq(Expr::var(&root), Expr::u32(SENTINEL)),
                                Expr::or(
                                    Expr::lt(Expr::var(&prec), Expr::var(&root_prec)),
                                    Expr::and(
                                        Expr::eq(Expr::var(&prec), Expr::var(&root_prec)),
                                        Expr::eq(Expr::var(&assoc), Expr::u32(C_EXPR_ASSOC_LEFT)),
                                    ),
                                ),
                            ),
                        ),
                        Node::if_then(
                            Expr::and(Expr::var(&is_operator), Expr::var(&replace_root)),
                            vec![
                                Node::assign(&root, Expr::var(&scan)),
                                Node::assign(&root_prec, Expr::var(&prec)),
                            ],
                        ),
                    ],
                ),
            ],
        ),
        Node::if_then(
            Expr::eq(Expr::var(&root), Expr::u32(SENTINEL)),
            vec![Node::assign(&root, Expr::var(&operand))],
        ),
    ]
}

fn any_token_eq(token: Expr, values: &[u32]) -> Expr {
    values
        .iter()
        .copied()
        .fold(Expr::bool(false), |acc, value| {
            Expr::or(acc, Expr::eq(token.clone(), Expr::u32(value)))
        })
}

fn is_gnu_typeof_symbol_hash(symbol_hash: Expr) -> Expr {
    C_GNU_TYPEOF_HASHES
        .iter()
        .copied()
        .fold(Expr::bool(false), |acc, hash| {
            Expr::or(acc, Expr::eq(symbol_hash.clone(), Expr::u32(hash)))
        })
}

fn is_typeof_operator_token(token: Expr, symbol_hash: Expr) -> Expr {
    Expr::or(
        Expr::or(
            Expr::eq(token.clone(), Expr::u32(TOK_GNU_TYPEOF)),
            Expr::eq(token.clone(), Expr::u32(TOK_GNU_TYPEOF_UNQUAL)),
        ),
        Expr::and(
            Expr::eq(token, Expr::u32(TOK_IDENTIFIER)),
            is_gnu_typeof_symbol_hash(symbol_hash),
        ),
    )
}

fn is_gnu_auto_type_symbol_hash(symbol_hash: Expr) -> Expr {
    Expr::eq(symbol_hash, Expr::u32(C_GNU_AUTO_TYPE_HASH))
}

fn c_attribute_kind_from_hash(symbol_hash: Expr) -> Expr {
    C_ATTRIBUTE_KIND_HASHES
        .iter()
        .rev()
        .fold(Expr::u32(0), |fallback, (hash, kind)| {
            Expr::select(
                Expr::eq(symbol_hash.clone(), Expr::u32(*hash)),
                Expr::u32(*kind),
                fallback,
            )
        })
}

fn is_type_name_start_token(token: Expr) -> Expr {
    any_token_eq(
        token,
        &[
            TOK_CONST,
            TOK_RESTRICT,
            TOK_VOLATILE,
            TOK_STRUCT,
            TOK_UNION,
            TOK_ENUM,
            TOK_VOID,
            TOK_CHAR_KW,
            TOK_INT,
            TOK_LONG,
            TOK_SHORT,
            TOK_SIGNED,
            TOK_UNSIGNED,
            TOK_FLOAT_KW,
            TOK_DOUBLE,
            TOK_BOOL,
            TOK_COMPLEX,
            TOK_IMAGINARY,
            TOK_ATOMIC,
            TOK_GNU_TYPEOF,
            TOK_GNU_TYPEOF_UNQUAL,
            TOK_GNU_INT128,
            TOK_GNU_BUILTIN_VA_LIST,
        ],
    )
}

fn is_decl_prefix_token(token: Expr) -> Expr {
    any_token_eq(
        token,
        &[
            TOK_TYPEDEF,
            TOK_EXTERN,
            TOK_STATIC,
            TOK_INLINE,
            TOK_CONST,
            TOK_RESTRICT,
            TOK_VOLATILE,
            TOK_STRUCT,
            TOK_UNION,
            TOK_ENUM,
            TOK_VOID,
            TOK_CHAR_KW,
            TOK_INT,
            TOK_LONG,
            TOK_SHORT,
            TOK_SIGNED,
            TOK_UNSIGNED,
            TOK_FLOAT_KW,
            TOK_DOUBLE,
            TOK_BOOL,
            TOK_COMPLEX,
            TOK_IMAGINARY,
            TOK_ALIGNAS,
            TOK_ATOMIC,
            TOK_NORETURN,
            TOK_STATIC_ASSERT,
            TOK_THREAD_LOCAL,
            TOK_GNU_TYPEOF,
            TOK_GNU_TYPEOF_UNQUAL,
            TOK_GNU_AUTO_TYPE,
            TOK_GNU_INT128,
            TOK_GNU_BUILTIN_VA_LIST,
            TOK_GNU_ADDRESS_SPACE,
            TOK_GNU_EXTENSION,
        ],
    )
}

fn is_decl_prefix_token_or_gnu_type_hash(token: Expr, symbol_hash: Expr) -> Expr {
    Expr::or(
        is_decl_prefix_token(token.clone()),
        Expr::or(
            is_typeof_operator_token(token.clone(), symbol_hash.clone()),
            Expr::and(
                Expr::eq(token, Expr::u32(TOK_IDENTIFIER)),
                is_gnu_auto_type_symbol_hash(symbol_hash),
            ),
        ),
    )
}

fn is_decl_prefix_reset_token(token: Expr) -> Expr {
    any_token_eq(
        token,
        &[TOK_SEMICOLON, TOK_LBRACE, TOK_RBRACE, TOK_ASSIGN, TOK_COLON],
    )
}

fn is_typedef_name_annotation(flags: Expr) -> Expr {
    Expr::ne(
        Expr::bitand(flags, Expr::u32(C_TYPEDEF_FLAG_VISIBLE_TYPEDEF_NAME)),
        Expr::u32(0),
    )
}

fn is_typedef_declarator_annotation(flags: Expr) -> Expr {
    Expr::ne(
        Expr::bitand(flags, Expr::u32(C_TYPEDEF_FLAG_TYPEDEF_DECLARATOR)),
        Expr::u32(0),
    )
}

fn is_ordinary_declarator_annotation(flags: Expr) -> Expr {
    Expr::ne(
        Expr::bitand(flags, Expr::u32(C_TYPEDEF_FLAG_ORDINARY_DECLARATOR)),
        Expr::u32(0),
    )
}

fn is_type_name_identifier(flags: Expr, fallback_has_prior_typedef: Expr) -> Expr {
    Expr::or(
        is_typedef_name_annotation(flags),
        fallback_has_prior_typedef,
    )
}

fn is_aggregate_specifier_body_open(
    open_kind: Expr,
    prev_kind: Expr,
    prev_prev_kind: Expr,
) -> Expr {
    Expr::and(
        Expr::eq(open_kind, Expr::u32(TOK_LBRACE)),
        Expr::or(
            any_token_eq(prev_kind.clone(), &[TOK_STRUCT, TOK_UNION, TOK_ENUM]),
            Expr::and(
                Expr::eq(prev_kind, Expr::u32(TOK_IDENTIFIER)),
                any_token_eq(prev_prev_kind, &[TOK_STRUCT, TOK_UNION, TOK_ENUM]),
            ),
        ),
    )
}

/// Build structural token-level C VAST rows with stable source spans.
///
/// This stage is the deterministic handoff between the C token stream and
/// generic VAST consumers. It emits one VAST row per token and derives
/// delimiter-tree parent, first-child, and next-sibling links so graph lowerers
/// receive a walkable packed node table instead of a flat token list.
#[must_use]
pub fn c11_build_vast_nodes(
    tok_types: &str,
    tok_starts: &str,
    tok_lens: &str,
    num_tokens: Expr,
    out_vast_nodes: &str,
    out_count: &str,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };

    let build_row = Expr::mul(Expr::var("build_i"), Expr::u32(VAST_NODE_STRIDE_U32));
    let parent_row = Expr::mul(Expr::var("parent_idx"), Expr::u32(VAST_NODE_STRIDE_U32));
    let previous_row = Expr::mul(
        Expr::var("previous_sibling"),
        Expr::u32(VAST_NODE_STRIDE_U32),
    );
    let stack_slot = Expr::add(
        Expr::mul(Expr::var("stack_depth"), Expr::u32(VAST_NODE_STRIDE_U32)),
        Expr::u32(9),
    );
    let top_slot = Expr::add(
        Expr::mul(
            Expr::sub(Expr::var("stack_depth"), Expr::u32(1)),
            Expr::u32(VAST_NODE_STRIDE_U32),
        ),
        Expr::u32(9),
    );

    let build_loop = vec![
        Node::let_bind("row", build_row),
        Node::let_bind("tok", Expr::load(tok_types, Expr::var("build_i"))),
        Node::let_bind("parent_idx", Expr::u32(SENTINEL)),
        Node::if_then(
            Expr::gt(Expr::var("stack_depth"), Expr::u32(0)),
            vec![Node::assign(
                "parent_idx",
                Expr::load(out_vast_nodes, top_slot.clone()),
            )],
        ),
        Node::store(out_vast_nodes, Expr::var("row"), Expr::var("tok")),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("row"), Expr::u32(1)),
            Expr::var("parent_idx"),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("row"), Expr::u32(2)),
            Expr::u32(SENTINEL),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("row"), Expr::u32(3)),
            Expr::u32(SENTINEL),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("row"), Expr::u32(4)),
            Expr::u32(SENTINEL),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("row"), Expr::u32(5)),
            Expr::load(tok_starts, Expr::var("build_i")),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("row"), Expr::u32(6)),
            Expr::load(tok_lens, Expr::var("build_i")),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("row"), Expr::u32(7)),
            Expr::u32(0),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("row"), Expr::u32(8)),
            Expr::u32(0),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("row"), Expr::u32(9)),
            Expr::u32(0),
        ),
        Node::let_bind(
            "previous_sibling",
            Expr::select(
                Expr::lt(Expr::var("parent_idx"), num_tokens.clone()),
                Expr::load(out_vast_nodes, Expr::add(parent_row.clone(), Expr::u32(4))),
                Expr::var("root_last_child"),
            ),
        ),
        Node::if_then_else(
            Expr::lt(Expr::var("previous_sibling"), num_tokens.clone()),
            vec![Node::store(
                out_vast_nodes,
                Expr::add(previous_row, Expr::u32(3)),
                Expr::var("build_i"),
            )],
            vec![Node::if_then(
                Expr::lt(Expr::var("parent_idx"), num_tokens.clone()),
                vec![Node::store(
                    out_vast_nodes,
                    Expr::add(parent_row.clone(), Expr::u32(2)),
                    Expr::var("build_i"),
                )],
            )],
        ),
        Node::if_then_else(
            Expr::lt(Expr::var("parent_idx"), num_tokens.clone()),
            vec![Node::store(
                out_vast_nodes,
                Expr::add(parent_row, Expr::u32(4)),
                Expr::var("build_i"),
            )],
            vec![Node::assign("root_last_child", Expr::var("build_i"))],
        ),
        Node::if_then(
            is_open_token(Expr::var("tok")),
            vec![
                Node::store(out_vast_nodes, stack_slot, Expr::var("build_i")),
                Node::assign(
                    "stack_depth",
                    Expr::add(Expr::var("stack_depth"), Expr::u32(1)),
                ),
            ],
        ),
        Node::let_bind("top_idx", Expr::u32(SENTINEL)),
        Node::if_then(
            Expr::gt(Expr::var("stack_depth"), Expr::u32(0)),
            vec![Node::assign(
                "top_idx",
                Expr::load(out_vast_nodes, top_slot),
            )],
        ),
        Node::let_bind(
            "top_kind",
            Expr::select(
                Expr::lt(Expr::var("top_idx"), num_tokens.clone()),
                Expr::load(tok_types, Expr::var("top_idx")),
                Expr::u32(0),
            ),
        ),
        Node::if_then(
            Expr::and(
                Expr::gt(Expr::var("stack_depth"), Expr::u32(0)),
                is_matching_close(Expr::var("top_kind"), Expr::var("tok")),
            ),
            vec![Node::assign(
                "stack_depth",
                Expr::sub(Expr::var("stack_depth"), Expr::u32(1)),
            )],
        ),
    ];

    let cleanup_loop = vec![
        Node::let_bind(
            "cleanup_row",
            Expr::mul(Expr::var("cleanup_i"), Expr::u32(VAST_NODE_STRIDE_U32)),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("cleanup_row"), Expr::u32(4)),
            Expr::u32(0),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("cleanup_row"), Expr::u32(7)),
            Expr::u32(0),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("cleanup_row"), Expr::u32(8)),
            Expr::u32(0),
        ),
        Node::store(
            out_vast_nodes,
            Expr::add(Expr::var("cleanup_row"), Expr::u32(9)),
            Expr::u32(0),
        ),
    ];

    let body = vec![Node::if_then(
        Expr::eq(t.clone(), Expr::u32(0)),
        vec![
            Node::store(out_count, Expr::u32(0), num_tokens.clone()),
            Node::let_bind("stack_depth", Expr::u32(0)),
            Node::let_bind("root_last_child", Expr::u32(SENTINEL)),
            Node::loop_for("build_i", Expr::u32(0), num_tokens.clone(), build_loop),
            Node::loop_for("cleanup_i", Expr::u32(0), num_tokens.clone(), cleanup_loop),
        ],
    )];

    let n = node_count(&num_tokens).max(1);
    Program::wrapped(
        vec![
            BufferDecl::storage(tok_types, 0, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::storage(tok_starts, 1, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::storage(tok_lens, 2, BufferAccess::ReadOnly, DataType::U32).with_count(n),
            BufferDecl::storage(out_vast_nodes, 3, BufferAccess::ReadWrite, DataType::U32)
                .with_count(n.saturating_mul(VAST_NODE_STRIDE_U32)),
            BufferDecl::storage(out_count, 4, BufferAccess::ReadWrite, DataType::U32).with_count(1),
        ],
        [1, 1, 1],
        vec![wrap_anonymous(BUILD_VAST_OP_ID, body)],
    )
    .with_entry_op_id(BUILD_VAST_OP_ID)
}

fn emit_identifier_hash_for_row(
    vast_nodes: &str,
    haystack: &str,
    haystack_len: &Expr,
    row_base: Expr,
    prefix: &str,
) -> Vec<Node> {
    let start = format!("{prefix}_start");
    let len = format!("{prefix}_len");
    let hash = format!("{prefix}_hash");
    let i = format!("{prefix}_i");
    let byte = format!("{prefix}_byte");

    vec![
        Node::let_bind(
            &start,
            Expr::load(vast_nodes, Expr::add(row_base.clone(), Expr::u32(5))),
        ),
        Node::let_bind(
            &len,
            Expr::load(vast_nodes, Expr::add(row_base, Expr::u32(6))),
        ),
        Node::let_bind(&hash, Expr::u32(0x811c9dc5)),
        Node::loop_for(
            &i,
            Expr::u32(0),
            Expr::var(&len),
            vec![Node::if_then(
                Expr::lt(
                    Expr::add(Expr::var(&start), Expr::var(&i)),
                    haystack_len.clone(),
                ),
                vec![
                    Node::let_bind(
                        &byte,
                        Expr::load(haystack, Expr::add(Expr::var(&start), Expr::var(&i))),
                    ),
                    Node::assign(&hash, Expr::bitxor(Expr::var(&hash), Expr::var(&byte))),
                    Node::assign(&hash, Expr::mul(Expr::var(&hash), Expr::u32(0x01000193))),
                ],
            )],
        ),
    ]
}

fn emit_scope_open_for_index(
    vast_nodes: &str,
    idx: Expr,
    out_name: &str,
    prefix: &str,
) -> Vec<Node> {
    let depth = format!("{prefix}_depth");
    let scan = format!("{prefix}_scan");
    let rev = format!("{prefix}_idx");
    let kind = format!("{prefix}_kind");

    vec![
        Node::let_bind(out_name, Expr::u32(SENTINEL)),
        Node::let_bind(&depth, Expr::u32(0)),
        Node::loop_for(
            &scan,
            Expr::u32(0),
            idx.clone(),
            vec![
                Node::let_bind(
                    &rev,
                    Expr::sub(Expr::sub(idx, Expr::u32(1)), Expr::var(&scan)),
                ),
                Node::let_bind(
                    &kind,
                    Expr::load(
                        vast_nodes,
                        Expr::mul(Expr::var(&rev), Expr::u32(VAST_NODE_STRIDE_U32)),
                    ),
                ),
                Node::if_then(
                    Expr::eq(Expr::var(&kind), Expr::u32(TOK_RBRACE)),
                    vec![Node::assign(
                        &depth,
                        Expr::add(Expr::var(&depth), Expr::u32(1)),
                    )],
                ),
                Node::if_then(
                    Expr::eq(Expr::var(out_name), Expr::u32(SENTINEL)),
                    vec![Node::if_then(
                        Expr::eq(Expr::var(&kind), Expr::u32(TOK_LBRACE)),
                        vec![Node::if_then_else(
                            Expr::eq(Expr::var(&depth), Expr::u32(0)),
                            vec![Node::assign(out_name, Expr::var(&rev))],
                            vec![Node::assign(
                                &depth,
                                Expr::sub(Expr::var(&depth), Expr::u32(1)),
                            )],
                        )],
                    )],
                ),
            ],
        ),
    ]
}

fn emit_enclosing_function_lparen_for_index(
    vast_nodes: &str,
    idx: Expr,
    out_name: &str,
    prefix: &str,
) -> Vec<Node> {
    let base = format!("{prefix}_base");
    let parent = format!("{prefix}_parent");
    let parent_walk = format!("{prefix}_parent_walk");
    let parent_base = format!("{prefix}_parent_base");
    let parent_kind = format!("{prefix}_parent_kind");
    let parent_prev_kind = format!("{prefix}_parent_prev_kind");
    let scope = format!("{prefix}_scope");
    let scope_walk = format!("{prefix}_scope_walk");
    let scope_base = format!("{prefix}_scope_base");
    let scope_kind = format!("{prefix}_scope_kind");
    let candidate = format!("{prefix}_candidate");
    let paren_depth = format!("{prefix}_paren_depth");
    let scan = format!("{prefix}_scan");
    let rev = format!("{prefix}_rev");
    let scan_kind = format!("{prefix}_scan_kind");
    let scan_prev_kind = format!("{prefix}_scan_prev_kind");

    let mut nodes = vec![
        Node::let_bind(out_name, Expr::u32(SENTINEL)),
        Node::let_bind(
            &base,
            Expr::mul(idx.clone(), Expr::u32(VAST_NODE_STRIDE_U32)),
        ),
        Node::let_bind(
            &parent,
            Expr::load(vast_nodes, Expr::add(Expr::var(&base), Expr::u32(1))),
        ),
        Node::loop_for(
            &parent_walk,
            Expr::u32(0),
            Expr::var("annot_num_nodes"),
            vec![Node::if_then(
                Expr::and(
                    Expr::eq(Expr::var(out_name), Expr::u32(SENTINEL)),
                    Expr::lt(Expr::var(&parent), Expr::var("annot_num_nodes")),
                ),
                vec![
                    Node::let_bind(
                        &parent_base,
                        Expr::mul(Expr::var(&parent), Expr::u32(VAST_NODE_STRIDE_U32)),
                    ),
                    Node::let_bind(
                        &parent_kind,
                        Expr::load(vast_nodes, Expr::var(&parent_base)),
                    ),
                    Node::let_bind(
                        &parent_prev_kind,
                        Expr::select(
                            Expr::gt(Expr::var(&parent), Expr::u32(0)),
                            Expr::load(
                                vast_nodes,
                                Expr::mul(
                                    Expr::sub(Expr::var(&parent), Expr::u32(1)),
                                    Expr::u32(VAST_NODE_STRIDE_U32),
                                ),
                            ),
                            Expr::u32(SENTINEL),
                        ),
                    ),
                    Node::if_then(
                        Expr::and(
                            Expr::eq(Expr::var(&parent_kind), Expr::u32(TOK_LPAREN)),
                            Expr::eq(Expr::var(&parent_prev_kind), Expr::u32(TOK_IDENTIFIER)),
                        ),
                        vec![Node::assign(out_name, Expr::var(&parent))],
                    ),
                    Node::assign(
                        &parent,
                        Expr::load(vast_nodes, Expr::add(Expr::var(&parent_base), Expr::u32(1))),
                    ),
                ],
            )],
        ),
    ];

    nodes.extend(emit_scope_open_for_index(
        vast_nodes,
        idx,
        &scope,
        &format!("{prefix}_scope_open"),
    ));
    nodes.push(Node::loop_for(
        &scope_walk,
        Expr::u32(0),
        Expr::var("annot_num_nodes"),
        vec![Node::if_then(
            Expr::and(
                Expr::eq(Expr::var(out_name), Expr::u32(SENTINEL)),
                Expr::lt(Expr::var(&scope), Expr::var("annot_num_nodes")),
            ),
            vec![
                Node::let_bind(
                    &scope_base,
                    Expr::mul(Expr::var(&scope), Expr::u32(VAST_NODE_STRIDE_U32)),
                ),
                Node::let_bind(&scope_kind, Expr::load(vast_nodes, Expr::var(&scope_base))),
                Node::if_then(
                    Expr::eq(Expr::var(&scope_kind), Expr::u32(TOK_LBRACE)),
                    vec![
                        Node::let_bind(&candidate, Expr::u32(SENTINEL)),
                        Node::let_bind(&paren_depth, Expr::u32(0)),
                        Node::loop_for(
                            &scan,
                            Expr::u32(0),
                            Expr::var(&scope),
                            vec![
                                Node::let_bind(
                                    &rev,
                                    Expr::sub(
                                        Expr::sub(Expr::var(&scope), Expr::u32(1)),
                                        Expr::var(&scan),
                                    ),
                                ),
                                Node::let_bind(
                                    &scan_kind,
                                    Expr::load(
                                        vast_nodes,
                                        Expr::mul(Expr::var(&rev), Expr::u32(VAST_NODE_STRIDE_U32)),
                                    ),
                                ),
                                Node::if_then(
                                    Expr::eq(Expr::var(&scan_kind), Expr::u32(TOK_RPAREN)),
                                    vec![Node::assign(
                                        &paren_depth,
                                        Expr::add(Expr::var(&paren_depth), Expr::u32(1)),
                                    )],
                                ),
                                Node::if_then(
                                    Expr::and(
                                        Expr::eq(Expr::var(&scan_kind), Expr::u32(TOK_LPAREN)),
                                        Expr::gt(Expr::var(&paren_depth), Expr::u32(0)),
                                    ),
                                    vec![
                                        Node::assign(
                                            &paren_depth,
                                            Expr::sub(Expr::var(&paren_depth), Expr::u32(1)),
                                        ),
                                        Node::if_then(
                                            Expr::and(
                                                Expr::eq(Expr::var(&paren_depth), Expr::u32(0)),
                                                Expr::eq(
                                                    Expr::var(&candidate),
                                                    Expr::u32(SENTINEL),
                                                ),
                                            ),
                                            vec![
                                                Node::let_bind(
                                                    &scan_prev_kind,
                                                    Expr::select(
                                                        Expr::gt(Expr::var(&rev), Expr::u32(0)),
                                                        Expr::load(
                                                            vast_nodes,
                                                            Expr::mul(
                                                                Expr::sub(
                                                                    Expr::var(&rev),
                                                                    Expr::u32(1),
                                                                ),
                                                                Expr::u32(VAST_NODE_STRIDE_U32),
                                                            ),
                                                        ),
                                                        Expr::u32(SENTINEL),
                                                    ),
                                                ),
                                                Node::if_then(
                                                    Expr::eq(
                                                        Expr::var(&scan_prev_kind),
                                                        Expr::u32(TOK_IDENTIFIER),
                                                    ),
                                                    vec![Node::assign(&candidate, Expr::var(&rev))],
                                                ),
                                            ],
                                        ),
                                    ],
                                ),
                            ],
                        ),
                        Node::if_then(
                            Expr::ne(Expr::var(&candidate), Expr::u32(SENTINEL)),
                            vec![Node::assign(out_name, Expr::var(&candidate))],
                        ),
                    ],
                ),
                Node::assign(
                    &scope,
                    Expr::load(vast_nodes, Expr::add(Expr::var(&scope_base), Expr::u32(1))),
                ),
            ],
        )],
    ));
    nodes
}

fn emit_declaration_kind_for_index(
    vast_nodes: &str,
    haystack: &str,
    haystack_len: &Expr,
    idx: Expr,
    out_name: &str,
    prefix: &str,
) -> Vec<Node> {
    emit_declaration_kind_for_index_inner(
        vast_nodes,
        idx,
        out_name,
        prefix,
        Some((haystack, haystack_len)),
    )
}

fn emit_builtin_declaration_kind_for_index(
    vast_nodes: &str,
    idx: Expr,
    out_name: &str,
    prefix: &str,
) -> Vec<Node> {
    emit_declaration_kind_for_index_inner(vast_nodes, idx, out_name, prefix, None)
}

fn emit_identifier_source_hash_for_index(
    vast_nodes: &str,
    haystack: &str,
    haystack_len: &Expr,
    idx: Expr,
    out_name: &str,
    prefix: &str,
) -> Vec<Node> {
    let base = format!("{prefix}_hash_base");
    let start = format!("{prefix}_hash_start");
    let len = format!("{prefix}_hash_len");
    let cursor = format!("{prefix}_hash_i");
    let byte = format!("{prefix}_hash_byte");

    vec![
        Node::let_bind(out_name, Expr::u32(0x811c9dc5)),
        Node::let_bind(&base, Expr::mul(idx, Expr::u32(VAST_NODE_STRIDE_U32))),
        Node::let_bind(
            &start,
            Expr::load(vast_nodes, Expr::add(Expr::var(&base), Expr::u32(5))),
        ),
        Node::let_bind(
            &len,
            Expr::load(vast_nodes, Expr::add(Expr::var(&base), Expr::u32(6))),
        ),
        Node::loop_for(
            &cursor,
            Expr::u32(0),
            Expr::var(&len),
            vec![Node::if_then(
                Expr::lt(
                    Expr::add(Expr::var(&start), Expr::var(&cursor)),
                    haystack_len.clone(),
                ),
                vec![
                    Node::let_bind(
                        &byte,
                        Expr::load(haystack, Expr::add(Expr::var(&start), Expr::var(&cursor))),
                    ),
                    Node::assign(
                        out_name,
                        Expr::bitxor(Expr::var(out_name), Expr::var(&byte)),
                    ),
                    Node::assign(
                        out_name,
                        Expr::mul(Expr::var(out_name), Expr::u32(0x01000193)),
                    ),
                ],
            )],
        ),
    ]
}

fn emit_declaration_kind_for_index_inner(
    vast_nodes: &str,
    idx: Expr,
    out_name: &str,
    prefix: &str,
    prefix_typedef_lookup: Option<(&str, &Expr)>,
) -> Vec<Node> {
    let base = format!("{prefix}_base");
    let kind = format!("{prefix}_kind");
    let prev_idx = format!("{prefix}_prev_idx");
    let prev_prev_idx = format!("{prefix}_prev_prev_idx");
    let next_idx = format!("{prefix}_next_idx");
    let prev_kind = format!("{prefix}_prev_kind");
    let prev_prev_kind = format!("{prefix}_prev_prev_kind");
    let next_kind = format!("{prefix}_next_kind");
    let parent_idx = format!("{prefix}_parent_idx");
    let parent_kind = format!("{prefix}_parent_kind");
    let parent_parent_idx = format!("{prefix}_parent_parent_idx");
    let parent_prev_kind = format!("{prefix}_parent_prev_kind");
    let parent_prev_prev_kind = format!("{prefix}_parent_prev_prev_kind");
    let parent_aggregate_prefix = format!("{prefix}_parent_aggregate_prefix");
    let parent_aggregate_scan = format!("{prefix}_parent_aggregate_scan");
    let parent_aggregate_base = format!("{prefix}_parent_aggregate_base");
    let parent_aggregate_kind = format!("{prefix}_parent_aggregate_kind");
    let parent_aggregate_parent = format!("{prefix}_parent_aggregate_parent");
    let in_aggregate_body = format!("{prefix}_in_aggregate_body");
    let prefix_has_typedef = format!("{prefix}_has_typedef");
    let prefix_has_type = format!("{prefix}_has_type");
    let prefix_done = format!("{prefix}_prefix_done");
    let prefix_skipped_paren_depth = format!("{prefix}_prefix_skipped_paren_depth");
    let prefix_skipped_brace_depth = format!("{prefix}_prefix_skipped_brace_depth");
    let prefix_scan = format!("{prefix}_prefix_scan");
    let prefix_idx = format!("{prefix}_prefix_idx");
    let prefix_base = format!("{prefix}_prefix_base");
    let prefix_kind = format!("{prefix}_prefix_kind");
    let prefix_symbol_hash = format!("{prefix}_prefix_symbol_hash");
    let prefix_in_skipped_paren = format!("{prefix}_prefix_in_skipped_paren");
    let prefix_in_skipped_brace = format!("{prefix}_prefix_in_skipped_brace");
    let prefix_visible_typedef = format!("{prefix}_prefix_visible_typedef");
    let is_identifier = format!("{prefix}_is_identifier");
    let declarator_follower = format!("{prefix}_declarator_follower");
    let sizeof_type_operand = format!("{prefix}_sizeof_type_operand");
    let cast_pointer_expr_operand = format!("{prefix}_cast_pointer_expr_operand");
    let prefix_typedef_lookup_node = if let Some((haystack, haystack_len)) = prefix_typedef_lookup {
        Node::if_then(
            Expr::eq(Expr::var(&prefix_kind), Expr::u32(TOK_IDENTIFIER)),
            {
                let mut body = emit_identifier_source_hash_for_index(
                    vast_nodes,
                    haystack,
                    haystack_len,
                    Expr::var(&prefix_idx),
                    &prefix_symbol_hash,
                    &format!("{prefix}_prefix_hash"),
                );
                body.push(Node::if_then(
                    is_gnu_typeof_symbol_hash(Expr::var(&prefix_symbol_hash)),
                    vec![Node::assign(&prefix_has_type, Expr::u32(1))],
                ));
                body.extend(emit_visible_typedef_name_for_index(
                    vast_nodes,
                    haystack,
                    haystack_len,
                    Expr::var(&prefix_idx),
                    &prefix_visible_typedef,
                    &format!("{prefix}_prefix_type_name"),
                ));
                body.push(Node::if_then(
                    Expr::eq(Expr::var(&prefix_visible_typedef), Expr::u32(1)),
                    vec![Node::assign(&prefix_has_type, Expr::u32(1))],
                ));
                body
            },
        )
    } else {
        Node::if_then(Expr::u32(0), Vec::new())
    };

    vec![
        Node::let_bind(out_name, Expr::u32(0)),
        Node::let_bind(
            &base,
            Expr::mul(idx.clone(), Expr::u32(VAST_NODE_STRIDE_U32)),
        ),
        Node::let_bind(&kind, Expr::load(vast_nodes, Expr::var(&base))),
        Node::let_bind(
            &parent_idx,
            Expr::load(vast_nodes, Expr::add(Expr::var(&base), Expr::u32(1))),
        ),
        Node::let_bind(
            &parent_kind,
            Expr::select(
                Expr::lt(Expr::var(&parent_idx), Expr::var("annot_num_nodes")),
                Expr::load(
                    vast_nodes,
                    Expr::mul(Expr::var(&parent_idx), Expr::u32(VAST_NODE_STRIDE_U32)),
                ),
                Expr::u32(SENTINEL),
            ),
        ),
        Node::let_bind(
            &parent_parent_idx,
            Expr::select(
                Expr::lt(Expr::var(&parent_idx), Expr::var("annot_num_nodes")),
                Expr::load(
                    vast_nodes,
                    Expr::add(
                        Expr::mul(Expr::var(&parent_idx), Expr::u32(VAST_NODE_STRIDE_U32)),
                        Expr::u32(1),
                    ),
                ),
                Expr::u32(SENTINEL),
            ),
        ),
        Node::let_bind(
            &parent_prev_kind,
            Expr::select(
                Expr::and(
                    Expr::lt(Expr::var(&parent_idx), Expr::var("annot_num_nodes")),
                    Expr::gt(Expr::var(&parent_idx), Expr::u32(0)),
                ),
                Expr::load(
                    vast_nodes,
                    Expr::mul(
                        Expr::sub(Expr::var(&parent_idx), Expr::u32(1)),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Expr::u32(SENTINEL),
            ),
        ),
        Node::let_bind(
            &parent_prev_prev_kind,
            Expr::select(
                Expr::and(
                    Expr::lt(Expr::var(&parent_idx), Expr::var("annot_num_nodes")),
                    Expr::gt(Expr::var(&parent_idx), Expr::u32(1)),
                ),
                Expr::load(
                    vast_nodes,
                    Expr::mul(
                        Expr::sub(Expr::var(&parent_idx), Expr::u32(2)),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Expr::u32(SENTINEL),
            ),
        ),
        Node::let_bind(&parent_aggregate_prefix, Expr::u32(0)),
        Node::if_then(
            Expr::eq(Expr::var(&parent_kind), Expr::u32(TOK_LBRACE)),
            vec![Node::loop_for(
                &parent_aggregate_scan,
                Expr::u32(0),
                Expr::var(&parent_idx),
                vec![
                    Node::let_bind(
                        &parent_aggregate_base,
                        Expr::mul(
                            Expr::var(&parent_aggregate_scan),
                            Expr::u32(VAST_NODE_STRIDE_U32),
                        ),
                    ),
                    Node::let_bind(
                        &parent_aggregate_kind,
                        Expr::load(vast_nodes, Expr::var(&parent_aggregate_base)),
                    ),
                    Node::let_bind(
                        &parent_aggregate_parent,
                        Expr::load(
                            vast_nodes,
                            Expr::add(Expr::var(&parent_aggregate_base), Expr::u32(1)),
                        ),
                    ),
                    Node::if_then(
                        Expr::eq(
                            Expr::var(&parent_aggregate_parent),
                            Expr::var(&parent_parent_idx),
                        ),
                        vec![
                            Node::if_then(
                                any_token_eq(
                                    Expr::var(&parent_aggregate_kind),
                                    &[TOK_SEMICOLON, TOK_ASSIGN, TOK_COMMA],
                                ),
                                vec![Node::assign(&parent_aggregate_prefix, Expr::u32(0))],
                            ),
                            Node::if_then(
                                any_token_eq(
                                    Expr::var(&parent_aggregate_kind),
                                    &[TOK_STRUCT, TOK_UNION, TOK_ENUM],
                                ),
                                vec![Node::assign(&parent_aggregate_prefix, Expr::u32(1))],
                            ),
                        ],
                    ),
                ],
            )],
        ),
        Node::let_bind(
            &in_aggregate_body,
            Expr::and(
                Expr::eq(Expr::var(&parent_kind), Expr::u32(TOK_LBRACE)),
                Expr::eq(Expr::var(&parent_aggregate_prefix), Expr::u32(1)),
            ),
        ),
        Node::let_bind(
            &prev_idx,
            Expr::select(
                Expr::gt(idx.clone(), Expr::u32(0)),
                Expr::sub(idx.clone(), Expr::u32(1)),
                idx.clone(),
            ),
        ),
        Node::let_bind(
            &prev_prev_idx,
            Expr::select(
                Expr::gt(idx.clone(), Expr::u32(1)),
                Expr::sub(idx.clone(), Expr::u32(2)),
                idx.clone(),
            ),
        ),
        Node::let_bind(&next_idx, Expr::add(idx.clone(), Expr::u32(1))),
        Node::let_bind(
            &prev_kind,
            Expr::select(
                Expr::gt(idx.clone(), Expr::u32(0)),
                Expr::load(
                    vast_nodes,
                    Expr::mul(Expr::var(&prev_idx), Expr::u32(VAST_NODE_STRIDE_U32)),
                ),
                Expr::u32(SENTINEL),
            ),
        ),
        Node::let_bind(
            &prev_prev_kind,
            Expr::select(
                Expr::gt(idx.clone(), Expr::u32(1)),
                Expr::load(
                    vast_nodes,
                    Expr::mul(Expr::var(&prev_prev_idx), Expr::u32(VAST_NODE_STRIDE_U32)),
                ),
                Expr::u32(SENTINEL),
            ),
        ),
        Node::let_bind(
            &next_kind,
            Expr::select(
                Expr::lt(Expr::var(&next_idx), Expr::var("annot_num_nodes")),
                Expr::load(
                    vast_nodes,
                    Expr::mul(Expr::var(&next_idx), Expr::u32(VAST_NODE_STRIDE_U32)),
                ),
                Expr::u32(SENTINEL),
            ),
        ),
        Node::let_bind(&prefix_has_typedef, Expr::u32(0)),
        Node::let_bind(&prefix_has_type, Expr::u32(0)),
        Node::let_bind(&prefix_done, Expr::u32(0)),
        Node::let_bind(&prefix_skipped_paren_depth, Expr::u32(0)),
        Node::let_bind(&prefix_skipped_brace_depth, Expr::u32(0)),
        Node::loop_for(
            &prefix_scan,
            Expr::u32(0),
            idx.clone(),
            vec![Node::if_then(
                Expr::eq(Expr::var(&prefix_done), Expr::u32(0)),
                vec![
                    Node::let_bind(
                        &prefix_idx,
                        Expr::sub(
                            Expr::sub(idx.clone(), Expr::u32(1)),
                            Expr::var(&prefix_scan),
                        ),
                    ),
                    Node::let_bind(
                        &prefix_base,
                        Expr::mul(Expr::var(&prefix_idx), Expr::u32(VAST_NODE_STRIDE_U32)),
                    ),
                    Node::let_bind(
                        &prefix_kind,
                        Expr::load(vast_nodes, Expr::var(&prefix_base)),
                    ),
                    Node::let_bind(
                        &prefix_in_skipped_paren,
                        Expr::or(
                            Expr::gt(Expr::var(&prefix_skipped_paren_depth), Expr::u32(0)),
                            Expr::eq(Expr::var(&prefix_kind), Expr::u32(TOK_RPAREN)),
                        ),
                    ),
                    Node::let_bind(
                        &prefix_in_skipped_brace,
                        Expr::or(
                            Expr::gt(Expr::var(&prefix_skipped_brace_depth), Expr::u32(0)),
                            Expr::eq(Expr::var(&prefix_kind), Expr::u32(TOK_RBRACE)),
                        ),
                    ),
                    Node::if_then(
                        Expr::eq(Expr::var(&prefix_kind), Expr::u32(TOK_RBRACE)),
                        vec![Node::assign(
                            &prefix_skipped_brace_depth,
                            Expr::add(Expr::var(&prefix_skipped_brace_depth), Expr::u32(1)),
                        )],
                    ),
                    Node::if_then(
                        Expr::and(
                            Expr::gt(Expr::var(&prefix_skipped_brace_depth), Expr::u32(0)),
                            Expr::eq(Expr::var(&prefix_kind), Expr::u32(TOK_LBRACE)),
                        ),
                        vec![Node::assign(
                            &prefix_skipped_brace_depth,
                            Expr::sub(Expr::var(&prefix_skipped_brace_depth), Expr::u32(1)),
                        )],
                    ),
                    Node::if_then(
                        Expr::eq(Expr::var(&prefix_kind), Expr::u32(TOK_RPAREN)),
                        vec![Node::assign(
                            &prefix_skipped_paren_depth,
                            Expr::add(Expr::var(&prefix_skipped_paren_depth), Expr::u32(1)),
                        )],
                    ),
                    Node::if_then(
                        Expr::and(
                            Expr::gt(Expr::var(&prefix_skipped_paren_depth), Expr::u32(0)),
                            Expr::eq(Expr::var(&prefix_kind), Expr::u32(TOK_LPAREN)),
                        ),
                        vec![Node::assign(
                            &prefix_skipped_paren_depth,
                            Expr::sub(Expr::var(&prefix_skipped_paren_depth), Expr::u32(1)),
                        )],
                    ),
                    Node::if_then(
                        Expr::not(Expr::or(
                            Expr::var(&prefix_in_skipped_brace),
                            Expr::var(&prefix_in_skipped_paren),
                        )),
                        vec![
                            Node::if_then(
                                is_decl_prefix_reset_token(Expr::var(&prefix_kind)),
                                vec![Node::assign(&prefix_done, Expr::u32(1))],
                            ),
                            Node::if_then(
                                Expr::eq(Expr::var(&prefix_kind), Expr::u32(TOK_TYPEDEF)),
                                vec![Node::assign(&prefix_has_typedef, Expr::u32(1))],
                            ),
                            Node::if_then(
                                is_decl_prefix_token(Expr::var(&prefix_kind)),
                                vec![Node::assign(&prefix_has_type, Expr::u32(1))],
                            ),
                            prefix_typedef_lookup_node,
                        ],
                    ),
                ],
            )],
        ),
        Node::let_bind(
            &is_identifier,
            Expr::eq(Expr::var(&kind), Expr::u32(TOK_IDENTIFIER)),
        ),
        Node::let_bind(
            &declarator_follower,
            any_token_eq(
                Expr::var(&next_kind),
                &[
                    TOK_SEMICOLON,
                    TOK_COMMA,
                    TOK_ASSIGN,
                    TOK_LBRACKET,
                    TOK_LPAREN,
                    TOK_RPAREN,
                ],
            ),
        ),
        Node::let_bind(
            &sizeof_type_operand,
            Expr::and(
                Expr::eq(Expr::var(&prev_kind), Expr::u32(TOK_LPAREN)),
                any_token_eq(
                    Expr::var(&parent_prev_kind),
                    &[TOK_SIZEOF, TOK_GNU_TYPEOF, TOK_ALIGNOF],
                ),
            ),
        ),
        Node::let_bind(
            &cast_pointer_expr_operand,
            Expr::and(
                Expr::eq(Expr::var(&prev_kind), Expr::u32(TOK_STAR)),
                Expr::eq(Expr::var(&prev_prev_kind), Expr::u32(TOK_RPAREN)),
            ),
        ),
        Node::if_then(
            Expr::and(
                Expr::var(&is_identifier),
                Expr::and(
                    Expr::and(
                        Expr::not(any_token_eq(
                            Expr::var(&prev_kind),
                            &[TOK_STRUCT, TOK_UNION, TOK_ENUM, TOK_DOT, TOK_ARROW],
                        )),
                        Expr::and(
                            Expr::ne(Expr::var(&next_kind), Expr::u32(TOK_COLON)),
                            Expr::and(
                                Expr::not(Expr::var(&in_aggregate_body)),
                                Expr::and(
                                    Expr::not(Expr::var(&sizeof_type_operand)),
                                    Expr::not(Expr::var(&cast_pointer_expr_operand)),
                                ),
                            ),
                        ),
                    ),
                    Expr::and(
                        Expr::var(&declarator_follower),
                        Expr::or(
                            Expr::eq(Expr::var(&prefix_has_typedef), Expr::u32(1)),
                            Expr::eq(Expr::var(&prefix_has_type), Expr::u32(1)),
                        ),
                    ),
                ),
            ),
            vec![Node::if_then_else(
                Expr::eq(Expr::var(&prefix_has_typedef), Expr::u32(1)),
                vec![Node::assign(out_name, Expr::u32(1))],
                vec![Node::assign(out_name, Expr::u32(2))],
            )],
        ),
    ]
}

fn emit_visible_typedef_name_for_index(
    vast_nodes: &str,
    haystack: &str,
    haystack_len: &Expr,
    idx: Expr,
    out_name: &str,
    prefix: &str,
) -> Vec<Node> {
    let target_base = format!("{prefix}_target_base");
    let target_scope = format!("{prefix}_target_scope");
    let target_function = format!("{prefix}_target_function");
    let last_decl_kind = format!("{prefix}_last_decl_kind");
    let scan = format!("{prefix}_scan");
    let scan_base = format!("{prefix}_scan_base");
    let scan_kind = format!("{prefix}_scan_kind");
    let scan_scope = format!("{prefix}_scan_scope");
    let scan_function = format!("{prefix}_scan_function");
    let scan_decl_kind = format!("{prefix}_scan_decl_result_kind");
    let scope_walk = format!("{prefix}_scope_walk");
    let scope_walk_depth = format!("{prefix}_scope_walk_depth");
    let same_name = format!("{prefix}_same_name");
    let visible_scope = format!("{prefix}_visible_scope");
    let visible_function = format!("{prefix}_visible_function");

    let mut nodes = vec![
        Node::let_bind(out_name, Expr::u32(0)),
        Node::let_bind(
            &target_base,
            Expr::mul(idx.clone(), Expr::u32(VAST_NODE_STRIDE_U32)),
        ),
    ];
    nodes.extend(emit_identifier_hash_for_row(
        vast_nodes,
        haystack,
        haystack_len,
        Expr::var(&target_base),
        &format!("{prefix}_target"),
    ));
    nodes.extend(emit_scope_open_for_index(
        vast_nodes,
        idx.clone(),
        &target_scope,
        &format!("{prefix}_scope"),
    ));
    nodes.extend(emit_enclosing_function_lparen_for_index(
        vast_nodes,
        idx.clone(),
        &target_function,
        &format!("{prefix}_function"),
    ));
    nodes.push(Node::let_bind(&last_decl_kind, Expr::u32(0)));
    nodes.push(Node::loop_for(
        &scan,
        Expr::u32(0),
        idx,
        vec![
            Node::let_bind(
                &scan_base,
                Expr::mul(Expr::var(&scan), Expr::u32(VAST_NODE_STRIDE_U32)),
            ),
            Node::let_bind(&scan_kind, Expr::load(vast_nodes, Expr::var(&scan_base))),
            Node::if_then(
                Expr::eq(Expr::var(&scan_kind), Expr::u32(TOK_IDENTIFIER)),
                {
                    let scan_hash_prefix = format!("{prefix}_scan_hash");
                    let target_hash = format!("{prefix}_target_hash");
                    let target_len = format!("{prefix}_target_len");
                    let mut body = emit_identifier_hash_for_row(
                        vast_nodes,
                        haystack,
                        haystack_len,
                        Expr::var(&scan_base),
                        &scan_hash_prefix,
                    );
                    body.extend(emit_scope_open_for_index(
                        vast_nodes,
                        Expr::var(&scan),
                        &scan_scope,
                        &format!("{prefix}_scan_scope"),
                    ));
                    body.extend(emit_enclosing_function_lparen_for_index(
                        vast_nodes,
                        Expr::var(&scan),
                        &scan_function,
                        &format!("{prefix}_scan_function"),
                    ));
                    body.extend(emit_builtin_declaration_kind_for_index(
                        vast_nodes,
                        Expr::var(&scan),
                        &scan_decl_kind,
                        &format!("{prefix}_scan_decl"),
                    ));
                    body.push(Node::let_bind(
                        &same_name,
                        Expr::and(
                            Expr::eq(
                                Expr::var(format!("{scan_hash_prefix}_hash")),
                                Expr::var(&target_hash),
                            ),
                            Expr::eq(
                                Expr::var(format!("{scan_hash_prefix}_len")),
                                Expr::var(&target_len),
                            ),
                        ),
                    ));
                    body.push(Node::let_bind(
                        &visible_function,
                        Expr::or(
                            Expr::ne(Expr::var(&scan_decl_kind), Expr::u32(2)),
                            Expr::or(
                                Expr::eq(Expr::var(&scan_function), Expr::u32(SENTINEL)),
                                Expr::eq(Expr::var(&scan_function), Expr::var(&target_function)),
                            ),
                        ),
                    ));
                    body.push(Node::let_bind(
                        &visible_scope,
                        Expr::eq(Expr::var(&scan_scope), Expr::u32(SENTINEL)),
                    ));
                    body.push(Node::let_bind(&scope_walk, Expr::var(&target_scope)));
                    body.push(Node::loop_for(
                        &scope_walk_depth,
                        Expr::u32(0),
                        Expr::var("annot_num_nodes"),
                        vec![
                            Node::if_then(
                                Expr::eq(Expr::var(&scope_walk), Expr::var(&scan_scope)),
                                vec![Node::assign(&visible_scope, Expr::bool(true))],
                            ),
                            Node::if_then(
                                Expr::ne(Expr::var(&scope_walk), Expr::u32(SENTINEL)),
                                vec![Node::assign(
                                    &scope_walk,
                                    Expr::load(
                                        vast_nodes,
                                        Expr::add(
                                            Expr::mul(
                                                Expr::var(&scope_walk),
                                                Expr::u32(VAST_NODE_STRIDE_U32),
                                            ),
                                            Expr::u32(1),
                                        ),
                                    ),
                                )],
                            ),
                        ],
                    ));
                    body.push(Node::if_then(
                        Expr::and(
                            Expr::var(&same_name),
                            Expr::and(
                                Expr::var(&visible_scope),
                                Expr::and(
                                    Expr::var(&visible_function),
                                    Expr::ne(Expr::var(&scan_decl_kind), Expr::u32(0)),
                                ),
                            ),
                        ),
                        vec![Node::assign(&last_decl_kind, Expr::var(&scan_decl_kind))],
                    ));
                    body
                },
            ),
        ],
    ));
    nodes.push(Node::if_then(
        Expr::eq(Expr::var(&last_decl_kind), Expr::u32(1)),
        vec![Node::assign(out_name, Expr::u32(1))],
    ));
    nodes
}

fn emit_typedef_visibility_scan(
    vast_nodes: &str,
    haystack: &str,
    haystack_len: &Expr,
    num_nodes: &Expr,
    t: Expr,
) -> Vec<Node> {
    let mut nodes = vec![Node::let_bind("annot_num_nodes", num_nodes.clone())];
    nodes.extend(emit_visible_typedef_name_for_index(
        vast_nodes,
        haystack,
        haystack_len,
        t,
        "current_visible_typedef_name",
        "current_visible_typedef",
    ));
    nodes.push(Node::assign(
        "last_decl_kind",
        Expr::select(
            Expr::eq(Expr::var("current_visible_typedef_name"), Expr::u32(1)),
            Expr::u32(1),
            Expr::u32(0),
        ),
    ));
    nodes
}

fn emit_current_declaration_annotation(
    vast_nodes: &str,
    haystack: &str,
    haystack_len: &Expr,
    t: Expr,
    _num_nodes: &Expr,
) -> Vec<Node> {
    let mut nodes = Vec::new();
    nodes.extend(emit_declaration_kind_for_index(
        vast_nodes,
        haystack,
        haystack_len,
        t,
        "current_decl_result_kind",
        "current_decl",
    ));
    nodes.push(Node::let_bind(
        "current_decl_flags",
        Expr::select(
            Expr::eq(Expr::var("current_decl_result_kind"), Expr::u32(1)),
            Expr::u32(C_TYPEDEF_FLAG_TYPEDEF_DECLARATOR),
            Expr::select(
                Expr::eq(Expr::var("current_decl_result_kind"), Expr::u32(2)),
                Expr::u32(C_TYPEDEF_FLAG_ORDINARY_DECLARATOR),
                Expr::u32(0),
            ),
        ),
    ));
    nodes
}

/// Annotate VAST rows with C ordinary-identifier namespace facts.
///
/// The structural VAST row remains a 10-word record. This pass writes only the
/// parser-reserved annotation words:
///
/// - word 7: typedef/name flags
/// - word 8: nearest lexical scope opener token index, or `u32::MAX`
/// - word 9: FNV-1a identifier symbol hash
///
/// The classifier consumes word 7 to distinguish typedef names from expression
/// identifiers without corpus-specific heuristics.
#[must_use]
pub fn c11_annotate_typedef_names(
    vast_nodes: &str,
    haystack: &str,
    haystack_len: Expr,
    num_nodes: Expr,
    out_annotated_vast_nodes: &str,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let base = Expr::mul(t.clone(), Expr::u32(VAST_NODE_STRIDE_U32));

    let mut loop_body = vec![
        Node::let_bind("raw_kind", Expr::load(vast_nodes, base.clone())),
        Node::let_bind(
            "tok_start",
            Expr::load(vast_nodes, Expr::add(base.clone(), Expr::u32(5))),
        ),
        Node::let_bind(
            "tok_len",
            Expr::load(vast_nodes, Expr::add(base.clone(), Expr::u32(6))),
        ),
        Node::let_bind("name_hash", Expr::u32(0)),
        Node::if_then(
            Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_IDENTIFIER)),
            vec![
                Node::assign("name_hash", Expr::u32(0x811c9dc5)),
                Node::loop_for(
                    "hash_i",
                    Expr::u32(0),
                    Expr::var("tok_len"),
                    vec![Node::if_then(
                        Expr::lt(
                            Expr::add(Expr::var("tok_start"), Expr::var("hash_i")),
                            haystack_len.clone(),
                        ),
                        vec![
                            Node::let_bind(
                                "hash_byte",
                                Expr::load(
                                    haystack,
                                    Expr::add(Expr::var("tok_start"), Expr::var("hash_i")),
                                ),
                            ),
                            Node::assign(
                                "name_hash",
                                Expr::bitxor(Expr::var("name_hash"), Expr::var("hash_byte")),
                            ),
                            Node::assign(
                                "name_hash",
                                Expr::mul(Expr::var("name_hash"), Expr::u32(0x01000193)),
                            ),
                        ],
                    )],
                ),
            ],
        ),
        Node::let_bind("scope_open", Expr::u32(SENTINEL)),
        Node::let_bind("scope_depth", Expr::u32(0)),
        Node::loop_for(
            "scope_scan",
            Expr::u32(0),
            t.clone(),
            vec![
                Node::let_bind(
                    "scope_idx",
                    Expr::sub(Expr::sub(t.clone(), Expr::u32(1)), Expr::var("scope_scan")),
                ),
                Node::let_bind(
                    "scope_kind",
                    Expr::load(
                        vast_nodes,
                        Expr::mul(Expr::var("scope_idx"), Expr::u32(VAST_NODE_STRIDE_U32)),
                    ),
                ),
                Node::if_then(
                    Expr::eq(Expr::var("scope_kind"), Expr::u32(TOK_RBRACE)),
                    vec![Node::assign(
                        "scope_depth",
                        Expr::add(Expr::var("scope_depth"), Expr::u32(1)),
                    )],
                ),
                Node::if_then(
                    Expr::eq(Expr::var("scope_open"), Expr::u32(SENTINEL)),
                    vec![Node::if_then(
                        Expr::eq(Expr::var("scope_kind"), Expr::u32(TOK_LBRACE)),
                        vec![Node::if_then_else(
                            Expr::eq(Expr::var("scope_depth"), Expr::u32(0)),
                            vec![Node::assign("scope_open", Expr::var("scope_idx"))],
                            vec![Node::assign(
                                "scope_depth",
                                Expr::sub(Expr::var("scope_depth"), Expr::u32(1)),
                            )],
                        )],
                    )],
                ),
            ],
        ),
        Node::let_bind("last_decl_kind", Expr::u32(0)),
    ];

    loop_body.extend(emit_typedef_visibility_scan(
        vast_nodes,
        haystack,
        &haystack_len,
        &num_nodes,
        t.clone(),
    ));
    loop_body.extend(emit_current_declaration_annotation(
        vast_nodes,
        haystack,
        &haystack_len,
        t.clone(),
        &num_nodes,
    ));

    loop_body.extend([
        Node::let_bind("typedef_flags", Expr::u32(0)),
        Node::if_then(
            Expr::and(
                Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_IDENTIFIER)),
                Expr::and(
                    Expr::eq(Expr::var("last_decl_kind"), Expr::u32(1)),
                    Expr::eq(Expr::var("current_decl_result_kind"), Expr::u32(0)),
                ),
            ),
            vec![Node::assign(
                "typedef_flags",
                Expr::bitor(
                    Expr::var("typedef_flags"),
                    Expr::u32(C_TYPEDEF_FLAG_VISIBLE_TYPEDEF_NAME),
                ),
            )],
        ),
        Node::if_then(
            is_typedef_declarator_annotation(Expr::var("current_decl_flags")),
            vec![Node::assign(
                "typedef_flags",
                Expr::bitor(
                    Expr::var("typedef_flags"),
                    Expr::u32(C_TYPEDEF_FLAG_TYPEDEF_DECLARATOR),
                ),
            )],
        ),
        Node::if_then(
            is_ordinary_declarator_annotation(Expr::var("current_decl_flags")),
            vec![Node::assign(
                "typedef_flags",
                Expr::bitor(
                    Expr::var("typedef_flags"),
                    Expr::u32(C_TYPEDEF_FLAG_ORDINARY_DECLARATOR),
                ),
            )],
        ),
    ]);

    for field in 0..VAST_NODE_STRIDE_U32 {
        let value = match field {
            VAST_TYPEDEF_FLAGS_FIELD => Expr::var("typedef_flags"),
            VAST_TYPEDEF_SCOPE_FIELD => Expr::var("scope_open"),
            VAST_TYPEDEF_SYMBOL_FIELD => Expr::var("name_hash"),
            _ => Expr::load(vast_nodes, Expr::add(base.clone(), Expr::u32(field))),
        };
        loop_body.push(Node::store(
            out_annotated_vast_nodes,
            Expr::add(base.clone(), Expr::u32(field)),
            value,
        ));
    }

    let n = node_count(&num_nodes).max(1);
    Program::wrapped(
        vec![
            BufferDecl::storage(vast_nodes, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.saturating_mul(VAST_NODE_STRIDE_U32)),
            BufferDecl::storage(haystack, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(node_count(&haystack_len).max(1)),
            BufferDecl::storage(
                out_annotated_vast_nodes,
                2,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(n.saturating_mul(VAST_NODE_STRIDE_U32)),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            ANNOTATE_TYPEDEF_OP_ID,
            vec![Node::if_then(Expr::lt(t, num_nodes), loop_body)],
        )],
    )
    .with_entry_op_id(ANNOTATE_TYPEDEF_OP_ID)
    .with_non_composable_with_self(true)
}

/// Classify token-level C VAST rows into canonical ProgramGraph node kinds.
///
/// The delimiter VAST builder is intentionally syntax-light: it recovers
/// balanced tree links and source spans. This pass is the first semantic C
/// parser layer over that handoff. It keeps the packed row layout stable while
/// rewriting row kind word 0 to graph kinds consumed by structural predicates.
#[must_use]
pub fn c11_classify_vast_node_kinds(
    vast_nodes: &str,
    num_nodes: Expr,
    out_typed_vast_nodes: &str,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let base = Expr::mul(t.clone(), Expr::u32(VAST_NODE_STRIDE_U32));

    let mut loop_body = vec![
        Node::let_bind("raw_kind", Expr::load(vast_nodes, base.clone())),
        Node::let_bind(
            "current_symbol_hash",
            Expr::load(
                vast_nodes,
                Expr::add(base.clone(), Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD)),
            ),
        ),
        Node::let_bind(
            "cur_parent",
            Expr::load(vast_nodes, Expr::add(base.clone(), Expr::u32(1))),
        ),
        Node::let_bind("prev_sibling_kind", Expr::u32(SENTINEL)),
        Node::let_bind("prev_prev_sibling_kind", Expr::u32(SENTINEL)),
        Node::let_bind("prev_sibling_symbol_hash", Expr::u32(0)),
        Node::let_bind("prev_sibling_idx", Expr::u32(SENTINEL)),
        Node::loop_for(
            "prev_sibling_scan",
            Expr::u32(0),
            t.clone(),
            vec![
                Node::let_bind(
                    "prev_scan_base",
                    Expr::mul(
                        Expr::var("prev_sibling_scan"),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Node::let_bind(
                    "prev_scan_parent",
                    Expr::load(
                        vast_nodes,
                        Expr::add(Expr::var("prev_scan_base"), Expr::u32(1)),
                    ),
                ),
                Node::if_then(
                    Expr::eq(Expr::var("prev_scan_parent"), Expr::var("cur_parent")),
                    vec![
                        Node::assign("prev_prev_sibling_kind", Expr::var("prev_sibling_kind")),
                        Node::assign(
                            "prev_sibling_kind",
                            Expr::load(vast_nodes, Expr::var("prev_scan_base")),
                        ),
                        Node::assign(
                            "prev_sibling_symbol_hash",
                            Expr::load(
                                vast_nodes,
                                Expr::add(
                                    Expr::var("prev_scan_base"),
                                    Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD),
                                ),
                            ),
                        ),
                        Node::assign("prev_sibling_idx", Expr::var("prev_sibling_scan")),
                    ],
                ),
            ],
        ),
        Node::let_bind(
            "first_child_idx",
            Expr::load(vast_nodes, Expr::add(base.clone(), Expr::u32(2))),
        ),
        Node::let_bind(
            "first_child_valid",
            Expr::lt(Expr::var("first_child_idx"), num_nodes.clone()),
        ),
        Node::let_bind(
            "safe_first_child_idx",
            Expr::select(
                Expr::var("first_child_valid"),
                Expr::var("first_child_idx"),
                t.clone(),
            ),
        ),
        Node::let_bind(
            "first_child_base",
            Expr::mul(
                Expr::var("safe_first_child_idx"),
                Expr::u32(VAST_NODE_STRIDE_U32),
            ),
        ),
        Node::let_bind(
            "first_child_kind",
            Expr::select(
                Expr::var("first_child_valid"),
                Expr::load(vast_nodes, Expr::var("first_child_base")),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "first_child_typedef_flags",
            Expr::select(
                Expr::var("first_child_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::add(
                        Expr::var("first_child_base"),
                        Expr::u32(VAST_TYPEDEF_FLAGS_FIELD),
                    ),
                ),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "first_child_symbol_hash",
            Expr::select(
                Expr::var("first_child_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::add(
                        Expr::var("first_child_base"),
                        Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD),
                    ),
                ),
                Expr::u32(0),
            ),
        ),
        Node::let_bind("raw_next_idx", Expr::add(t.clone(), Expr::u32(1))),
        Node::let_bind(
            "raw_next_valid",
            Expr::lt(Expr::var("raw_next_idx"), num_nodes.clone()),
        ),
        Node::let_bind(
            "raw_next_base",
            Expr::mul(
                Expr::select(
                    Expr::var("raw_next_valid"),
                    Expr::var("raw_next_idx"),
                    t.clone(),
                ),
                Expr::u32(VAST_NODE_STRIDE_U32),
            ),
        ),
        Node::let_bind(
            "raw_next_kind",
            Expr::select(
                Expr::var("raw_next_valid"),
                Expr::load(vast_nodes, Expr::var("raw_next_base")),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "raw_next_typedef_flags",
            Expr::select(
                Expr::var("raw_next_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::add(
                        Expr::var("raw_next_base"),
                        Expr::u32(VAST_TYPEDEF_FLAGS_FIELD),
                    ),
                ),
                Expr::u32(0),
            ),
        ),
        Node::let_bind("raw_after_next_idx", Expr::add(t.clone(), Expr::u32(2))),
        Node::let_bind(
            "raw_after_next_valid",
            Expr::lt(Expr::var("raw_after_next_idx"), num_nodes.clone()),
        ),
        Node::let_bind(
            "raw_after_next_kind",
            Expr::select(
                Expr::var("raw_after_next_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::mul(
                        Expr::var("raw_after_next_idx"),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Expr::u32(0),
            ),
        ),
        Node::let_bind("raw_after_after_idx", Expr::add(t.clone(), Expr::u32(3))),
        Node::let_bind(
            "raw_after_after_valid",
            Expr::lt(Expr::var("raw_after_after_idx"), num_nodes.clone()),
        ),
        Node::let_bind(
            "raw_after_after_kind",
            Expr::select(
                Expr::var("raw_after_after_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::mul(
                        Expr::var("raw_after_after_idx"),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "next_idx",
            Expr::load(vast_nodes, Expr::add(base.clone(), Expr::u32(3))),
        ),
        Node::let_bind(
            "next_valid",
            Expr::lt(Expr::var("next_idx"), num_nodes.clone()),
        ),
        Node::let_bind(
            "safe_next_idx",
            Expr::select(Expr::var("next_valid"), Expr::var("next_idx"), t.clone()),
        ),
        Node::let_bind(
            "next_base",
            Expr::mul(Expr::var("safe_next_idx"), Expr::u32(VAST_NODE_STRIDE_U32)),
        ),
        Node::let_bind(
            "next_kind",
            Expr::select(
                Expr::var("next_valid"),
                Expr::load(vast_nodes, Expr::var("next_base")),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "after_param_idx",
            Expr::select(
                Expr::var("next_valid"),
                Expr::load(vast_nodes, Expr::add(Expr::var("next_base"), Expr::u32(3))),
                Expr::u32(SENTINEL),
            ),
        ),
        Node::let_bind(
            "after_param_valid",
            Expr::lt(Expr::var("after_param_idx"), num_nodes.clone()),
        ),
        Node::let_bind(
            "after_param_kind",
            Expr::select(
                Expr::var("after_param_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::mul(
                        Expr::var("after_param_idx"),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "prev_sibling_valid",
            Expr::lt(Expr::var("prev_sibling_idx"), num_nodes.clone()),
        ),
        Node::let_bind(
            "safe_prev_sibling_idx",
            Expr::select(
                Expr::var("prev_sibling_valid"),
                Expr::var("prev_sibling_idx"),
                t.clone(),
            ),
        ),
        Node::let_bind(
            "prev_sibling_base",
            Expr::mul(
                Expr::var("safe_prev_sibling_idx"),
                Expr::u32(VAST_NODE_STRIDE_U32),
            ),
        ),
        Node::let_bind(
            "prev_sibling_first_child_idx",
            Expr::load(
                vast_nodes,
                Expr::add(Expr::var("prev_sibling_base"), Expr::u32(2)),
            ),
        ),
        Node::let_bind(
            "prev_sibling_first_child_valid",
            Expr::lt(Expr::var("prev_sibling_first_child_idx"), num_nodes.clone()),
        ),
        Node::let_bind(
            "safe_prev_sibling_first_child_idx",
            Expr::select(
                Expr::var("prev_sibling_first_child_valid"),
                Expr::var("prev_sibling_first_child_idx"),
                t.clone(),
            ),
        ),
        Node::let_bind(
            "prev_sibling_first_child_base",
            Expr::mul(
                Expr::var("safe_prev_sibling_first_child_idx"),
                Expr::u32(VAST_NODE_STRIDE_U32),
            ),
        ),
        Node::let_bind(
            "prev_sibling_first_child_kind",
            Expr::select(
                Expr::var("prev_sibling_first_child_valid"),
                Expr::load(vast_nodes, Expr::var("prev_sibling_first_child_base")),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "prev_sibling_typedef_flags",
            Expr::select(
                Expr::var("prev_sibling_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::add(
                        Expr::var("prev_sibling_base"),
                        Expr::u32(VAST_TYPEDEF_FLAGS_FIELD),
                    ),
                ),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "prev_sibling_first_child_typedef_flags",
            Expr::select(
                Expr::var("prev_sibling_first_child_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::add(
                        Expr::var("prev_sibling_first_child_base"),
                        Expr::u32(VAST_TYPEDEF_FLAGS_FIELD),
                    ),
                ),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "prev_sibling_first_child_symbol_hash",
            Expr::select(
                Expr::var("prev_sibling_first_child_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::add(
                        Expr::var("prev_sibling_first_child_base"),
                        Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD),
                    ),
                ),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "cur_parent_valid",
            Expr::lt(Expr::var("cur_parent"), num_nodes.clone()),
        ),
        Node::let_bind(
            "safe_cur_parent_idx",
            Expr::select(
                Expr::var("cur_parent_valid"),
                Expr::var("cur_parent"),
                t.clone(),
            ),
        ),
        Node::let_bind(
            "cur_parent_base",
            Expr::mul(
                Expr::var("safe_cur_parent_idx"),
                Expr::u32(VAST_NODE_STRIDE_U32),
            ),
        ),
        Node::let_bind(
            "cur_parent_kind",
            Expr::select(
                Expr::var("cur_parent_valid"),
                Expr::load(vast_nodes, Expr::var("cur_parent_base")),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "cur_parent_parent",
            Expr::select(
                Expr::var("cur_parent_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::add(Expr::var("cur_parent_base"), Expr::u32(1)),
                ),
                Expr::u32(SENTINEL),
            ),
        ),
        Node::let_bind(
            "cur_parent_parent_valid",
            Expr::lt(Expr::var("cur_parent_parent"), num_nodes.clone()),
        ),
        Node::let_bind(
            "cur_parent_parent_base",
            Expr::mul(
                Expr::select(
                    Expr::var("cur_parent_parent_valid"),
                    Expr::var("cur_parent_parent"),
                    t.clone(),
                ),
                Expr::u32(VAST_NODE_STRIDE_U32),
            ),
        ),
        Node::let_bind(
            "cur_parent_parent_kind",
            Expr::select(
                Expr::var("cur_parent_parent_valid"),
                Expr::load(vast_nodes, Expr::var("cur_parent_parent_base")),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "cur_parent_parent_symbol_hash",
            Expr::select(
                Expr::var("cur_parent_parent_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::add(
                        Expr::var("cur_parent_parent_base"),
                        Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD),
                    ),
                ),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "cur_parent_parent_parent",
            Expr::select(
                Expr::var("cur_parent_parent_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::add(Expr::var("cur_parent_parent_base"), Expr::u32(1)),
                ),
                Expr::u32(SENTINEL),
            ),
        ),
        Node::let_bind("cur_parent_prev_sibling_kind", Expr::u32(SENTINEL)),
        Node::let_bind("cur_parent_prev_prev_sibling_kind", Expr::u32(SENTINEL)),
        Node::loop_for(
            "cur_parent_prev_scan",
            Expr::u32(0),
            Expr::var("safe_cur_parent_idx"),
            vec![
                Node::let_bind(
                    "cur_parent_prev_scan_base",
                    Expr::mul(
                        Expr::var("cur_parent_prev_scan"),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Node::let_bind(
                    "cur_parent_prev_scan_parent",
                    Expr::load(
                        vast_nodes,
                        Expr::add(Expr::var("cur_parent_prev_scan_base"), Expr::u32(1)),
                    ),
                ),
                Node::if_then(
                    Expr::and(
                        Expr::var("cur_parent_valid"),
                        Expr::eq(
                            Expr::var("cur_parent_prev_scan_parent"),
                            Expr::var("cur_parent_parent"),
                        ),
                    ),
                    vec![
                        Node::assign(
                            "cur_parent_prev_prev_sibling_kind",
                            Expr::var("cur_parent_prev_sibling_kind"),
                        ),
                        Node::assign(
                            "cur_parent_prev_sibling_kind",
                            Expr::load(vast_nodes, Expr::var("cur_parent_prev_scan_base")),
                        ),
                    ],
                ),
            ],
        ),
        Node::let_bind(
            "cur_parent_parent_safe_idx",
            Expr::select(
                Expr::var("cur_parent_parent_valid"),
                Expr::var("cur_parent_parent"),
                t.clone(),
            ),
        ),
        Node::let_bind("cur_grandparent_prev_sibling_kind", Expr::u32(SENTINEL)),
        Node::loop_for(
            "cur_grandparent_prev_scan",
            Expr::u32(0),
            Expr::var("cur_parent_parent_safe_idx"),
            vec![
                Node::let_bind(
                    "cur_grandparent_prev_scan_base",
                    Expr::mul(
                        Expr::var("cur_grandparent_prev_scan"),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Node::let_bind(
                    "cur_grandparent_prev_scan_parent",
                    Expr::load(
                        vast_nodes,
                        Expr::add(Expr::var("cur_grandparent_prev_scan_base"), Expr::u32(1)),
                    ),
                ),
                Node::if_then(
                    Expr::and(
                        Expr::var("cur_parent_parent_valid"),
                        Expr::eq(
                            Expr::var("cur_grandparent_prev_scan_parent"),
                            Expr::var("cur_parent_parent_parent"),
                        ),
                    ),
                    vec![Node::assign(
                        "cur_grandparent_prev_sibling_kind",
                        Expr::load(vast_nodes, Expr::var("cur_grandparent_prev_scan_base")),
                    )],
                ),
            ],
        ),
        Node::let_bind(
            "cur_parent_parent_prev_adjacent_valid",
            Expr::and(
                Expr::var("cur_parent_parent_valid"),
                Expr::gt(Expr::var("cur_parent_parent"), Expr::u32(0)),
            ),
        ),
        Node::let_bind(
            "cur_parent_parent_prev_adjacent_base",
            Expr::mul(
                Expr::select(
                    Expr::var("cur_parent_parent_prev_adjacent_valid"),
                    Expr::sub(Expr::var("cur_parent_parent"), Expr::u32(1)),
                    t.clone(),
                ),
                Expr::u32(VAST_NODE_STRIDE_U32),
            ),
        ),
        Node::let_bind(
            "cur_parent_parent_prev_adjacent_kind",
            Expr::select(
                Expr::var("cur_parent_parent_prev_adjacent_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::var("cur_parent_parent_prev_adjacent_base"),
                ),
                Expr::u32(SENTINEL),
            ),
        ),
        Node::let_bind("colon_count_before", Expr::u32(0)),
        Node::loop_for(
            "colon_count_scan",
            Expr::u32(0),
            t.clone(),
            vec![
                Node::let_bind(
                    "colon_count_scan_base",
                    Expr::mul(
                        Expr::var("colon_count_scan"),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Node::let_bind(
                    "colon_count_scan_parent",
                    Expr::load(
                        vast_nodes,
                        Expr::add(Expr::var("colon_count_scan_base"), Expr::u32(1)),
                    ),
                ),
                Node::let_bind(
                    "colon_count_scan_kind",
                    Expr::load(vast_nodes, Expr::var("colon_count_scan_base")),
                ),
                Node::if_then(
                    Expr::and(
                        Expr::eq(
                            Expr::var("colon_count_scan_parent"),
                            Expr::var("cur_parent"),
                        ),
                        Expr::eq(Expr::var("colon_count_scan_kind"), Expr::u32(TOK_COLON)),
                    ),
                    vec![Node::assign(
                        "colon_count_before",
                        Expr::add(Expr::var("colon_count_before"), Expr::u32(1)),
                    )],
                ),
            ],
        ),
        Node::let_bind(
            "cur_parent_next_idx",
            Expr::select(
                Expr::var("cur_parent_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::add(Expr::var("cur_parent_base"), Expr::u32(3)),
                ),
                Expr::u32(SENTINEL),
            ),
        ),
        Node::let_bind(
            "cur_parent_next_valid",
            Expr::lt(Expr::var("cur_parent_next_idx"), num_nodes.clone()),
        ),
        Node::let_bind(
            "cur_parent_next_kind",
            Expr::select(
                Expr::var("cur_parent_next_valid"),
                Expr::load(
                    vast_nodes,
                    Expr::mul(
                        Expr::var("cur_parent_next_idx"),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Expr::u32(0),
            ),
        ),
        Node::let_bind("parent_prev_kind", Expr::u32(SENTINEL)),
        Node::let_bind("parent_prev_prev_kind", Expr::u32(SENTINEL)),
        Node::let_bind("parent_has_decl_prefix", Expr::u32(0)),
        Node::let_bind(
            "parent_ctx_scan_limit",
            Expr::select(
                Expr::var("cur_parent_valid"),
                Expr::var("cur_parent"),
                Expr::u32(0),
            ),
        ),
        Node::loop_for(
            "parent_ctx_scan",
            Expr::u32(0),
            Expr::var("parent_ctx_scan_limit"),
            vec![
                Node::let_bind(
                    "parent_ctx_base",
                    Expr::mul(
                        Expr::var("parent_ctx_scan"),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Node::let_bind(
                    "parent_ctx_kind",
                    Expr::load(vast_nodes, Expr::var("parent_ctx_base")),
                ),
                Node::let_bind(
                    "parent_ctx_typedef_flags",
                    Expr::load(
                        vast_nodes,
                        Expr::add(
                            Expr::var("parent_ctx_base"),
                            Expr::u32(VAST_TYPEDEF_FLAGS_FIELD),
                        ),
                    ),
                ),
                Node::let_bind(
                    "parent_ctx_symbol_hash",
                    Expr::load(
                        vast_nodes,
                        Expr::add(
                            Expr::var("parent_ctx_base"),
                            Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD),
                        ),
                    ),
                ),
                Node::let_bind(
                    "parent_ctx_parent",
                    Expr::load(
                        vast_nodes,
                        Expr::add(Expr::var("parent_ctx_base"), Expr::u32(1)),
                    ),
                ),
                Node::if_then(
                    Expr::eq(
                        Expr::var("parent_ctx_parent"),
                        Expr::var("cur_parent_parent"),
                    ),
                    vec![
                        Node::let_bind(
                            "parent_ctx_aggregate_body_open",
                            is_aggregate_specifier_body_open(
                                Expr::var("parent_ctx_kind"),
                                Expr::var("parent_prev_kind"),
                                Expr::var("parent_prev_prev_kind"),
                            ),
                        ),
                        Node::if_then(
                            is_decl_prefix_reset_token(Expr::var("parent_ctx_kind")),
                            vec![Node::assign("parent_has_decl_prefix", Expr::u32(0))],
                        ),
                        Node::if_then(
                            Expr::or(
                                is_decl_prefix_token_or_gnu_type_hash(
                                    Expr::var("parent_ctx_kind"),
                                    Expr::var("parent_ctx_symbol_hash"),
                                ),
                                Expr::or(
                                    Expr::var("parent_ctx_aggregate_body_open"),
                                    Expr::and(
                                        Expr::eq(
                                            Expr::var("parent_ctx_kind"),
                                            Expr::u32(TOK_IDENTIFIER),
                                        ),
                                        is_typedef_name_annotation(Expr::var(
                                            "parent_ctx_typedef_flags",
                                        )),
                                    ),
                                ),
                            ),
                            vec![Node::assign("parent_has_decl_prefix", Expr::u32(1))],
                        ),
                        Node::assign("parent_prev_prev_kind", Expr::var("parent_prev_kind")),
                        Node::assign(
                            "parent_prev_kind",
                            Expr::load(vast_nodes, Expr::var("parent_ctx_base")),
                        ),
                    ],
                ),
            ],
        ),
        Node::let_bind("parent_parent_prev_kind", Expr::u32(SENTINEL)),
        Node::let_bind("parent_parent_prev_prev_kind", Expr::u32(SENTINEL)),
        Node::let_bind("parent_parent_has_decl_prefix", Expr::u32(0)),
        Node::if_then(
            Expr::var("cur_parent_parent_valid"),
            vec![Node::loop_for(
                "parent_parent_ctx_scan",
                Expr::u32(0),
                Expr::var("cur_parent_parent"),
                vec![
                    Node::let_bind(
                        "parent_parent_ctx_base",
                        Expr::mul(
                            Expr::var("parent_parent_ctx_scan"),
                            Expr::u32(VAST_NODE_STRIDE_U32),
                        ),
                    ),
                    Node::let_bind(
                        "parent_parent_ctx_kind",
                        Expr::load(vast_nodes, Expr::var("parent_parent_ctx_base")),
                    ),
                    Node::let_bind(
                        "parent_parent_ctx_typedef_flags",
                        Expr::load(
                            vast_nodes,
                            Expr::add(
                                Expr::var("parent_parent_ctx_base"),
                                Expr::u32(VAST_TYPEDEF_FLAGS_FIELD),
                            ),
                        ),
                    ),
                    Node::let_bind(
                        "parent_parent_ctx_symbol_hash",
                        Expr::load(
                            vast_nodes,
                            Expr::add(
                                Expr::var("parent_parent_ctx_base"),
                                Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD),
                            ),
                        ),
                    ),
                    Node::let_bind(
                        "parent_parent_ctx_parent",
                        Expr::load(
                            vast_nodes,
                            Expr::add(Expr::var("parent_parent_ctx_base"), Expr::u32(1)),
                        ),
                    ),
                    Node::if_then(
                        Expr::eq(
                            Expr::var("parent_parent_ctx_parent"),
                            Expr::var("cur_parent_parent_parent"),
                        ),
                        vec![
                            Node::let_bind(
                                "parent_parent_ctx_aggregate_body_open",
                                is_aggregate_specifier_body_open(
                                    Expr::var("parent_parent_ctx_kind"),
                                    Expr::var("parent_parent_prev_kind"),
                                    Expr::var("parent_parent_prev_prev_kind"),
                                ),
                            ),
                            Node::if_then(
                                is_decl_prefix_reset_token(Expr::var("parent_parent_ctx_kind")),
                                vec![Node::assign("parent_parent_has_decl_prefix", Expr::u32(0))],
                            ),
                            Node::if_then(
                                Expr::or(
                                    is_decl_prefix_token_or_gnu_type_hash(
                                        Expr::var("parent_parent_ctx_kind"),
                                        Expr::var("parent_parent_ctx_symbol_hash"),
                                    ),
                                    Expr::or(
                                        Expr::var("parent_parent_ctx_aggregate_body_open"),
                                        Expr::and(
                                            Expr::eq(
                                                Expr::var("parent_parent_ctx_kind"),
                                                Expr::u32(TOK_IDENTIFIER),
                                            ),
                                            is_typedef_name_annotation(Expr::var(
                                                "parent_parent_ctx_typedef_flags",
                                            )),
                                        ),
                                    ),
                                ),
                                vec![Node::assign("parent_parent_has_decl_prefix", Expr::u32(1))],
                            ),
                            Node::assign(
                                "parent_parent_prev_prev_kind",
                                Expr::var("parent_parent_prev_kind"),
                            ),
                            Node::assign(
                                "parent_parent_prev_kind",
                                Expr::var("parent_parent_ctx_kind"),
                            ),
                        ],
                    ),
                ],
            )],
        ),
        Node::let_bind("ancestor_decl_prefix", Expr::u32(0)),
        Node::let_bind("decl_ancestor", Expr::var("cur_parent")),
        Node::let_bind("decl_ancestor_active", Expr::u32(1)),
        Node::loop_for(
            "decl_ancestor_depth",
            Expr::u32(0),
            num_nodes.clone(),
            vec![Node::if_then(
                Expr::and(
                    Expr::eq(Expr::var("decl_ancestor_active"), Expr::u32(1)),
                    Expr::lt(Expr::var("decl_ancestor"), num_nodes.clone()),
                ),
                vec![
                    Node::let_bind(
                        "decl_ancestor_base",
                        Expr::mul(Expr::var("decl_ancestor"), Expr::u32(VAST_NODE_STRIDE_U32)),
                    ),
                    Node::let_bind(
                        "decl_ancestor_kind",
                        Expr::load(vast_nodes, Expr::var("decl_ancestor_base")),
                    ),
                    Node::let_bind(
                        "decl_ancestor_parent",
                        Expr::load(
                            vast_nodes,
                            Expr::add(Expr::var("decl_ancestor_base"), Expr::u32(1)),
                        ),
                    ),
                    Node::if_then(
                        Expr::ne(Expr::var("decl_ancestor_kind"), Expr::u32(TOK_LPAREN)),
                        vec![Node::assign("decl_ancestor_active", Expr::u32(0))],
                    ),
                    Node::if_then(
                        Expr::and(
                            Expr::eq(Expr::var("decl_ancestor_active"), Expr::u32(1)),
                            Expr::eq(Expr::var("decl_ancestor_kind"), Expr::u32(TOK_LPAREN)),
                        ),
                        vec![
                            Node::let_bind("ancestor_prev_kind", Expr::u32(SENTINEL)),
                            Node::let_bind("ancestor_prev_prev_kind", Expr::u32(SENTINEL)),
                            Node::let_bind("ancestor_has_decl_prefix", Expr::u32(0)),
                            Node::loop_for(
                                "ancestor_ctx_scan",
                                Expr::u32(0),
                                Expr::var("decl_ancestor"),
                                vec![
                                    Node::let_bind(
                                        "ancestor_ctx_base",
                                        Expr::mul(
                                            Expr::var("ancestor_ctx_scan"),
                                            Expr::u32(VAST_NODE_STRIDE_U32),
                                        ),
                                    ),
                                    Node::let_bind(
                                        "ancestor_ctx_kind",
                                        Expr::load(vast_nodes, Expr::var("ancestor_ctx_base")),
                                    ),
                                    Node::let_bind(
                                        "ancestor_ctx_typedef_flags",
                                        Expr::load(
                                            vast_nodes,
                                            Expr::add(
                                                Expr::var("ancestor_ctx_base"),
                                                Expr::u32(VAST_TYPEDEF_FLAGS_FIELD),
                                            ),
                                        ),
                                    ),
                                    Node::let_bind(
                                        "ancestor_ctx_symbol_hash",
                                        Expr::load(
                                            vast_nodes,
                                            Expr::add(
                                                Expr::var("ancestor_ctx_base"),
                                                Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD),
                                            ),
                                        ),
                                    ),
                                    Node::let_bind(
                                        "ancestor_ctx_parent",
                                        Expr::load(
                                            vast_nodes,
                                            Expr::add(Expr::var("ancestor_ctx_base"), Expr::u32(1)),
                                        ),
                                    ),
                                    Node::if_then(
                                        Expr::eq(
                                            Expr::var("ancestor_ctx_parent"),
                                            Expr::var("decl_ancestor_parent"),
                                        ),
                                        vec![
                                            Node::let_bind(
                                                "ancestor_ctx_aggregate_body_open",
                                                is_aggregate_specifier_body_open(
                                                    Expr::var("ancestor_ctx_kind"),
                                                    Expr::var("ancestor_prev_kind"),
                                                    Expr::var("ancestor_prev_prev_kind"),
                                                ),
                                            ),
                                            Node::if_then(
                                                is_decl_prefix_reset_token(Expr::var(
                                                    "ancestor_ctx_kind",
                                                )),
                                                vec![Node::assign(
                                                    "ancestor_has_decl_prefix",
                                                    Expr::u32(0),
                                                )],
                                            ),
                                            Node::if_then(
                                                Expr::or(
                                                    is_decl_prefix_token_or_gnu_type_hash(
                                                        Expr::var("ancestor_ctx_kind"),
                                                        Expr::var("ancestor_ctx_symbol_hash"),
                                                    ),
                                                    Expr::or(
                                                        Expr::var(
                                                            "ancestor_ctx_aggregate_body_open",
                                                        ),
                                                        Expr::and(
                                                            Expr::eq(
                                                                Expr::var("ancestor_ctx_kind"),
                                                                Expr::u32(TOK_IDENTIFIER),
                                                            ),
                                                            is_typedef_name_annotation(Expr::var(
                                                                "ancestor_ctx_typedef_flags",
                                                            )),
                                                        ),
                                                    ),
                                                ),
                                                vec![Node::assign(
                                                    "ancestor_has_decl_prefix",
                                                    Expr::u32(1),
                                                )],
                                            ),
                                            Node::assign(
                                                "ancestor_prev_prev_kind",
                                                Expr::var("ancestor_prev_kind"),
                                            ),
                                            Node::assign(
                                                "ancestor_prev_kind",
                                                Expr::var("ancestor_ctx_kind"),
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                            Node::if_then(
                                Expr::eq(Expr::var("ancestor_has_decl_prefix"), Expr::u32(1)),
                                vec![Node::assign("ancestor_decl_prefix", Expr::u32(1))],
                            ),
                        ],
                    ),
                    Node::if_then(
                        Expr::eq(Expr::var("decl_ancestor_active"), Expr::u32(1)),
                        vec![Node::assign(
                            "decl_ancestor",
                            Expr::var("decl_ancestor_parent"),
                        )],
                    ),
                ],
            )],
        ),
        Node::let_bind("parent_open_record_prefix", Expr::u32(0)),
        Node::let_bind("parent_open_enum_prefix", Expr::u32(0)),
        Node::if_then(
            Expr::and(
                Expr::var("cur_parent_valid"),
                Expr::eq(Expr::var("cur_parent_kind"), Expr::u32(TOK_LBRACE)),
            ),
            vec![Node::loop_for(
                "parent_open_ctx_scan",
                Expr::u32(0),
                Expr::var("cur_parent"),
                vec![
                    Node::let_bind(
                        "parent_open_ctx_base",
                        Expr::mul(
                            Expr::var("parent_open_ctx_scan"),
                            Expr::u32(VAST_NODE_STRIDE_U32),
                        ),
                    ),
                    Node::let_bind(
                        "parent_open_ctx_kind",
                        Expr::load(vast_nodes, Expr::var("parent_open_ctx_base")),
                    ),
                    Node::let_bind(
                        "parent_open_ctx_parent",
                        Expr::load(
                            vast_nodes,
                            Expr::add(Expr::var("parent_open_ctx_base"), Expr::u32(1)),
                        ),
                    ),
                    Node::if_then(
                        Expr::eq(
                            Expr::var("parent_open_ctx_parent"),
                            Expr::var("cur_parent_parent"),
                        ),
                        vec![
                            Node::if_then(
                                any_token_eq(
                                    Expr::var("parent_open_ctx_kind"),
                                    &[TOK_SEMICOLON, TOK_ASSIGN, TOK_COMMA],
                                ),
                                vec![
                                    Node::assign("parent_open_record_prefix", Expr::u32(0)),
                                    Node::assign("parent_open_enum_prefix", Expr::u32(0)),
                                ],
                            ),
                            Node::if_then(
                                any_token_eq(
                                    Expr::var("parent_open_ctx_kind"),
                                    &[TOK_STRUCT, TOK_UNION],
                                ),
                                vec![
                                    Node::assign("parent_open_record_prefix", Expr::u32(1)),
                                    Node::assign("parent_open_enum_prefix", Expr::u32(0)),
                                ],
                            ),
                            Node::if_then(
                                Expr::eq(Expr::var("parent_open_ctx_kind"), Expr::u32(TOK_ENUM)),
                                vec![
                                    Node::assign("parent_open_record_prefix", Expr::u32(0)),
                                    Node::assign("parent_open_enum_prefix", Expr::u32(1)),
                                ],
                            ),
                        ],
                    ),
                ],
            )],
        ),
        Node::let_bind(
            "parent_is_record_body",
            Expr::and(
                Expr::and(
                    Expr::var("cur_parent_valid"),
                    Expr::eq(Expr::var("cur_parent_kind"), Expr::u32(TOK_LBRACE)),
                ),
                Expr::eq(Expr::var("parent_open_record_prefix"), Expr::u32(1)),
            ),
        ),
        Node::let_bind(
            "parent_is_enum_body",
            Expr::and(
                Expr::and(
                    Expr::var("cur_parent_valid"),
                    Expr::eq(Expr::var("cur_parent_kind"), Expr::u32(TOK_LBRACE)),
                ),
                Expr::eq(Expr::var("parent_open_enum_prefix"), Expr::u32(1)),
            ),
        ),
        Node::let_bind(
            "identifier_then_paren",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_IDENTIFIER)),
                    Expr::var("next_valid"),
                ),
                Expr::eq(Expr::var("next_kind"), Expr::u32(TOK_LPAREN)),
            ),
        ),
        Node::let_bind("has_decl_prefix", Expr::u32(0)),
        Node::let_bind("decl_ctx_leading_gnu_attribute", Expr::u32(0)),
        Node::let_bind("decl_ctx_last_reset_idx", Expr::u32(SENTINEL)),
        Node::let_bind("last_decl_ctx_kind", Expr::u32(SENTINEL)),
        Node::let_bind("prev_decl_ctx_kind", Expr::u32(SENTINEL)),
        Node::let_bind("suffix_has_gnu_attribute", Expr::u32(0)),
        Node::let_bind("suffix_boundary", Expr::u32(0)),
        Node::let_bind("suffix_boundary_kind", Expr::u32(SENTINEL)),
        Node::let_bind(
            "needs_decl_context",
            Expr::or(
                Expr::or(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_IDENTIFIER)),
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_STAR)),
                ),
                Expr::or(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_LBRACKET)),
                    Expr::or(
                        Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_LPAREN)),
                        Expr::or(
                            Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_LBRACE)),
                            Expr::or(
                                Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_ASSIGN)),
                                Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_COLON)),
                            ),
                        ),
                    ),
                ),
            ),
        ),
        Node::if_then(
            Expr::var("needs_decl_context"),
            vec![Node::loop_for(
                "decl_ctx_scan",
                Expr::u32(0),
                t.clone(),
                vec![
                    Node::let_bind(
                        "decl_ctx_base",
                        Expr::mul(Expr::var("decl_ctx_scan"), Expr::u32(VAST_NODE_STRIDE_U32)),
                    ),
                    Node::let_bind(
                        "decl_ctx_kind",
                        Expr::load(vast_nodes, Expr::var("decl_ctx_base")),
                    ),
                    Node::let_bind(
                        "decl_ctx_typedef_flags",
                        Expr::load(
                            vast_nodes,
                            Expr::add(
                                Expr::var("decl_ctx_base"),
                                Expr::u32(VAST_TYPEDEF_FLAGS_FIELD),
                            ),
                        ),
                    ),
                    Node::let_bind(
                        "decl_ctx_symbol_hash",
                        Expr::load(
                            vast_nodes,
                            Expr::add(
                                Expr::var("decl_ctx_base"),
                                Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD),
                            ),
                        ),
                    ),
                    Node::let_bind(
                        "decl_ctx_parent",
                        Expr::load(
                            vast_nodes,
                            Expr::add(Expr::var("decl_ctx_base"), Expr::u32(1)),
                        ),
                    ),
                    Node::if_then(
                        Expr::eq(Expr::var("decl_ctx_parent"), Expr::var("cur_parent")),
                        vec![
                            Node::let_bind(
                                "decl_ctx_aggregate_body_open",
                                is_aggregate_specifier_body_open(
                                    Expr::var("decl_ctx_kind"),
                                    Expr::var("last_decl_ctx_kind"),
                                    Expr::var("prev_decl_ctx_kind"),
                                ),
                            ),
                            Node::if_then(
                                is_decl_prefix_reset_token(Expr::var("decl_ctx_kind")),
                                vec![
                                    Node::assign("has_decl_prefix", Expr::u32(0)),
                                    Node::assign("decl_ctx_leading_gnu_attribute", Expr::u32(0)),
                                    Node::assign(
                                        "decl_ctx_last_reset_idx",
                                        Expr::var("decl_ctx_scan"),
                                    ),
                                ],
                            ),
                            Node::if_then(
                                Expr::and(
                                    Expr::eq(
                                        Expr::var("decl_ctx_kind"),
                                        Expr::u32(TOK_GNU_ATTRIBUTE),
                                    ),
                                    Expr::and(
                                        Expr::eq(Expr::var("has_decl_prefix"), Expr::u32(0)),
                                        Expr::or(
                                            Expr::eq(
                                                Expr::var("last_decl_ctx_kind"),
                                                Expr::u32(SENTINEL),
                                            ),
                                            is_decl_prefix_reset_token(Expr::var(
                                                "last_decl_ctx_kind",
                                            )),
                                        ),
                                    ),
                                ),
                                vec![Node::assign("decl_ctx_leading_gnu_attribute", Expr::u32(1))],
                            ),
                            Node::if_then(
                                Expr::or(
                                    is_decl_prefix_token_or_gnu_type_hash(
                                        Expr::var("decl_ctx_kind"),
                                        Expr::var("decl_ctx_symbol_hash"),
                                    ),
                                    Expr::or(
                                        Expr::var("decl_ctx_aggregate_body_open"),
                                        Expr::and(
                                            Expr::eq(
                                                Expr::var("decl_ctx_kind"),
                                                Expr::u32(TOK_IDENTIFIER),
                                            ),
                                            is_typedef_name_annotation(Expr::var(
                                                "decl_ctx_typedef_flags",
                                            )),
                                        ),
                                    ),
                                ),
                                vec![Node::assign("has_decl_prefix", Expr::u32(1))],
                            ),
                            Node::assign("prev_decl_ctx_kind", Expr::var("last_decl_ctx_kind")),
                            Node::assign("last_decl_ctx_kind", Expr::var("decl_ctx_kind")),
                        ],
                    ),
                ],
            )],
        ),
        Node::let_bind("decl_ctx_leading_definition_attribute", Expr::u32(0)),
        Node::if_then(
            Expr::eq(Expr::var("decl_ctx_leading_gnu_attribute"), Expr::u32(1)),
            vec![Node::loop_for(
                "decl_ctx_attr_scan",
                Expr::u32(0),
                t.clone(),
                vec![
                    Node::let_bind(
                        "decl_ctx_attr_after_reset",
                        Expr::or(
                            Expr::eq(Expr::var("decl_ctx_last_reset_idx"), Expr::u32(SENTINEL)),
                            Expr::gt(
                                Expr::var("decl_ctx_attr_scan"),
                                Expr::var("decl_ctx_last_reset_idx"),
                            ),
                        ),
                    ),
                    Node::if_then(
                        Expr::var("decl_ctx_attr_after_reset"),
                        vec![
                            Node::let_bind(
                                "decl_ctx_attr_base",
                                Expr::mul(
                                    Expr::var("decl_ctx_attr_scan"),
                                    Expr::u32(VAST_NODE_STRIDE_U32),
                                ),
                            ),
                            Node::let_bind(
                                "decl_ctx_attr_kind",
                                Expr::load(vast_nodes, Expr::var("decl_ctx_attr_base")),
                            ),
                            Node::if_then(
                                any_token_eq(
                                    Expr::var("decl_ctx_attr_kind"),
                                    &[TOK_IDENTIFIER, TOK_CONST],
                                ),
                                vec![
                                    Node::let_bind(
                                        "decl_ctx_attr_parent",
                                        Expr::load(
                                            vast_nodes,
                                            Expr::add(
                                                Expr::var("decl_ctx_attr_base"),
                                                Expr::u32(1),
                                            ),
                                        ),
                                    ),
                                    Node::let_bind(
                                        "decl_ctx_attr_parent_valid",
                                        Expr::lt(
                                            Expr::var("decl_ctx_attr_parent"),
                                            num_nodes.clone(),
                                        ),
                                    ),
                                    Node::let_bind(
                                        "decl_ctx_attr_parent_base",
                                        Expr::mul(
                                            Expr::select(
                                                Expr::var("decl_ctx_attr_parent_valid"),
                                                Expr::var("decl_ctx_attr_parent"),
                                                t.clone(),
                                            ),
                                            Expr::u32(VAST_NODE_STRIDE_U32),
                                        ),
                                    ),
                                    Node::let_bind(
                                        "decl_ctx_attr_parent_kind",
                                        Expr::select(
                                            Expr::var("decl_ctx_attr_parent_valid"),
                                            Expr::load(
                                                vast_nodes,
                                                Expr::var("decl_ctx_attr_parent_base"),
                                            ),
                                            Expr::u32(0),
                                        ),
                                    ),
                                    Node::let_bind(
                                        "decl_ctx_attr_parent_parent",
                                        Expr::select(
                                            Expr::var("decl_ctx_attr_parent_valid"),
                                            Expr::load(
                                                vast_nodes,
                                                Expr::add(
                                                    Expr::var("decl_ctx_attr_parent_base"),
                                                    Expr::u32(1),
                                                ),
                                            ),
                                            Expr::u32(SENTINEL),
                                        ),
                                    ),
                                    Node::let_bind(
                                        "decl_ctx_attr_parent_parent_valid",
                                        Expr::lt(
                                            Expr::var("decl_ctx_attr_parent_parent"),
                                            num_nodes.clone(),
                                        ),
                                    ),
                                    Node::let_bind(
                                        "decl_ctx_attr_parent_parent_base",
                                        Expr::mul(
                                            Expr::select(
                                                Expr::var("decl_ctx_attr_parent_parent_valid"),
                                                Expr::var("decl_ctx_attr_parent_parent"),
                                                t.clone(),
                                            ),
                                            Expr::u32(VAST_NODE_STRIDE_U32),
                                        ),
                                    ),
                                    Node::let_bind(
                                        "decl_ctx_attr_parent_parent_kind",
                                        Expr::select(
                                            Expr::var("decl_ctx_attr_parent_parent_valid"),
                                            Expr::load(
                                                vast_nodes,
                                                Expr::var("decl_ctx_attr_parent_parent_base"),
                                            ),
                                            Expr::u32(0),
                                        ),
                                    ),
                                    Node::let_bind(
                                        "decl_ctx_attr_grandparent",
                                        Expr::select(
                                            Expr::var("decl_ctx_attr_parent_parent_valid"),
                                            Expr::load(
                                                vast_nodes,
                                                Expr::add(
                                                    Expr::var("decl_ctx_attr_parent_parent_base"),
                                                    Expr::u32(1),
                                                ),
                                            ),
                                            Expr::u32(SENTINEL),
                                        ),
                                    ),
                                    Node::let_bind(
                                        "decl_ctx_attr_prefix_kind",
                                        Expr::u32(SENTINEL),
                                    ),
                                    Node::loop_for(
                                        "decl_ctx_attr_prev_scan",
                                        Expr::u32(0),
                                        Expr::select(
                                            Expr::var("decl_ctx_attr_parent_parent_valid"),
                                            Expr::var("decl_ctx_attr_parent_parent"),
                                            Expr::u32(0),
                                        ),
                                        vec![
                                            Node::let_bind(
                                                "decl_ctx_attr_prev_base",
                                                Expr::mul(
                                                    Expr::var("decl_ctx_attr_prev_scan"),
                                                    Expr::u32(VAST_NODE_STRIDE_U32),
                                                ),
                                            ),
                                            Node::let_bind(
                                                "decl_ctx_attr_prev_parent",
                                                Expr::load(
                                                    vast_nodes,
                                                    Expr::add(
                                                        Expr::var("decl_ctx_attr_prev_base"),
                                                        Expr::u32(1),
                                                    ),
                                                ),
                                            ),
                                            Node::if_then(
                                                Expr::eq(
                                                    Expr::var("decl_ctx_attr_prev_parent"),
                                                    Expr::var("decl_ctx_attr_grandparent"),
                                                ),
                                                vec![Node::assign(
                                                    "decl_ctx_attr_prefix_kind",
                                                    Expr::load(
                                                        vast_nodes,
                                                        Expr::var("decl_ctx_attr_prev_base"),
                                                    ),
                                                )],
                                            ),
                                        ],
                                    ),
                                    Node::let_bind(
                                        "decl_ctx_attr_symbol",
                                        Expr::load(
                                            vast_nodes,
                                            Expr::add(
                                                Expr::var("decl_ctx_attr_base"),
                                                Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD),
                                            ),
                                        ),
                                    ),
                                    Node::let_bind(
                                        "decl_ctx_attr_specific_kind",
                                        Expr::select(
                                            Expr::eq(
                                                Expr::var("decl_ctx_attr_kind"),
                                                Expr::u32(TOK_CONST),
                                            ),
                                            Expr::u32(C_AST_KIND_ATTRIBUTE_CONST),
                                            c_attribute_kind_from_hash(Expr::var(
                                                "decl_ctx_attr_symbol",
                                            )),
                                        ),
                                    ),
                                    Node::if_then(
                                        Expr::and(
                                            Expr::and(
                                                Expr::eq(
                                                    Expr::var("decl_ctx_attr_parent_kind"),
                                                    Expr::u32(TOK_LPAREN),
                                                ),
                                                Expr::eq(
                                                    Expr::var("decl_ctx_attr_parent_parent_kind"),
                                                    Expr::u32(TOK_LPAREN),
                                                ),
                                            ),
                                            Expr::and(
                                                Expr::eq(
                                                    Expr::var("decl_ctx_attr_prefix_kind"),
                                                    Expr::u32(TOK_GNU_ATTRIBUTE),
                                                ),
                                                any_token_eq(
                                                    Expr::var("decl_ctx_attr_specific_kind"),
                                                    &[
                                                        C_AST_KIND_ATTRIBUTE_CONSTRUCTOR,
                                                        C_AST_KIND_ATTRIBUTE_DESTRUCTOR,
                                                    ],
                                                ),
                                            ),
                                        ),
                                        vec![Node::assign(
                                            "decl_ctx_leading_definition_attribute",
                                            Expr::u32(1),
                                        )],
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
            )],
        ),
        Node::let_bind(
            "in_parenthesized_declarator",
            Expr::and(
                Expr::eq(Expr::var("cur_parent_kind"), Expr::u32(TOK_LPAREN)),
                Expr::or(
                    Expr::eq(Expr::var("parent_has_decl_prefix"), Expr::u32(1)),
                    Expr::or(
                        is_typeof_operator_token(
                            Expr::var("cur_parent_parent_kind"),
                            Expr::var("cur_parent_parent_symbol_hash"),
                        ),
                        Expr::and(
                            Expr::or(
                                Expr::eq(
                                    Expr::var("cur_parent_parent_kind"),
                                    Expr::u32(TOK_LPAREN),
                                ),
                                Expr::eq(Expr::var("ancestor_decl_prefix"), Expr::u32(1)),
                            ),
                            Expr::or(
                                Expr::eq(Expr::var("parent_parent_has_decl_prefix"), Expr::u32(1)),
                                Expr::eq(Expr::var("ancestor_decl_prefix"), Expr::u32(1)),
                            ),
                        ),
                    ),
                ),
            ),
        ),
        Node::let_bind(
            "effective_has_decl_prefix",
            Expr::select(
                Expr::or(
                    Expr::eq(Expr::var("has_decl_prefix"), Expr::u32(1)),
                    Expr::var("in_parenthesized_declarator"),
                ),
                Expr::u32(1),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "raw_lparen",
            Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_LPAREN)),
        ),
        Node::let_bind("has_typedef_annotations", Expr::u32(0)),
        Node::loop_for(
            "typedef_annotation_scan",
            Expr::u32(0),
            num_nodes.clone(),
            vec![Node::if_then(
                Expr::ne(
                    Expr::load(
                        vast_nodes,
                        Expr::add(
                            Expr::mul(
                                Expr::var("typedef_annotation_scan"),
                                Expr::u32(VAST_NODE_STRIDE_U32),
                            ),
                            Expr::u32(VAST_TYPEDEF_FLAGS_FIELD),
                        ),
                    ),
                    Expr::u32(0),
                ),
                vec![Node::assign("has_typedef_annotations", Expr::u32(1))],
            )],
        ),
        Node::let_bind("has_prior_typedef", Expr::u32(0)),
        Node::let_bind("has_prior_ordinary_decl", Expr::u32(0)),
        Node::let_bind("has_prior_parenthesized_identifier_statement", Expr::u32(0)),
        Node::loop_for(
            "prior_typedef_scan",
            Expr::u32(0),
            t.clone(),
            vec![
                Node::let_bind(
                    "prior_typedef_base",
                    Expr::mul(
                        Expr::var("prior_typedef_scan"),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Node::if_then(
                    Expr::eq(
                        Expr::load(vast_nodes, Expr::var("prior_typedef_base")),
                        Expr::u32(TOK_TYPEDEF),
                    ),
                    vec![Node::assign("has_prior_typedef", Expr::u32(1))],
                ),
                Node::let_bind(
                    "prior_scan_prev_kind",
                    Expr::select(
                        Expr::gt(Expr::var("prior_typedef_scan"), Expr::u32(0)),
                        Expr::load(
                            vast_nodes,
                            Expr::sub(
                                Expr::var("prior_typedef_base"),
                                Expr::u32(VAST_NODE_STRIDE_U32),
                            ),
                        ),
                        Expr::u32(SENTINEL),
                    ),
                ),
                Node::let_bind(
                    "prior_scan_prev_prev_kind",
                    Expr::select(
                        Expr::gt(Expr::var("prior_typedef_scan"), Expr::u32(1)),
                        Expr::load(
                            vast_nodes,
                            Expr::sub(
                                Expr::var("prior_typedef_base"),
                                Expr::u32(VAST_NODE_STRIDE_U32 * 2),
                            ),
                        ),
                        Expr::u32(SENTINEL),
                    ),
                ),
                Node::let_bind(
                    "prior_scan_parent",
                    Expr::load(
                        vast_nodes,
                        Expr::add(Expr::var("prior_typedef_base"), Expr::u32(1)),
                    ),
                ),
                Node::let_bind(
                    "prior_scan_parent_kind",
                    Expr::select(
                        Expr::lt(Expr::var("prior_scan_parent"), num_nodes.clone()),
                        Expr::load(
                            vast_nodes,
                            Expr::mul(
                                Expr::var("prior_scan_parent"),
                                Expr::u32(VAST_NODE_STRIDE_U32),
                            ),
                        ),
                        Expr::u32(SENTINEL),
                    ),
                ),
                Node::let_bind(
                    "prior_scan_parent_prev_kind",
                    Expr::select(
                        Expr::and(
                            Expr::lt(Expr::var("prior_scan_parent"), num_nodes.clone()),
                            Expr::gt(Expr::var("prior_scan_parent"), Expr::u32(0)),
                        ),
                        Expr::load(
                            vast_nodes,
                            Expr::mul(
                                Expr::sub(Expr::var("prior_scan_parent"), Expr::u32(1)),
                                Expr::u32(VAST_NODE_STRIDE_U32),
                            ),
                        ),
                        Expr::u32(SENTINEL),
                    ),
                ),
                Node::let_bind(
                    "prior_scan_parent_prev_prev_kind",
                    Expr::select(
                        Expr::and(
                            Expr::lt(Expr::var("prior_scan_parent"), num_nodes.clone()),
                            Expr::gt(Expr::var("prior_scan_parent"), Expr::u32(1)),
                        ),
                        Expr::load(
                            vast_nodes,
                            Expr::mul(
                                Expr::sub(Expr::var("prior_scan_parent"), Expr::u32(2)),
                                Expr::u32(VAST_NODE_STRIDE_U32),
                            ),
                        ),
                        Expr::u32(SENTINEL),
                    ),
                ),
                Node::let_bind(
                    "prior_scan_in_aggregate_body",
                    Expr::and(
                        Expr::eq(Expr::var("prior_scan_parent_kind"), Expr::u32(TOK_LBRACE)),
                        Expr::or(
                            any_token_eq(
                                Expr::var("prior_scan_parent_prev_kind"),
                                &[TOK_STRUCT, TOK_UNION, TOK_ENUM],
                            ),
                            Expr::and(
                                Expr::eq(
                                    Expr::var("prior_scan_parent_prev_kind"),
                                    Expr::u32(TOK_IDENTIFIER),
                                ),
                                any_token_eq(
                                    Expr::var("prior_scan_parent_prev_prev_kind"),
                                    &[TOK_STRUCT, TOK_UNION, TOK_ENUM],
                                ),
                            ),
                        ),
                    ),
                ),
                Node::let_bind(
                    "prior_scan_next_kind",
                    Expr::select(
                        Expr::lt(
                            Expr::add(Expr::var("prior_typedef_scan"), Expr::u32(1)),
                            num_nodes.clone(),
                        ),
                        Expr::load(
                            vast_nodes,
                            Expr::add(
                                Expr::var("prior_typedef_base"),
                                Expr::u32(VAST_NODE_STRIDE_U32),
                            ),
                        ),
                        Expr::u32(SENTINEL),
                    ),
                ),
                Node::if_then(
                    Expr::and(
                        Expr::and(
                            Expr::eq(
                                Expr::load(vast_nodes, Expr::var("prior_typedef_base")),
                                Expr::u32(TOK_IDENTIFIER),
                            ),
                            Expr::and(
                                is_decl_prefix_token(Expr::var("prior_scan_prev_kind")),
                                Expr::and(
                                    Expr::ne(
                                        Expr::var("prior_scan_prev_kind"),
                                        Expr::u32(TOK_TYPEDEF),
                                    ),
                                    Expr::ne(
                                        Expr::var("prior_scan_prev_prev_kind"),
                                        Expr::u32(TOK_TYPEDEF),
                                    ),
                                ),
                            ),
                        ),
                        Expr::and(
                            Expr::not(Expr::var("prior_scan_in_aggregate_body")),
                            any_token_eq(
                                Expr::var("prior_scan_next_kind"),
                                &[TOK_SEMICOLON, TOK_COMMA, TOK_ASSIGN, TOK_LBRACKET],
                            ),
                        ),
                    ),
                    vec![Node::assign("has_prior_ordinary_decl", Expr::u32(1))],
                ),
                Node::if_then(
                    Expr::and(
                        Expr::lt(
                            Expr::add(Expr::var("prior_typedef_scan"), Expr::u32(5)),
                            t.clone(),
                        ),
                        Expr::and(
                            Expr::eq(
                                Expr::load(vast_nodes, Expr::var("prior_typedef_base")),
                                Expr::u32(TOK_LPAREN),
                            ),
                            Expr::and(
                                Expr::eq(
                                    Expr::load(
                                        vast_nodes,
                                        Expr::add(
                                            Expr::var("prior_typedef_base"),
                                            Expr::u32(VAST_NODE_STRIDE_U32),
                                        ),
                                    ),
                                    Expr::u32(TOK_IDENTIFIER),
                                ),
                                Expr::and(
                                    Expr::eq(
                                        Expr::load(
                                            vast_nodes,
                                            Expr::add(
                                                Expr::var("prior_typedef_base"),
                                                Expr::u32(VAST_NODE_STRIDE_U32 * 2),
                                            ),
                                        ),
                                        Expr::u32(TOK_RPAREN),
                                    ),
                                    Expr::eq(
                                        Expr::load(
                                            vast_nodes,
                                            Expr::add(
                                                Expr::var("prior_typedef_base"),
                                                Expr::u32(VAST_NODE_STRIDE_U32 * 5),
                                            ),
                                        ),
                                        Expr::u32(TOK_SEMICOLON),
                                    ),
                                ),
                            ),
                        ),
                    ),
                    vec![Node::assign(
                        "has_prior_parenthesized_identifier_statement",
                        Expr::u32(1),
                    )],
                ),
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("has_typedef_annotations"), Expr::u32(0)),
                        Expr::eq(
                            Expr::load(
                                vast_nodes,
                                Expr::add(
                                    Expr::var("prior_typedef_base"),
                                    Expr::u32(VAST_TYPEDEF_FLAGS_FIELD),
                                ),
                            ),
                            Expr::u32(C_TYPEDEF_FLAG_ORDINARY_DECLARATOR),
                        ),
                    ),
                    vec![Node::assign("has_prior_ordinary_decl", Expr::u32(1))],
                ),
            ],
        ),
        Node::let_bind(
            "ambiguous_parenthesized_identifier_multiply",
            Expr::and(
                Expr::and(
                    Expr::var("raw_lparen"),
                    Expr::eq(Expr::var("next_kind"), Expr::u32(TOK_STAR)),
                ),
                Expr::eq(
                    Expr::var("has_prior_parenthesized_identifier_statement"),
                    Expr::u32(1),
                ),
            ),
        ),
        Node::let_bind(
            "fallback_has_prior_typedef",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("has_typedef_annotations"), Expr::u32(0)),
                    Expr::eq(Expr::var("has_prior_typedef"), Expr::u32(1)),
                ),
                Expr::and(
                    Expr::eq(Expr::var("has_prior_ordinary_decl"), Expr::u32(0)),
                    Expr::not(Expr::var("ambiguous_parenthesized_identifier_multiply")),
                ),
            ),
        ),
        Node::if_then(
            Expr::or(Expr::var("identifier_then_paren"), Expr::var("raw_lparen")),
            vec![
                Node::let_bind(
                    "suffix_start_idx",
                    Expr::select(
                        Expr::var("identifier_then_paren"),
                        Expr::var("after_param_idx"),
                        Expr::var("next_idx"),
                    ),
                ),
                Node::let_bind("suffix_scan_idx", Expr::var("after_param_idx")),
                Node::assign("suffix_scan_idx", Expr::var("suffix_start_idx")),
                Node::loop_for(
                    "suffix_scan_step",
                    Expr::u32(0),
                    Expr::u32(16),
                    vec![Node::if_then(
                        Expr::and(
                            Expr::lt(Expr::var("suffix_scan_idx"), num_nodes.clone()),
                            Expr::eq(Expr::var("suffix_boundary"), Expr::u32(0)),
                        ),
                        vec![
                            Node::let_bind(
                                "suffix_scan_base",
                                Expr::mul(
                                    Expr::var("suffix_scan_idx"),
                                    Expr::u32(VAST_NODE_STRIDE_U32),
                                ),
                            ),
                            Node::let_bind(
                                "suffix_scan_kind",
                                Expr::load(vast_nodes, Expr::var("suffix_scan_base")),
                            ),
                            Node::if_then(
                                Expr::eq(
                                    Expr::var("suffix_scan_kind"),
                                    Expr::u32(TOK_GNU_ATTRIBUTE),
                                ),
                                vec![Node::assign("suffix_has_gnu_attribute", Expr::u32(1))],
                            ),
                            Node::if_then(
                                Expr::or(
                                    Expr::eq(Expr::var("suffix_scan_kind"), Expr::u32(TOK_LBRACE)),
                                    Expr::eq(
                                        Expr::var("suffix_scan_kind"),
                                        Expr::u32(TOK_SEMICOLON),
                                    ),
                                ),
                                vec![
                                    Node::assign("suffix_boundary", Expr::u32(1)),
                                    Node::assign(
                                        "suffix_boundary_kind",
                                        Expr::var("suffix_scan_kind"),
                                    ),
                                ],
                            ),
                            Node::if_then(
                                Expr::eq(Expr::var("suffix_scan_kind"), Expr::u32(TOK_RPAREN)),
                                vec![
                                    Node::let_bind(
                                        "suffix_scan_parent",
                                        Expr::load(
                                            vast_nodes,
                                            Expr::add(Expr::var("suffix_scan_base"), Expr::u32(1)),
                                        ),
                                    ),
                                    Node::if_then(
                                        Expr::lt(
                                            Expr::var("suffix_scan_parent"),
                                            num_nodes.clone(),
                                        ),
                                        vec![
                                            Node::let_bind(
                                                "suffix_parent_base",
                                                Expr::mul(
                                                    Expr::var("suffix_scan_parent"),
                                                    Expr::u32(VAST_NODE_STRIDE_U32),
                                                ),
                                            ),
                                            Node::let_bind(
                                                "suffix_parent_next",
                                                Expr::load(
                                                    vast_nodes,
                                                    Expr::add(
                                                        Expr::var("suffix_parent_base"),
                                                        Expr::u32(3),
                                                    ),
                                                ),
                                            ),
                                            Node::if_then(
                                                Expr::lt(
                                                    Expr::var("suffix_parent_next"),
                                                    num_nodes.clone(),
                                                ),
                                                vec![
                                                    Node::let_bind(
                                                        "suffix_parent_next_kind",
                                                        Expr::load(
                                                            vast_nodes,
                                                            Expr::mul(
                                                                Expr::var("suffix_parent_next"),
                                                                Expr::u32(VAST_NODE_STRIDE_U32),
                                                            ),
                                                        ),
                                                    ),
                                                    Node::if_then(
                                                        any_token_eq(
                                                            Expr::var("suffix_parent_next_kind"),
                                                            &[
                                                                TOK_LPAREN,
                                                                TOK_LBRACKET,
                                                                TOK_SEMICOLON,
                                                            ],
                                                        ),
                                                        vec![
                                                            Node::assign(
                                                                "suffix_boundary",
                                                                Expr::u32(1),
                                                            ),
                                                            Node::assign(
                                                                "suffix_boundary_kind",
                                                                Expr::var(
                                                                    "suffix_parent_next_kind",
                                                                ),
                                                            ),
                                                        ],
                                                    ),
                                                    Node::if_then(
                                                        Expr::and(
                                                            Expr::eq(
                                                                Expr::var(
                                                                    "suffix_parent_next_kind",
                                                                ),
                                                                Expr::u32(TOK_RPAREN),
                                                            ),
                                                            Expr::eq(
                                                                Expr::var("suffix_boundary"),
                                                                Expr::u32(0),
                                                            ),
                                                        ),
                                                        vec![
                                                            Node::let_bind(
                                                                "suffix_parent_next_base",
                                                                Expr::mul(
                                                                    Expr::var(
                                                                        "suffix_parent_next",
                                                                    ),
                                                                    Expr::u32(
                                                                        VAST_NODE_STRIDE_U32,
                                                                    ),
                                                                ),
                                                            ),
                                                            Node::let_bind(
                                                                "suffix_parent_next_parent",
                                                                Expr::load(
                                                                    vast_nodes,
                                                                    Expr::add(
                                                                        Expr::var(
                                                                            "suffix_parent_next_base",
                                                                        ),
                                                                        Expr::u32(1),
                                                                    ),
                                                                ),
                                                            ),
                                                            Node::if_then(
                                                                Expr::lt(
                                                                    Expr::var(
                                                                        "suffix_parent_next_parent",
                                                                    ),
                                                                    num_nodes.clone(),
                                                                ),
                                                                vec![
                                                                    Node::let_bind(
                                                                        "suffix_parent_next_parent_base",
                                                                        Expr::mul(
                                                                            Expr::var(
                                                                                "suffix_parent_next_parent",
                                                                            ),
                                                                            Expr::u32(
                                                                                VAST_NODE_STRIDE_U32,
                                                                            ),
                                                                        ),
                                                                    ),
                                                                    Node::let_bind(
                                                                        "suffix_parent_next_parent_next",
                                                                        Expr::load(
                                                                            vast_nodes,
                                                                            Expr::add(
                                                                                Expr::var(
                                                                                    "suffix_parent_next_parent_base",
                                                                                ),
                                                                                Expr::u32(3),
                                                                            ),
                                                                        ),
                                                                    ),
                                                                    Node::if_then(
                                                                        Expr::lt(
                                                                            Expr::var(
                                                                                "suffix_parent_next_parent_next",
                                                                            ),
                                                                            num_nodes.clone(),
                                                                        ),
                                                                        vec![
                                                                            Node::let_bind(
                                                                                "suffix_parent_next_parent_next_kind",
                                                                                Expr::load(
                                                                                    vast_nodes,
                                                                                    Expr::mul(
                                                                                        Expr::var(
                                                                                            "suffix_parent_next_parent_next",
                                                                                        ),
                                                                                        Expr::u32(
                                                                                            VAST_NODE_STRIDE_U32,
                                                                                        ),
                                                                                    ),
                                                                                ),
                                                                            ),
                                                                            Node::if_then(
                                                                                any_token_eq(
                                                                                    Expr::var(
                                                                                        "suffix_parent_next_parent_next_kind",
                                                                                    ),
                                                                                    &[
                                                                                        TOK_LPAREN,
                                                                                        TOK_LBRACKET,
                                                                                        TOK_SEMICOLON,
                                                                                    ],
                                                                                ),
                                                                                vec![
                                                                                    Node::assign(
                                                                                        "suffix_boundary",
                                                                                        Expr::u32(1),
                                                                                    ),
                                                                                    Node::assign(
                                                                                        "suffix_boundary_kind",
                                                                                        Expr::var(
                                                                                            "suffix_parent_next_parent_next_kind",
                                                                                        ),
                                                                                    ),
                                                                                ],
                                                                            ),
                                                                        ],
                                                                    ),
                                                                ],
                                                            ),
                                                        ],
                                                    ),
                                                ],
                                            ),
                                        ],
                                    ),
                                ],
                            ),
                            Node::assign(
                                "suffix_scan_idx",
                                Expr::load(
                                    vast_nodes,
                                    Expr::add(Expr::var("suffix_scan_base"), Expr::u32(3)),
                                ),
                            ),
                        ],
                    )],
                ),
            ],
        ),
        Node::let_bind(
            "function_boundary",
            Expr::eq(Expr::var("suffix_boundary"), Expr::u32(1)),
        ),
        Node::let_bind(
            "type_name_expr_follower",
            any_token_eq(
                Expr::var("next_kind"),
                &[
                    TOK_LBRACE,
                    TOK_LPAREN,
                    TOK_IDENTIFIER,
                    TOK_INTEGER,
                    TOK_FLOAT,
                    TOK_STRING,
                    TOK_CHAR,
                    TOK_STAR,
                    TOK_AMP,
                    TOK_PLUS,
                    TOK_MINUS,
                    TOK_BANG,
                    TOK_TILDE,
                    TOK_INC,
                    TOK_DEC,
                ],
            ),
        ),
        Node::let_bind(
            "flat_type_name_expr_follower",
            any_token_eq(
                Expr::var("raw_after_after_kind"),
                &[
                    TOK_LBRACE,
                    TOK_LPAREN,
                    TOK_IDENTIFIER,
                    TOK_INTEGER,
                    TOK_FLOAT,
                    TOK_STRING,
                    TOK_CHAR,
                    TOK_STAR,
                    TOK_AMP,
                    TOK_PLUS,
                    TOK_MINUS,
                    TOK_BANG,
                    TOK_TILDE,
                    TOK_INC,
                    TOK_DEC,
                ],
            ),
        ),
        Node::let_bind(
            "identifier_type_name_paren",
            Expr::and(
                Expr::and(
                    Expr::var("raw_lparen"),
                    Expr::eq(Expr::var("first_child_kind"), Expr::u32(TOK_IDENTIFIER)),
                ),
                Expr::var("type_name_expr_follower"),
            ),
        ),
        Node::let_bind(
            "flat_identifier_type_name_paren",
            Expr::and(
                Expr::and(
                    Expr::and(
                        Expr::var("raw_lparen"),
                        Expr::eq(Expr::var("raw_next_kind"), Expr::u32(TOK_IDENTIFIER)),
                    ),
                    Expr::and(
                        is_type_name_identifier(
                            Expr::var("raw_next_typedef_flags"),
                            Expr::var("fallback_has_prior_typedef"),
                        ),
                        Expr::eq(Expr::var("raw_after_next_kind"), Expr::u32(TOK_RPAREN)),
                    ),
                ),
                Expr::var("flat_type_name_expr_follower"),
            ),
        ),
        Node::let_bind(
            "type_name_paren",
            Expr::and(
                Expr::and(
                    Expr::var("raw_lparen"),
                    Expr::not(Expr::or(
                        any_token_eq(
                            Expr::var("prev_sibling_kind"),
                            &[TOK_SIZEOF, TOK_ALIGNOF, TOK_ATOMIC],
                        ),
                        is_typeof_operator_token(
                            Expr::var("prev_sibling_kind"),
                            Expr::var("prev_sibling_symbol_hash"),
                        ),
                    )),
                ),
                Expr::or(
                    Expr::or(
                        is_type_name_start_token(Expr::var("first_child_kind")),
                        is_typeof_operator_token(
                            Expr::var("first_child_kind"),
                            Expr::var("first_child_symbol_hash"),
                        ),
                    ),
                    Expr::and(
                        Expr::or(
                            is_type_name_identifier(
                                Expr::var("first_child_typedef_flags"),
                                Expr::var("fallback_has_prior_typedef"),
                            ),
                            Expr::var("flat_identifier_type_name_paren"),
                        ),
                        Expr::or(
                            Expr::var("identifier_type_name_paren"),
                            Expr::var("flat_identifier_type_name_paren"),
                        ),
                    ),
                ),
            ),
        ),
        Node::let_bind(
            "is_return_function_suffix",
            Expr::and(
                Expr::and(
                    Expr::and(Expr::var("raw_lparen"), Expr::var("type_name_paren")),
                    Expr::var("function_boundary"),
                ),
                Expr::and(
                    Expr::eq(Expr::var("effective_has_decl_prefix"), Expr::u32(1)),
                    Expr::eq(Expr::var("prev_sibling_kind"), Expr::u32(TOK_LPAREN)),
                ),
            ),
        ),
        Node::let_bind(
            "is_function_declarator",
            Expr::or(
                Expr::or(
                    Expr::and(
                        Expr::and(Expr::var("raw_lparen"), Expr::var("function_boundary")),
                        Expr::and(
                            Expr::eq(Expr::var("effective_has_decl_prefix"), Expr::u32(1)),
                            any_token_eq(
                                Expr::var("prev_sibling_kind"),
                                &[TOK_IDENTIFIER, TOK_LPAREN, TOK_RPAREN],
                            ),
                        ),
                    ),
                    Expr::and(
                        Expr::and(
                            Expr::var("raw_lparen"),
                            Expr::or(
                                Expr::var("type_name_paren"),
                                is_type_name_start_token(Expr::var("first_child_kind")),
                            ),
                        ),
                        any_token_eq(Expr::var("prev_sibling_kind"), &[TOK_LPAREN, TOK_RPAREN]),
                    ),
                ),
                Expr::var("is_return_function_suffix"),
            ),
        ),
        Node::let_bind(
            "is_function_decl",
            Expr::and(
                Expr::and(
                    Expr::var("identifier_then_paren"),
                    Expr::var("function_boundary"),
                ),
                Expr::and(
                    Expr::eq(Expr::var("effective_has_decl_prefix"), Expr::u32(1)),
                    Expr::ne(Expr::var("prev_sibling_kind"), Expr::u32(TOK_LPAREN)),
                ),
            ),
        ),
        Node::let_bind(
            "is_function_definition",
            Expr::and(
                Expr::var("is_function_decl"),
                Expr::eq(Expr::var("suffix_boundary_kind"), Expr::u32(TOK_LBRACE)),
            ),
        ),
        Node::let_bind(
            "aggregate_decl_kind",
            Expr::select(
                Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_STRUCT)),
                Expr::u32(C_AST_KIND_STRUCT_DECL),
                Expr::select(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_UNION)),
                    Expr::u32(C_AST_KIND_UNION_DECL),
                    Expr::select(
                        Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_ENUM)),
                        Expr::u32(C_AST_KIND_ENUM_DECL),
                        Expr::u32(0),
                    ),
                ),
            ),
        ),
        Node::let_bind(
            "is_typedef_decl",
            Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_TYPEDEF)),
        ),
        Node::let_bind(
            "is_static_assert_decl",
            Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_STATIC_ASSERT)),
        ),
        Node::let_bind(
            "is_call",
            Expr::and(
                Expr::var("identifier_then_paren"),
                Expr::not(Expr::var("is_function_decl")),
            ),
        ),
        Node::let_bind(
            "inside_gnu_statement_expr_body",
            Expr::and(
                Expr::eq(Expr::var("cur_parent_kind"), Expr::u32(TOK_LBRACE)),
                Expr::eq(Expr::var("cur_parent_parent_kind"), Expr::u32(TOK_LPAREN)),
            ),
        ),
        Node::let_bind(
            "c99_for_init_statement_assign",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_ASSIGN)),
                    Expr::and(
                        Expr::eq(Expr::var("cur_parent_kind"), Expr::u32(TOK_LPAREN)),
                        Expr::eq(Expr::var("effective_has_decl_prefix"), Expr::u32(1)),
                    ),
                ),
                Expr::or(
                    Expr::eq(
                        Expr::var("cur_parent_prev_sibling_kind"),
                        Expr::u32(TOK_FOR),
                    ),
                    Expr::eq(Expr::var("cur_parent_parent_kind"), Expr::u32(TOK_FOR)),
                ),
            ),
        ),
        Node::let_bind("declaration_initializer_prefix", Expr::u32(0)),
        Node::if_then(
            Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_ASSIGN)),
            vec![Node::loop_for(
                "decl_init_scan",
                Expr::u32(0),
                t.clone(),
                vec![
                    Node::let_bind(
                        "decl_init_base",
                        Expr::mul(Expr::var("decl_init_scan"), Expr::u32(VAST_NODE_STRIDE_U32)),
                    ),
                    Node::let_bind(
                        "decl_init_parent",
                        Expr::load(
                            vast_nodes,
                            Expr::add(Expr::var("decl_init_base"), Expr::u32(1)),
                        ),
                    ),
                    Node::if_then(
                        Expr::eq(Expr::var("decl_init_parent"), Expr::var("cur_parent")),
                        vec![
                            Node::let_bind(
                                "decl_init_kind",
                                Expr::load(vast_nodes, Expr::var("decl_init_base")),
                            ),
                            Node::let_bind(
                                "decl_init_symbol_hash",
                                Expr::load(
                                    vast_nodes,
                                    Expr::add(
                                        Expr::var("decl_init_base"),
                                        Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD),
                                    ),
                                ),
                            ),
                            Node::if_then(
                                any_token_eq(
                                    Expr::var("decl_init_kind"),
                                    &[TOK_SEMICOLON, TOK_LBRACE, TOK_RBRACE],
                                ),
                                vec![Node::assign("declaration_initializer_prefix", Expr::u32(0))],
                            ),
                            Node::if_then(
                                is_decl_prefix_token_or_gnu_type_hash(
                                    Expr::var("decl_init_kind"),
                                    Expr::var("decl_init_symbol_hash"),
                                ),
                                vec![Node::assign("declaration_initializer_prefix", Expr::u32(1))],
                            ),
                        ],
                    ),
                ],
            )],
        ),
        Node::let_bind(
            "parent_is_initializer_list_context",
            Expr::and(
                Expr::eq(Expr::var("cur_parent_kind"), Expr::u32(TOK_LBRACE)),
                Expr::or(
                    any_token_eq(
                        Expr::var("cur_parent_prev_sibling_kind"),
                        &[TOK_ASSIGN, TOK_COMMA],
                    ),
                    Expr::and(
                        Expr::eq(
                            Expr::var("cur_parent_prev_sibling_kind"),
                            Expr::u32(TOK_LBRACE),
                        ),
                        Expr::and(
                            Expr::eq(Expr::var("cur_parent_parent_kind"), Expr::u32(TOK_LBRACE)),
                            any_token_eq(
                                Expr::var("cur_grandparent_prev_sibling_kind"),
                                &[TOK_ASSIGN, TOK_COMMA, TOK_LBRACE],
                            ),
                        ),
                    ),
                ),
            ),
        ),
        Node::let_bind(
            "is_array_declaration_initializer_assign",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_ASSIGN)),
                    Expr::eq(Expr::var("prev_sibling_kind"), Expr::u32(TOK_LBRACKET)),
                ),
                Expr::and(
                    Expr::eq(Expr::var("effective_has_decl_prefix"), Expr::u32(1)),
                    Expr::and(
                        Expr::not(Expr::var("parent_is_initializer_list_context")),
                        Expr::eq(Expr::var("next_kind"), Expr::u32(TOK_STRING)),
                    ),
                ),
            ),
        ),
        Node::let_bind(
            "is_declaration_initializer_assign",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_ASSIGN)),
                    Expr::or(
                        Expr::eq(Expr::var("declaration_initializer_prefix"), Expr::u32(1)),
                        Expr::or(
                            Expr::eq(Expr::var("effective_has_decl_prefix"), Expr::u32(1)),
                            Expr::var("c99_for_init_statement_assign"),
                        ),
                    ),
                ),
                Expr::and(
                    Expr::not(Expr::var("inside_gnu_statement_expr_body")),
                    Expr::not(Expr::var("is_array_declaration_initializer_assign")),
                ),
            ),
        ),
        Node::let_bind(
            "is_pointer_decl",
            Expr::and(
                Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_STAR)),
                Expr::or(
                    Expr::eq(Expr::var("effective_has_decl_prefix"), Expr::u32(1)),
                    Expr::and(
                        Expr::and(
                            is_type_name_identifier(
                                Expr::var("prev_sibling_typedef_flags"),
                                Expr::var("fallback_has_prior_typedef"),
                            ),
                            Expr::eq(Expr::var("prev_sibling_kind"), Expr::u32(TOK_IDENTIFIER)),
                        ),
                        Expr::and(
                            Expr::eq(Expr::var("next_kind"), Expr::u32(TOK_IDENTIFIER)),
                            any_token_eq(
                                Expr::var("prev_prev_sibling_kind"),
                                &[SENTINEL, TOK_LBRACE, TOK_LPAREN, TOK_SEMICOLON, TOK_COMMA],
                            ),
                        ),
                    ),
                ),
            ),
        ),
        Node::let_bind(
            "is_array_decl",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_LBRACKET)),
                    Expr::or(
                        Expr::eq(Expr::var("prev_sibling_kind"), Expr::u32(TOK_IDENTIFIER)),
                        Expr::and(
                            Expr::eq(Expr::var("prev_sibling_kind"), Expr::u32(TOK_LPAREN)),
                            any_token_eq(
                                Expr::var("prev_sibling_first_child_kind"),
                                &[TOK_STAR, TOK_IDENTIFIER, TOK_LPAREN],
                            ),
                        ),
                    ),
                ),
                Expr::eq(Expr::var("effective_has_decl_prefix"), Expr::u32(1)),
            ),
        ),
        Node::let_bind(
            "is_array_designator_expr",
            Expr::and(
                Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_LBRACKET)),
                Expr::eq(Expr::var("next_kind"), Expr::u32(TOK_ASSIGN)),
            ),
        ),
        Node::let_bind("declarator_parent_override", Expr::var("cur_parent")),
        Node::if_then(
            Expr::and(
                Expr::var("is_array_decl"),
                Expr::and(
                    Expr::eq(Expr::var("prev_sibling_kind"), Expr::u32(TOK_LPAREN)),
                    Expr::eq(
                        Expr::var("prev_sibling_first_child_kind"),
                        Expr::u32(TOK_STAR),
                    ),
                ),
            ),
            vec![Node::assign(
                "declarator_parent_override",
                Expr::var("prev_sibling_first_child_idx"),
            )],
        ),
        Node::let_bind(
            "is_compound_literal",
            Expr::and(
                Expr::and(Expr::var("raw_lparen"), Expr::var("type_name_paren")),
                Expr::eq(Expr::var("next_kind"), Expr::u32(TOK_LBRACE)),
            ),
        ),
        Node::let_bind(
            "is_cast_expr",
            Expr::and(
                Expr::and(Expr::var("raw_lparen"), Expr::var("type_name_paren")),
                Expr::and(
                    Expr::not(Expr::var("is_function_declarator")),
                    Expr::not(Expr::var("is_compound_literal")),
                ),
            ),
        ),
        Node::let_bind(
            "star_after_parenthesized_identifier_expr",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_STAR)),
                    Expr::eq(Expr::var("prev_sibling_kind"), Expr::u32(TOK_LPAREN)),
                ),
                Expr::and(
                    Expr::eq(
                        Expr::var("prev_sibling_first_child_kind"),
                        Expr::u32(TOK_IDENTIFIER),
                    ),
                    Expr::or(
                        Expr::and(
                            Expr::eq(Expr::var("has_typedef_annotations"), Expr::u32(1)),
                            Expr::not(is_typedef_name_annotation(Expr::var(
                                "prev_sibling_first_child_typedef_flags",
                            ))),
                        ),
                        Expr::and(
                            Expr::eq(Expr::var("has_typedef_annotations"), Expr::u32(0)),
                            Expr::or(
                                Expr::eq(Expr::var("has_prior_typedef"), Expr::u32(0)),
                                Expr::or(
                                    Expr::eq(Expr::var("has_prior_ordinary_decl"), Expr::u32(1)),
                                    Expr::eq(
                                        Expr::var("has_prior_parenthesized_identifier_statement"),
                                        Expr::u32(1),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
        Node::let_bind(
            "brace_after_compound_literal_type",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("prev_sibling_kind"), Expr::u32(TOK_LPAREN)),
                    Expr::or(
                        Expr::or(
                            is_type_name_start_token(Expr::var("prev_sibling_first_child_kind")),
                            is_typeof_operator_token(
                                Expr::var("prev_sibling_first_child_kind"),
                                Expr::var("prev_sibling_first_child_symbol_hash"),
                            ),
                        ),
                        Expr::and(
                            Expr::eq(
                                Expr::var("prev_sibling_first_child_kind"),
                                Expr::u32(TOK_IDENTIFIER),
                            ),
                            is_type_name_identifier(
                                Expr::var("prev_sibling_first_child_typedef_flags"),
                                Expr::var("fallback_has_prior_typedef"),
                            ),
                        ),
                    ),
                ),
                any_token_eq(
                    Expr::var("prev_prev_sibling_kind"),
                    &[TOK_ASSIGN, TOK_RETURN, TOK_COMMA, TOK_LPAREN],
                ),
            ),
        ),
        Node::let_bind(
            "is_initializer_list",
            Expr::and(
                Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_LBRACE)),
                Expr::or(
                    Expr::eq(Expr::var("prev_sibling_kind"), Expr::u32(TOK_ASSIGN)),
                    Expr::or(
                        Expr::var("brace_after_compound_literal_type"),
                        Expr::and(
                            any_token_eq(
                                Expr::var("prev_sibling_kind"),
                                &[SENTINEL, TOK_LBRACE, TOK_COMMA],
                            ),
                            Expr::var("parent_is_initializer_list_context"),
                        ),
                    ),
                ),
            ),
        ),
        Node::let_bind(
            "field_decl_follower",
            any_token_eq(
                Expr::var("next_kind"),
                &[
                    TOK_SEMICOLON,
                    TOK_COMMA,
                    TOK_ASSIGN,
                    TOK_LBRACKET,
                    TOK_COLON,
                ],
            ),
        ),
        Node::let_bind(
            "is_field_decl",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_IDENTIFIER)),
                    Expr::var("parent_is_record_body"),
                ),
                Expr::and(
                    Expr::eq(Expr::var("has_decl_prefix"), Expr::u32(1)),
                    Expr::var("field_decl_follower"),
                ),
            ),
        ),
        Node::let_bind(
            "is_bit_field_decl",
            Expr::and(
                Expr::var("is_field_decl"),
                Expr::eq(Expr::var("next_kind"), Expr::u32(TOK_COLON)),
            ),
        ),
        Node::let_bind(
            "is_anonymous_bit_field_decl",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_COLON)),
                    Expr::var("parent_is_record_body"),
                ),
                Expr::and(
                    Expr::eq(Expr::var("has_decl_prefix"), Expr::u32(1)),
                    Expr::ne(Expr::var("prev_sibling_kind"), Expr::u32(TOK_IDENTIFIER)),
                ),
            ),
        ),
        Node::let_bind(
            "enumerator_decl_follower",
            any_token_eq(Expr::var("next_kind"), &[TOK_COMMA, TOK_ASSIGN, TOK_RBRACE]),
        ),
        Node::let_bind(
            "is_enumerator_decl",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_IDENTIFIER)),
                    Expr::var("parent_is_enum_body"),
                ),
                Expr::and(
                    Expr::or(
                        Expr::eq(Expr::var("prev_sibling_kind"), Expr::u32(SENTINEL)),
                        Expr::eq(Expr::var("prev_sibling_kind"), Expr::u32(TOK_COMMA)),
                    ),
                    Expr::var("enumerator_decl_follower"),
                ),
            ),
        ),
        Node::let_bind(
            "is_label_stmt",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_IDENTIFIER)),
                    Expr::eq(Expr::var("next_kind"), Expr::u32(TOK_COLON)),
                ),
                Expr::and(
                    Expr::not(Expr::var("parent_is_record_body")),
                    Expr::not(Expr::var("parent_is_enum_body")),
                ),
            ),
        ),
        Node::let_bind(
            "is_gnu_statement_expr",
            Expr::and(
                Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_LPAREN)),
                Expr::eq(Expr::var("first_child_kind"), Expr::u32(TOK_LBRACE)),
            ),
        ),
        Node::let_bind(
            "asm_prefix_before_current",
            Expr::or(
                Expr::eq(Expr::var("prev_sibling_kind"), Expr::u32(TOK_GNU_ASM)),
                Expr::and(
                    any_token_eq(Expr::var("prev_sibling_kind"), &[TOK_VOLATILE, TOK_GOTO]),
                    Expr::eq(Expr::var("prev_prev_sibling_kind"), Expr::u32(TOK_GNU_ASM)),
                ),
            ),
        ),
        Node::let_bind(
            "asm_prefix_before_parent",
            Expr::or(
                Expr::eq(
                    Expr::var("cur_parent_prev_sibling_kind"),
                    Expr::u32(TOK_GNU_ASM),
                ),
                Expr::or(
                    Expr::and(
                        any_token_eq(
                            Expr::var("cur_parent_prev_sibling_kind"),
                            &[TOK_VOLATILE, TOK_GOTO],
                        ),
                        Expr::eq(
                            Expr::var("cur_parent_prev_prev_sibling_kind"),
                            Expr::u32(TOK_GNU_ASM),
                        ),
                    ),
                    Expr::and(
                        Expr::eq(
                            Expr::var("cur_parent_prev_sibling_kind"),
                            Expr::u32(TOK_GOTO),
                        ),
                        Expr::eq(
                            Expr::var("cur_parent_prev_prev_sibling_kind"),
                            Expr::u32(TOK_VOLATILE),
                        ),
                    ),
                ),
            ),
        ),
        Node::let_bind(
            "is_asm_goto_qualifier",
            Expr::and(
                Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_GOTO)),
                Expr::var("asm_prefix_before_current"),
            ),
        ),
        Node::let_bind(
            "is_asm_volatile_qualifier",
            Expr::and(
                Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_VOLATILE)),
                Expr::var("asm_prefix_before_current"),
            ),
        ),
        Node::let_bind(
            "asm_paren_context",
            Expr::and(
                Expr::eq(Expr::var("cur_parent_kind"), Expr::u32(TOK_LPAREN)),
                Expr::var("asm_prefix_before_parent"),
            ),
        ),
        Node::let_bind(
            "is_asm_template",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_STRING)),
                    Expr::var("asm_paren_context"),
                ),
                Expr::eq(Expr::var("colon_count_before"), Expr::u32(0)),
            ),
        ),
        Node::let_bind(
            "is_asm_output_operand",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_LPAREN)),
                    Expr::var("asm_paren_context"),
                ),
                Expr::and(
                    Expr::eq(Expr::var("prev_sibling_kind"), Expr::u32(TOK_STRING)),
                    Expr::eq(Expr::var("colon_count_before"), Expr::u32(1)),
                ),
            ),
        ),
        Node::let_bind(
            "is_asm_input_operand",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_LPAREN)),
                    Expr::var("asm_paren_context"),
                ),
                Expr::and(
                    Expr::eq(Expr::var("prev_sibling_kind"), Expr::u32(TOK_STRING)),
                    Expr::eq(Expr::var("colon_count_before"), Expr::u32(2)),
                ),
            ),
        ),
        Node::let_bind(
            "is_asm_clobbers_list",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_STRING)),
                    Expr::var("asm_paren_context"),
                ),
                Expr::ge(Expr::var("colon_count_before"), Expr::u32(3)),
            ),
        ),
        Node::let_bind(
            "is_asm_goto_label",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_IDENTIFIER)),
                    Expr::var("asm_paren_context"),
                ),
                Expr::and(
                    Expr::ge(Expr::var("colon_count_before"), Expr::u32(4)),
                    Expr::or(
                        Expr::eq(
                            Expr::var("cur_parent_prev_sibling_kind"),
                            Expr::u32(TOK_GOTO),
                        ),
                        Expr::eq(
                            Expr::var("cur_parent_prev_prev_sibling_kind"),
                            Expr::u32(TOK_GOTO),
                        ),
                    ),
                ),
            ),
        ),
        Node::let_bind(
            "attribute_name_context",
            Expr::and(
                Expr::and(
                    any_token_eq(Expr::var("raw_kind"), &[TOK_IDENTIFIER, TOK_CONST]),
                    Expr::eq(Expr::var("cur_parent_kind"), Expr::u32(TOK_LPAREN)),
                ),
                Expr::and(
                    Expr::eq(Expr::var("cur_parent_parent_kind"), Expr::u32(TOK_LPAREN)),
                    Expr::or(
                        Expr::eq(
                            Expr::var("cur_grandparent_prev_sibling_kind"),
                            Expr::u32(TOK_GNU_ATTRIBUTE),
                        ),
                        Expr::eq(
                            Expr::var("cur_parent_parent_prev_adjacent_kind"),
                            Expr::u32(TOK_GNU_ATTRIBUTE),
                        ),
                    ),
                ),
            ),
        ),
        Node::let_bind(
            "attribute_kind",
            Expr::select(
                Expr::var("attribute_name_context"),
                Expr::select(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_CONST)),
                    Expr::u32(C_AST_KIND_ATTRIBUTE_CONST),
                    c_attribute_kind_from_hash(Expr::var("current_symbol_hash")),
                ),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "direct_attribute_kind",
            Expr::select(
                Expr::and(
                    Expr::and(
                        any_token_eq(Expr::var("raw_kind"), &[TOK_IDENTIFIER, TOK_CONST]),
                        Expr::eq(Expr::var("cur_parent_kind"), Expr::u32(TOK_LPAREN)),
                    ),
                    Expr::and(
                        Expr::eq(Expr::var("cur_parent_parent_kind"), Expr::u32(TOK_LPAREN)),
                        Expr::eq(
                            Expr::var("cur_parent_parent_prev_adjacent_kind"),
                            Expr::u32(TOK_GNU_ATTRIBUTE),
                        ),
                    ),
                ),
                Expr::select(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_CONST)),
                    Expr::u32(C_AST_KIND_ATTRIBUTE_CONST),
                    c_attribute_kind_from_hash(Expr::var("current_symbol_hash")),
                ),
                Expr::u32(0),
            ),
        ),
        Node::let_bind(
            "statement_kind",
            Expr::select(
                Expr::var("is_asm_goto_qualifier"),
                Expr::u32(0),
                c_statement_kind(Expr::var("raw_kind")),
            ),
        ),
        Node::let_bind(
            "expression_kind",
            Expr::select(
                Expr::var("is_declaration_initializer_assign"),
                Expr::u32(0),
                c_expression_operator_kind(
                    Expr::var("raw_kind"),
                    Expr::var("prev_sibling_kind"),
                    Expr::var("prev_prev_sibling_kind"),
                ),
            ),
        ),
        Node::let_bind("builtin_expression_kind", {
            let token_kind = c_builtin_expression_kind(Expr::var("raw_kind"));
            Expr::select(
                Expr::ne(token_kind.clone(), Expr::u32(0)),
                token_kind,
                c_builtin_identifier_expression_kind(
                    Expr::var("raw_kind"),
                    Expr::var("current_symbol_hash"),
                    Expr::var("next_kind"),
                ),
            )
        }),
        Node::let_bind(
            "is_gnu_label_address_expr",
            Expr::and(
                Expr::and(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_AND)),
                    c_unary_context(Expr::var("prev_sibling_kind")),
                ),
                Expr::eq(Expr::var("next_kind"), Expr::u32(TOK_IDENTIFIER)),
            ),
        ),
        Node::let_bind("typed_kind", {
            let mut kind = Expr::u32(0);
            kind = Expr::select(
                Expr::and(
                    Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_IDENTIFIER)),
                    Expr::not(is_gnu_auto_type_symbol_hash(Expr::var(
                        "current_symbol_hash",
                    ))),
                ),
                Expr::u32(node_kind::VARIABLE),
                kind,
            );
            kind = Expr::select(
                is_c_literal_token(Expr::var("raw_kind")),
                Expr::u32(node_kind::LITERAL),
                kind,
            );
            kind = Expr::select(
                Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_GNU_ATTRIBUTE)),
                Expr::u32(C_AST_KIND_GNU_ATTRIBUTE),
                kind,
            );
            kind = Expr::select(
                Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_GNU_ASM)),
                Expr::u32(C_AST_KIND_INLINE_ASM),
                kind,
            );
            kind = Expr::select(
                Expr::ne(Expr::var("expression_kind"), Expr::u32(0)),
                Expr::var("expression_kind"),
                kind,
            );
            kind = Expr::select(
                Expr::ne(Expr::var("builtin_expression_kind"), Expr::u32(0)),
                Expr::var("builtin_expression_kind"),
                kind,
            );
            kind = Expr::select(
                Expr::ne(Expr::var("attribute_kind"), Expr::u32(0)),
                Expr::var("attribute_kind"),
                kind,
            );
            kind = Expr::select(
                Expr::var("is_asm_goto_label"),
                Expr::u32(C_AST_KIND_ASM_GOTO_LABELS),
                kind,
            );
            kind = Expr::select(
                Expr::var("is_asm_clobbers_list"),
                Expr::u32(C_AST_KIND_ASM_CLOBBERS_LIST),
                kind,
            );
            kind = Expr::select(
                Expr::var("is_asm_input_operand"),
                Expr::u32(C_AST_KIND_ASM_INPUT_OPERAND),
                kind,
            );
            kind = Expr::select(
                Expr::var("is_asm_output_operand"),
                Expr::u32(C_AST_KIND_ASM_OUTPUT_OPERAND),
                kind,
            );
            kind = Expr::select(
                Expr::var("is_asm_template"),
                Expr::u32(C_AST_KIND_ASM_TEMPLATE),
                kind,
            );
            kind = Expr::select(
                Expr::var("is_gnu_label_address_expr"),
                Expr::u32(C_AST_KIND_GNU_LABEL_ADDRESS_EXPR),
                kind,
            );
            kind = Expr::select(
                Expr::var("star_after_parenthesized_identifier_expr"),
                Expr::u32(node_kind::BINARY),
                kind,
            );
            kind = Expr::select(
                Expr::ne(Expr::var("statement_kind"), Expr::u32(0)),
                Expr::var("statement_kind"),
                kind,
            );
            kind = Expr::select(
                Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_LBRACE)),
                Expr::u32(node_kind::BASIC_BLOCK),
                kind,
            );
            kind = Expr::select(
                Expr::ne(Expr::var("direct_attribute_kind"), Expr::u32(0)),
                Expr::var("direct_attribute_kind"),
                kind,
            );
            kind = Expr::select(Expr::var("is_call"), Expr::u32(node_kind::CALL), kind);
            kind = Expr::select(
                Expr::ne(Expr::var("attribute_kind"), Expr::u32(0)),
                Expr::var("attribute_kind"),
                kind,
            );
            kind = Expr::select(
                Expr::var("is_enumerator_decl"),
                Expr::u32(C_AST_KIND_ENUMERATOR_DECL),
                kind,
            );
            kind = Expr::select(
                Expr::var("is_field_decl"),
                Expr::u32(C_AST_KIND_FIELD_DECL),
                kind,
            );
            kind = Expr::select(
                Expr::var("is_initializer_list"),
                Expr::u32(C_AST_KIND_INITIALIZER_LIST),
                kind,
            );
            kind = Expr::select(
                Expr::var("is_compound_literal"),
                Expr::u32(C_AST_KIND_COMPOUND_LITERAL_EXPR),
                kind,
            );
            kind = Expr::select(
                Expr::var("is_cast_expr"),
                Expr::u32(C_AST_KIND_CAST_EXPR),
                kind,
            );
            kind = Expr::select(
                Expr::var("is_array_designator_expr"),
                Expr::u32(C_AST_KIND_ARRAY_SUBSCRIPT_EXPR),
                kind,
            );
            kind = Expr::select(
                Expr::var("is_array_decl"),
                Expr::u32(C_AST_KIND_ARRAY_DECL),
                kind,
            );
            kind = Expr::select(
                Expr::var("is_pointer_decl"),
                Expr::u32(C_AST_KIND_POINTER_DECL),
                kind,
            );
            kind = Expr::select(
                Expr::var("is_function_declarator"),
                Expr::u32(C_AST_KIND_FUNCTION_DECLARATOR),
                kind,
            );
            Expr::select(
                Expr::var("is_function_decl"),
                Expr::u32(node_kind::FUNCTION_DECL),
                kind,
            )
        }),
        Node::let_bind(
            "final_typed_kind",
            Expr::select(
                Expr::var("is_function_definition"),
                Expr::u32(C_AST_KIND_FUNCTION_DEFINITION),
                Expr::select(
                    Expr::ne(Expr::var("aggregate_decl_kind"), Expr::u32(0)),
                    Expr::var("aggregate_decl_kind"),
                    Expr::select(
                        Expr::var("is_typedef_decl"),
                        Expr::u32(C_AST_KIND_TYPEDEF_DECL),
                        Expr::select(
                            Expr::var("is_static_assert_decl"),
                            Expr::u32(C_AST_KIND_STATIC_ASSERT_DECL),
                            Expr::select(
                                Expr::eq(Expr::var("raw_kind"), Expr::u32(TOK_GNU_LABEL)),
                                Expr::u32(C_AST_KIND_GNU_LOCAL_LABEL_DECL),
                                Expr::select(
                                    Expr::or(
                                        Expr::var("is_bit_field_decl"),
                                        Expr::var("is_anonymous_bit_field_decl"),
                                    ),
                                    Expr::u32(C_AST_KIND_BIT_FIELD_DECL),
                                    Expr::select(
                                        Expr::var("is_label_stmt"),
                                        Expr::u32(C_AST_KIND_LABEL_STMT),
                                        Expr::select(
                                            Expr::var("is_gnu_statement_expr"),
                                            Expr::u32(C_AST_KIND_GNU_STATEMENT_EXPR),
                                            Expr::select(
                                                Expr::or(
                                                    Expr::var("is_asm_goto_qualifier"),
                                                    Expr::var("is_asm_volatile_qualifier"),
                                                ),
                                                Expr::u32(C_AST_KIND_ASM_QUALIFIER),
                                                Expr::select(
                                                    Expr::ne(
                                                        Expr::var("builtin_expression_kind"),
                                                        Expr::u32(0),
                                                    ),
                                                    Expr::var("builtin_expression_kind"),
                                                    Expr::var("typed_kind"),
                                                ),
                                            ),
                                        ),
                                    ),
                                ),
                            ),
                        ),
                    ),
                ),
            ),
        ),
        Node::if_then(
            Expr::ne(Expr::var("direct_attribute_kind"), Expr::u32(0)),
            vec![Node::assign(
                "final_typed_kind",
                Expr::var("direct_attribute_kind"),
            )],
        ),
        Node::store(
            out_typed_vast_nodes,
            base.clone(),
            Expr::var("final_typed_kind"),
        ),
    ];

    for field in 1..VAST_NODE_STRIDE_U32 {
        let value = if field == 1 {
            Expr::var("declarator_parent_override")
        } else {
            Expr::load(vast_nodes, Expr::add(base.clone(), Expr::u32(field)))
        };
        loop_body.push(Node::store(
            out_typed_vast_nodes,
            Expr::add(base.clone(), Expr::u32(field)),
            value,
        ));
    }

    let n = node_count(&num_nodes).max(1);
    Program::wrapped(
        vec![
            BufferDecl::storage(vast_nodes, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.saturating_mul(VAST_NODE_STRIDE_U32)),
            BufferDecl::storage(
                out_typed_vast_nodes,
                1,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(n.saturating_mul(VAST_NODE_STRIDE_U32)),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            CLASSIFY_VAST_OP_ID,
            vec![Node::if_then(Expr::lt(t.clone(), num_nodes), loop_body)],
        )],
    )
    .with_entry_op_id(CLASSIFY_VAST_OP_ID)
}

/// Build packed C expression-shape rows from raw and typed VAST streams.
///
/// The classifier intentionally keeps VAST rows token-aligned. This pass adds a
/// semantic expression track without changing those rows. Each output row is:
///
/// `(shape_kind, source_idx, raw_operator_token, precedence, associativity,
///   lhs_or_condition_root, rhs_or_then_root, else_root)`.
///
/// Binary rows cover both ordinary binary operators and assignment operators.
/// Conditional rows are emitted on the `?` token and point at condition, then,
/// and else expression roots when a matching same-parent `:` is present.
#[must_use]
pub fn c11_build_expression_shape_nodes(
    raw_vast_nodes: &str,
    typed_vast_nodes: &str,
    num_nodes: Expr,
    out_expr_shape_nodes: &str,
) -> Program {
    let t = Expr::InvocationId { axis: 0 };
    let vast_base = Expr::mul(t.clone(), Expr::u32(VAST_NODE_STRIDE_U32));
    let out_base = Expr::mul(t.clone(), Expr::u32(C_EXPR_SHAPE_STRIDE_U32));

    let mut loop_body = vec![
        Node::let_bind("raw_kind", Expr::load(raw_vast_nodes, vast_base.clone())),
        Node::let_bind(
            "typed_kind",
            Expr::load(typed_vast_nodes, vast_base.clone()),
        ),
        Node::let_bind(
            "cur_parent",
            Expr::load(raw_vast_nodes, Expr::add(vast_base.clone(), Expr::u32(1))),
        ),
        Node::let_bind(
            "shape_kind",
            c_expr_shape_kind(Expr::var("raw_kind"), Expr::var("typed_kind")),
        ),
        Node::let_bind(
            "precedence",
            c_expr_operator_precedence(Expr::var("raw_kind"), Expr::var("typed_kind")),
        ),
        Node::let_bind(
            "associativity",
            c_expr_operator_associativity(Expr::var("typed_kind")),
        ),
    ];

    loop_body.extend(emit_prior_ternary_boundary_flag(
        raw_vast_nodes,
        Expr::var("cur_parent"),
        t.clone(),
        "bin",
    ));
    loop_body.extend(emit_expr_segment_bounds(
        raw_vast_nodes,
        Expr::var("cur_parent"),
        t.clone(),
        num_nodes.clone(),
        "bin_plain",
        false,
    ));
    loop_body.extend(emit_expr_segment_bounds(
        raw_vast_nodes,
        Expr::var("cur_parent"),
        t.clone(),
        num_nodes.clone(),
        "bin_ternary",
        true,
    ));
    loop_body.extend(vec![
        Node::let_bind(
            "bin_seg_start",
            Expr::select(
                Expr::eq(Expr::var("bin_use_ternary_boundaries"), Expr::u32(1)),
                Expr::var("bin_ternary_seg_start"),
                Expr::var("bin_plain_seg_start"),
            ),
        ),
        Node::let_bind(
            "bin_seg_end",
            Expr::select(
                Expr::eq(Expr::var("bin_use_ternary_boundaries"), Expr::u32(1)),
                Expr::var("bin_ternary_seg_end"),
                Expr::var("bin_plain_seg_end"),
            ),
        ),
        Node::let_bind("bin_left_bound", Expr::var("bin_seg_start")),
        Node::let_bind("bin_right_bound", Expr::var("bin_seg_end")),
        Node::let_bind("bin_left_parent_op", Expr::u32(SENTINEL)),
        Node::let_bind("bin_right_parent_op", Expr::u32(SENTINEL)),
        Node::loop_for(
            "bin_parent_scan",
            Expr::var("bin_seg_start"),
            Expr::var("bin_seg_end"),
            vec![
                Node::let_bind(
                    "bin_parent_base",
                    Expr::mul(
                        Expr::var("bin_parent_scan"),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Node::let_bind(
                    "bin_parent_raw",
                    Expr::load(raw_vast_nodes, Expr::var("bin_parent_base")),
                ),
                Node::let_bind(
                    "bin_parent_typed",
                    Expr::load(typed_vast_nodes, Expr::var("bin_parent_base")),
                ),
                Node::let_bind(
                    "bin_parent_parent",
                    Expr::load(
                        raw_vast_nodes,
                        Expr::add(Expr::var("bin_parent_base"), Expr::u32(1)),
                    ),
                ),
                Node::let_bind(
                    "bin_parent_shape",
                    c_expr_shape_kind(Expr::var("bin_parent_raw"), Expr::var("bin_parent_typed")),
                ),
                Node::let_bind(
                    "bin_parent_prec",
                    c_expr_operator_precedence(
                        Expr::var("bin_parent_raw"),
                        Expr::var("bin_parent_typed"),
                    ),
                ),
                Node::let_bind(
                    "bin_parent_is_operator",
                    Expr::and(
                        Expr::ne(Expr::var("bin_parent_shape"), Expr::u32(C_EXPR_SHAPE_NONE)),
                        Expr::ne(Expr::var("bin_parent_scan"), t.clone()),
                    ),
                ),
                Node::let_bind(
                    "bin_parent_equal_assoc",
                    Expr::and(
                        Expr::eq(Expr::var("bin_parent_prec"), Expr::var("precedence")),
                        Expr::or(
                            Expr::and(
                                Expr::eq(Expr::var("associativity"), Expr::u32(C_EXPR_ASSOC_LEFT)),
                                Expr::lt(t.clone(), Expr::var("bin_parent_scan")),
                            ),
                            Expr::and(
                                Expr::eq(Expr::var("associativity"), Expr::u32(C_EXPR_ASSOC_RIGHT)),
                                Expr::lt(Expr::var("bin_parent_scan"), t.clone()),
                            ),
                        ),
                    ),
                ),
                Node::let_bind(
                    "bin_parent_is_ancestor",
                    Expr::and(
                        Expr::and(
                            Expr::eq(Expr::var("bin_parent_parent"), Expr::var("cur_parent")),
                            Expr::var("bin_parent_is_operator"),
                        ),
                        Expr::or(
                            Expr::lt(Expr::var("bin_parent_prec"), Expr::var("precedence")),
                            Expr::var("bin_parent_equal_assoc"),
                        ),
                    ),
                ),
                Node::if_then(
                    Expr::and(
                        Expr::var("bin_parent_is_ancestor"),
                        Expr::lt(Expr::var("bin_parent_scan"), t.clone()),
                    ),
                    vec![Node::assign(
                        "bin_left_parent_op",
                        Expr::var("bin_parent_scan"),
                    )],
                ),
                Node::if_then(
                    Expr::and(
                        Expr::var("bin_parent_is_ancestor"),
                        Expr::and(
                            Expr::lt(t.clone(), Expr::var("bin_parent_scan")),
                            Expr::or(
                                Expr::eq(Expr::var("bin_right_parent_op"), Expr::u32(SENTINEL)),
                                Expr::lt(
                                    Expr::var("bin_parent_scan"),
                                    Expr::var("bin_right_parent_op"),
                                ),
                            ),
                        ),
                    ),
                    vec![Node::assign(
                        "bin_right_parent_op",
                        Expr::var("bin_parent_scan"),
                    )],
                ),
            ],
        ),
        Node::if_then(
            Expr::ne(Expr::var("bin_left_parent_op"), Expr::u32(SENTINEL)),
            vec![Node::assign(
                "bin_left_bound",
                Expr::add(Expr::var("bin_left_parent_op"), Expr::u32(1)),
            )],
        ),
        Node::if_then(
            Expr::ne(Expr::var("bin_right_parent_op"), Expr::u32(SENTINEL)),
            vec![Node::assign(
                "bin_right_bound",
                Expr::var("bin_right_parent_op"),
            )],
        ),
    ]);
    loop_body.extend(emit_expr_root_scan(
        raw_vast_nodes,
        typed_vast_nodes,
        Expr::var("bin_left_bound"),
        t.clone(),
        Expr::var("cur_parent"),
        "bin_lhs",
    ));
    loop_body.extend(emit_expr_root_scan(
        raw_vast_nodes,
        typed_vast_nodes,
        Expr::add(t.clone(), Expr::u32(1)),
        Expr::var("bin_right_bound"),
        Expr::var("cur_parent"),
        "bin_rhs",
    ));

    loop_body.extend(emit_expr_segment_bounds(
        raw_vast_nodes,
        Expr::var("cur_parent"),
        t.clone(),
        num_nodes.clone(),
        "cond",
        false,
    ));
    loop_body.extend(emit_expr_segment_bounds(
        raw_vast_nodes,
        Expr::var("cur_parent"),
        t.clone(),
        num_nodes.clone(),
        "cond_condition",
        true,
    ));
    loop_body.extend(vec![
        Node::let_bind("cond_colon", Expr::u32(SENTINEL)),
        Node::let_bind("cond_depth", Expr::u32(0)),
        Node::loop_for(
            "cond_colon_scan",
            Expr::add(t.clone(), Expr::u32(1)),
            Expr::var("cond_seg_end"),
            vec![Node::if_then(
                Expr::eq(Expr::var("cond_colon"), Expr::u32(SENTINEL)),
                vec![
                    Node::let_bind(
                        "cond_colon_base",
                        Expr::mul(
                            Expr::var("cond_colon_scan"),
                            Expr::u32(VAST_NODE_STRIDE_U32),
                        ),
                    ),
                    Node::let_bind(
                        "cond_colon_raw",
                        Expr::load(raw_vast_nodes, Expr::var("cond_colon_base")),
                    ),
                    Node::let_bind(
                        "cond_colon_parent",
                        Expr::load(
                            raw_vast_nodes,
                            Expr::add(Expr::var("cond_colon_base"), Expr::u32(1)),
                        ),
                    ),
                    Node::if_then(
                        Expr::eq(Expr::var("cond_colon_parent"), Expr::var("cur_parent")),
                        vec![
                            Node::if_then(
                                Expr::eq(Expr::var("cond_colon_raw"), Expr::u32(TOK_QUESTION)),
                                vec![Node::assign(
                                    "cond_depth",
                                    Expr::add(Expr::var("cond_depth"), Expr::u32(1)),
                                )],
                            ),
                            Node::if_then(
                                Expr::eq(Expr::var("cond_colon_raw"), Expr::u32(TOK_COLON)),
                                vec![
                                    Node::if_then(
                                        Expr::eq(Expr::var("cond_depth"), Expr::u32(0)),
                                        vec![Node::assign(
                                            "cond_colon",
                                            Expr::var("cond_colon_scan"),
                                        )],
                                    ),
                                    Node::if_then(
                                        Expr::gt(Expr::var("cond_depth"), Expr::u32(0)),
                                        vec![Node::assign(
                                            "cond_depth",
                                            Expr::sub(Expr::var("cond_depth"), Expr::u32(1)),
                                        )],
                                    ),
                                ],
                            ),
                        ],
                    ),
                ],
            )],
        ),
        Node::let_bind(
            "cond_has_colon",
            Expr::ne(Expr::var("cond_colon"), Expr::u32(SENTINEL)),
        ),
        Node::let_bind(
            "cond_then_end",
            Expr::select(
                Expr::var("cond_has_colon"),
                Expr::var("cond_colon"),
                Expr::add(t.clone(), Expr::u32(1)),
            ),
        ),
        Node::let_bind(
            "cond_else_start",
            Expr::select(
                Expr::var("cond_has_colon"),
                Expr::add(Expr::var("cond_colon"), Expr::u32(1)),
                Expr::var("cond_seg_end"),
            ),
        ),
        Node::let_bind(
            "cond_condition_start",
            Expr::var("cond_condition_seg_start"),
        ),
        Node::let_bind("cond_parent_op", Expr::u32(SENTINEL)),
        Node::loop_for(
            "cond_parent_scan",
            Expr::var("cond_seg_start"),
            t.clone(),
            vec![
                Node::let_bind(
                    "cond_parent_base",
                    Expr::mul(
                        Expr::var("cond_parent_scan"),
                        Expr::u32(VAST_NODE_STRIDE_U32),
                    ),
                ),
                Node::let_bind(
                    "cond_parent_raw",
                    Expr::load(raw_vast_nodes, Expr::var("cond_parent_base")),
                ),
                Node::let_bind(
                    "cond_parent_typed",
                    Expr::load(typed_vast_nodes, Expr::var("cond_parent_base")),
                ),
                Node::let_bind(
                    "cond_parent_parent",
                    Expr::load(
                        raw_vast_nodes,
                        Expr::add(Expr::var("cond_parent_base"), Expr::u32(1)),
                    ),
                ),
                Node::let_bind(
                    "cond_parent_shape",
                    c_expr_shape_kind(Expr::var("cond_parent_raw"), Expr::var("cond_parent_typed")),
                ),
                Node::let_bind(
                    "cond_parent_prec",
                    c_expr_operator_precedence(
                        Expr::var("cond_parent_raw"),
                        Expr::var("cond_parent_typed"),
                    ),
                ),
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("cond_parent_parent"), Expr::var("cur_parent")),
                        Expr::and(
                            Expr::ne(Expr::var("cond_parent_shape"), Expr::u32(C_EXPR_SHAPE_NONE)),
                            Expr::lt(Expr::var("cond_parent_prec"), Expr::var("precedence")),
                        ),
                    ),
                    vec![Node::assign(
                        "cond_parent_op",
                        Expr::var("cond_parent_scan"),
                    )],
                ),
            ],
        ),
        Node::if_then(
            Expr::ne(Expr::var("cond_parent_op"), Expr::u32(SENTINEL)),
            vec![Node::assign(
                "cond_condition_start",
                Expr::add(Expr::var("cond_parent_op"), Expr::u32(1)),
            )],
        ),
    ]);
    loop_body.extend(emit_expr_root_scan(
        raw_vast_nodes,
        typed_vast_nodes,
        Expr::var("cond_condition_start"),
        t.clone(),
        Expr::var("cur_parent"),
        "cond_condition",
    ));
    loop_body.extend(emit_expr_root_scan(
        raw_vast_nodes,
        typed_vast_nodes,
        Expr::add(t.clone(), Expr::u32(1)),
        Expr::var("cond_then_end"),
        Expr::var("cur_parent"),
        "cond_then",
    ));
    loop_body.extend(emit_expr_root_scan(
        raw_vast_nodes,
        typed_vast_nodes,
        Expr::var("cond_else_start"),
        Expr::var("cond_seg_end"),
        Expr::var("cur_parent"),
        "cond_else",
    ));

    loop_body.extend(vec![
        Node::let_bind(
            "field5",
            Expr::select(
                Expr::eq(Expr::var("shape_kind"), Expr::u32(C_EXPR_SHAPE_CONDITIONAL)),
                Expr::var("cond_condition_root"),
                Expr::var("bin_lhs_root"),
            ),
        ),
        Node::let_bind(
            "field6",
            Expr::select(
                Expr::eq(Expr::var("shape_kind"), Expr::u32(C_EXPR_SHAPE_CONDITIONAL)),
                Expr::var("cond_then_root"),
                Expr::var("bin_rhs_root"),
            ),
        ),
        Node::let_bind(
            "field7",
            Expr::select(
                Expr::eq(Expr::var("shape_kind"), Expr::u32(C_EXPR_SHAPE_CONDITIONAL)),
                Expr::var("cond_else_root"),
                Expr::u32(SENTINEL),
            ),
        ),
        Node::store(
            out_expr_shape_nodes,
            out_base.clone(),
            Expr::var("shape_kind"),
        ),
        Node::store(
            out_expr_shape_nodes,
            Expr::add(out_base.clone(), Expr::u32(1)),
            Expr::select(
                Expr::eq(Expr::var("shape_kind"), Expr::u32(C_EXPR_SHAPE_NONE)),
                Expr::u32(SENTINEL),
                t.clone(),
            ),
        ),
        Node::store(
            out_expr_shape_nodes,
            Expr::add(out_base.clone(), Expr::u32(2)),
            Expr::var("raw_kind"),
        ),
        Node::store(
            out_expr_shape_nodes,
            Expr::add(out_base.clone(), Expr::u32(3)),
            Expr::var("precedence"),
        ),
        Node::store(
            out_expr_shape_nodes,
            Expr::add(out_base.clone(), Expr::u32(4)),
            Expr::var("associativity"),
        ),
        Node::store(
            out_expr_shape_nodes,
            Expr::add(out_base.clone(), Expr::u32(5)),
            Expr::select(
                Expr::eq(Expr::var("shape_kind"), Expr::u32(C_EXPR_SHAPE_NONE)),
                Expr::u32(SENTINEL),
                Expr::var("field5"),
            ),
        ),
        Node::store(
            out_expr_shape_nodes,
            Expr::add(out_base.clone(), Expr::u32(6)),
            Expr::select(
                Expr::eq(Expr::var("shape_kind"), Expr::u32(C_EXPR_SHAPE_NONE)),
                Expr::u32(SENTINEL),
                Expr::var("field6"),
            ),
        ),
        Node::store(
            out_expr_shape_nodes,
            Expr::add(out_base, Expr::u32(7)),
            Expr::select(
                Expr::eq(Expr::var("shape_kind"), Expr::u32(C_EXPR_SHAPE_NONE)),
                Expr::u32(SENTINEL),
                Expr::var("field7"),
            ),
        ),
    ]);

    let n = node_count(&num_nodes).max(1);
    Program::wrapped(
        vec![
            BufferDecl::storage(raw_vast_nodes, 0, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.saturating_mul(VAST_NODE_STRIDE_U32)),
            BufferDecl::storage(typed_vast_nodes, 1, BufferAccess::ReadOnly, DataType::U32)
                .with_count(n.saturating_mul(VAST_NODE_STRIDE_U32)),
            BufferDecl::storage(
                out_expr_shape_nodes,
                2,
                BufferAccess::ReadWrite,
                DataType::U32,
            )
            .with_count(n.saturating_mul(C_EXPR_SHAPE_STRIDE_U32)),
        ],
        [256, 1, 1],
        vec![wrap_anonymous(
            EXPR_SHAPE_OP_ID,
            vec![Node::if_then(Expr::lt(t.clone(), num_nodes), loop_body)],
        )],
    )
    .with_entry_op_id(EXPR_SHAPE_OP_ID)
}

fn u32_words_to_bytes(words: &[u32]) -> Vec<u8> {
    words.iter().flat_map(|word| word.to_le_bytes()).collect()
}

/// CPU oracle for token-level VAST row construction.
#[must_use]
pub fn reference_c11_build_vast_nodes(
    tok_types: &[u32],
    tok_starts: &[u32],
    tok_lens: &[u32],
) -> Vec<u8> {
    let n = tok_types.len().min(tok_starts.len()).min(tok_lens.len());
    let mut parent = vec![SENTINEL; n];
    let mut first_child = vec![SENTINEL; n];
    let mut next_sibling = vec![SENTINEL; n];
    let mut stack: Vec<u32> = Vec::new();
    let mut last_child: Vec<Option<u32>> = vec![None; n];
    let mut root_last: Option<u32> = None;

    for i in 0..n {
        let parent_idx = stack.last().copied().unwrap_or(SENTINEL);
        parent[i] = parent_idx;

        if let Some(previous) = if parent_idx == SENTINEL {
            root_last
        } else {
            last_child[parent_idx as usize]
        } {
            next_sibling[previous as usize] = i as u32;
        } else if parent_idx != SENTINEL {
            first_child[parent_idx as usize] = i as u32;
        }

        if parent_idx == SENTINEL {
            root_last = Some(i as u32);
        } else {
            last_child[parent_idx as usize] = Some(i as u32);
        }

        match tok_types[i] {
            TOK_LPAREN | TOK_LBRACE | TOK_LBRACKET => stack.push(i as u32),
            TOK_RPAREN => pop_matching(&mut stack, tok_types, TOK_LPAREN),
            TOK_RBRACE => pop_matching(&mut stack, tok_types, TOK_LBRACE),
            TOK_RBRACKET => pop_matching(&mut stack, tok_types, TOK_LBRACKET),
            _ => {}
        }
    }

    let mut rows = Vec::with_capacity(n.saturating_mul(VAST_NODE_STRIDE_U32 as usize));
    for i in 0..n {
        rows.extend_from_slice(&[
            tok_types[i],
            parent[i],
            first_child[i],
            next_sibling[i],
            0,
            tok_starts[i],
            tok_lens[i],
            0,
            0,
            0,
        ]);
    }
    u32_words_to_bytes(&rows)
}

/// Malformed byte input for C VAST CPU oracle decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CReferenceDecodeError {
    /// Input byte length is not a whole number of `u32` words.
    MisalignedBytes {
        /// Actual byte length.
        len: usize,
    },
    /// Input word count is not a whole number of VAST rows.
    PartialVastRow {
        /// Actual decoded word count.
        words: usize,
        /// Required row stride.
        stride: usize,
    },
}

impl std::fmt::Display for CReferenceDecodeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MisalignedBytes { len } => write!(
                formatter,
                "C VAST byte input has {len} bytes, which is not 4-byte aligned. Fix: pass complete u32 rows to the C VAST reference oracle."
            ),
            Self::PartialVastRow { words, stride } => write!(
                formatter,
                "C VAST word input has {words} words, which is not a multiple of row stride {stride}. Fix: pass complete C VAST rows to the reference oracle."
            ),
        }
    }
}

impl std::error::Error for CReferenceDecodeError {}

fn try_u32_words_from_bytes(bytes: &[u8]) -> Result<Vec<u32>, CReferenceDecodeError> {
    if bytes.len() % 4 != 0 {
        return Err(CReferenceDecodeError::MisalignedBytes { len: bytes.len() });
    }
    Ok(bytes
        .chunks_exact(4)
        .map(|chunk| u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]))
        .collect())
}

fn try_vast_words_from_bytes(bytes: &[u8]) -> Result<Vec<u32>, CReferenceDecodeError> {
    let words = try_u32_words_from_bytes(bytes)?;
    if words.len() % VAST_NODE_STRIDE_U32 as usize != 0 {
        return Err(CReferenceDecodeError::PartialVastRow {
            words: words.len(),
            stride: VAST_NODE_STRIDE_U32 as usize,
        });
    }
    Ok(words)
}

/// CPU oracle for `c11_annotate_typedef_names`.
///
/// # Errors
///
/// Returns [`CReferenceDecodeError`] when `vast_node_bytes` is not
/// `u32`-aligned or does not contain complete C VAST rows.
pub fn try_reference_c11_annotate_typedef_names(
    vast_node_bytes: &[u8],
    haystack: &[u8],
) -> Result<Vec<u8>, CReferenceDecodeError> {
    let raw_vast_nodes = try_vast_words_from_bytes(vast_node_bytes)?;
    Ok(reference_c11_annotate_typedef_names_from_words(
        raw_vast_nodes,
        haystack,
    ))
}

/// CPU oracle for `c11_annotate_typedef_names`.
#[must_use]
pub fn reference_c11_annotate_typedef_names(vast_node_bytes: &[u8], haystack: &[u8]) -> Vec<u8> {
    try_reference_c11_annotate_typedef_names(vast_node_bytes, haystack).expect(
        "Fix: pass complete u32-aligned C VAST rows to reference_c11_annotate_typedef_names",
    )
}

fn reference_c11_annotate_typedef_names_from_words(
    raw_vast_nodes: Vec<u32>,
    haystack: &[u8],
) -> Vec<u8> {
    let node_count = raw_vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    let mut annotated = raw_vast_nodes.clone();

    for node_idx in 0..node_count {
        let base = node_idx * VAST_NODE_STRIDE_U32 as usize;
        let raw_kind = raw_vast_nodes.get(base).copied().unwrap_or_default();
        let name = identifier_lexeme(&raw_vast_nodes, node_idx, haystack);
        let scope_open = scope_open_before(&raw_vast_nodes, node_idx);
        let mut flags = 0u32;
        let decl_kind = declaration_kind_at(&raw_vast_nodes, node_idx, haystack);

        if raw_kind == TOK_IDENTIFIER && decl_kind == 0 {
            if let Some(name) = name {
                let visible_kind =
                    visible_declaration_kind(&raw_vast_nodes, node_idx, haystack, name);
                if visible_kind == 1 {
                    flags |= C_TYPEDEF_FLAG_VISIBLE_TYPEDEF_NAME;
                }
            }
        }

        match decl_kind {
            1 => flags |= C_TYPEDEF_FLAG_TYPEDEF_DECLARATOR,
            2 => flags |= C_TYPEDEF_FLAG_ORDINARY_DECLARATOR,
            _ => {}
        }

        annotated[base + VAST_TYPEDEF_FLAGS_FIELD as usize] = flags;
        annotated[base + VAST_TYPEDEF_SCOPE_FIELD as usize] = scope_open;
        annotated[base + VAST_TYPEDEF_SYMBOL_FIELD as usize] = name.map(fnv1a32).unwrap_or(0);
    }

    u32_words_to_bytes(&annotated)
}

fn identifier_lexeme<'a>(
    vast_nodes: &[u32],
    node_idx: usize,
    haystack: &'a [u8],
) -> Option<&'a [u8]> {
    if kind_at(vast_nodes, node_idx) != TOK_IDENTIFIER {
        return None;
    }
    let base = node_idx * VAST_NODE_STRIDE_U32 as usize;
    let start = vast_nodes.get(base + 5).copied().unwrap_or_default() as usize;
    let len = vast_nodes.get(base + 6).copied().unwrap_or_default() as usize;
    haystack.get(start..start.saturating_add(len))
}

fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x0100_0193);
    }
    hash
}

fn is_gnu_typeof_hash_raw(hash: u32) -> bool {
    C_GNU_TYPEOF_HASHES.contains(&hash)
}

fn is_gnu_auto_type_hash_raw(hash: u32) -> bool {
    hash == C_GNU_AUTO_TYPE_HASH
}

fn symbol_hash_at(vast_nodes: &[u32], node_idx: usize) -> u32 {
    vast_nodes
        .get(node_idx * VAST_NODE_STRIDE_U32 as usize + VAST_TYPEDEF_SYMBOL_FIELD as usize)
        .copied()
        .unwrap_or_default()
}

fn is_typeof_operator_raw(kind: u32, symbol_hash: u32) -> bool {
    matches!(kind, TOK_GNU_TYPEOF | TOK_GNU_TYPEOF_UNQUAL)
        || (kind == TOK_IDENTIFIER && is_gnu_typeof_hash_raw(symbol_hash))
}

fn is_decl_prefix_at(vast_nodes: &[u32], node_idx: usize) -> bool {
    let kind = kind_at(vast_nodes, node_idx);
    let symbol_hash = symbol_hash_at(vast_nodes, node_idx);
    is_decl_prefix_raw(kind)
        || is_typeof_operator_raw(kind, symbol_hash)
        || (kind == TOK_IDENTIFIER && is_gnu_auto_type_hash_raw(symbol_hash))
}

fn visible_declaration_kind(
    vast_nodes: &[u32],
    node_idx: usize,
    haystack: &[u8],
    name: &[u8],
) -> u32 {
    let current_scope = scope_open_before(vast_nodes, node_idx);
    let current_function = enclosing_function_lparen(vast_nodes, node_idx);

    for scan_idx in (0..node_idx).rev() {
        if identifier_lexeme(vast_nodes, scan_idx, haystack) != Some(name) {
            continue;
        }
        let decl_kind = declaration_kind_at(vast_nodes, scan_idx, haystack);
        if decl_kind == 0 {
            continue;
        }
        if decl_kind == 2 {
            let decl_function = enclosing_function_lparen(vast_nodes, scan_idx);
            if decl_function != SENTINEL && decl_function != current_function {
                continue;
            }
            if let Some(scope_end) = for_init_scope_end(vast_nodes, scan_idx) {
                if node_idx > scope_end {
                    continue;
                }
            }
        }
        let decl_scope = scope_open_before(vast_nodes, scan_idx);
        if scope_is_visible_from(vast_nodes, decl_scope, current_scope) {
            return decl_kind;
        }
    }

    0
}

fn scope_is_visible_from(vast_nodes: &[u32], decl_scope: u32, current_scope: u32) -> bool {
    if decl_scope == SENTINEL {
        return true;
    }
    let node_count = vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    let mut scope = current_scope;
    for _ in 0..node_count {
        if scope == decl_scope {
            return true;
        }
        if scope == SENTINEL {
            return false;
        }
        let Ok(scope_idx) = usize::try_from(scope) else {
            return false;
        };
        let parent_word = scope_idx * VAST_NODE_STRIDE_U32 as usize + 1;
        scope = vast_nodes.get(parent_word).copied().unwrap_or(SENTINEL);
    }
    false
}

fn declaration_kind_at(vast_nodes: &[u32], node_idx: usize, haystack: &[u8]) -> u32 {
    if kind_at(vast_nodes, node_idx) != TOK_IDENTIFIER {
        return 0;
    }
    let prev_kind = if node_idx > 0 {
        kind_at(vast_nodes, node_idx - 1)
    } else {
        SENTINEL
    };
    let next_kind = if node_idx + 1 < vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize {
        kind_at(vast_nodes, node_idx + 1)
    } else {
        SENTINEL
    };
    if matches!(
        prev_kind,
        TOK_STRUCT | TOK_UNION | TOK_ENUM | TOK_DOT | TOK_ARROW
    ) || next_kind == TOK_COLON
    {
        return 0;
    }
    if prev_kind == TOK_LPAREN
        && node_idx >= 2
        && matches!(
            kind_at(vast_nodes, node_idx.saturating_sub(2)),
            TOK_SIZEOF | TOK_GNU_TYPEOF | TOK_GNU_TYPEOF_UNQUAL | TOK_ALIGNOF
        )
    {
        return 0;
    }
    if prev_kind == TOK_STAR
        && node_idx >= 2
        && kind_at(vast_nodes, node_idx.saturating_sub(2)) == TOK_RPAREN
    {
        return 0;
    }
    if parent_context(
        vast_nodes,
        vast_nodes[node_idx * VAST_NODE_STRIDE_U32 as usize + 1],
    )
    .is_record_body
    {
        return 0;
    }

    let mut has_typedef = false;
    let mut has_type = false;
    let mut skipped_paren_depth = 0u32;
    let mut skipped_brace_depth = 0u32;
    for scan_idx in (0..node_idx).rev() {
        let scan_kind = kind_at(vast_nodes, scan_idx);
        if scan_kind == TOK_RBRACE {
            skipped_brace_depth = skipped_brace_depth.saturating_add(1);
            continue;
        }
        if skipped_brace_depth != 0 {
            if scan_kind == TOK_LBRACE {
                skipped_brace_depth = skipped_brace_depth.saturating_sub(1);
            }
            continue;
        }
        if scan_kind == TOK_RPAREN {
            skipped_paren_depth = skipped_paren_depth.saturating_add(1);
            continue;
        }
        if skipped_paren_depth != 0 {
            if scan_kind == TOK_LPAREN {
                skipped_paren_depth = skipped_paren_depth.saturating_sub(1);
            }
            continue;
        }
        if is_decl_prefix_reset_raw(scan_kind) {
            break;
        }
        if scan_kind == TOK_TYPEDEF {
            has_typedef = true;
        }
        if is_decl_prefix_at(vast_nodes, scan_idx) {
            has_type = true;
        }
        if scan_kind == TOK_IDENTIFIER {
            if let Some(name) = identifier_lexeme(vast_nodes, scan_idx, haystack) {
                if visible_declaration_kind(vast_nodes, scan_idx, haystack, name) == 1 {
                    has_type = true;
                }
            }
        }
    }

    let declarator_follower = matches!(
        next_kind,
        TOK_SEMICOLON | TOK_COMMA | TOK_ASSIGN | TOK_LBRACKET | TOK_LPAREN | TOK_RPAREN
    );
    if declarator_follower && prev_kind == TOK_IDENTIFIER {
        if let Some(prev_name) = identifier_lexeme(vast_nodes, node_idx - 1, haystack) {
            if visible_declaration_kind(vast_nodes, node_idx - 1, haystack, prev_name) == 1 {
                return 2;
            }
        }
    }
    if declarator_follower && (has_typedef || has_type) {
        if has_typedef {
            1
        } else {
            2
        }
    } else {
        0
    }
}

fn scope_open_before(vast_nodes: &[u32], node_idx: usize) -> u32 {
    let mut depth = 0u32;
    for scan_idx in (0..node_idx).rev() {
        match kind_at(vast_nodes, scan_idx) {
            TOK_RBRACE => depth = depth.saturating_add(1),
            TOK_LBRACE => {
                if depth == 0 {
                    return scan_idx as u32;
                }
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    SENTINEL
}

fn enclosing_function_lparen(vast_nodes: &[u32], node_idx: usize) -> u32 {
    let node_count = vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    let mut parent = vast_nodes
        .get(node_idx * VAST_NODE_STRIDE_U32 as usize + 1)
        .copied()
        .unwrap_or(SENTINEL);
    for _ in 0..node_count {
        let Ok(parent_idx) = usize::try_from(parent) else {
            break;
        };
        if parent_idx >= node_count {
            break;
        }
        if kind_at(vast_nodes, parent_idx) == TOK_LPAREN
            && lparen_starts_function_declarator(vast_nodes, parent_idx)
        {
            return parent;
        }
        parent = vast_nodes
            .get(parent_idx * VAST_NODE_STRIDE_U32 as usize + 1)
            .copied()
            .unwrap_or(SENTINEL);
    }

    let mut scope = scope_open_before(vast_nodes, node_idx);
    for _ in 0..node_count {
        let Ok(scope_idx) = usize::try_from(scope) else {
            break;
        };
        if scope_idx >= node_count || kind_at(vast_nodes, scope_idx) != TOK_LBRACE {
            break;
        }
        let candidate = function_lparen_before(vast_nodes, scope_idx);
        if candidate != SENTINEL {
            return candidate;
        }
        scope = vast_nodes
            .get(scope_idx * VAST_NODE_STRIDE_U32 as usize + 1)
            .copied()
            .unwrap_or(SENTINEL);
    }

    SENTINEL
}

fn function_lparen_before(vast_nodes: &[u32], before_idx: usize) -> u32 {
    let mut depth = 0u32;
    for scan_idx in (0..before_idx).rev() {
        match kind_at(vast_nodes, scan_idx) {
            TOK_RPAREN => depth = depth.saturating_add(1),
            TOK_LPAREN => {
                if depth == 0 {
                    continue;
                }
                depth = depth.saturating_sub(1);
                if depth == 0 && lparen_starts_function_declarator(vast_nodes, scan_idx) {
                    return scan_idx as u32;
                }
            }
            _ => {}
        }
    }
    SENTINEL
}

fn lparen_starts_function_declarator(vast_nodes: &[u32], lparen_idx: usize) -> bool {
    lparen_idx > 0 && kind_at(vast_nodes, lparen_idx - 1) == TOK_IDENTIFIER
}

fn for_init_scope_end(vast_nodes: &[u32], decl_idx: usize) -> Option<usize> {
    let control_lparen = enclosing_for_control_lparen(vast_nodes, decl_idx)?;
    let control_rparen = matching_raw_rparen(vast_nodes, control_lparen)?;
    match kind_at(vast_nodes, control_rparen.saturating_add(1)) {
        TOK_LBRACE => matching_raw_rbrace(vast_nodes, control_rparen + 1),
        TOK_SEMICOLON => Some(control_rparen + 1),
        _ => Some(control_rparen),
    }
}

fn enclosing_for_control_lparen(vast_nodes: &[u32], node_idx: usize) -> Option<usize> {
    let mut depth = 0u32;
    for scan_idx in (0..node_idx).rev() {
        match kind_at(vast_nodes, scan_idx) {
            TOK_RPAREN => depth = depth.saturating_add(1),
            TOK_LPAREN => {
                if depth == 0 {
                    return (scan_idx > 0 && kind_at(vast_nodes, scan_idx - 1) == TOK_FOR)
                        .then_some(scan_idx);
                }
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    None
}

fn matching_raw_rparen(vast_nodes: &[u32], lparen_idx: usize) -> Option<usize> {
    let node_count = vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    let mut depth = 1u32;
    for scan_idx in (lparen_idx + 1)..node_count {
        match kind_at(vast_nodes, scan_idx) {
            TOK_LPAREN => depth = depth.saturating_add(1),
            TOK_RPAREN => {
                if depth == 1 {
                    return Some(scan_idx);
                }
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    None
}

fn matching_raw_rbrace(vast_nodes: &[u32], lbrace_idx: usize) -> Option<usize> {
    let node_count = vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    let mut depth = 1u32;
    for scan_idx in (lbrace_idx + 1)..node_count {
        match kind_at(vast_nodes, scan_idx) {
            TOK_LBRACE => depth = depth.saturating_add(1),
            TOK_RBRACE => {
                if depth == 1 {
                    return Some(scan_idx);
                }
                depth = depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    None
}

fn c99_for_init_statement_assign(
    vast_nodes: &[u32],
    raw_kind: u32,
    cur_parent: u32,
    effective_has_decl_prefix: bool,
) -> bool {
    if raw_kind != TOK_ASSIGN || !effective_has_decl_prefix {
        return false;
    }
    let node_count = vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    let Ok(control_lparen_idx) = usize::try_from(cur_parent) else {
        return false;
    };
    if control_lparen_idx >= node_count || kind_at(vast_nodes, control_lparen_idx) != TOK_LPAREN {
        return false;
    }
    let control_parent = vast_nodes
        .get(control_lparen_idx * VAST_NODE_STRIDE_U32 as usize + 1)
        .copied()
        .unwrap_or(SENTINEL);
    let Ok(control_parent_idx) = usize::try_from(control_parent) else {
        return false;
    };
    let control_parent_kind = kind_at(vast_nodes, control_parent_idx);
    if control_parent_kind == TOK_FOR {
        return true;
    }
    if control_parent_kind != TOK_LBRACE {
        return false;
    }
    previous_sibling_context(vast_nodes, control_lparen_idx, control_parent).kind == TOK_FOR
}

fn reference_typed_kind(vast_nodes: &[u32], node_idx: usize) -> u32 {
    let base = node_idx * VAST_NODE_STRIDE_U32 as usize;
    let raw_kind = vast_nodes.get(base).copied().unwrap_or_default();
    let cur_parent = vast_nodes.get(base + 1).copied().unwrap_or(SENTINEL);
    let symbol = vast_nodes
        .get(base + VAST_TYPEDEF_SYMBOL_FIELD as usize)
        .copied()
        .unwrap_or_default();
    let current_is_typeof_operator = is_typeof_operator_raw(raw_kind, symbol);
    let first_child_kind = child_kind(vast_nodes, node_idx);
    let first_child_flags = child_flags(vast_nodes, node_idx);
    let first_child_symbol = child_symbol_hash(vast_nodes, node_idx);
    let raw_next_kind = if node_idx + 1 < vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize {
        kind_at(vast_nodes, node_idx + 1)
    } else {
        0
    };
    let raw_next_flags = vast_nodes
        .get((node_idx + 1) * VAST_NODE_STRIDE_U32 as usize + VAST_TYPEDEF_FLAGS_FIELD as usize)
        .copied()
        .unwrap_or_default();
    let raw_after_next_kind = if node_idx + 2 < vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize {
        kind_at(vast_nodes, node_idx + 2)
    } else {
        0
    };
    let raw_after_after_kind = if node_idx + 3 < vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize {
        kind_at(vast_nodes, node_idx + 3)
    } else {
        0
    };
    let next_idx = vast_nodes.get(base + 3).copied().unwrap_or(SENTINEL);
    let next_valid = usize::try_from(next_idx)
        .ok()
        .is_some_and(|idx| idx < vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize);

    let next_kind = if next_valid {
        vast_nodes
            .get(next_idx as usize * VAST_NODE_STRIDE_U32 as usize)
            .copied()
            .unwrap_or_default()
    } else {
        0
    };
    let after_param_idx = if next_valid {
        vast_nodes
            .get(next_idx as usize * VAST_NODE_STRIDE_U32 as usize + 3)
            .copied()
            .unwrap_or(SENTINEL)
    } else {
        SENTINEL
    };
    let decl_context = decl_context_before(vast_nodes, node_idx, cur_parent);
    let prev = previous_sibling_context(vast_nodes, node_idx, cur_parent);
    let has_prior_typedef = prior_typedef_seen(vast_nodes, node_idx);
    let has_typedef_annotations = has_any_typedef_annotations(vast_nodes);
    let has_prior_parenthesized_identifier_statement =
        prior_parenthesized_identifier_statement_seen(vast_nodes, node_idx);
    let ambiguous_parenthesized_identifier_multiply = raw_kind == TOK_LPAREN
        && next_kind == TOK_STAR
        && has_prior_parenthesized_identifier_statement;
    let fallback_has_prior_typedef = !has_typedef_annotations
        && has_prior_typedef
        && !prior_ordinary_decl_seen(vast_nodes, node_idx)
        && !prior_raw_ordinary_decl_seen(vast_nodes, node_idx)
        && !ambiguous_parenthesized_identifier_multiply;
    let raw_lparen = raw_kind == TOK_LPAREN;
    let suffix_start_idx = if raw_lparen {
        next_idx
    } else {
        after_param_idx
    };
    let suffix_boundary_kind = suffix_function_boundary_kind(vast_nodes, suffix_start_idx, 16);
    let function_boundary = suffix_boundary_kind != SENTINEL;
    let identifier_type_name_paren = raw_lparen
        && first_child_kind == TOK_IDENTIFIER
        && matches!(
            next_kind,
            TOK_LBRACE
                | TOK_LPAREN
                | TOK_IDENTIFIER
                | TOK_INTEGER
                | TOK_FLOAT
                | TOK_STRING
                | TOK_CHAR
                | TOK_STAR
                | TOK_AMP
                | TOK_PLUS
                | TOK_MINUS
                | TOK_BANG
                | TOK_TILDE
                | TOK_INC
                | TOK_DEC
        );
    let flat_identifier_type_name_paren = raw_lparen
        && raw_next_kind == TOK_IDENTIFIER
        && is_reference_typedef_name(raw_next_flags, fallback_has_prior_typedef)
        && raw_after_next_kind == TOK_RPAREN
        && matches!(
            raw_after_after_kind,
            TOK_LBRACE
                | TOK_LPAREN
                | TOK_IDENTIFIER
                | TOK_INTEGER
                | TOK_FLOAT
                | TOK_STRING
                | TOK_CHAR
                | TOK_STAR
                | TOK_AMP
                | TOK_PLUS
                | TOK_MINUS
                | TOK_BANG
                | TOK_TILDE
                | TOK_INC
                | TOK_DEC
        );
    let type_name_paren = raw_lparen
        && !matches!(prev.kind, TOK_SIZEOF | TOK_ALIGNOF | TOK_ATOMIC)
        && !is_typeof_operator_raw(prev.kind, prev.symbol_hash)
        && (is_type_name_start_raw(first_child_kind)
            || is_typeof_operator_raw(first_child_kind, first_child_symbol)
            || (is_reference_typedef_name(first_child_flags, fallback_has_prior_typedef)
                && identifier_type_name_paren)
            || flat_identifier_type_name_paren);
    let parent = parent_context(vast_nodes, cur_parent);
    let inherited_decl_prefix = parenthesized_declarator_context(vast_nodes, cur_parent);
    let effective_has_decl_prefix = decl_context.has_prefix || inherited_decl_prefix;

    let identifier_then_paren = raw_kind == TOK_IDENTIFIER && next_valid && next_kind == TOK_LPAREN;
    let is_function_declarator = raw_lparen
        && (function_boundary
            || ((type_name_paren || is_type_name_start_raw(first_child_kind))
                && matches!(prev.kind, TOK_LPAREN | TOK_RPAREN)))
        && matches!(prev.kind, TOK_IDENTIFIER | TOK_LPAREN | TOK_RPAREN)
        && (effective_has_decl_prefix || prev.kind == TOK_RPAREN);
    let is_return_function_suffix = raw_lparen
        && type_name_paren
        && function_boundary
        && effective_has_decl_prefix
        && prev.kind == TOK_LPAREN;
    let typedef_pointer_decl = raw_kind == TOK_STAR
        && is_reference_typedef_name(prev.flags, fallback_has_prior_typedef)
        && prev.kind == TOK_IDENTIFIER
        && next_kind == TOK_IDENTIFIER
        && matches!(
            prev.prev_kind,
            SENTINEL | TOK_LBRACE | TOK_LPAREN | TOK_SEMICOLON | TOK_COMMA
        );
    let is_pointer_decl =
        raw_kind == TOK_STAR && (effective_has_decl_prefix || typedef_pointer_decl);
    let parenthesized_declarator_suffix = prev.kind == TOK_LPAREN
        && matches!(
            child_kind(vast_nodes, prev.idx as usize),
            TOK_STAR | TOK_IDENTIFIER | TOK_LPAREN
        );
    let is_array_decl = raw_kind == TOK_LBRACKET
        && (prev.kind == TOK_IDENTIFIER || parenthesized_declarator_suffix)
        && effective_has_decl_prefix;
    let is_array_designator_expr = raw_kind == TOK_LBRACKET && next_kind == TOK_ASSIGN;
    let is_array_declaration_initializer_assign = raw_kind == TOK_ASSIGN
        && prev.kind == TOK_LBRACKET
        && effective_has_decl_prefix
        && !enclosing_brace_is_initializer_list(vast_nodes, cur_parent)
        && next_kind == TOK_STRING;
    let is_compound_literal = raw_lparen && type_name_paren && next_kind == TOK_LBRACE;
    let is_cast_expr =
        raw_lparen && type_name_paren && !is_function_declarator && !is_compound_literal;
    let brace_after_compound_literal_type = prev.kind == TOK_LPAREN
        && (matches!(
            child_kind(vast_nodes, prev.idx as usize),
            TOK_VOID
                | TOK_BOOL
                | TOK_CHAR_KW
                | TOK_SHORT
                | TOK_INT
                | TOK_LONG
                | TOK_FLOAT_KW
                | TOK_DOUBLE
                | TOK_SIGNED
                | TOK_UNSIGNED
                | TOK_STRUCT
                | TOK_UNION
                | TOK_ENUM
                | TOK_CONST
                | TOK_RESTRICT
                | TOK_VOLATILE
                | TOK_ATOMIC
        ) || (child_kind(vast_nodes, prev.idx as usize) == TOK_IDENTIFIER
            && is_reference_typedef_name(
                child_flags(vast_nodes, prev.idx as usize),
                fallback_has_prior_typedef,
            ))
            || is_typeof_operator_raw(
                child_kind(vast_nodes, prev.idx as usize),
                child_symbol_hash(vast_nodes, prev.idx as usize),
            ))
        && matches!(
            prev.prev_kind,
            TOK_ASSIGN | TOK_RETURN | TOK_COMMA | TOK_LPAREN
        );
    let is_initializer_list = raw_kind == TOK_LBRACE
        && (prev.kind == TOK_ASSIGN
            || brace_after_compound_literal_type
            || (matches!(prev.kind, SENTINEL | TOK_LBRACE | TOK_COMMA)
                && enclosing_brace_is_initializer_list(vast_nodes, cur_parent)));
    let is_field_decl = raw_kind == TOK_IDENTIFIER
        && parent.is_record_body
        && decl_context.has_prefix
        && matches!(
            next_kind,
            TOK_SEMICOLON | TOK_COMMA | TOK_ASSIGN | TOK_LBRACKET | TOK_COLON
        );
    let is_anonymous_bit_field_decl = raw_kind == TOK_COLON
        && parent.is_record_body
        && decl_context.has_prefix
        && prev.kind != TOK_IDENTIFIER;
    let is_enumerator_decl = raw_kind == TOK_IDENTIFIER
        && parent.is_enum_body
        && matches!(prev.kind, SENTINEL | TOK_COMMA)
        && matches!(next_kind, TOK_COMMA | TOK_ASSIGN | TOK_RBRACE);
    let is_label_stmt = raw_kind == TOK_IDENTIFIER
        && next_kind == TOK_COLON
        && !parent.is_record_body
        && !parent.is_enum_body;
    let is_gnu_statement_expr = raw_kind == TOK_LPAREN && first_child_kind == TOK_LBRACE;
    let is_gnu_label_address_expr =
        raw_kind == TOK_AND && reference_c_unary_context(prev.kind) && next_kind == TOK_IDENTIFIER;
    let is_asm_goto_qualifier =
        raw_kind == TOK_GOTO && asm_prefix_before(vast_nodes, node_idx, cur_parent);
    let is_asm_volatile_qualifier =
        raw_kind == TOK_VOLATILE && asm_prefix_before(vast_nodes, node_idx, cur_parent);
    let asm_kind = reference_c_asm_context_kind(vast_nodes, node_idx, raw_kind, cur_parent);
    let attribute_kind = reference_c_attribute_kind(vast_nodes, node_idx, raw_kind, cur_parent)
        .or_else(|| reference_c_direct_attribute_kind(vast_nodes, raw_kind, cur_parent, symbol));
    let cur_parent_parent_kind = usize::try_from(cur_parent)
        .ok()
        .and_then(|parent_idx| {
            vast_nodes
                .get(parent_idx * VAST_NODE_STRIDE_U32 as usize + 1)
                .copied()
        })
        .and_then(|parent_parent| usize::try_from(parent_parent).ok())
        .map(|parent_parent_idx| kind_at(vast_nodes, parent_parent_idx))
        .unwrap_or_default();
    let inside_gnu_statement_expr_body = kind_at(vast_nodes, cur_parent as usize) == TOK_LBRACE
        && cur_parent_parent_kind == TOK_LPAREN;
    let builtin_kind = reference_c_builtin_expression_kind(raw_kind)
        .or_else(|| reference_c_builtin_identifier_expression_kind(raw_kind, symbol, next_kind));
    let c99_for_init_statement_assign =
        c99_for_init_statement_assign(vast_nodes, raw_kind, cur_parent, effective_has_decl_prefix);
    let is_declaration_initializer_assign = raw_kind == TOK_ASSIGN
        && (effective_has_decl_prefix
            || declaration_initializer_prefix_before(vast_nodes, node_idx, cur_parent)
            || c99_for_init_statement_assign)
        && !inside_gnu_statement_expr_body
        && !is_array_declaration_initializer_assign;
    let expression_kind = if is_declaration_initializer_assign {
        None
    } else {
        reference_c_expression_operator_kind(raw_kind, prev.kind, prev.prev_kind)
    };
    let star_after_parenthesized_identifier_expr = raw_kind == TOK_STAR
        && prev.kind == TOK_LPAREN
        && child_kind(vast_nodes, prev.idx as usize) == TOK_IDENTIFIER
        && if has_typedef_annotations {
            !is_reference_typedef_name(child_flags(vast_nodes, prev.idx as usize), false)
        } else {
            !has_prior_typedef
                || prior_ordinary_decl_seen(vast_nodes, node_idx)
                || prior_raw_ordinary_decl_seen(vast_nodes, node_idx)
                || has_prior_parenthesized_identifier_statement
        };

    if identifier_then_paren
        && function_boundary
        && effective_has_decl_prefix
        && prev.kind != TOK_LPAREN
        && suffix_boundary_kind == TOK_LBRACE
    {
        C_AST_KIND_FUNCTION_DEFINITION
    } else if matches!(raw_kind, TOK_STRUCT | TOK_UNION | TOK_ENUM) {
        match raw_kind {
            TOK_STRUCT => C_AST_KIND_STRUCT_DECL,
            TOK_UNION => C_AST_KIND_UNION_DECL,
            TOK_ENUM => C_AST_KIND_ENUM_DECL,
            _ => 0,
        }
    } else if raw_kind == TOK_TYPEDEF {
        C_AST_KIND_TYPEDEF_DECL
    } else if raw_kind == TOK_STATIC_ASSERT {
        C_AST_KIND_STATIC_ASSERT_DECL
    } else if raw_kind == TOK_GNU_LABEL {
        C_AST_KIND_GNU_LOCAL_LABEL_DECL
    } else if let Some(kind) = attribute_kind {
        kind
    } else if (is_field_decl && next_kind == TOK_COLON) || is_anonymous_bit_field_decl {
        C_AST_KIND_BIT_FIELD_DECL
    } else if let Some(kind) = builtin_kind {
        kind
    } else if current_is_typeof_operator {
        C_AST_KIND_SIZEOF_EXPR
    } else if identifier_then_paren
        && function_boundary
        && effective_has_decl_prefix
        && prev.kind != TOK_LPAREN
    {
        node_kind::FUNCTION_DECL
    } else if is_function_declarator || is_return_function_suffix {
        C_AST_KIND_FUNCTION_DECLARATOR
    } else if is_pointer_decl {
        C_AST_KIND_POINTER_DECL
    } else if is_array_decl {
        C_AST_KIND_ARRAY_DECL
    } else if is_array_designator_expr {
        C_AST_KIND_ARRAY_SUBSCRIPT_EXPR
    } else if is_cast_expr {
        C_AST_KIND_CAST_EXPR
    } else if is_compound_literal {
        C_AST_KIND_COMPOUND_LITERAL_EXPR
    } else if is_initializer_list {
        C_AST_KIND_INITIALIZER_LIST
    } else if is_field_decl {
        C_AST_KIND_FIELD_DECL
    } else if is_enumerator_decl {
        C_AST_KIND_ENUMERATOR_DECL
    } else if is_label_stmt {
        C_AST_KIND_LABEL_STMT
    } else if is_gnu_statement_expr {
        C_AST_KIND_GNU_STATEMENT_EXPR
    } else if identifier_then_paren {
        node_kind::CALL
    } else if raw_kind == TOK_LBRACE {
        node_kind::BASIC_BLOCK
    } else if is_asm_goto_qualifier || is_asm_volatile_qualifier {
        C_AST_KIND_ASM_QUALIFIER
    } else if let Some(kind) = reference_c_statement_kind(raw_kind) {
        kind
    } else if star_after_parenthesized_identifier_expr {
        node_kind::BINARY
    } else if is_gnu_label_address_expr {
        C_AST_KIND_GNU_LABEL_ADDRESS_EXPR
    } else if let Some(kind) = asm_kind {
        kind
    } else if let Some(kind) = expression_kind {
        kind
    } else if raw_kind == TOK_GNU_ASM {
        C_AST_KIND_INLINE_ASM
    } else if raw_kind == TOK_GNU_ATTRIBUTE {
        C_AST_KIND_GNU_ATTRIBUTE
    } else if matches!(raw_kind, TOK_INTEGER | TOK_FLOAT | TOK_STRING | TOK_CHAR) {
        node_kind::LITERAL
    } else if raw_kind == TOK_IDENTIFIER && !is_gnu_auto_type_hash_raw(symbol) {
        node_kind::VARIABLE
    } else {
        0
    }
}

fn enclosing_brace_is_initializer_list(vast_nodes: &[u32], cur_parent: u32) -> bool {
    let node_count = vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    let Ok(parent_idx) = usize::try_from(cur_parent) else {
        return false;
    };
    if parent_idx >= node_count || kind_at(vast_nodes, parent_idx) != TOK_LBRACE {
        return false;
    }

    let parent_parent = vast_nodes
        .get(parent_idx * VAST_NODE_STRIDE_U32 as usize + 1)
        .copied()
        .unwrap_or(SENTINEL);
    let parent_prev = previous_sibling_context(vast_nodes, parent_idx, parent_parent);
    if matches!(parent_prev.kind, TOK_ASSIGN | TOK_COMMA) {
        return true;
    }
    if parent_prev.kind != TOK_LBRACE {
        return false;
    }

    let Ok(grandparent_idx) = usize::try_from(parent_parent) else {
        return false;
    };
    if grandparent_idx >= node_count || kind_at(vast_nodes, grandparent_idx) != TOK_LBRACE {
        return false;
    }
    let grandparent_parent = vast_nodes
        .get(grandparent_idx * VAST_NODE_STRIDE_U32 as usize + 1)
        .copied()
        .unwrap_or(SENTINEL);
    let grandparent_prev =
        previous_sibling_context(vast_nodes, grandparent_idx, grandparent_parent);
    matches!(grandparent_prev.kind, TOK_ASSIGN | TOK_COMMA | TOK_LBRACE)
}

fn reference_c_asm_context_kind(
    vast_nodes: &[u32],
    node_idx: usize,
    raw_kind: u32,
    cur_parent: u32,
) -> Option<u32> {
    let Ok(parent_idx) = usize::try_from(cur_parent) else {
        return None;
    };
    if parent_idx >= vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize
        || kind_at(vast_nodes, parent_idx) != TOK_LPAREN
    {
        return None;
    }
    let parent_parent = vast_nodes
        .get(parent_idx * VAST_NODE_STRIDE_U32 as usize + 1)
        .copied()
        .unwrap_or(SENTINEL);
    if !asm_prefix_before(vast_nodes, parent_idx, parent_parent) {
        return None;
    }
    let colon_count = sibling_colons_before(vast_nodes, node_idx, cur_parent);
    let prev = previous_sibling_context(vast_nodes, node_idx, cur_parent);
    match raw_kind {
        TOK_STRING if colon_count == 0 => Some(C_AST_KIND_ASM_TEMPLATE),
        TOK_STRING if colon_count >= 3 => Some(C_AST_KIND_ASM_CLOBBERS_LIST),
        TOK_LPAREN if prev.kind == TOK_STRING && colon_count == 1 => {
            Some(C_AST_KIND_ASM_OUTPUT_OPERAND)
        }
        TOK_LPAREN if prev.kind == TOK_STRING && colon_count == 2 => {
            Some(C_AST_KIND_ASM_INPUT_OPERAND)
        }
        TOK_IDENTIFIER
            if colon_count >= 4
                && asm_has_goto_qualifier_before(vast_nodes, parent_idx, parent_parent) =>
        {
            Some(C_AST_KIND_ASM_GOTO_LABELS)
        }
        _ => None,
    }
}

fn asm_prefix_before(vast_nodes: &[u32], before_idx: usize, parent: u32) -> bool {
    for scan_idx in (0..before_idx).rev() {
        let base = scan_idx * VAST_NODE_STRIDE_U32 as usize;
        if vast_nodes.get(base + 1).copied().unwrap_or(SENTINEL) != parent {
            continue;
        }
        match vast_nodes.get(base).copied().unwrap_or_default() {
            TOK_GNU_ASM => return true,
            TOK_VOLATILE | TOK_GOTO => continue,
            _ => return false,
        }
    }
    false
}

fn asm_has_goto_qualifier_before(vast_nodes: &[u32], before_idx: usize, parent: u32) -> bool {
    let mut saw_goto = false;
    for scan_idx in (0..before_idx).rev() {
        let base = scan_idx * VAST_NODE_STRIDE_U32 as usize;
        if vast_nodes.get(base + 1).copied().unwrap_or(SENTINEL) != parent {
            continue;
        }
        match vast_nodes.get(base).copied().unwrap_or_default() {
            TOK_GOTO => saw_goto = true,
            TOK_VOLATILE => continue,
            TOK_GNU_ASM => return saw_goto,
            _ => return false,
        }
    }
    false
}

fn sibling_colons_before(vast_nodes: &[u32], node_idx: usize, cur_parent: u32) -> u32 {
    let mut colons = 0u32;
    for scan_idx in 0..node_idx {
        let base = scan_idx * VAST_NODE_STRIDE_U32 as usize;
        if vast_nodes.get(base + 1).copied().unwrap_or(SENTINEL) == cur_parent
            && vast_nodes.get(base).copied().unwrap_or_default() == TOK_COLON
        {
            colons = colons.saturating_add(1);
        }
    }
    colons
}

fn reference_c_attribute_kind(
    vast_nodes: &[u32],
    node_idx: usize,
    raw_kind: u32,
    cur_parent: u32,
) -> Option<u32> {
    if !matches!(raw_kind, TOK_IDENTIFIER | TOK_CONST) {
        return None;
    }
    let node_count = vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    let Ok(parent_idx) = usize::try_from(cur_parent) else {
        return None;
    };
    if parent_idx >= node_count || kind_at(vast_nodes, parent_idx) != TOK_LPAREN {
        return None;
    }
    let parent_parent = vast_nodes
        .get(parent_idx * VAST_NODE_STRIDE_U32 as usize + 1)
        .copied()
        .unwrap_or(SENTINEL);
    let Ok(parent_parent_idx) = usize::try_from(parent_parent) else {
        return None;
    };
    if parent_parent_idx >= node_count || kind_at(vast_nodes, parent_parent_idx) != TOK_LPAREN {
        return None;
    }
    let grand_parent = vast_nodes
        .get(parent_parent_idx * VAST_NODE_STRIDE_U32 as usize + 1)
        .copied()
        .unwrap_or(SENTINEL);
    let attr_prefix = previous_sibling_context(vast_nodes, parent_parent_idx, grand_parent);
    let adjacent_attr_prefix = parent_parent_idx > 0
        && kind_at(vast_nodes, parent_parent_idx.saturating_sub(1)) == TOK_GNU_ATTRIBUTE;
    if attr_prefix.kind != TOK_GNU_ATTRIBUTE && !adjacent_attr_prefix {
        return None;
    }
    if raw_kind == TOK_CONST {
        return Some(C_AST_KIND_ATTRIBUTE_CONST);
    }

    let symbol = vast_nodes
        .get(node_idx * VAST_NODE_STRIDE_U32 as usize + VAST_TYPEDEF_SYMBOL_FIELD as usize)
        .copied()
        .unwrap_or_default();
    C_ATTRIBUTE_KIND_HASHES
        .iter()
        .find_map(|(hash, kind)| (*hash == symbol).then_some(*kind))
}

fn reference_c_direct_attribute_kind(
    vast_nodes: &[u32],
    raw_kind: u32,
    cur_parent: u32,
    symbol: u32,
) -> Option<u32> {
    if !matches!(raw_kind, TOK_IDENTIFIER | TOK_CONST) {
        return None;
    }
    let node_count = vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    let parent_idx = usize::try_from(cur_parent).ok()?;
    if parent_idx >= node_count || kind_at(vast_nodes, parent_idx) != TOK_LPAREN {
        return None;
    }
    let parent_parent = vast_nodes
        .get(parent_idx * VAST_NODE_STRIDE_U32 as usize + 1)
        .copied()
        .unwrap_or(SENTINEL);
    let parent_parent_idx = usize::try_from(parent_parent).ok()?;
    if parent_parent_idx == 0
        || parent_parent_idx >= node_count
        || kind_at(vast_nodes, parent_parent_idx) != TOK_LPAREN
        || kind_at(vast_nodes, parent_parent_idx - 1) != TOK_GNU_ATTRIBUTE
    {
        return None;
    }
    if raw_kind == TOK_CONST {
        return Some(C_AST_KIND_ATTRIBUTE_CONST);
    }
    C_ATTRIBUTE_KIND_HASHES
        .iter()
        .find_map(|(hash, kind)| (*hash == symbol).then_some(*kind))
}

fn reference_c_builtin_expression_kind(token: u32) -> Option<u32> {
    match token {
        TOK_BUILTIN_CONSTANT_P => Some(C_AST_KIND_BUILTIN_CONSTANT_P_EXPR),
        TOK_BUILTIN_CHOOSE_EXPR => Some(C_AST_KIND_BUILTIN_CHOOSE_EXPR),
        TOK_BUILTIN_TYPES_COMPATIBLE_P => Some(C_AST_KIND_BUILTIN_TYPES_COMPATIBLE_P_EXPR),
        TOK_GENERIC => Some(C_AST_KIND_GENERIC_SELECTION_EXPR),
        TOK_ELLIPSIS => Some(C_AST_KIND_RANGE_DESIGNATOR_EXPR),
        _ => None,
    }
}

fn reference_c_builtin_identifier_expression_kind(
    raw_kind: u32,
    symbol: u32,
    next_kind: u32,
) -> Option<u32> {
    if raw_kind != TOK_IDENTIFIER || next_kind != TOK_LPAREN {
        return None;
    }
    if is_gnu_typeof_hash_raw(symbol) {
        return Some(C_AST_KIND_SIZEOF_EXPR);
    }
    match symbol {
        0x749d_f71e => Some(C_AST_KIND_BUILTIN_EXPECT_EXPR),
        0xdcec_13f5 => Some(C_AST_KIND_BUILTIN_OFFSETOF_EXPR),
        0x7900_03c8 => Some(C_AST_KIND_BUILTIN_OBJECT_SIZE_EXPR),
        0x21a7_53f0 => Some(C_AST_KIND_BUILTIN_PREFETCH_EXPR),
        0x4a9a_c967 => Some(C_AST_KIND_BUILTIN_UNREACHABLE_STMT),
        0x7f55_6bd5 | 0xb0bc_f282 | 0x8cc7_b276 => Some(C_AST_KIND_BUILTIN_OVERFLOW_EXPR),
        0x3909_1622 => Some(C_AST_KIND_BUILTIN_CLASSIFY_TYPE_EXPR),
        _ => None,
    }
}

fn reference_effective_expression_prev_kind(prev_kind: u32, prev_prev_kind: u32) -> u32 {
    if prev_kind == TOK_LPAREN
        && matches!(
            prev_prev_kind,
            TOK_SIZEOF | TOK_ALIGNOF | TOK_GNU_TYPEOF | TOK_GNU_TYPEOF_UNQUAL
        )
    {
        TOK_RPAREN
    } else {
        prev_kind
    }
}

fn reference_c_expression_operator_kind(
    token: u32,
    prev_kind: u32,
    prev_prev_kind: u32,
) -> Option<u32> {
    let effective_prev_kind = reference_effective_expression_prev_kind(prev_kind, prev_prev_kind);
    let unary_context = reference_c_unary_context(effective_prev_kind);
    match token {
        TOK_ASSIGN | TOK_PLUS_EQ | TOK_MINUS_EQ | TOK_STAR_EQ | TOK_SLASH_EQ | TOK_PERCENT_EQ
        | TOK_AMP_EQ | TOK_PIPE_EQ | TOK_CARET_EQ | TOK_LSHIFT_EQ | TOK_RSHIFT_EQ => {
            Some(C_AST_KIND_ASSIGN_EXPR)
        }
        TOK_DOT | TOK_ARROW => Some(C_AST_KIND_MEMBER_ACCESS_EXPR),
        TOK_LBRACKET if reference_c_can_end_expression(effective_prev_kind) => {
            Some(C_AST_KIND_ARRAY_SUBSCRIPT_EXPR)
        }
        TOK_SIZEOF | TOK_GNU_TYPEOF | TOK_GNU_TYPEOF_UNQUAL => Some(C_AST_KIND_SIZEOF_EXPR),
        TOK_ALIGNOF => Some(C_AST_KIND_ALIGNOF_EXPR),
        TOK_QUESTION => Some(C_AST_KIND_CONDITIONAL_EXPR),
        TOK_INC | TOK_DEC if unary_context => Some(C_AST_KIND_UNARY_EXPR),
        TOK_STAR | TOK_AMP | TOK_PLUS | TOK_MINUS | TOK_BANG | TOK_TILDE | TOK_GNU_REAL
        | TOK_GNU_IMAG
            if unary_context =>
        {
            Some(C_AST_KIND_UNARY_EXPR)
        }
        TOK_PLUS | TOK_MINUS | TOK_STAR | TOK_SLASH | TOK_PERCENT | TOK_AMP | TOK_PIPE
        | TOK_CARET | TOK_EQ | TOK_NE | TOK_LE | TOK_GE | TOK_AND | TOK_OR | TOK_LSHIFT
        | TOK_RSHIFT | TOK_LT | TOK_GT
            if !unary_context =>
        {
            Some(node_kind::BINARY)
        }
        _ => None,
    }
}

struct SiblingContext {
    idx: u32,
    kind: u32,
    prev_kind: u32,
    flags: u32,
    symbol_hash: u32,
}

fn previous_sibling_context(
    vast_nodes: &[u32],
    node_idx: usize,
    cur_parent: u32,
) -> SiblingContext {
    let mut prev_idx = SENTINEL;
    let mut prev_kind = SENTINEL;
    let mut prev_prev_kind = SENTINEL;
    let mut prev_flags = 0;
    let mut prev_symbol_hash = 0;
    for scan_idx in 0..node_idx {
        let base = scan_idx * VAST_NODE_STRIDE_U32 as usize;
        let scan_parent = vast_nodes.get(base + 1).copied().unwrap_or(SENTINEL);
        if scan_parent == cur_parent {
            prev_prev_kind = prev_kind;
            prev_kind = vast_nodes.get(base).copied().unwrap_or(SENTINEL);
            prev_flags = vast_nodes
                .get(base + VAST_TYPEDEF_FLAGS_FIELD as usize)
                .copied()
                .unwrap_or_default();
            prev_symbol_hash = vast_nodes
                .get(base + VAST_TYPEDEF_SYMBOL_FIELD as usize)
                .copied()
                .unwrap_or_default();
            prev_idx = scan_idx as u32;
        }
    }
    SiblingContext {
        idx: prev_idx,
        kind: prev_kind,
        prev_kind: prev_prev_kind,
        flags: prev_flags,
        symbol_hash: prev_symbol_hash,
    }
}

struct ParentContext {
    is_record_body: bool,
    is_enum_body: bool,
}

fn parent_context(vast_nodes: &[u32], cur_parent: u32) -> ParentContext {
    let node_count = vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    let Ok(parent_idx) = usize::try_from(cur_parent) else {
        return ParentContext {
            is_record_body: false,
            is_enum_body: false,
        };
    };
    if parent_idx >= node_count || kind_at(vast_nodes, parent_idx) != TOK_LBRACE {
        return ParentContext {
            is_record_body: false,
            is_enum_body: false,
        };
    }

    let parent_parent = vast_nodes
        .get(parent_idx * VAST_NODE_STRIDE_U32 as usize + 1)
        .copied()
        .unwrap_or(SENTINEL);
    let aggregate_prefix = aggregate_prefix_before_open(vast_nodes, parent_idx, parent_parent);
    let is_record_body = aggregate_prefix == AggregatePrefix::Record;
    let is_enum_body = aggregate_prefix == AggregatePrefix::Enum;

    ParentContext {
        is_record_body,
        is_enum_body,
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum AggregatePrefix {
    None,
    Record,
    Enum,
}

fn aggregate_prefix_before_open(
    vast_nodes: &[u32],
    open_idx: usize,
    open_parent: u32,
) -> AggregatePrefix {
    let mut prefix = AggregatePrefix::None;
    for scan_idx in 0..open_idx {
        let base = scan_idx * VAST_NODE_STRIDE_U32 as usize;
        if vast_nodes.get(base + 1).copied().unwrap_or(SENTINEL) != open_parent {
            continue;
        }
        match vast_nodes.get(base).copied().unwrap_or(SENTINEL) {
            TOK_STRUCT | TOK_UNION => prefix = AggregatePrefix::Record,
            TOK_ENUM => prefix = AggregatePrefix::Enum,
            TOK_SEMICOLON | TOK_ASSIGN | TOK_COMMA => prefix = AggregatePrefix::None,
            _ => {}
        }
    }
    prefix
}

fn parenthesized_declarator_context(vast_nodes: &[u32], cur_parent: u32) -> bool {
    let node_count = vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    let mut parent = cur_parent;
    for _ in 0..8 {
        let Ok(parent_idx) = usize::try_from(parent) else {
            return false;
        };
        if parent_idx >= node_count || kind_at(vast_nodes, parent_idx) != TOK_LPAREN {
            return false;
        }

        let parent_parent = vast_nodes
            .get(parent_idx * VAST_NODE_STRIDE_U32 as usize + 1)
            .copied()
            .unwrap_or(SENTINEL);
        if decl_context_before(vast_nodes, parent_idx, parent_parent).has_prefix {
            return true;
        }

        let Ok(parent_parent_idx) = usize::try_from(parent_parent) else {
            return false;
        };
        if parent_parent_idx < node_count
            && is_typeof_operator_raw(
                kind_at(vast_nodes, parent_parent_idx),
                symbol_hash_at(vast_nodes, parent_parent_idx),
            )
        {
            return true;
        }
        if parent_parent_idx >= node_count || kind_at(vast_nodes, parent_parent_idx) != TOK_LPAREN {
            return false;
        }
        parent = parent_parent;
    }
    false
}

fn kind_at(vast_nodes: &[u32], node_idx: usize) -> u32 {
    vast_nodes
        .get(node_idx * VAST_NODE_STRIDE_U32 as usize)
        .copied()
        .unwrap_or_default()
}

fn child_kind(vast_nodes: &[u32], node_idx: usize) -> u32 {
    let node_count = vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    let child_idx = vast_nodes
        .get(node_idx * VAST_NODE_STRIDE_U32 as usize + 2)
        .copied()
        .unwrap_or(SENTINEL);
    let Ok(child_idx) = usize::try_from(child_idx) else {
        return 0;
    };
    if child_idx >= node_count {
        return 0;
    }
    kind_at(vast_nodes, child_idx)
}

fn child_flags(vast_nodes: &[u32], node_idx: usize) -> u32 {
    let node_count = vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    let child_idx = vast_nodes
        .get(node_idx * VAST_NODE_STRIDE_U32 as usize + 2)
        .copied()
        .unwrap_or(SENTINEL);
    let Ok(child_idx) = usize::try_from(child_idx) else {
        return 0;
    };
    if child_idx >= node_count {
        return 0;
    }
    vast_nodes
        .get(child_idx * VAST_NODE_STRIDE_U32 as usize + VAST_TYPEDEF_FLAGS_FIELD as usize)
        .copied()
        .unwrap_or_default()
}

fn child_symbol_hash(vast_nodes: &[u32], node_idx: usize) -> u32 {
    let node_count = vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    let child_idx = vast_nodes
        .get(node_idx * VAST_NODE_STRIDE_U32 as usize + 2)
        .copied()
        .unwrap_or(SENTINEL);
    let Ok(child_idx) = usize::try_from(child_idx) else {
        return 0;
    };
    if child_idx >= node_count {
        return 0;
    }
    symbol_hash_at(vast_nodes, child_idx)
}

fn has_any_typedef_annotations(vast_nodes: &[u32]) -> bool {
    vast_nodes
        .chunks_exact(VAST_NODE_STRIDE_U32 as usize)
        .any(|row| row[VAST_TYPEDEF_FLAGS_FIELD as usize] != 0)
}

fn is_reference_typedef_name(flags: u32, fallback_has_prior_typedef: bool) -> bool {
    (flags & C_TYPEDEF_FLAG_VISIBLE_TYPEDEF_NAME) != 0 || fallback_has_prior_typedef
}

fn prior_typedef_seen(vast_nodes: &[u32], node_idx: usize) -> bool {
    (0..node_idx).any(|scan_idx| kind_at(vast_nodes, scan_idx) == TOK_TYPEDEF)
}

fn prior_ordinary_decl_seen(vast_nodes: &[u32], node_idx: usize) -> bool {
    (0..node_idx).any(|scan_idx| {
        (vast_nodes
            .get(scan_idx * VAST_NODE_STRIDE_U32 as usize + VAST_TYPEDEF_FLAGS_FIELD as usize)
            .copied()
            .unwrap_or_default()
            & C_TYPEDEF_FLAG_ORDINARY_DECLARATOR)
            != 0
    })
}

fn prior_raw_ordinary_decl_seen(vast_nodes: &[u32], node_idx: usize) -> bool {
    (0..node_idx).any(|scan_idx| {
        if kind_at(vast_nodes, scan_idx) != TOK_IDENTIFIER {
            return false;
        }
        let parent = parent_context(
            vast_nodes,
            vast_nodes
                .get(scan_idx * VAST_NODE_STRIDE_U32 as usize + 1)
                .copied()
                .unwrap_or(SENTINEL),
        );
        if parent.is_record_body || parent.is_enum_body {
            return false;
        }
        let prev_kind = scan_idx
            .checked_sub(1)
            .map(|prev_idx| kind_at(vast_nodes, prev_idx))
            .unwrap_or(SENTINEL);
        let next_kind = if scan_idx + 1 < vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize {
            kind_at(vast_nodes, scan_idx + 1)
        } else {
            SENTINEL
        };
        is_decl_prefix_raw(prev_kind)
            && prev_kind != TOK_TYPEDEF
            && !declaration_prefix_contains_typedef(vast_nodes, scan_idx)
            && matches!(
                next_kind,
                TOK_SEMICOLON | TOK_COMMA | TOK_ASSIGN | TOK_LBRACKET
            )
    })
}

fn prior_parenthesized_identifier_statement_seen(vast_nodes: &[u32], node_idx: usize) -> bool {
    (0..node_idx).any(|scan_idx| {
        scan_idx + 5 < node_idx
            && kind_at(vast_nodes, scan_idx) == TOK_LPAREN
            && kind_at(vast_nodes, scan_idx + 1) == TOK_IDENTIFIER
            && kind_at(vast_nodes, scan_idx + 2) == TOK_RPAREN
            && kind_at(vast_nodes, scan_idx + 5) == TOK_SEMICOLON
    })
}

fn declaration_prefix_contains_typedef(vast_nodes: &[u32], node_idx: usize) -> bool {
    (0..node_idx).rev().find_map(|scan_idx| {
        let kind = kind_at(vast_nodes, scan_idx);
        if kind == TOK_TYPEDEF {
            Some(true)
        } else if is_decl_prefix_reset_raw(kind) {
            Some(false)
        } else {
            None
        }
    }) == Some(true)
}

fn reference_c_unary_context(prev_kind: u32) -> bool {
    matches!(
        prev_kind,
        SENTINEL
            | TOK_LPAREN
            | TOK_LBRACKET
            | TOK_LBRACE
            | TOK_COMMA
            | TOK_ASSIGN
            | TOK_PLUS_EQ
            | TOK_MINUS_EQ
            | TOK_STAR_EQ
            | TOK_SLASH_EQ
            | TOK_PERCENT_EQ
            | TOK_AMP_EQ
            | TOK_PIPE_EQ
            | TOK_CARET_EQ
            | TOK_LSHIFT_EQ
            | TOK_RSHIFT_EQ
            | TOK_QUESTION
            | TOK_COLON
            | TOK_SEMICOLON
            | TOK_RETURN
            | TOK_CASE
            | TOK_SIZEOF
            | TOK_GNU_TYPEOF
            | TOK_GNU_TYPEOF_UNQUAL
            | TOK_ALIGNOF
            | TOK_PLUS
            | TOK_MINUS
            | TOK_STAR
            | TOK_SLASH
            | TOK_PERCENT
            | TOK_AMP
            | TOK_PIPE
            | TOK_CARET
            | TOK_BANG
            | TOK_TILDE
            | TOK_EQ
            | TOK_NE
            | TOK_LE
            | TOK_GE
            | TOK_AND
            | TOK_OR
            | TOK_LSHIFT
            | TOK_RSHIFT
            | TOK_LT
            | TOK_GT
    )
}

fn reference_c_can_end_expression(prev_kind: u32) -> bool {
    matches!(
        prev_kind,
        TOK_IDENTIFIER
            | TOK_INTEGER
            | TOK_FLOAT
            | TOK_STRING
            | TOK_CHAR
            | TOK_RPAREN
            | TOK_RBRACKET
            | TOK_INC
            | TOK_DEC
    )
}

fn reference_c_statement_kind(token: u32) -> Option<u32> {
    match token {
        TOK_IF => Some(C_AST_KIND_IF_STMT),
        TOK_ELSE => Some(C_AST_KIND_ELSE_STMT),
        TOK_SWITCH => Some(C_AST_KIND_SWITCH_STMT),
        TOK_CASE => Some(C_AST_KIND_CASE_STMT),
        TOK_DEFAULT => Some(C_AST_KIND_DEFAULT_STMT),
        TOK_FOR => Some(C_AST_KIND_FOR_STMT),
        TOK_WHILE => Some(C_AST_KIND_WHILE_STMT),
        TOK_DO => Some(C_AST_KIND_DO_STMT),
        TOK_RETURN => Some(C_AST_KIND_RETURN_STMT),
        TOK_BREAK => Some(C_AST_KIND_BREAK_STMT),
        TOK_CONTINUE => Some(C_AST_KIND_CONTINUE_STMT),
        TOK_GOTO => Some(C_AST_KIND_GOTO_STMT),
        _ => None,
    }
}

struct DeclContext {
    has_prefix: bool,
}

fn decl_context_before(vast_nodes: &[u32], node_idx: usize, cur_parent: u32) -> DeclContext {
    let mut has_decl_prefix = false;
    let mut last_kind = SENTINEL;
    let mut prev_kind = SENTINEL;
    for scan_idx in 0..node_idx {
        let base = scan_idx * VAST_NODE_STRIDE_U32 as usize;
        let scan_parent = vast_nodes.get(base + 1).copied().unwrap_or(SENTINEL);
        if scan_parent != cur_parent {
            continue;
        }
        let scan_kind = vast_nodes.get(base).copied().unwrap_or_default();
        let aggregate_body_open =
            is_aggregate_specifier_body_open_raw(scan_kind, last_kind, prev_kind);
        if is_decl_prefix_reset_raw(scan_kind) {
            has_decl_prefix = false;
        }
        let scan_typedef_flags = vast_nodes
            .get(base + VAST_TYPEDEF_FLAGS_FIELD as usize)
            .copied()
            .unwrap_or_default();
        if is_decl_prefix_at(vast_nodes, scan_idx)
            || aggregate_body_open
            || (scan_kind == TOK_IDENTIFIER
                && (scan_typedef_flags & C_TYPEDEF_FLAG_VISIBLE_TYPEDEF_NAME) != 0)
        {
            has_decl_prefix = true;
        }
        prev_kind = last_kind;
        last_kind = scan_kind;
    }
    DeclContext {
        has_prefix: has_decl_prefix,
    }
}

fn declaration_initializer_prefix_before(
    vast_nodes: &[u32],
    node_idx: usize,
    cur_parent: u32,
) -> bool {
    let mut has_decl_prefix = false;
    for scan_idx in 0..node_idx {
        let base = scan_idx * VAST_NODE_STRIDE_U32 as usize;
        if vast_nodes.get(base + 1).copied().unwrap_or(SENTINEL) != cur_parent {
            continue;
        }
        let scan_kind = vast_nodes.get(base).copied().unwrap_or_default();
        if matches!(scan_kind, TOK_SEMICOLON | TOK_LBRACE | TOK_RBRACE) {
            has_decl_prefix = false;
        }
        if is_decl_prefix_at(vast_nodes, scan_idx) {
            has_decl_prefix = true;
        }
    }
    has_decl_prefix
}

fn suffix_function_boundary_kind(vast_nodes: &[u32], start_idx: u32, max_steps: usize) -> u32 {
    let node_count = vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    let mut scan_idx = start_idx;
    for _ in 0..max_steps {
        let Ok(idx) = usize::try_from(scan_idx) else {
            return SENTINEL;
        };
        if idx >= node_count {
            return SENTINEL;
        }
        let base = idx * VAST_NODE_STRIDE_U32 as usize;
        let scan_kind = vast_nodes.get(base).copied().unwrap_or_default();
        if matches!(scan_kind, TOK_LBRACE | TOK_SEMICOLON) {
            return scan_kind;
        }
        if scan_kind == TOK_RPAREN {
            let scan_parent = vast_nodes.get(base + 1).copied().unwrap_or(SENTINEL);
            if let Ok(parent_idx) = usize::try_from(scan_parent) {
                let parent_next = vast_nodes
                    .get(parent_idx * VAST_NODE_STRIDE_U32 as usize + 3)
                    .copied()
                    .unwrap_or(SENTINEL);
                if let Ok(parent_next_idx) = usize::try_from(parent_next) {
                    if parent_next_idx < node_count {
                        let parent_next_kind = kind_at(vast_nodes, parent_next_idx);
                        if matches!(parent_next_kind, TOK_LPAREN | TOK_LBRACKET | TOK_SEMICOLON) {
                            return parent_next_kind;
                        }
                        if parent_next_kind == TOK_RPAREN {
                            let parent_next_parent = vast_nodes
                                .get(parent_next_idx * VAST_NODE_STRIDE_U32 as usize + 1)
                                .copied()
                                .unwrap_or(SENTINEL);
                            if let Ok(parent_next_parent_idx) = usize::try_from(parent_next_parent)
                            {
                                let outer_next = vast_nodes
                                    .get(parent_next_parent_idx * VAST_NODE_STRIDE_U32 as usize + 3)
                                    .copied()
                                    .unwrap_or(SENTINEL);
                                if let Ok(outer_next_idx) = usize::try_from(outer_next) {
                                    if outer_next_idx < node_count {
                                        let outer_next_kind = kind_at(vast_nodes, outer_next_idx);
                                        if matches!(
                                            outer_next_kind,
                                            TOK_LPAREN | TOK_LBRACKET | TOK_SEMICOLON
                                        ) {
                                            return outer_next_kind;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
        scan_idx = vast_nodes.get(base + 3).copied().unwrap_or(SENTINEL);
    }
    SENTINEL
}

fn is_decl_prefix_raw(token: u32) -> bool {
    matches!(
        token,
        TOK_TYPEDEF
            | TOK_EXTERN
            | TOK_STATIC
            | TOK_INLINE
            | TOK_CONST
            | TOK_RESTRICT
            | TOK_VOLATILE
            | TOK_STRUCT
            | TOK_UNION
            | TOK_ENUM
            | TOK_VOID
            | TOK_CHAR_KW
            | TOK_INT
            | TOK_LONG
            | TOK_SHORT
            | TOK_SIGNED
            | TOK_UNSIGNED
            | TOK_FLOAT_KW
            | TOK_DOUBLE
            | TOK_BOOL
            | TOK_COMPLEX
            | TOK_IMAGINARY
            | TOK_ALIGNAS
            | TOK_ATOMIC
            | TOK_GNU_TYPEOF
            | TOK_GNU_AUTO_TYPE
            | TOK_GNU_EXTENSION
            | TOK_NORETURN
            | TOK_STATIC_ASSERT
            | TOK_THREAD_LOCAL
            | TOK_GNU_TYPEOF_UNQUAL
            | TOK_GNU_INT128
            | TOK_GNU_BUILTIN_VA_LIST
            | TOK_GNU_ADDRESS_SPACE
    )
}

fn is_aggregate_specifier_body_open_raw(
    open_kind: u32,
    prev_kind: u32,
    prev_prev_kind: u32,
) -> bool {
    open_kind == TOK_LBRACE
        && (matches!(prev_kind, TOK_STRUCT | TOK_UNION | TOK_ENUM)
            || (prev_kind == TOK_IDENTIFIER
                && matches!(prev_prev_kind, TOK_STRUCT | TOK_UNION | TOK_ENUM)))
}

fn is_type_name_start_raw(token: u32) -> bool {
    matches!(
        token,
        TOK_CONST
            | TOK_VOLATILE
            | TOK_STRUCT
            | TOK_UNION
            | TOK_ENUM
            | TOK_VOID
            | TOK_CHAR_KW
            | TOK_INT
            | TOK_LONG
            | TOK_SHORT
            | TOK_SIGNED
            | TOK_UNSIGNED
            | TOK_FLOAT_KW
            | TOK_DOUBLE
            | TOK_BOOL
            | TOK_COMPLEX
            | TOK_IMAGINARY
            | TOK_ATOMIC
            | TOK_RESTRICT
            | TOK_GNU_TYPEOF
            | TOK_GNU_TYPEOF_UNQUAL
            | TOK_GNU_INT128
            | TOK_GNU_BUILTIN_VA_LIST
    )
}

fn is_decl_prefix_reset_raw(token: u32) -> bool {
    matches!(
        token,
        TOK_SEMICOLON | TOK_LBRACE | TOK_RBRACE | TOK_ASSIGN | TOK_COLON
    )
}

/// CPU oracle for `c11_classify_vast_node_kinds`.
///
/// # Errors
///
/// Returns [`CReferenceDecodeError`] when `vast_node_bytes` is not
/// `u32`-aligned or does not contain complete C VAST rows.
pub fn try_reference_c11_classify_vast_node_kinds(
    vast_node_bytes: &[u8],
) -> Result<Vec<u8>, CReferenceDecodeError> {
    let raw_vast_nodes = try_vast_words_from_bytes(vast_node_bytes)?;
    Ok(reference_c11_classify_vast_node_kinds_from_words(
        &raw_vast_nodes,
    ))
}

/// CPU oracle for `c11_classify_vast_node_kinds`.
#[must_use]
pub fn reference_c11_classify_vast_node_kinds(vast_node_bytes: &[u8]) -> Vec<u8> {
    try_reference_c11_classify_vast_node_kinds(vast_node_bytes).expect(
        "Fix: pass complete u32-aligned C VAST rows to reference_c11_classify_vast_node_kinds",
    )
}

fn reference_c11_classify_vast_node_kinds_from_words(raw_vast_nodes: &[u32]) -> Vec<u8> {
    let mut typed_vast_nodes = raw_vast_nodes.to_vec();
    let node_count = raw_vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;

    for node_idx in 0..node_count {
        let base = node_idx * VAST_NODE_STRIDE_U32 as usize;
        let typed_kind = reference_typed_kind(raw_vast_nodes, node_idx);
        typed_vast_nodes[base] = typed_kind;
        if let Some(parent) =
            reference_declarator_parent_override(raw_vast_nodes, node_idx, typed_kind)
        {
            typed_vast_nodes[base + 1] = parent;
        }
    }

    u32_words_to_bytes(&typed_vast_nodes)
}

fn reference_declarator_parent_override(
    vast_nodes: &[u32],
    node_idx: usize,
    typed_kind: u32,
) -> Option<u32> {
    let node_count = vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    match typed_kind {
        C_AST_KIND_POINTER_DECL => None,
        C_AST_KIND_ARRAY_DECL => {
            let prev_idx = previous_sibling_idx(vast_nodes, node_idx)?;
            if kind_at(vast_nodes, prev_idx) != TOK_LPAREN {
                return None;
            }
            let first_child = vast_nodes
                .get(prev_idx * VAST_NODE_STRIDE_U32 as usize + 2)
                .copied()
                .and_then(|idx| usize::try_from(idx).ok())
                .filter(|idx| *idx < node_count)?;
            (kind_at(vast_nodes, first_child) == TOK_STAR).then_some(first_child as u32)
        }
        _ => None,
    }
}

fn previous_sibling_idx(vast_nodes: &[u32], node_idx: usize) -> Option<usize> {
    let parent = vast_nodes
        .get(node_idx * VAST_NODE_STRIDE_U32 as usize + 1)
        .copied()
        .unwrap_or(SENTINEL);
    (0..node_idx).rev().find(|scan_idx| {
        vast_nodes
            .get(scan_idx * VAST_NODE_STRIDE_U32 as usize + 1)
            .copied()
            .unwrap_or(SENTINEL)
            == parent
    })
}

/// CPU oracle for `c11_build_expression_shape_nodes`.
///
/// # Errors
///
/// Returns [`CReferenceDecodeError`] when either input is not `u32`-aligned or
/// does not contain complete C VAST rows.
pub fn try_reference_c11_build_expression_shape_nodes(
    raw_vast_node_bytes: &[u8],
    typed_vast_node_bytes: &[u8],
) -> Result<Vec<u8>, CReferenceDecodeError> {
    let raw_vast_nodes = try_vast_words_from_bytes(raw_vast_node_bytes)?;
    let typed_vast_nodes = try_vast_words_from_bytes(typed_vast_node_bytes)?;
    Ok(reference_c11_build_expression_shape_nodes_from_words(
        &raw_vast_nodes,
        &typed_vast_nodes,
    ))
}

/// CPU oracle for `c11_build_expression_shape_nodes`.
#[must_use]
pub fn reference_c11_build_expression_shape_nodes(
    raw_vast_node_bytes: &[u8],
    typed_vast_node_bytes: &[u8],
) -> Vec<u8> {
    try_reference_c11_build_expression_shape_nodes(raw_vast_node_bytes, typed_vast_node_bytes)
        .expect(
        "Fix: pass complete u32-aligned C VAST rows to reference_c11_build_expression_shape_nodes",
    )
}

fn reference_c11_build_expression_shape_nodes_from_words(
    raw_vast_nodes: &[u32],
    typed_vast_nodes: &[u32],
) -> Vec<u8> {
    let node_count =
        raw_vast_nodes.len().min(typed_vast_nodes.len()) / VAST_NODE_STRIDE_U32 as usize;
    let mut out = Vec::with_capacity(node_count * C_EXPR_SHAPE_STRIDE_U32 as usize);

    for node_idx in 0..node_count {
        let base = node_idx * VAST_NODE_STRIDE_U32 as usize;
        let raw_kind = raw_vast_nodes.get(base).copied().unwrap_or_default();
        let typed_kind = typed_vast_nodes.get(base).copied().unwrap_or_default();
        let parent = raw_vast_nodes.get(base + 1).copied().unwrap_or(SENTINEL);
        let shape = reference_c_expr_shape_kind(raw_kind, typed_kind);
        let precedence = reference_c_expr_operator_precedence(raw_kind, typed_kind);
        let associativity = reference_c_expr_operator_associativity(typed_kind);

        let (field5, field6, field7) = match shape {
            C_EXPR_SHAPE_BINARY => {
                let use_ternary_boundaries =
                    reference_binary_segment_uses_ternary_boundaries(raw_vast_nodes, node_idx);
                let (seg_start, seg_end) =
                    reference_expr_segment_bounds(raw_vast_nodes, node_idx, use_ternary_boundaries);
                let (left_bound, right_bound) = reference_binary_operand_bounds(
                    raw_vast_nodes,
                    typed_vast_nodes,
                    node_idx,
                    parent,
                    seg_start,
                    seg_end,
                    precedence,
                    associativity,
                );
                (
                    reference_expr_root(
                        raw_vast_nodes,
                        typed_vast_nodes,
                        left_bound,
                        node_idx,
                        parent,
                    ),
                    reference_expr_root(
                        raw_vast_nodes,
                        typed_vast_nodes,
                        node_idx.saturating_add(1),
                        right_bound,
                        parent,
                    ),
                    SENTINEL,
                )
            }
            C_EXPR_SHAPE_CONDITIONAL => {
                let (_, seg_end) = reference_expr_segment_bounds(raw_vast_nodes, node_idx, false);
                let (condition_start, _) =
                    reference_expr_segment_bounds(raw_vast_nodes, node_idx, true);
                let condition_start = reference_conditional_condition_start(
                    raw_vast_nodes,
                    typed_vast_nodes,
                    condition_start,
                    node_idx,
                    parent,
                    precedence,
                );
                let colon = reference_matching_ternary_colon(raw_vast_nodes, node_idx, seg_end);
                if let Some(colon_idx) = colon {
                    (
                        reference_expr_root(
                            raw_vast_nodes,
                            typed_vast_nodes,
                            condition_start,
                            node_idx,
                            parent,
                        ),
                        reference_expr_root(
                            raw_vast_nodes,
                            typed_vast_nodes,
                            node_idx.saturating_add(1),
                            colon_idx,
                            parent,
                        ),
                        reference_expr_root(
                            raw_vast_nodes,
                            typed_vast_nodes,
                            colon_idx.saturating_add(1),
                            seg_end,
                            parent,
                        ),
                    )
                } else {
                    (SENTINEL, SENTINEL, SENTINEL)
                }
            }
            _ => (SENTINEL, SENTINEL, SENTINEL),
        };

        out.extend_from_slice(&[
            shape,
            if shape == C_EXPR_SHAPE_NONE {
                SENTINEL
            } else {
                node_idx as u32
            },
            raw_kind,
            precedence,
            associativity,
            field5,
            field6,
            field7,
        ]);
    }

    u32_words_to_bytes(&out)
}

fn reference_c_expr_shape_kind(raw_kind: u32, typed_kind: u32) -> u32 {
    if typed_kind == C_AST_KIND_CONDITIONAL_EXPR || raw_kind == TOK_QUESTION {
        C_EXPR_SHAPE_CONDITIONAL
    } else if typed_kind == node_kind::BINARY || typed_kind == C_AST_KIND_ASSIGN_EXPR {
        C_EXPR_SHAPE_BINARY
    } else {
        C_EXPR_SHAPE_NONE
    }
}

fn reference_c_expr_operator_precedence(raw_kind: u32, typed_kind: u32) -> u32 {
    if typed_kind != node_kind::BINARY
        && typed_kind != C_AST_KIND_ASSIGN_EXPR
        && typed_kind != C_AST_KIND_CONDITIONAL_EXPR
        && raw_kind != TOK_QUESTION
    {
        0
    } else if typed_kind == C_AST_KIND_ASSIGN_EXPR {
        2
    } else if typed_kind == C_AST_KIND_CONDITIONAL_EXPR {
        3
    } else {
        match raw_kind {
            TOK_OR => 4,
            TOK_AND => 5,
            TOK_PIPE => 6,
            TOK_CARET => 7,
            TOK_AMP => 8,
            TOK_EQ | TOK_NE => 9,
            TOK_LT | TOK_GT | TOK_LE | TOK_GE => 10,
            TOK_LSHIFT | TOK_RSHIFT => 11,
            TOK_PLUS | TOK_MINUS => 12,
            TOK_STAR | TOK_SLASH | TOK_PERCENT => 13,
            _ => 0,
        }
    }
}

fn reference_c_expr_operator_associativity(typed_kind: u32) -> u32 {
    if typed_kind == C_AST_KIND_ASSIGN_EXPR || typed_kind == C_AST_KIND_CONDITIONAL_EXPR {
        C_EXPR_ASSOC_RIGHT
    } else if typed_kind == node_kind::BINARY {
        C_EXPR_ASSOC_LEFT
    } else {
        C_EXPR_ASSOC_NONE
    }
}

fn reference_expr_segment_bounds(
    raw_vast_nodes: &[u32],
    node_idx: usize,
    include_ternary_parts: bool,
) -> (usize, usize) {
    let node_count = raw_vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    let base = node_idx * VAST_NODE_STRIDE_U32 as usize;
    let parent = raw_vast_nodes.get(base + 1).copied().unwrap_or(SENTINEL);
    let mut start = 0usize;
    let mut scan = node_idx;
    while scan > 0 {
        scan -= 1;
        let scan_base = scan * VAST_NODE_STRIDE_U32 as usize;
        let scan_parent = raw_vast_nodes
            .get(scan_base + 1)
            .copied()
            .unwrap_or(SENTINEL);
        let scan_raw = raw_vast_nodes.get(scan_base).copied().unwrap_or_default();
        if scan_parent == parent
            && reference_is_expr_shape_boundary(scan_raw, include_ternary_parts)
        {
            start = scan.saturating_add(1);
            break;
        }
    }

    let mut end = node_count;
    for scan in node_idx.saturating_add(1)..node_count {
        let scan_base = scan * VAST_NODE_STRIDE_U32 as usize;
        let scan_parent = raw_vast_nodes
            .get(scan_base + 1)
            .copied()
            .unwrap_or(SENTINEL);
        let scan_raw = raw_vast_nodes.get(scan_base).copied().unwrap_or_default();
        if scan_parent == parent
            && reference_is_expr_shape_boundary(scan_raw, include_ternary_parts)
        {
            end = scan;
            break;
        }
    }

    (start, end)
}

fn reference_is_expr_shape_boundary(raw_kind: u32, include_ternary_parts: bool) -> bool {
    matches!(raw_kind, TOK_SEMICOLON | TOK_COMMA)
        || (include_ternary_parts && matches!(raw_kind, TOK_QUESTION | TOK_COLON))
}

fn reference_binary_segment_uses_ternary_boundaries(
    raw_vast_nodes: &[u32],
    node_idx: usize,
) -> bool {
    let base = node_idx * VAST_NODE_STRIDE_U32 as usize;
    let parent = raw_vast_nodes.get(base + 1).copied().unwrap_or(SENTINEL);
    let mut scan = node_idx;
    while scan > 0 {
        scan -= 1;
        let scan_base = scan * VAST_NODE_STRIDE_U32 as usize;
        if raw_vast_nodes
            .get(scan_base + 1)
            .copied()
            .unwrap_or(SENTINEL)
            != parent
        {
            continue;
        }
        match raw_vast_nodes.get(scan_base).copied().unwrap_or_default() {
            TOK_QUESTION | TOK_COLON => return true,
            TOK_SEMICOLON | TOK_COMMA => return false,
            _ => {}
        }
    }
    false
}

fn reference_conditional_condition_start(
    raw_vast_nodes: &[u32],
    typed_vast_nodes: &[u32],
    segment_start: usize,
    question_idx: usize,
    parent: u32,
    conditional_precedence: u32,
) -> usize {
    let mut condition_start = segment_start;
    for scan in segment_start..question_idx {
        let base = scan * VAST_NODE_STRIDE_U32 as usize;
        if raw_vast_nodes.get(base + 1).copied().unwrap_or(SENTINEL) != parent {
            continue;
        }
        let raw_kind = raw_vast_nodes.get(base).copied().unwrap_or_default();
        let typed_kind = typed_vast_nodes.get(base).copied().unwrap_or_default();
        if reference_c_expr_shape_kind(raw_kind, typed_kind) == C_EXPR_SHAPE_NONE {
            continue;
        }
        if reference_c_expr_operator_precedence(raw_kind, typed_kind) < conditional_precedence {
            condition_start = scan.saturating_add(1);
        }
    }
    condition_start
}

fn reference_binary_operand_bounds(
    raw_vast_nodes: &[u32],
    typed_vast_nodes: &[u32],
    node_idx: usize,
    parent: u32,
    seg_start: usize,
    seg_end: usize,
    target_precedence: u32,
    target_associativity: u32,
) -> (usize, usize) {
    let mut left_bound = seg_start;
    let mut right_bound = seg_end;
    let mut left_parent_op = SENTINEL;
    let mut right_parent_op = SENTINEL;

    for scan in seg_start..seg_end {
        if scan == node_idx {
            continue;
        }
        let base = scan * VAST_NODE_STRIDE_U32 as usize;
        if raw_vast_nodes.get(base + 1).copied().unwrap_or(SENTINEL) != parent {
            continue;
        }
        let raw_kind = raw_vast_nodes.get(base).copied().unwrap_or_default();
        let typed_kind = typed_vast_nodes.get(base).copied().unwrap_or_default();
        if reference_c_expr_shape_kind(raw_kind, typed_kind) == C_EXPR_SHAPE_NONE {
            continue;
        }
        let precedence = reference_c_expr_operator_precedence(raw_kind, typed_kind);
        let equal_assoc_parent = precedence == target_precedence
            && ((target_associativity == C_EXPR_ASSOC_LEFT && node_idx < scan)
                || (target_associativity == C_EXPR_ASSOC_RIGHT && scan < node_idx));
        if precedence < target_precedence || equal_assoc_parent {
            if scan < node_idx {
                left_parent_op = scan as u32;
            } else if scan > node_idx
                && (right_parent_op == SENTINEL || scan < right_parent_op as usize)
            {
                right_parent_op = scan as u32;
            }
        }
    }

    if left_parent_op != SENTINEL {
        left_bound = (left_parent_op as usize).saturating_add(1);
    }
    if right_parent_op != SENTINEL {
        right_bound = right_parent_op as usize;
    }

    (left_bound, right_bound)
}

fn reference_expr_root(
    raw_vast_nodes: &[u32],
    typed_vast_nodes: &[u32],
    lo: usize,
    hi: usize,
    parent: u32,
) -> u32 {
    let node_count =
        raw_vast_nodes.len().min(typed_vast_nodes.len()) / VAST_NODE_STRIDE_U32 as usize;
    let end = hi.min(node_count);
    let mut root = SENTINEL;
    let mut root_prec = u32::MAX;
    let mut first_operand = SENTINEL;

    for scan in lo.min(end)..end {
        let base = scan * VAST_NODE_STRIDE_U32 as usize;
        let scan_parent = raw_vast_nodes.get(base + 1).copied().unwrap_or(SENTINEL);
        let raw_kind = raw_vast_nodes.get(base).copied().unwrap_or_default();
        let typed_kind = typed_vast_nodes.get(base).copied().unwrap_or_default();
        let shape = reference_c_expr_shape_kind(raw_kind, typed_kind);
        if scan_parent != parent && shape == C_EXPR_SHAPE_NONE {
            continue;
        }
        if shape == C_EXPR_SHAPE_NONE {
            if scan_parent == parent
                && first_operand == SENTINEL
                && !reference_is_expr_shape_boundary(raw_kind, true)
            {
                first_operand = scan as u32;
            }
            continue;
        }

        let prec = reference_c_expr_operator_precedence(raw_kind, typed_kind);
        let assoc = reference_c_expr_operator_associativity(typed_kind);
        if root == SENTINEL || prec < root_prec || (prec == root_prec && assoc == C_EXPR_ASSOC_LEFT)
        {
            root = scan as u32;
            root_prec = prec;
        }
    }

    if root == SENTINEL {
        first_operand
    } else {
        root
    }
}

fn reference_matching_ternary_colon(
    raw_vast_nodes: &[u32],
    question_idx: usize,
    seg_end: usize,
) -> Option<usize> {
    let node_count = raw_vast_nodes.len() / VAST_NODE_STRIDE_U32 as usize;
    let base = question_idx * VAST_NODE_STRIDE_U32 as usize;
    let parent = raw_vast_nodes.get(base + 1).copied().unwrap_or(SENTINEL);
    let mut depth = 0u32;

    for scan in question_idx.saturating_add(1)..seg_end.min(node_count) {
        let scan_base = scan * VAST_NODE_STRIDE_U32 as usize;
        if raw_vast_nodes
            .get(scan_base + 1)
            .copied()
            .unwrap_or(SENTINEL)
            != parent
        {
            continue;
        }
        match raw_vast_nodes.get(scan_base).copied().unwrap_or_default() {
            TOK_QUESTION => depth = depth.saturating_add(1),
            TOK_COLON if depth == 0 => return Some(scan),
            TOK_COLON => depth = depth.saturating_sub(1),
            _ => {}
        }
    }

    None
}

fn pop_matching(stack: &mut Vec<u32>, tok_types: &[u32], opener: u32) {
    if stack
        .last()
        .and_then(|idx| tok_types.get(*idx as usize))
        .copied()
        == Some(opener)
    {
        stack.pop();
    }
}

fn witness_inputs() -> Vec<Vec<Vec<u8>>> {
    let tok_types = [107u32, 1, 10, 11, 12, 104, 2, 16, 13];
    let tok_starts = [0u32, 4, 8, 9, 10, 11, 18, 19, 20];
    let tok_lens = [3u32, 4, 1, 1, 1, 6, 1, 1, 1];
    vec![vec![
        u32_words_to_bytes(&tok_types),
        u32_words_to_bytes(&tok_starts),
        u32_words_to_bytes(&tok_lens),
        vec![0u8; tok_types.len() * VAST_NODE_STRIDE_U32 as usize * 4],
        vec![0u8; 4],
    ]]
}

fn witness_expected() -> Vec<Vec<Vec<u8>>> {
    let tok_types = [107u32, 1, 10, 11, 12, 104, 2, 16, 13];
    let tok_starts = [0u32, 4, 8, 9, 10, 11, 18, 19, 20];
    let tok_lens = [3u32, 4, 1, 1, 1, 6, 1, 1, 1];
    vec![vec![
        reference_c11_build_vast_nodes(&tok_types, &tok_starts, &tok_lens),
        u32_words_to_bytes(&[tok_types.len() as u32]),
    ]]
}

inventory::submit! {
    OpEntry::new(
        BUILD_VAST_OP_ID,
        || c11_build_vast_nodes("tok_types", "tok_starts", "tok_lens", Expr::u32(9), "out_vast_nodes", "out_count"),
        Some(witness_inputs),
        Some(witness_expected),
    )
}

fn classify_witness_vast() -> Vec<u8> {
    let tok_types = [
        TOK_INT,
        TOK_IDENTIFIER,
        TOK_LPAREN,
        TOK_RPAREN,
        TOK_LBRACE,
        TOK_RETURN,
        TOK_INTEGER,
        TOK_SEMICOLON,
        TOK_RBRACE,
    ];
    let tok_starts = [0u32, 4, 8, 9, 10, 11, 18, 19, 20];
    let tok_lens = [3u32, 4, 1, 1, 1, 6, 1, 1, 1];
    reference_c11_build_vast_nodes(&tok_types, &tok_starts, &tok_lens)
}

fn classify_witness_inputs() -> Vec<Vec<Vec<u8>>> {
    let vast = classify_witness_vast();
    vec![vec![vast, vec![0u8; 9 * VAST_NODE_STRIDE_U32 as usize * 4]]]
}

fn classify_witness_expected() -> Vec<Vec<Vec<u8>>> {
    vec![vec![reference_c11_classify_vast_node_kinds(
        &classify_witness_vast(),
    )]]
}

inventory::submit! {
    OpEntry::new(
        CLASSIFY_VAST_OP_ID,
        || c11_classify_vast_node_kinds("vast_nodes", Expr::u32(9), "out_typed_vast_nodes"),
        Some(classify_witness_inputs),
        Some(classify_witness_expected),
    )
}

fn expression_shape_witness_raw_vast() -> Vec<u8> {
    let tok_types = [
        TOK_IDENTIFIER,
        TOK_PLUS,
        TOK_IDENTIFIER,
        TOK_STAR,
        TOK_IDENTIFIER,
        TOK_QUESTION,
        TOK_IDENTIFIER,
        TOK_PLUS,
        TOK_IDENTIFIER,
        TOK_COLON,
        TOK_IDENTIFIER,
        TOK_STAR,
        TOK_IDENTIFIER,
        TOK_SEMICOLON,
    ];
    let tok_lens = [1u32; 14];
    let tok_starts = (0..14u32).collect::<Vec<_>>();
    reference_c11_build_vast_nodes(&tok_types, &tok_starts, &tok_lens)
}

fn expression_shape_witness_inputs() -> Vec<Vec<Vec<u8>>> {
    let raw = expression_shape_witness_raw_vast();
    let typed = reference_c11_classify_vast_node_kinds(&raw);
    vec![vec![
        raw,
        typed,
        vec![0; 14 * C_EXPR_SHAPE_STRIDE_U32 as usize * 4],
    ]]
}

fn expression_shape_witness_expected() -> Vec<Vec<Vec<u8>>> {
    expression_shape_witness_inputs()
        .into_iter()
        .map(|input| {
            vec![reference_c11_build_expression_shape_nodes(
                &input[0], &input[1],
            )]
        })
        .collect()
}

inventory::submit! {
    OpEntry::new(
        EXPR_SHAPE_OP_ID,
        || c11_build_expression_shape_nodes(
            "raw_vast_nodes",
            "typed_vast_nodes",
            Expr::u32(14),
            "out_expr_shape_nodes",
        ),
        Some(expression_shape_witness_inputs),
        Some(expression_shape_witness_expected),
    )
}

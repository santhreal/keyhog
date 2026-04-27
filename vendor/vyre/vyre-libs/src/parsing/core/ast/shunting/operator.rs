use crate::parsing::c::lex::tokens::*;
use crate::parsing::core::ast::node::*;
use vyre::ir::Expr;

pub(super) fn is_value_token(token: Expr) -> Expr {
    Expr::or(
        Expr::eq(token.clone(), Expr::u32(TOK_INTEGER)),
        Expr::eq(token, Expr::u32(TOK_IDENTIFIER)),
    )
}

fn is_assignment_token(token: Expr) -> Expr {
    Expr::or(
        Expr::eq(token.clone(), Expr::u32(TOK_ASSIGN)),
        Expr::or(
            Expr::eq(token.clone(), Expr::u32(TOK_PLUS_EQ)),
            Expr::or(
                Expr::eq(token.clone(), Expr::u32(TOK_MINUS_EQ)),
                Expr::or(
                    Expr::eq(token.clone(), Expr::u32(TOK_STAR_EQ)),
                    Expr::eq(token, Expr::u32(TOK_SLASH_EQ)),
                ),
            ),
        ),
    )
}

pub(super) fn is_binary_token(token: Expr) -> Expr {
    Expr::or(
        is_assignment_token(token.clone()),
        Expr::or(
            Expr::or(
                Expr::eq(token.clone(), Expr::u32(TOK_PLUS)),
                Expr::or(
                    Expr::eq(token.clone(), Expr::u32(TOK_MINUS)),
                    Expr::eq(token.clone(), Expr::u32(TOK_STAR)),
                ),
            ),
            Expr::or(
                Expr::or(
                    Expr::eq(token.clone(), Expr::u32(TOK_SLASH)),
                    Expr::eq(token.clone(), Expr::u32(TOK_PERCENT)),
                ),
                Expr::or(
                    Expr::or(
                        Expr::eq(token.clone(), Expr::u32(TOK_EQ)),
                        Expr::eq(token.clone(), Expr::u32(TOK_NE)),
                    ),
                    Expr::or(
                        Expr::or(
                            Expr::eq(token.clone(), Expr::u32(TOK_LT)),
                            Expr::eq(token.clone(), Expr::u32(TOK_GT)),
                        ),
                        Expr::or(
                            Expr::or(
                                Expr::eq(token.clone(), Expr::u32(TOK_LE)),
                                Expr::eq(token.clone(), Expr::u32(TOK_GE)),
                            ),
                            Expr::or(
                                Expr::eq(token.clone(), Expr::u32(TOK_AND)),
                                Expr::eq(token, Expr::u32(TOK_OR)),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
}

fn precedence(token: Expr) -> Expr {
    Expr::select(
        is_assignment_token(token.clone()),
        Expr::u32(1),
        Expr::select(
            Expr::eq(token.clone(), Expr::u32(TOK_OR)),
            Expr::u32(2),
            Expr::select(
                Expr::eq(token.clone(), Expr::u32(TOK_AND)),
                Expr::u32(3),
                Expr::select(
                    Expr::or(
                        Expr::eq(token.clone(), Expr::u32(TOK_EQ)),
                        Expr::eq(token.clone(), Expr::u32(TOK_NE)),
                    ),
                    Expr::u32(4),
                    Expr::select(
                        Expr::or(
                            Expr::or(
                                Expr::eq(token.clone(), Expr::u32(TOK_LT)),
                                Expr::eq(token.clone(), Expr::u32(TOK_GT)),
                            ),
                            Expr::or(
                                Expr::eq(token.clone(), Expr::u32(TOK_LE)),
                                Expr::eq(token.clone(), Expr::u32(TOK_GE)),
                            ),
                        ),
                        Expr::u32(5),
                        Expr::select(
                            Expr::or(
                                Expr::eq(token.clone(), Expr::u32(TOK_PLUS)),
                                Expr::eq(token.clone(), Expr::u32(TOK_MINUS)),
                            ),
                            Expr::u32(6),
                            Expr::select(
                                Expr::or(
                                    Expr::or(
                                        Expr::eq(token.clone(), Expr::u32(TOK_STAR)),
                                        Expr::eq(token.clone(), Expr::u32(TOK_SLASH)),
                                    ),
                                    Expr::eq(token, Expr::u32(TOK_PERCENT)),
                                ),
                                Expr::u32(7),
                                Expr::u32(0),
                            ),
                        ),
                    ),
                ),
            ),
        ),
    )
}

pub(super) fn ast_opcode(token: Expr) -> Expr {
    Expr::select(
        is_assignment_token(token.clone()),
        Expr::u32(AST_ASSIGN),
        Expr::select(
            Expr::eq(token.clone(), Expr::u32(TOK_MINUS)),
            Expr::u32(AST_SUB),
            Expr::select(
                Expr::eq(token.clone(), Expr::u32(TOK_STAR)),
                Expr::u32(AST_MUL),
                Expr::select(
                    Expr::eq(token.clone(), Expr::u32(TOK_SLASH)),
                    Expr::u32(AST_DIV),
                    Expr::select(
                        Expr::eq(token.clone(), Expr::u32(TOK_PERCENT)),
                        Expr::u32(AST_MOD),
                        Expr::select(
                            Expr::eq(token.clone(), Expr::u32(TOK_EQ)),
                            Expr::u32(AST_EQ),
                            Expr::select(
                                Expr::eq(token.clone(), Expr::u32(TOK_NE)),
                                Expr::u32(AST_NE),
                                Expr::select(
                                    Expr::eq(token.clone(), Expr::u32(TOK_LT)),
                                    Expr::u32(AST_LT),
                                    Expr::select(
                                        Expr::eq(token.clone(), Expr::u32(TOK_GT)),
                                        Expr::u32(AST_GT),
                                        Expr::select(
                                            Expr::eq(token.clone(), Expr::u32(TOK_LE)),
                                            Expr::u32(AST_LE),
                                            Expr::select(
                                                Expr::eq(token.clone(), Expr::u32(TOK_GE)),
                                                Expr::u32(AST_GE),
                                                Expr::select(
                                                    Expr::eq(token.clone(), Expr::u32(TOK_AND)),
                                                    Expr::u32(AST_LOGICAL_AND),
                                                    Expr::select(
                                                        Expr::eq(token, Expr::u32(TOK_OR)),
                                                        Expr::u32(AST_LOGICAL_OR),
                                                        Expr::u32(AST_ADD),
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

pub(super) fn should_pop(top: Expr, current: Expr) -> Expr {
    let top_prec = precedence(top.clone());
    let current_prec = precedence(current.clone());
    Expr::and(
        Expr::and(
            Expr::ne(top.clone(), Expr::u32(TOK_LPAREN)),
            is_binary_token(top),
        ),
        Expr::select(
            is_assignment_token(current),
            Expr::gt(top_prec.clone(), current_prec.clone()),
            Expr::ge(top_prec, current_prec),
        ),
    )
}

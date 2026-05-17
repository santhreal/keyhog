use super::super::*;
use crate::parsing::c::lex::tokens::*;
use vyre::ir::Expr;

pub(crate) fn is_open_token(token: Expr) -> Expr {
    Expr::or(
        Expr::or(
            Expr::eq(token.clone(), Expr::u32(TOK_LPAREN)),
            Expr::eq(token.clone(), Expr::u32(TOK_LBRACE)),
        ),
        Expr::eq(token, Expr::u32(TOK_LBRACKET)),
    )
}

pub(crate) fn is_matching_close(current: Expr, candidate: Expr) -> Expr {
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

pub(crate) fn is_c_literal_token(token: Expr) -> Expr {
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

pub(crate) fn c_statement_kind(token: Expr) -> Expr {
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

pub(crate) fn any_token_eq(token: Expr, values: &[u32]) -> Expr {
    let ranges = merged_token_ranges(values);
    let mut iter = ranges.into_iter();
    let Some((first_lo, first_hi)) = iter.next() else {
        return Expr::bool(false);
    };
    iter.fold(
        token_range_expr(&token, first_lo, first_hi),
        |acc, (lo, hi)| Expr::or(acc, token_range_expr(&token, lo, hi)),
    )
}

pub(crate) fn token_range_expr(token: &Expr, lo: u32, hi: u32) -> Expr {
    if lo == hi {
        Expr::eq(token.clone(), Expr::u32(lo))
    } else {
        Expr::and(
            Expr::ge(token.clone(), Expr::u32(lo)),
            Expr::le(token.clone(), Expr::u32(hi)),
        )
    }
}

pub(crate) fn merged_token_ranges(values: &[u32]) -> Vec<(u32, u32)> {
    let mut sorted = values.to_vec();
    sorted.sort_unstable();
    sorted.dedup();

    let mut ranges: Vec<(u32, u32)> = Vec::new();
    for value in sorted {
        match ranges.last_mut() {
            Some((_, hi)) if hi.checked_add(1) == Some(value) => *hi = value,
            _ => ranges.push((value, value)),
        }
    }
    ranges
}

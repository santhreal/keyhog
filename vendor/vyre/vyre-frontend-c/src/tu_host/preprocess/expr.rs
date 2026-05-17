use std::collections::HashMap;

use super::{is_ident_continue, is_ident_start, MacroDef};

#[derive(Clone, Debug, PartialEq, Eq)]
enum ExprTok {
    Num(i64),
    Not,
    And,
    Or,
    Eq,
    Ne,
    LParen,
    RParen,
}

fn tokenize_preproc_expr(expr: &str, macros: &HashMap<String, MacroDef>) -> Vec<ExprTok> {
    let bytes = expr.as_bytes();
    let mut out = Vec::new();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes[i].is_ascii_whitespace() {
            i += 1;
        } else if bytes[i].is_ascii_digit() {
            let start = i;
            i += 1;
            while i < bytes.len() && bytes[i].is_ascii_digit() {
                i += 1;
            }
            out.push(ExprTok::Num(expr[start..i].parse::<i64>().unwrap_or(0)));
        } else if is_ident_start(bytes[i]) {
            let start = i;
            i += 1;
            while i < bytes.len() && is_ident_continue(bytes[i]) {
                i += 1;
            }
            let ident = &expr[start..i];
            if ident == "defined" {
                while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                let paren = bytes.get(i).copied() == Some(b'(');
                if paren {
                    i += 1;
                }
                while i < bytes.len() && bytes[i].is_ascii_whitespace() {
                    i += 1;
                }
                let name_start = i;
                if bytes.get(i).is_some_and(|b| is_ident_start(*b)) {
                    i += 1;
                    while i < bytes.len() && is_ident_continue(bytes[i]) {
                        i += 1;
                    }
                }
                let name = &expr[name_start..i];
                if paren {
                    while i < bytes.len() && bytes[i] != b')' {
                        i += 1;
                    }
                    if i < bytes.len() {
                        i += 1;
                    }
                }
                out.push(ExprTok::Num(i64::from(macros.contains_key(name))));
            } else {
                let value = macros
                    .get(ident)
                    .and_then(|m| (m.params.is_none()).then_some(m.replacement.trim()))
                    .and_then(|v| v.parse::<i64>().ok())
                    .unwrap_or(0);
                out.push(ExprTok::Num(value));
            }
        } else {
            match bytes[i] {
                b'!' if bytes.get(i + 1).copied() == Some(b'=') => {
                    out.push(ExprTok::Ne);
                    i += 2;
                }
                b'=' if bytes.get(i + 1).copied() == Some(b'=') => {
                    out.push(ExprTok::Eq);
                    i += 2;
                }
                b'&' if bytes.get(i + 1).copied() == Some(b'&') => {
                    out.push(ExprTok::And);
                    i += 2;
                }
                b'|' if bytes.get(i + 1).copied() == Some(b'|') => {
                    out.push(ExprTok::Or);
                    i += 2;
                }
                b'!' => {
                    out.push(ExprTok::Not);
                    i += 1;
                }
                b'(' => {
                    out.push(ExprTok::LParen);
                    i += 1;
                }
                b')' => {
                    out.push(ExprTok::RParen);
                    i += 1;
                }
                _ => i += 1,
            }
        }
    }
    out
}

fn parse_expr_or(tokens: &[ExprTok], idx: &mut usize) -> i64 {
    let mut lhs = parse_expr_and(tokens, idx);
    while tokens.get(*idx) == Some(&ExprTok::Or) {
        *idx += 1;
        let rhs = parse_expr_and(tokens, idx);
        lhs = i64::from(lhs != 0 || rhs != 0);
    }
    lhs
}

fn parse_expr_and(tokens: &[ExprTok], idx: &mut usize) -> i64 {
    let mut lhs = parse_expr_eq(tokens, idx);
    while tokens.get(*idx) == Some(&ExprTok::And) {
        *idx += 1;
        let rhs = parse_expr_eq(tokens, idx);
        lhs = i64::from(lhs != 0 && rhs != 0);
    }
    lhs
}

fn parse_expr_eq(tokens: &[ExprTok], idx: &mut usize) -> i64 {
    let mut lhs = parse_expr_unary(tokens, idx);
    loop {
        match tokens.get(*idx) {
            Some(ExprTok::Eq) => {
                *idx += 1;
                lhs = i64::from(lhs == parse_expr_unary(tokens, idx));
            }
            Some(ExprTok::Ne) => {
                *idx += 1;
                lhs = i64::from(lhs != parse_expr_unary(tokens, idx));
            }
            _ => return lhs,
        }
    }
}

fn parse_expr_unary(tokens: &[ExprTok], idx: &mut usize) -> i64 {
    match tokens.get(*idx) {
        Some(ExprTok::Not) => {
            *idx += 1;
            i64::from(parse_expr_unary(tokens, idx) == 0)
        }
        Some(ExprTok::LParen) => {
            *idx += 1;
            let value = parse_expr_or(tokens, idx);
            if tokens.get(*idx) == Some(&ExprTok::RParen) {
                *idx += 1;
            }
            value
        }
        Some(ExprTok::Num(value)) => {
            *idx += 1;
            *value
        }
        _ => 0,
    }
}

pub(super) fn eval_preproc_expr(expr: &str, macros: &HashMap<String, MacroDef>) -> bool {
    let tokens = tokenize_preproc_expr(expr, macros);
    let mut idx = 0usize;
    parse_expr_or(&tokens, &mut idx) != 0
}

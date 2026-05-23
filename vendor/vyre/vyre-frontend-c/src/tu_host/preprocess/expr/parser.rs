use super::*;
pub(super) fn parse_expr_conditional(tokens: &[ExprTok], idx: &mut usize) -> i128 {
    parse_expr_conditional_active(tokens, idx, true)
}

pub(super) fn parse_expr_conditional_active(
    tokens: &[ExprTok],
    idx: &mut usize,
    active: bool,
) -> i128 {
    let cond = parse_expr_or(tokens, idx, active);
    if tokens.get(*idx) != Some(&ExprTok::Question) {
        return cond;
    }
    *idx += 1;
    let if_true = parse_expr_conditional_active(tokens, idx, active && cond != 0);
    if tokens.get(*idx) != Some(&ExprTok::Colon) {
        panic!("preprocessor #if ternary expression is missing `:`. Fix: pass a complete `cond ? a : b` expression.");
    }
    *idx += 1;
    let if_false = parse_expr_conditional_active(tokens, idx, active && cond == 0);
    if !active {
        0
    } else if cond != 0 {
        if_true
    } else {
        if_false
    }
}

pub(super) fn parse_expr_or(tokens: &[ExprTok], idx: &mut usize, active: bool) -> i128 {
    let mut lhs = parse_expr_and(tokens, idx, active);
    while tokens.get(*idx) == Some(&ExprTok::Or) {
        *idx += 1;
        let rhs = parse_expr_and(tokens, idx, active && lhs == 0);
        if active {
            lhs = i128::from(lhs != 0 || rhs != 0);
        }
    }
    lhs
}

pub(super) fn parse_expr_and(tokens: &[ExprTok], idx: &mut usize, active: bool) -> i128 {
    let mut lhs = parse_expr_bit_or(tokens, idx, active);
    while tokens.get(*idx) == Some(&ExprTok::And) {
        *idx += 1;
        let rhs = parse_expr_bit_or(tokens, idx, active && lhs != 0);
        if active {
            lhs = i128::from(lhs != 0 && rhs != 0);
        }
    }
    lhs
}

pub(super) fn parse_expr_bit_or(tokens: &[ExprTok], idx: &mut usize, active: bool) -> i128 {
    let mut lhs = parse_expr_bit_xor(tokens, idx, active);
    while tokens.get(*idx) == Some(&ExprTok::BitOr) {
        *idx += 1;
        let rhs = parse_expr_bit_xor(tokens, idx, active);
        if active {
            lhs |= rhs;
        }
    }
    lhs
}

pub(super) fn parse_expr_bit_xor(tokens: &[ExprTok], idx: &mut usize, active: bool) -> i128 {
    let mut lhs = parse_expr_bit_and(tokens, idx, active);
    while tokens.get(*idx) == Some(&ExprTok::BitXor) {
        *idx += 1;
        let rhs = parse_expr_bit_and(tokens, idx, active);
        if active {
            lhs ^= rhs;
        }
    }
    lhs
}

pub(super) fn parse_expr_bit_and(tokens: &[ExprTok], idx: &mut usize, active: bool) -> i128 {
    let mut lhs = parse_expr_eq(tokens, idx, active);
    while tokens.get(*idx) == Some(&ExprTok::BitAnd) {
        *idx += 1;
        let rhs = parse_expr_eq(tokens, idx, active);
        if active {
            lhs &= rhs;
        }
    }
    lhs
}

pub(super) fn parse_expr_eq(tokens: &[ExprTok], idx: &mut usize, active: bool) -> i128 {
    let mut lhs = parse_expr_rel(tokens, idx, active);
    loop {
        match tokens.get(*idx) {
            Some(ExprTok::Eq) => {
                *idx += 1;
                let rhs = parse_expr_rel(tokens, idx, active);
                if active {
                    lhs = i128::from(lhs == rhs);
                }
            }
            Some(ExprTok::Ne) => {
                *idx += 1;
                let rhs = parse_expr_rel(tokens, idx, active);
                if active {
                    lhs = i128::from(lhs != rhs);
                }
            }
            _ => return lhs,
        }
    }
}

pub(super) fn parse_expr_rel(tokens: &[ExprTok], idx: &mut usize, active: bool) -> i128 {
    let mut lhs = parse_expr_shift(tokens, idx, active);
    loop {
        match tokens.get(*idx) {
            Some(ExprTok::Lt) => {
                *idx += 1;
                let rhs = parse_expr_shift(tokens, idx, active);
                if active {
                    lhs = i128::from(lhs < rhs);
                }
            }
            Some(ExprTok::Le) => {
                *idx += 1;
                let rhs = parse_expr_shift(tokens, idx, active);
                if active {
                    lhs = i128::from(lhs <= rhs);
                }
            }
            Some(ExprTok::Gt) => {
                *idx += 1;
                let rhs = parse_expr_shift(tokens, idx, active);
                if active {
                    lhs = i128::from(lhs > rhs);
                }
            }
            Some(ExprTok::Ge) => {
                *idx += 1;
                let rhs = parse_expr_shift(tokens, idx, active);
                if active {
                    lhs = i128::from(lhs >= rhs);
                }
            }
            _ => return lhs,
        }
    }
}

pub(super) fn parse_expr_shift(tokens: &[ExprTok], idx: &mut usize, active: bool) -> i128 {
    let mut lhs = parse_expr_add(tokens, idx, active);
    loop {
        match tokens.get(*idx) {
            Some(ExprTok::Shl) => {
                *idx += 1;
                let rhs = parse_expr_add(tokens, idx, active);
                if active {
                    let amount = shift_amount(rhs);
                    lhs = lhs.checked_shl(amount).unwrap_or_else(|| {
                        panic!(
                            "preprocessor #if expression left shift by {amount} exceeded evaluator width after validation. Fix: keep shift_amount and i128 evaluator limits in sync."
                        )
                    });
                }
            }
            Some(ExprTok::Shr) => {
                *idx += 1;
                let rhs = parse_expr_add(tokens, idx, active);
                if active {
                    let amount = shift_amount(rhs);
                    lhs = lhs.checked_shr(amount).unwrap_or_else(|| {
                        panic!(
                            "preprocessor #if expression right shift by {amount} exceeded evaluator width after validation. Fix: keep shift_amount and i128 evaluator limits in sync."
                        )
                    });
                }
            }
            _ => return lhs,
        }
    }
}

pub(super) fn parse_expr_add(tokens: &[ExprTok], idx: &mut usize, active: bool) -> i128 {
    let mut lhs = parse_expr_mul(tokens, idx, active);
    loop {
        match tokens.get(*idx) {
            Some(ExprTok::Plus) => {
                *idx += 1;
                let rhs = parse_expr_mul(tokens, idx, active);
                if active {
                    lhs = lhs.wrapping_add(rhs);
                }
            }
            Some(ExprTok::Minus) => {
                *idx += 1;
                let rhs = parse_expr_mul(tokens, idx, active);
                if active {
                    lhs = lhs.wrapping_sub(rhs);
                }
            }
            _ => return lhs,
        }
    }
}

pub(super) fn parse_expr_mul(tokens: &[ExprTok], idx: &mut usize, active: bool) -> i128 {
    let mut lhs = parse_expr_unary(tokens, idx, active);
    loop {
        match tokens.get(*idx) {
            Some(ExprTok::Star) => {
                *idx += 1;
                let rhs = parse_expr_unary(tokens, idx, active);
                if active {
                    lhs = lhs.wrapping_mul(rhs);
                }
            }
            Some(ExprTok::Slash) => {
                *idx += 1;
                let rhs = parse_expr_unary(tokens, idx, active);
                if active && rhs == 0 {
                    panic!("preprocessor #if expression divides by zero. Fix: guard divisor macros before division.");
                }
                if active {
                    lhs /= rhs;
                }
            }
            Some(ExprTok::Percent) => {
                *idx += 1;
                let rhs = parse_expr_unary(tokens, idx, active);
                if active && rhs == 0 {
                    panic!("preprocessor #if expression takes remainder by zero. Fix: guard divisor macros before modulo.");
                }
                if active {
                    lhs %= rhs;
                }
            }
            _ => return lhs,
        }
    }
}

pub(super) fn shift_amount(value: i128) -> u32 {
    if value < 0 {
        panic!("preprocessor #if expression uses a negative shift count. Fix: guard shift-count macros before shifting.");
    }
    if value > 127 {
        panic!(
            "preprocessor #if expression uses shift count {value}, exceeding the i128 evaluator width. Fix: use bounded shift counts or extend the preprocessor integer model."
        );
    }
    value as u32
}

pub(super) fn parse_expr_unary(tokens: &[ExprTok], idx: &mut usize, active: bool) -> i128 {
    match tokens.get(*idx) {
        Some(ExprTok::Not) => {
            *idx += 1;
            let value = parse_expr_unary(tokens, idx, active);
            if active {
                i128::from(value == 0)
            } else {
                0
            }
        }
        Some(ExprTok::Plus) => {
            *idx += 1;
            parse_expr_unary(tokens, idx, active)
        }
        Some(ExprTok::Minus) => {
            *idx += 1;
            let value = parse_expr_unary(tokens, idx, active);
            if active {
                value.wrapping_neg()
            } else {
                0
            }
        }
        Some(ExprTok::BitNot) => {
            *idx += 1;
            let value = parse_expr_unary(tokens, idx, active);
            if active {
                !value
            } else {
                0
            }
        }
        Some(ExprTok::LParen) => {
            *idx += 1;
            let value = parse_expr_conditional_active(tokens, idx, active);
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

pub(in crate::tu_host::preprocess) fn eval_preproc_expr(
    expr: &str,
    macros: &HashMap<String, MacroDef>,
) -> bool {
    let tokens = tokenize_preproc_expr(expr, macros);
    let mut idx = 0usize;
    let value = parse_expr_conditional(&tokens, &mut idx);
    if idx != tokens.len() {
        panic!(
            "preprocessor #if expression `{expr}` left {} unparsed tokens. Fix: extend expression parsing instead of silently choosing a branch.",
            tokens.len().saturating_sub(idx)
        );
    }
    value != 0
}

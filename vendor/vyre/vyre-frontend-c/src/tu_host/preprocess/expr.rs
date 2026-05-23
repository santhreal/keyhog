use std::collections::HashMap;

use super::{is_ident_continue, is_ident_start, MacroDef};

mod literals;
mod parser;
#[cfg(test)]
mod tests;
mod tokenize;

use literals::{
    parse_hex_escape, parse_octal_escape, parse_preproc_char_literal, parse_preproc_escape,
    parse_preproc_integer_literal,
};
use parser::{
    parse_expr_add, parse_expr_and, parse_expr_bit_and, parse_expr_bit_or, parse_expr_bit_xor,
    parse_expr_conditional, parse_expr_conditional_active, parse_expr_eq, parse_expr_mul,
    parse_expr_or, parse_expr_rel, parse_expr_shift, parse_expr_unary, shift_amount,
};
use tokenize::{
    is_preprocessor_probe_builtin, parse_expr_macro_args, substitute_expr_macro_params,
    tokenize_preproc_expr, tokenize_preproc_expr_inner, ExprTok, MAX_PREPROC_EXPR_MACRO_DEPTH,
};

pub(super) use parser::eval_preproc_expr;

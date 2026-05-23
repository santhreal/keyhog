use super::*;

pub fn c11_lexer_regular_sparse_packed_haystack_with_flags(
    haystack: &str,
    out_tok_types: &str,
    out_tok_starts: &str,
    out_tok_lens: &str,
    out_counts: &str,
    haystack_len: u32,
) -> Program {
    c11_lexer_regular_sparse_impl(
        haystack,
        out_tok_types,
        out_tok_starts,
        out_tok_lens,
        out_counts,
        haystack_len,
        false,
        true,
        true,
        true,
        true,
        None,
    )
}

pub fn c11_lexer_regular_sparse_packed_haystack_with_flags_no_directives(
    haystack: &str,
    out_tok_types: &str,
    out_tok_starts: &str,
    out_tok_lens: &str,
    out_counts: &str,
    haystack_len: u32,
) -> Program {
    c11_lexer_regular_sparse_impl(
        haystack,
        out_tok_types,
        out_tok_starts,
        out_tok_lens,
        out_counts,
        haystack_len,
        false,
        true,
        true,
        false,
        true,
        None,
    )
}

pub fn c11_lexer_regular_sparse_packed_haystack_with_flags_no_directives_no_backscan(
    haystack: &str,
    out_tok_types: &str,
    out_tok_starts: &str,
    out_tok_lens: &str,
    out_counts: &str,
    haystack_len: u32,
) -> Program {
    c11_lexer_regular_sparse_impl(
        haystack,
        out_tok_types,
        out_tok_starts,
        out_tok_lens,
        out_counts,
        haystack_len,
        false,
        true,
        true,
        false,
        false,
        None,
    )
}

pub fn c11_lexer_regular_sparse_no_directives_no_backscan(
    haystack: &str,
    out_tok_types: &str,
    out_tok_starts: &str,
    out_tok_lens: &str,
    out_counts: &str,
    haystack_len: u32,
) -> Program {
    c11_lexer_regular_sparse_impl(
        haystack,
        out_tok_types,
        out_tok_starts,
        out_tok_lens,
        out_counts,
        haystack_len,
        true,
        false,
        false,
        false,
        false,
        None,
    )
}

use super::*;

pub(super) fn load_packed_byte_u32(buf: &'static str, addr: Expr) -> Expr {
    let word_idx = Expr::div(addr.clone(), Expr::u32(4));
    let byte_in_word = Expr::rem(addr, Expr::u32(4));
    let word = Expr::cast(DataType::U32, Expr::load(buf, word_idx));
    let shift = Expr::mul(byte_in_word, Expr::u32(8));
    Expr::bitand(Expr::shr(word, shift), Expr::u32(0xFF))
}

pub(super) fn safe_load_src_expr(addr: Expr, source_byte_len: Expr) -> Expr {
    Expr::select(
        Expr::lt(addr.clone(), source_byte_len),
        load_packed_byte_u32("source", addr),
        Expr::u32(0),
    )
}

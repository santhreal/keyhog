use super::*;

pub(super) fn safe_load_src_expr(addr: Expr, source_byte_len: Expr) -> Expr {
    super::super::gpu_source_bytes::safe_load_source_byte_expr(addr, source_byte_len)
}

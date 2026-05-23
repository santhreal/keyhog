use super::*;

pub(super) fn emit_enclosing_function_lookup(
    functions: &str,
    num_functions: Expr,
    token_idx: Expr,
) -> Vec<Node> {
    vec![
        Node::let_bind("caller_id", Expr::u32(u32::MAX)),
        Node::loop_for(
            "caller_fn_scan",
            Expr::u32(0),
            num_functions,
            vec![
                Node::let_bind(
                    "fn_rec_base",
                    Expr::mul(Expr::var("caller_fn_scan"), Expr::u32(3)),
                ),
                Node::let_bind(
                    "fn_body_start",
                    Expr::load(functions, Expr::add(Expr::var("fn_rec_base"), Expr::u32(1))),
                ),
                Node::let_bind(
                    "fn_body_end",
                    Expr::load(functions, Expr::add(Expr::var("fn_rec_base"), Expr::u32(2))),
                ),
                Node::if_then(
                    Expr::and(
                        Expr::eq(Expr::var("caller_id"), Expr::u32(u32::MAX)),
                        Expr::and(
                            Expr::ge(token_idx.clone(), Expr::var("fn_body_start")),
                            Expr::le(token_idx.clone(), Expr::var("fn_body_end")),
                        ),
                    ),
                    vec![Node::assign("caller_id", Expr::var("caller_fn_scan"))],
                ),
            ],
        ),
    ]
}

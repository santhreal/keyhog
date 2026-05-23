use super::*;

pub(crate) fn emit_identifier_source_hash_for_index(
    vast_nodes: &str,
    haystack: &str,
    haystack_len: &Expr,
    idx: Expr,
    out_name: &str,
    prefix: &str,
    packed_haystack: bool,
) -> Vec<Node> {
    let base = format!("{prefix}_hash_base");
    let start = format!("{prefix}_hash_start");
    let len = format!("{prefix}_hash_len");
    let cursor = format!("{prefix}_hash_i");
    let byte = format!("{prefix}_hash_byte");

    vec![
        Node::let_bind(&base, Expr::mul(idx, Expr::u32(VAST_NODE_STRIDE_U32))),
        Node::let_bind(
            &start,
            Expr::load(vast_nodes, Expr::add(Expr::var(&base), Expr::u32(5))),
        ),
        Node::let_bind(
            &len,
            Expr::load(vast_nodes, Expr::add(Expr::var(&base), Expr::u32(6))),
        ),
        Node::let_bind(
            out_name,
            Expr::load(
                vast_nodes,
                Expr::add(Expr::var(&base), Expr::u32(VAST_TYPEDEF_SYMBOL_FIELD)),
            ),
        ),
        Node::if_then(
            Expr::eq(Expr::var(out_name), Expr::u32(0)),
            vec![
                Node::assign(out_name, Expr::u32(0x811c9dc5)),
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
                                load_source_byte(
                                    haystack,
                                    Expr::add(Expr::var(&start), Expr::var(&cursor)),
                                    packed_haystack,
                                ),
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
            ],
        ),
    ]
}

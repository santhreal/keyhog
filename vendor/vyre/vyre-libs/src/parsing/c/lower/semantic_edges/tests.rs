use super::*;

#[test]
#[should_panic(expected = "truncated VAST")]
fn resolved_semantic_edges_rejects_truncated_vast_rows() {
    let _ = resolved_semantic_edges(&[], 0, 1, C_AST_KIND_GOTO_STMT);
}

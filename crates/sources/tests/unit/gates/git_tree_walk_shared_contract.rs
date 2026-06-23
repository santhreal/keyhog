#[test]
fn git_tree_walk_uses_shared_visitor_boundary() {
    let git_mod = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/git/mod.rs"))
        .expect("git mod source readable");
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/git/source.rs"))
        .expect("git source readable");

    for required in [
        "trait GitTreeVisitor",
        "fn walk_tree_recursive",
        "fn join_tree_path(",
        "visitor.handle_entry_error",
        "visitor.handle_subtree_object_error",
        "visitor.handle_subtree_type_error",
    ] {
        assert!(
            git_mod.contains(required),
            "git module must own shared tree-walk detail `{required}`"
        );
    }

    for required in [
        "struct HistoricalBlobCollector",
        "struct HeadBlobPathCollector",
        "impl super::GitTreeVisitor for HistoricalBlobCollector",
        "impl super::GitTreeVisitor for HeadBlobPathCollector",
        "super::walk_tree_recursive(repo, tree, prefix, &mut visitor)",
        "super::walk_tree_recursive(repo, &tree, b\"\", &mut visitor)",
    ] {
        assert!(
            source.contains(required),
            "git source must delegate tree walking through visitor boundary `{required}`"
        );
    }

    assert!(
        !source.contains("fn walk_tree_for_blob_paths("),
        "git source must not keep a second recursive HEAD tree walker"
    );

    let historical_body = source
        .split("fn collect_tree_blobs_metadata(")
        .nth(1)
        .and_then(|tail| tail.split("fn collect_head_blob_path_set").next())
        .unwrap_or("");
    assert!(
        !historical_body.contains("tree.iter()"),
        "collect_tree_blobs_metadata must not re-own recursive tree iteration"
    );
}

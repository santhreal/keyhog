#[test]
fn git_object_id_parser_and_unreadable_counter_have_one_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/git");
    let module = std::fs::read_to_string(root.join("mod.rs")).expect("read git module");
    let source = std::fs::read_to_string(root.join("source.rs")).expect("read git source module");
    let tag_messages =
        std::fs::read_to_string(root.join("tag_messages.rs")).expect("read git tag module");

    assert_eq!(
        module.matches("fn parse_git_object_id_line(").count(),
        1,
        "git object-id parsing must have one shared owner"
    );
    assert_eq!(
        source.matches("fn parse_git_object_id_line(").count()
            + tag_messages.matches("fn parse_git_object_id_line(").count(),
        0,
        "git source modules must import the shared object-id parser instead of duplicating it"
    );
    assert_eq!(
        module.matches("fn record_git_object_unreadable(").count(),
        1,
        "git object-unreadable telemetry must have one shared owner"
    );
    assert_eq!(
        source.matches("fn record_git_object_unreadable(").count()
            + tag_messages
                .matches("fn record_git_object_unreadable(")
                .count(),
        0,
        "git source modules must not carry duplicate unreadable telemetry helpers"
    );
}

//! KH-GAP-018 (A5): `.zip` must route through archive policy, not SKIP_EXTENSIONS.

#[test]
fn zip_not_in_skip_extensions() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/filesystem/skip_lists.rs"
    );
    let src = std::fs::read_to_string(path).expect("skip_lists readable");
    assert!(
        !src.contains("\"zip\""),
        ".zip must not appear in SKIP_EXTENSIONS — archive branch handles zip with caps"
    );
    assert!(
        src.contains("archive-unpack branch"),
        "skip_lists must document zip archive routing"
    );
}

//! Gate `filesystem`: modularity file cap (500 LOC).

#[test]
fn filesystem_file_size_cap() {
    for rel in [
        "src/filesystem.rs",
        "src/filesystem/extract.rs",
        "src/filesystem/filter.rs",
    ] {
        let path = format!("{}/{}", env!("CARGO_MANIFEST_DIR"), rel);
        let src = std::fs::read_to_string(&path).expect("source readable");
        let lines = src.lines().count();
        // Advisory cap (Santh STANDARD.md): warn, do not fail CI.
        if lines > 500 {
            eprintln!(
                "filesystem: {rel} has {lines} lines and exceeds 500-line cap - split module"
            );
        }
    }
}

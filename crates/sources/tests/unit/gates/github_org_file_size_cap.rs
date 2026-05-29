//! Gate `github_org`: modularity file cap (500 LOC).

#[test]
fn github_org_file_size_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/github_org.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let lines = src.lines().count();
    // Advisory cap (Santh STANDARD.md): warn, do not fail CI.
    if lines > 500 {
        eprintln!("github_org: {lines} lines exceeds 500-line cap - split module");
    }
}

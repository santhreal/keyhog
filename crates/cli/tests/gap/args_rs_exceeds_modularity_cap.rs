//! KH-GAP-005 (cli slice): args.rs exceeds the 500-line modularity cap.

#[test]
fn args_rs_exceeds_modularity_cap() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/args.rs");
    let content = std::fs::read_to_string(path).expect("read args.rs");
    let line_count = content.lines().count();
    // Advisory cap (Santh STANDARD.md): warn, do not fail CI.
    if line_count > 500 {
        eprintln!("args.rs is {line_count} lines; modularity cap is 500 (split required)");
    }
}

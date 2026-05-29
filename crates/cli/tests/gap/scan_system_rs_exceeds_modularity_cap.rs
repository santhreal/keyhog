//! KH-GAP-005 (cli slice): scan_system.rs exceeds the 500-line modularity cap.

#[test]
fn scan_system_rs_exceeds_modularity_cap() {
    let path = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/scan_system.rs"
    );
    let content = std::fs::read_to_string(path).expect("read scan_system.rs");
    let line_count = content.lines().count();
    // Advisory cap (Santh STANDARD.md): warn, do not fail CI.
    if line_count > 500 {
        eprintln!("scan_system.rs is {line_count} lines; modularity cap is 500 (split required)");
    }
}

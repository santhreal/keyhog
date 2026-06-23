#[test]
fn args_scan_enums_have_one_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let args = std::fs::read_to_string(root.join("src/args.rs")).expect("args.rs readable");
    let scan = std::fs::read_to_string(root.join("src/args/scan.rs")).expect("scan.rs readable");

    assert!(
        args.contains(
            "pub use scan::{CliDedupScope, DaemonMode, OutputFormat, ScanArgs, SeverityFilter};"
        ),
        "args.rs must re-export scan-owned enums from the scan module"
    );

    for owned in [
        "pub enum SeverityFilter",
        "pub enum OutputFormat",
        "pub enum CliDedupScope",
        "pub enum DaemonMode",
    ] {
        assert!(scan.contains(owned), "args/scan.rs must own `{owned}`");
        assert!(
            !args.contains(owned),
            "args.rs must not re-own `{owned}` after the scan enum split"
        );
    }
}

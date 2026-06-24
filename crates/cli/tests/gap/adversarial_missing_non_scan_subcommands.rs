//! KH-GAP-141: Adversarial suite covers scan argv only — daemon/hook/baseline/scan-system/watch absent.

use std::path::PathBuf;

#[test]
fn adversarial_suite_covers_non_scan_subcommands() {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/adversarial");
    let mut combined = String::new();
    for entry in std::fs::read_dir(&dir).expect("adversarial dir") {
        let path = entry.expect("entry").path();
        if path.extension().is_some_and(|e| e == "rs")
            && path.file_name() != Some("mod.rs".as_ref())
        {
            combined.push_str(&std::fs::read_to_string(path).expect("read"));
        }
    }
    for needle in [
        "\"daemon\"",
        "\"hook\"",
        "\"baseline\"",
        "scan-system",
        "\"watch\"",
    ] {
        assert!(
            combined.contains(needle),
            "adversarial/ must include hostile subprocess coverage for {needle}"
        );
    }
}

use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::sources::merge_scan_ignore_paths;

#[test]
fn merge_scan_ignore_paths_appends_multiple_excludes() {
    let args = ScanArgs::try_parse_from([
        "scan",
        ".",
        "--exclude-paths",
        "one",
        "--exclude-paths",
        "two",
    ])
    .unwrap();
    let merged = merge_scan_ignore_paths(&args, vec![]);
    assert!(merged.contains(&"one".to_string()));
    assert!(merged.contains(&"two".to_string()));
}

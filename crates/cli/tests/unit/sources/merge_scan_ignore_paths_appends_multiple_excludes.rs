use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};

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
    let merged = API.merge_scan_ignore_paths(&args, vec![]);
    assert!(merged.contains(&"one".to_string()));
    assert!(merged.contains(&"two".to_string()));
}

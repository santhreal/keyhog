use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::sources::merge_scan_ignore_paths;

#[test]
fn merge_scan_ignore_paths_includes_cli_exclude() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--exclude-paths", "skip-me.env"]).unwrap();
    let merged = merge_scan_ignore_paths(&args, vec![]);
    assert!(merged.iter().any(|p| p == "skip-me.env"));
}

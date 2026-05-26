use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::sources::merge_scan_ignore_paths;

#[test]
fn merge_scan_ignore_paths_empty_when_no_excludes() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--no-default-excludes"]).unwrap();
    let merged = merge_scan_ignore_paths(&args, vec![]);
    assert!(merged.is_empty());
}

use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::sources::merge_scan_ignore_paths;

#[test]
fn sources_merge_preserves_allowlist_when_defaults_off() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--no-default-excludes"]).unwrap();
    let merged = merge_scan_ignore_paths(&args, vec!["ignored.txt".into()]);
    assert_eq!(merged, vec!["ignored.txt"]);
}

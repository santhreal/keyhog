use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::sources::merge_scan_ignore_paths;

#[test]
fn merge_scan_ignore_paths_merges_allowlist_and_exclude() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--exclude-paths", "local.secret"]).unwrap();
    let merged = merge_scan_ignore_paths(&args, vec!["from-allowlist".into()]);
    assert!(merged.contains(&"from-allowlist".to_string()));
    assert!(merged.contains(&"local.secret".to_string()));
}

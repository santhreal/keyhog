use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::sources::merge_scan_ignore_paths;

#[test]
fn merge_scan_ignore_paths_no_default_excludes_omits_vendor() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--no-default-excludes"]).unwrap();
    let merged = merge_scan_ignore_paths(&args, vec![]);
    assert!(!merged.iter().any(|p| p.contains("vendor")));
}

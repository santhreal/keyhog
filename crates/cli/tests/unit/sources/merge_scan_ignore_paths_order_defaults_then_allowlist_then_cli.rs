use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::sources::merge_scan_ignore_paths;

#[test]
fn merge_scan_ignore_paths_order_defaults_then_allowlist_then_cli() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--exclude-paths", "cli-only"]).unwrap();
    let merged = merge_scan_ignore_paths(&args, vec!["allow-only".into()]);
    let allow_idx = merged.iter().position(|p| p == "allow-only").unwrap();
    let cli_idx = merged.iter().position(|p| p == "cli-only").unwrap();
    assert!(allow_idx < cli_idx, "allowlist paths precede CLI excludes");
}

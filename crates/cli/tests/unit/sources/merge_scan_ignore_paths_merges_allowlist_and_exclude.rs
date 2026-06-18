use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};

#[test]
fn merge_scan_ignore_paths_merges_allowlist_and_exclude() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--exclude-paths", "local.secret"]).unwrap();
    let merged = API.merge_scan_ignore_paths(&args, vec!["from-allowlist".into()]);
    assert!(merged.contains(&"from-allowlist".to_string()));
    assert!(merged.contains(&"local.secret".to_string()));
}

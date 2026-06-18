use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};

#[test]
fn merge_scan_ignore_paths_never_injects_vendor_default() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--no-default-excludes"]).unwrap();
    let merged = API.merge_scan_ignore_paths(&args, vec![]);
    assert!(
        !merged.iter().any(|p| p.contains("vendor")),
        "source-owned default excludes must not be duplicated in CLI merge output"
    );
}

use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};

#[test]
fn merge_scan_ignore_paths_does_not_own_default_excludes() {
    let args = ScanArgs::try_parse_from(["scan", "."]).unwrap();
    let merged = API.merge_scan_ignore_paths(&args, vec![]);
    assert!(
        merged.is_empty(),
        "CLI must not mirror source-owned default excludes; got {merged:?}"
    );
}

use super::scan_targets;
use crate::args::ScanArgs;
use clap::Parser;

#[test]
fn filesystem_scan_reports_the_worktree_root() {
    let args = ScanArgs::try_parse_from(["scan", "."]).expect("parse filesystem scan");
    assert_eq!(scan_targets(&args), ["path:."]);
}

#[cfg(feature = "git")]
#[test]
fn staged_scan_reports_only_the_index_root() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--git-staged"]).expect("parse staged scan");
    assert_eq!(scan_targets(&args), ["git-staged:."]);
}

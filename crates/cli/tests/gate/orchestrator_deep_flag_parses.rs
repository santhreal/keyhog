//! LR1-A8 replacement gate: `orchestrator_config.rs` deep scan flag.

use clap::Parser;
use keyhog::args::ScanArgs;

#[test]
fn deep_scan_flag_enables_thorough_mode() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--deep"]).unwrap();
    assert!(args.deep);
    assert!(!args.fast);
}

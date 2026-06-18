use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};

#[test]
fn build_scanner_config_respects_no_entropy() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--no-entropy"]).unwrap();
    let cfg = API.build_scanner_config(&args);
    assert!(!cfg.entropy_enabled);
}

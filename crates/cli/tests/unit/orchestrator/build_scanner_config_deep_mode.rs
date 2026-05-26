use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::orchestrator_config::build_scanner_config;

#[test]
fn build_scanner_config_deep_mode() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--deep"]).unwrap();
    let _cfg = build_scanner_config(&args);
    assert!(args.deep);
}

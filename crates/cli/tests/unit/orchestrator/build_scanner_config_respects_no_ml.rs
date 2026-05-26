use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::orchestrator_config::build_scanner_config;

#[test]
fn build_scanner_config_respects_no_ml() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--no-ml"]).unwrap();
    let cfg = build_scanner_config(&args);
    assert!(!cfg.ml_enabled);
}

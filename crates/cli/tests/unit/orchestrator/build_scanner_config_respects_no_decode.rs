use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::orchestrator_config::build_scanner_config;

#[test]
fn build_scanner_config_respects_no_decode() {
    let default_args = ScanArgs::try_parse_from(["scan", "."]).unwrap();
    let no_decode_args = ScanArgs::try_parse_from(["scan", ".", "--no-decode"]).unwrap();

    let default_cfg = build_scanner_config(&default_args);
    let no_decode_cfg = build_scanner_config(&no_decode_args);

    assert!(
        default_cfg.max_decode_depth > 0,
        "default scan must enable decode-through (max_decode_depth > 0), got {}",
        default_cfg.max_decode_depth
    );
    assert_eq!(
        no_decode_cfg.max_decode_depth, 0,
        "--no-decode must set max_decode_depth to 0"
    );
}

use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};

#[test]
fn build_scanner_config_respects_no_entropy() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--no-entropy"]).unwrap();
    let cfg = API.build_scanner_config(&args);
    assert!(!cfg.entropy_enabled);
}

#[test]
fn build_scanner_config_no_entropy_survives_post_config_preset_merge() {
    let mut args = ScanArgs::try_parse_from(["scan", ".", "--deep"]).unwrap();
    args.no_entropy = true;

    let cfg = API.build_scanner_config(&args);

    assert!(
        !cfg.entropy_enabled,
        "TOML no_entropy merged with a preset must disable entropy instead of \
         being ignored by the preset base"
    );
}

use clap::Parser;
use keyhog::args::ScanArgs;
use keyhog::testing::{CliTestApi as _, API};

#[test]
fn build_scanner_config_respects_min_secret_len() {
    let args = ScanArgs::try_parse_from(["scan", ".", "--min-secret-len", "31"]).unwrap();
    let cfg = API.build_scanner_config(&args);
    assert_eq!(cfg.min_secret_len, 31);
}

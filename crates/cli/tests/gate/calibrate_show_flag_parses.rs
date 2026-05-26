//! LR1-A8 replacement gate: `subcommands/calibrate.rs` `--show` flag.

use clap::Parser;
use keyhog::args::{Cli, Command};

#[test]
fn calibrate_show_sets_show_only_mode() {
    let cli = Cli::try_parse_from(["keyhog", "calibrate", "--show"]).unwrap();
    match cli.command {
        Some(Command::Calibrate(args)) => {
            assert!(args.show);
            assert!(args.tp.is_empty());
            assert!(args.fp.is_empty());
        }
        other => panic!("expected Calibrate subcommand"),
    }
}

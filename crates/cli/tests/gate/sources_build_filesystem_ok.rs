//! LR1-A8 replacement gate: `sources.rs` build filesystem source for `.`.

use clap::Parser;
use keyhog::args::ScanArgs;

#[test]
fn build_sources_accepts_current_directory() {
    let args = ScanArgs::try_parse_from(["scan", "--path", "."]).unwrap();
    let sources = keyhog::sources::build_sources(&args, vec![], None);
    assert!(
        sources.is_ok(),
        "scan of '.' must build at least one source: {:?}",
        sources.err()
    );
    let built = sources.unwrap();
    assert!(
        !built.is_empty(),
        "filesystem scan must produce a non-empty source list"
    );
}

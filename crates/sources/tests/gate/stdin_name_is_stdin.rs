//! LR1-A8 replacement gate: `stdin.rs` source name.

use keyhog_core::Source;
use keyhog_sources::StdinSource;

#[test]
fn stdin_source_name_is_stdin() {
    assert_eq!(StdinSource.name(), "stdin");
}

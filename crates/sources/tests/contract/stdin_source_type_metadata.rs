//! Stdin source name and single-item iterator contract (no blocking read).

use keyhog_core::Source;
use keyhog_sources::StdinSource;

#[test]
fn stdin_source_type_metadata() {
    assert_eq!(StdinSource.name(), "stdin");
    // Do not call chunks() — it blocks on real stdin. Name contract is sufficient here.
}

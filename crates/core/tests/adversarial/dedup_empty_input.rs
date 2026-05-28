//! Empty dedup input yields empty output - no panic, no phantom groups.

use keyhog_core::{dedup_matches, DedupScope};

#[test]
fn empty_matches_slice_yields_empty_vec() {
    let out = dedup_matches(vec![], &DedupScope::Credential);
    assert_eq!(out.len(), 0, "empty input must produce zero deduped groups");
}

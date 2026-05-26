//! Path globs with oversized segments must not match (DoS guard).

use keyhog_core::Allowlist;

#[test]
fn allowlist_oversized_glob_segment_does_not_match() {
    let huge = "a".repeat(2048);
    let pattern = format!("{huge}/*.txt");
    let al = Allowlist::parse(&format!("path:{pattern}"));
    assert!(
        !al.is_path_ignored("anything.txt"),
        "oversized segment glob must not match"
    );
}

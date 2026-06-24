#[test]
fn git_commit_enumeration_is_split_from_blob_stream() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/git/source.rs"))
        .expect("git source readable");

    for required in [
        "struct GitCommitEnumerator",
        "fn next_id(&mut self, seen_commit_count: usize)",
        "collect_unreachable_objects(&self.repo_arg, remaining, self.limits)",
        "fn has_collection_capacity(&mut self, limits: crate::SourceLimits)",
        "take_unreachable_truncation_error",
        "fn take_unreachable_non_commit_objects(&mut self)",
        "super::wait_for_git_child(",
    ] {
        assert!(
            source.contains(required),
            "git commit enumeration boundary must own `{required}`"
        );
    }

    let stream_git_blobs = source
        .split("fn stream_git_blobs(")
        .nth(1)
        .and_then(|tail| tail.split("fn git_ref_exists(").next())
        .expect("stream_git_blobs body extractable");
    for forbidden in [
        "log_lines.next()",
        "collect_unreachable_objects(",
        "unreachable_loaded",
        "unreachable_commits",
        "super::wait_for_git_child(",
    ] {
        assert!(
            !stream_git_blobs.contains(forbidden),
            "stream_git_blobs must not re-own commit enumeration detail `{forbidden}`"
        );
    }
}

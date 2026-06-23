#[test]
fn git_commit_enumeration_is_split_from_blob_stream() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/git/source.rs"))
        .expect("git source readable");

    for required in [
        "struct GitCommitEnumerator",
        "fn next_id(&mut self, seen_commit_count: usize)",
        "collect_unreachable_commit_ids(&self.repo_arg, remaining)",
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
        "collect_unreachable_commit_ids(",
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

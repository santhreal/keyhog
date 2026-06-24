#[test]
fn git_blob_chunk_decoding_is_split_from_blob_stream() {
    let source = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/git/source.rs"))
        .expect("git source readable");

    for required in [
        "struct GitCommitBlobSet",
        "fn load_commit_blob_set(",
        "struct GitBlobChunkDecoder",
        "fn decode_commit_chunks(",
        "fn chunk_from_decoded_blob(",
        "pending_errors: &mut VecDeque<SourceError>",
        "record_git_blob_skip(skip, pending_errors)",
        "blob was not scanned",
    ] {
        assert!(
            source.contains(required),
            "git blob streaming boundary must own `{required}`"
        );
    }

    let stream_git_blobs = source
        .split("fn stream_git_blobs(")
        .nth(1)
        .and_then(|tail| tail.split("fn load_commit_blob_set(").next())
        .expect("stream_git_blobs body extractable");
    for forbidden in [
        "repo.find_object(",
        "try_into_commit()",
        "commit.tree()",
        "collect_tree_blobs_metadata(",
        "next_git_blob_batch(",
        "decode_git_blob_candidates_parallel(",
        "GitBlobBatchItem::",
        "GitBlobDecodeOutcome::",
        "current_tree_blobs.push_back(",
    ] {
        assert!(
            !stream_git_blobs.contains(forbidden),
            "stream_git_blobs must not re-own commit loading or blob decoding detail `{forbidden}`"
        );
    }
}

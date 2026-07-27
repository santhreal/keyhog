//! Gate decode recursion ownership: screen-failing chunks move into the queue;
//! screen-passing chunks share one `Arc<Chunk>` between queue and return vec.

#[test]
fn decode_pipeline_moves_screen_failures_without_clone() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/decode/pipeline.rs");
    let src = std::fs::read_to_string(path).expect("decode/pipeline.rs source readable");
    assert!(
        !src.contains("decoded.clone()"),
        "decoded chunks must not be cloned for BFS enqueue; use Arc sharing"
    );
    assert!(
        src.contains("let shared = Arc::new(decoded);")
            && src.contains(
                ".push_back((Arc::clone(&shared), self.depth + 1, decoded_offset));"
            )
            && src.contains("self.decoded_chunks.push(shared);")
            && src.contains(".push_back((Arc::new(decoded), self.depth + 1, decoded_offset));"),
        "screen-passing chunks share one Arc between queue and return vec; screen failures move into the queue"
    );
}

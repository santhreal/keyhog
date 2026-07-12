//! Gate decode recursion ownership: screen-failing chunks move into the queue;
//! screen-passing chunks share one `Arc<Chunk>` between queue and return vec.

#[test]
fn decode_pipeline_moves_screen_failures_without_clone() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/decode/pipeline.rs");
    let src = std::fs::read_to_string(path).expect("decode/pipeline.rs source readable");
    let body = src
        .split("let passes_screen = if let Some(screen) = screen")
        .nth(1)
        .and_then(|tail| tail.split("}\n            }\n        }").next())
        .expect("screen handling body is extractable");

    assert!(
        !body.contains("decoded.clone()"),
        "decoded chunks must not be cloned for BFS enqueue; use Arc sharing"
    );
    assert!(
        body.contains(
            "if passes_screen {\n                        let shared = Arc::new(decoded);\n                        queue.push_back((Arc::clone(&shared), depth + 1));\n                        decoded_chunks.push(shared);\n                    } else {\n                        queue.push_back((Arc::new(decoded), depth + 1));\n                    }"
        ),
        "screen-passing chunks share one Arc between queue and return vec; screen failures move into the queue"
    );
}

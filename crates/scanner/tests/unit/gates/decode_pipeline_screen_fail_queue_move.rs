//! Gate decode recursion ownership: screen-failing chunks move into the queue.

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
        !body.contains(
            "queue.push_back((decoded.clone(), depth + 1));\n                    if passes_screen"
        ),
        "screen-failing decoded chunks must not clone before discovering they are not returned"
    );
    assert!(
        body.contains("if passes_screen {\n                        queue.push_back((decoded.clone(), depth + 1));\n                        decoded_chunks.push(decoded);\n                    } else {\n                        queue.push_back((decoded, depth + 1));\n                    }"),
        "screen-passing chunks need one clone for queue+return, while screen failures move into the queue"
    );
}

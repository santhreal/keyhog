//! decode_chunk stops recursing once max_depth is reached.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;

#[test]
fn max_depth_zero_yields_no_recursive_layers() {
    let inner = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"nested",
    );
    let outer = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        inner.as_bytes(),
    );
    let chunk = Chunk { data: outer.into(), metadata: Default::default() };
    let at_zero = decode_chunk(&chunk, 0, false, None, None);
    assert!(at_zero.is_empty(), "depth 0 must not emit any decoded chunks");
}

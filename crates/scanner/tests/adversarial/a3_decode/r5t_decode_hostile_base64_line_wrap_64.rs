//! R5-T decode hostile: base64 64-col wrap bounded.

use keyhog_core::Chunk;
use keyhog_scanner::decode::decode_chunk;
use std::time::{Duration, Instant};

#[test]
fn r5t_decode_hostile_base64_line_wrap_64() {
    let chunk = Chunk {
        data: "wrap=QUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\nQUtJQVFMUE1ONUhGSVFSN1hZQQ==\\n".into(),
        metadata: Default::default(),
    };
    let start = Instant::now();
    let _ = decode_chunk(&chunk, 8, true, None, None);
    assert!(
        start.elapsed() < Duration::from_secs(3),
        "base64 64-col wrap bounded; took {:?}",
        start.elapsed()
    );
}

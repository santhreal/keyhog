//! Cross-chunk window-boundary reassembly regression test.
//!
//! Background: a single file too big for one scan window is split by
//! `FilesystemSource` into adjacent chunks. A secret that physically
//! straddles the boundary is invisible to in-chunk scanning. The
//! boundary reassembly path (`crates/scanner/src/engine/boundary.rs`)
//! splices the tail of one chunk to the head of the next and rescans
//! the seam.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

#[test]
fn test_window_boundary_detection() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");

    let detectors = keyhog_core::load_detectors(&d).unwrap();
    let scanner = CompiledScanner::compile(detectors).unwrap();

    // AWS access-key ID format: `AKIA` + 16 uppercase alphanumerics.
    // The embedded `aws-access-key.toml` detector matches this exact
    // shape; it isn't suppressed by the placeholder/EXAMPLE filter the
    // way the previous synthetic shape (`XX_FAKE_*`) was, so the test
    // actually exercises the reassembly path end-to-end instead of
    // silently masking failure.
    let secret = "AKIAQYLPMN5HFIQR7XYZ";
    assert_eq!(secret.len(), 20);

    // Split the secret across two contiguous chunks. After the split
    // neither chunk alone contains the full credential — only the
    // boundary reassembler can stitch it back together.
    let split_at = 12;

    // Chunk A: 8 MiB of newline-separated filler + first 12 chars of
    // the secret at the tail. 8 MiB is enough to exercise the
    // large-file path without dragging the test runtime past a couple
    // of seconds. The newline-separated pad keeps line accounting
    // realistic and stops any spurious upstream regex run-on into the
    // padding.
    let pad_a_len = (8 * 1024 * 1024) - split_at;
    let mut data_a = "x\n".repeat(pad_a_len / 2);
    if data_a.len() < pad_a_len {
        data_a.push('x');
    }
    data_a.push_str(&secret[..split_at]);
    let len_a = data_a.len();
    let chunk_a = Chunk {
        data: data_a.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some("big.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    };

    // Chunk B: rest of the secret followed by a non-token boundary
    // (`";\n"`) and filler text. The boundary char stops the scanner's
    // known-prefix credential extension at the end of the AKIA token,
    // mirroring how real source code looks (`AKIA…XYZ"; // comment`).
    let mut data_b = secret[split_at..].to_string();
    data_b.push_str("\";\n");
    data_b.push_str(&"x".repeat(1024));
    let chunk_b = Chunk {
        data: data_b.into(),
        metadata: ChunkMetadata {
            source_type: "test".into(),
            path: Some("big.txt".into()),
            base_offset: len_a,
            ..Default::default()
        },
    };

    let results = scanner.scan_coalesced(&[chunk_a, chunk_b]);

    let mut found = false;
    let secret_offset = pad_a_len; // file-level offset where the secret starts
    for chunk_results in &results {
        for m in chunk_results {
            if m.credential.as_ref() == secret {
                found = true;
                assert_eq!(
                    m.location.offset, secret_offset,
                    "boundary match should report the file-level offset where the secret starts"
                );
            }
        }
    }
    assert!(
        found,
        "AKIA secret straddling chunk boundary was not reassembled (per-chunk findings: {:?})",
        results.iter().map(|v| v.len()).collect::<Vec<_>>()
    );
}

//! HUNT-1 (memory amplification): a zstd frame whose decompression window
//! EXCEEDS the extraction budget must be REFUSED, not honored with a giant
//! up-front allocation. `decompress_to_bytes` caps `window_log_max` to
//! ~log2(budget) (crates/sources/src/filesystem/extract.rs), so libzstd rejects
//! an oversize-window frame instead of allocating its window.
//!
//! The two legs scan the SAME `.zst` file and differ only in `max_file_size`
//! (which sets the 4× decompression budget, and hence the window cap):
//!   * control (budget ≫ window): the frame decodes and the secret is found —
//!     proving the cap never rejects a legitimately-sized frame;
//!   * guard   (budget < window): the frame is refused and the secret is NOT
//!     found — proving the oversize window is rejected rather than allocated.
//! The secret sits on the FIRST line, so a "not found" in the guard leg can only
//! mean the frame was refused (a mere output-budget truncation would still keep
//! the head where the secret lives).

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;

/// AWS access key id, split so the literal never sits as a plaintext secret in
/// this source file.
const SECRET: &str = concat!("AKIA", "IOSFODNN7EXAMPLE");

fn write_bomb(dir: &std::path::Path) {
    // ≥ 8 MiB of decompressed content so the frame's window is the full level-19
    // window (~8 MiB, windowLog 23) rather than being reduced to a smaller
    // content size. Highly repetitive → the COMPRESSED file is only tens of KiB,
    // so it clears the per-file size gate under both budgets below.
    let mut payload = format!("aws_access_key_id = \"{SECRET}\"\n");
    payload.push_str(&"padding_line_to_grow_the_window_0123456789abcdef\n".repeat(200_000));
    assert!(
        payload.len() >= 9 * 1024 * 1024,
        "payload must exceed the window"
    );
    let compressed = zstd::stream::encode_all(payload.as_bytes(), 19).expect("zstd encode");
    assert!(
        compressed.len() < 256 * 1024,
        "repetitive payload must compress small enough to clear the file-size gate; got {} bytes",
        compressed.len()
    );
    std::fs::write(dir.join("bomb.zst"), &compressed).expect("write bomb.zst");
}

fn scan_finds_secret(root: &std::path::Path, max_file_size: u64) -> bool {
    FilesystemSource::new(root.to_path_buf())
        .with_max_file_size(max_file_size)
        .chunks()
        .flatten()
        .any(|c| c.data.contains(SECRET))
}

#[test]
fn zst_oversize_window_is_refused_under_small_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    write_bomb(dir.path());

    // Control: a 100 MiB max-file-size → 400 MiB budget → window cap ~29, far
    // above the frame's windowLog 23, so the frame decodes and the secret (on
    // the first decoded line) is recovered. This proves the window cap does NOT
    // reject a normal frame.
    assert!(
        scan_finds_secret(dir.path(), 100 * 1024 * 1024),
        "control: a frame whose window fits the budget must decode and surface \
         the secret — the window cap must not reject legitimately-sized frames"
    );

    // Guard: a 512 KiB max-file-size → 2 MiB budget → window cap ~21, BELOW the
    // frame's windowLog 23 (8 MiB window). Pre-fix, libzstd honored the 8 MiB
    // window and decoded the head (secret found after the big allocation);
    // post-fix the frame is refused, the file yields nothing, and the secret is
    // NOT found. The compressed file is tens of KiB, well under 512 KiB, so it
    // is the WINDOW that is refused here, not the file being skipped for size.
    assert!(
        !scan_finds_secret(dir.path(), 512 * 1024),
        "guard: a frame advertising a window LARGER than the extraction budget \
         must be refused (HUNT-1), not honored with a giant up-front allocation. \
         The secret was recovered, which means the oversize window was allocated."
    );
}

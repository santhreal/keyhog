#[test]
fn per_chunk_gpu_presence_reuses_and_zeroes_scratch() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/backend_triggered.rs"
    ))
    .expect("backend_triggered.rs readable");

    assert!(
        src.contains("GPU_PRESENCE_SCRATCH"),
        "per-chunk GPU trigger production must keep caller-owned scratch"
    );
    assert!(
        src.contains("scan_presence_with_scratch"),
        "per-chunk GPU trigger production must call Vyre's scratch-reuse presence API"
    );
    assert!(
        !src.contains("matcher.scan_presence(&**gpu_backend, text.as_bytes())"),
        "per-chunk GPU trigger production must not use the allocating scan_presence wrapper"
    );
    assert!(
        src.contains("zero_gpu_presence_scratch")
            && src.contains("scratch.haystack_bytes.fill(0);")
            && src.contains("scratch.hit_bytes.fill(0);"),
        "reused GPU presence scratch must be zeroed before retention"
    );
    assert!(
        src.contains("try_borrow_mut()"),
        "thread-local GPU scratch borrow failures must return a loud error, not panic"
    );
}

#[test]
fn megakernel_batch_file_id_is_plainly_unused() {
    let src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/engine/megakernel.rs"
    ))
    .expect("megakernel.rs readable");

    assert!(
        !src.contains("(i as u64) ^ (i as u64)"),
        "do not hide the constant file_id behind a self-xor expression"
    );
    assert!(
        src.contains("BatchFile::new(0, 0, bytes)")
            && src.contains("firings are mapped by file_index"),
        "the unused BatchFile file_id must be explicit and documented"
    );
}

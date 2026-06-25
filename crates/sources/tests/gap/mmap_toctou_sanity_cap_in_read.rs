//! mmap paths must re-stat after open and refuse multi-GiB TOCTOU growth.

#[test]
fn mmap_toctou_sanity_cap_in_read() {
    let mod_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/filesystem/read/mod.rs"
    ))
    .expect("read/mod.rs");
    assert!(mod_src.contains("MMAP_TOCTOU_SANITY_CAP_BYTES"));
    assert!(mod_src.contains("2 * 1024 * 1024 * 1024"));

    let raw_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/filesystem/read/raw.rs"
    ))
    .expect("read/raw.rs");
    let window_src = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/filesystem/read/window.rs"
    ))
    .expect("read/window.rs");
    assert!(raw_src.contains("MMAP_TOCTOU_SANITY_CAP_BYTES"));
    assert!(window_src.contains("MMAP_TOCTOU_SANITY_CAP_BYTES"));
    assert!(
        raw_src.contains("let meta = match file.metadata()")
            && raw_src.contains("cannot stat opened file for mmap sanity cap; skipping")
            && raw_src.contains("SourceSkipEvent::Unreadable"),
        "whole-file mmap must fail closed when the post-open stat fails; without a live stat, the hard mmap sanity cap is unproven"
    );
    assert!(
        window_src.contains("let meta = match file.metadata()")
            && window_src
                .contains("cannot stat opened large file for windowed mmap sanity cap; skipping")
            && window_src.contains("cannot stat opened large file for windowed mmap")
            && window_src.contains("SourceSkipEvent::Unreadable"),
        "windowed mmap must consume post-open stat failures as visible unreadable skips instead of falling through to an unproven fallback"
    );
}

//! Gate: canonical line offsets must be one whole-buffer newline scan.

#[test]
fn pipeline_compute_line_offsets_single_pass() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = std::fs::read_to_string(root.join("src/pipeline/context_window.rs"))
        .expect("pipeline context_window source readable");
    let body = src
        .split("pub fn compute_line_offsets")
        .nth(1)
        .expect("compute_line_offsets present")
        .split("pub(crate) fn match_line_number")
        .next()
        .expect("match_line_number follows compute_line_offsets");

    assert!(
        body.contains("for pos in memchr::memchr_iter(b'\\n', bytes)"),
        "compute_line_offsets must use one memchr_iter pass over the full byte buffer"
    );
    assert!(
        !body.contains("while let Some(pos) = memchr::memchr(b'\\n', &bytes[start..])")
            && !body.contains("start += pos + 1"),
        "compute_line_offsets must not restart memchr on a shrinking sub-slice per line"
    );
}

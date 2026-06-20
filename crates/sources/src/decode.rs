/// Decode a file's raw bytes into scannable text using the EXACT logic the
/// filesystem walker uses: UTF-8 fast path, UTF-16 BOM dispatch, lossy recovery
/// for partially-corrupt text (so a config with one stray non-UTF-8 byte still
/// yields its secrets), and binary rejection. Returns `None` when the bytes are
/// binary (genuinely no text to scan).
///
/// Exposed so non-walker entry points decode IDENTICALLY to `keyhog scan`. The
/// `keyhog watch` daemon previously used `std::fs::read_to_string`, which fails
/// on the first non-UTF-8 byte and silently dropped the whole file — a recall
/// divergence between `watch` and `scan` invisible to the operator (Law 10).
/// Routing both through this one function makes their text extraction the same.
pub fn decode_file_bytes(bytes: &[u8]) -> Option<String> {
    crate::filesystem::decode_text_file(bytes)
}

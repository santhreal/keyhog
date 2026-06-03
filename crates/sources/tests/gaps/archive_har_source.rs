//! Gap-closure integration tests for the archive + HAR expansion paths
//! of `keyhog-sources`.
//!
//! Two code surfaces are exercised, every expected value derived by
//! reading the real implementation:
//!
//!   * `crate::har::try_expand_har` (re-readable; the only public HAR
//!     entry point) — `crates/sources/src/har.rs`. This is a pure
//!     `(&[u8], &str, u64) -> Option<Vec<Result<Chunk, _>>>` function,
//!     so its behavior is asserted directly with byte-exact expectations:
//!       - sniff: `trim_bom_and_whitespace` then `starts_with(b"{")` AND
//!         `contains_har_marker` (both `"log"` and `"entries"` in the
//!         first 2048 bytes) before serde even runs (har.rs:55-61,145-152).
//!       - malformed-but-marked JSON -> `None` (fall through to text scan)
//!         (har.rs:63-73).
//!       - one `wire:har:request` + one `wire:har:response` chunk per
//!         entry, path `"{path_str}#{url}"` (har.rs:79-125).
//!       - `render_request`: `"METHOD URL\n"`, then `"name: value\n"`
//!         headers, optional `"# query\n"` block, optional `"\n"+postData`
//!         (har.rs:154-182).
//!       - `render_response`: `"status[ status_text]\n"`, headers, optional
//!         `"\n"+decoded body` (har.rs:184-205).
//!       - `decoded_content_text`: base64 decode iff `encoding=="base64"`,
//!         malformed base64 falls back to raw text (har.rs:212-223).
//!       - 4x `max_size` cumulative request+response byte budget, the break
//!         firing BEFORE the over-budget chunk is pushed (har.rs:77-124).
//!
//!   * The archive / compressed branch of `extract::process_entry`
//!     (`crates/sources/src/filesystem/extract.rs:119-217`), reachable
//!     only through the public `FilesystemSource::chunks()` walk. Derived
//!     gate facts:
//!       - extensions `zip|apk|ipa|crx|jar` -> openpack unpack; symlink at
//!         the archive path is refused (extract.rs:119-127).
//!       - per archive entry: skip `is_dir || is_default_excluded(name)`;
//!         skip when `uncompressed_size > max_size` (STRICTLY greater);
//!         else add to `total_uncompressed`, break when
//!         `> max_size*4` (zip-bomb guard) (extract.rs:133-154).
//!       - UTF-8 entry -> `filesystem/archive`, path `"{archive}//{name}"`;
//!         non-UTF-8 entry -> printable-strings (>=8) tagged
//!         `filesystem/archive-binary` (extract.rs:155-189).
//!       - `gz|zst|lz4|sz` -> `extract_compressed_chunks`, source_type
//!         `filesystem/compressed`, 4x decompressed budget guard
//!         (extract.rs:194-196,342-410).
//!       - `tar` is unpacked per-entry (mirroring the zip branch): each entry
//!         becomes a `filesystem/archive` chunk with path `"{archive}//{name}"`
//!         (AUD-capability-1). It is no longer skipped by extension.

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs::File;
use std::io::Write;
use std::path::Path;
use zip::write::SimpleFileOptions;
use zip::ChunkMethodShim as _; // no-op alias guard; replaced below

// ───────────────────────────── helpers ─────────────────────────────

/// All successfully-emitted chunks from a default whole-tree walk of `dir`.
fn walk_chunks(dir: &Path) -> Vec<keyhog_core::Chunk> {
    FilesystemSource::new(dir.to_path_buf())
        .chunks()
        .flatten()
        .collect()
}

/// All chunks from a walk with an explicit per-file size cap.
fn walk_chunks_capped(dir: &Path, max_size: u64) -> Vec<keyhog_core::Chunk> {
    FilesystemSource::new(dir.to_path_buf())
        .with_max_file_size(max_size)
        .chunks()
        .flatten()
        .collect()
}

/// Concatenate every chunk body (the walk is parallel/unordered).
fn bodies(chunks: &[keyhog_core::Chunk]) -> String {
    chunks.iter().map(|c| c.data.to_string()).collect()
}

/// Write a single-entry STORED zip (no compression) so uncompressed_size
/// equals the bytes we wrote and the openpack compression-ratio guard
/// never fires on the fixture.
fn write_stored_zip(path: &Path, entry_name: &str, content: &[u8]) {
    let f = File::create(path).unwrap();
    let mut zip = zip::ZipWriter::new(f);
    let opts = SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file(entry_name, opts).unwrap();
    zip.write_all(content).unwrap();
    zip.finish().unwrap();
}

/// Build a one-entry HAR with a fully-specified request + response.
/// `query` and `post` are inlined verbatim when `Some`.
fn one_entry_har(
    method: &str,
    url: &str,
    req_headers: &[(&str, &str)],
    query: &[(&str, &str)],
    post_text: Option<&str>,
    status: i64,
    status_text: Option<&str>,
    resp_headers: &[(&str, &str)],
    resp_body: Option<(Option<&str>, &str)>, // (encoding, text)
) -> String {
    let render_kv = |kvs: &[(&str, &str)]| -> String {
        kvs.iter()
            .map(|(n, v)| format!(r#"{{"name":"{n}","value":"{v}"}}"#))
            .collect::<Vec<_>>()
            .join(",")
    };
    let post_field = match post_text {
        Some(t) => format!(r#","postData":{{"mimeType":"text/plain","text":"{t}"}}"#),
        None => String::new(),
    };
    let status_text_field = match status_text {
        Some(s) => format!(r#","statusText":"{s}""#),
        None => String::new(),
    };
    let content_field = match resp_body {
        Some((enc, text)) => {
            let enc_field = match enc {
                Some(e) => format!(r#""encoding":"{e}","#),
                None => String::new(),
            };
            format!(
                r#","content":{{"size":1,"mimeType":"application/json",{enc_field}"text":"{text}"}}"#
            )
        }
        None => String::new(),
    };
    format!(
        r#"{{"log":{{"version":"1.2","creator":{{"name":"t","version":"1"}},"entries":[
        {{"request":{{"method":"{method}","url":"{url}","headers":[{rh}],"queryString":[{q}]{post_field}}},
        "response":{{"status":{status}{status_text_field},"headers":[{rsh}]{content_field}}}}}]}}}}"#,
        rh = render_kv(req_headers),
        q = render_kv(query),
        rsh = render_kv(resp_headers),
    )
}

/// Run `try_expand_har` and unwrap each `Result<Chunk,_>`.
fn expand(har: &str, path: &str, max: u64) -> Vec<keyhog_core::Chunk> {
    keyhog_sources::testing_har_try_expand(har.as_bytes(), path, max)
        .expect("fixture should parse")
        .into_iter()
        .map(|c| c.unwrap())
        .collect()
}

fn request_chunk(chunks: &[keyhog_core::Chunk]) -> &keyhog_core::Chunk {
    chunks
        .iter()
        .find(|c| c.metadata.source_type == "wire:har:request")
        .expect("a request chunk")
}

fn response_chunk(chunks: &[keyhog_core::Chunk]) -> &keyhog_core::Chunk {
    chunks
        .iter()
        .find(|c| c.metadata.source_type == "wire:har:response")
        .expect("a response chunk")
}

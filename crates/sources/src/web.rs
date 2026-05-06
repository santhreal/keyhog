//! Web content source: scan JavaScript, source maps, and WASM binaries at URLs.
//!
//! Fetches web content over HTTP(S) and produces [`Chunk`]s for the scanner.
//! Handles three content types:
//!
//! - **JavaScript**: fetched as text, scanned directly for hardcoded secrets.
//! - **Source maps**: fetched as JSON, each `sourcesContent` entry becomes a
//!   separate chunk tagged with its original filename.
//! - **WASM binaries**: fetched as bytes, printable ASCII strings ≥ 8 chars are
//!   extracted (identical to `strings` CLI) and scanned as text.
//!
//! # Examples
//!
//! ```rust,no_run
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! use keyhog_sources::WebSource;
//! use keyhog_core::Source;
//!
//! let source = WebSource::new(vec![
//!     "https://example.com/app.js".to_string(),
//!     "https://example.com/app.js.map".to_string(),
//!     "https://example.com/module.wasm".to_string(),
//! ]);
//!
//! for chunk in source.chunks() {
//!     let chunk = chunk?;
//!     println!("{}: {} bytes", chunk.metadata.source_type, chunk.data.len());
//! }
//! # Ok(()) }
//! ```

use keyhog_core::{Chunk, ChunkMetadata, Source, SourceError};

/// Minimum printable string length for WASM binary string extraction.
const MIN_WASM_STRING_LEN: usize = 8;

/// Maximum response body size to prevent OOM on malicious targets (10 MB).
const MAX_RESPONSE_BYTES: usize = 10 * 1024 * 1024;

/// WASM magic bytes: `\0asm`.
const WASM_MAGIC: &[u8; 4] = b"\x00asm";

/// Web content source that fetches JavaScript, source maps, and WASM from URLs.
///
/// URLs ending in `.wasm` are treated as binary and have strings extracted.
/// URLs ending in `.map` are treated as source maps and have `sourcesContent`
/// entries split into individual chunks. Everything else is treated as
/// JavaScript text.
pub struct WebSource {
    urls: Vec<String>,
}

impl WebSource {
    /// Create a web source from a list of URLs to scan.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_sources::WebSource;
    /// use keyhog_core::Source;
    ///
    /// let source = WebSource::new(vec!["https://example.com/app.js".into()]);
    /// assert_eq!(source.name(), "web");
    /// ```
    pub fn new(urls: Vec<String>) -> Self {
        Self { urls }
    }

    /// Create a web source from a single URL.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use keyhog_sources::WebSource;
    /// use keyhog_core::Source;
    ///
    /// let source = WebSource::from_url("https://example.com/app.js");
    /// assert_eq!(source.name(), "web");
    /// ```
    pub fn from_url(url: &str) -> Self {
        Self {
            urls: vec![url.to_string()],
        }
    }

    /// Fetch all URLs and produce chunks.
    ///
    /// Uses `reqwest::blocking` directly; the blocking client internally manages
    /// its own background runtime, so no dedicated thread wrapper is required.
    fn fetch_all(&self) -> Vec<Result<Chunk, SourceError>> {
        // Auto-decompression DISABLED — without this, reqwest expands gzip
        // bodies to completion before we can check size, opening a gzip-bomb
        // DoS. Decompression is opt-in per call where we explicitly want it.
        let client = reqwest::blocking::Client::builder()
            .timeout(crate::timeouts::HTTP_REQUEST)
            .danger_accept_invalid_certs(false)
            .redirect(reqwest::redirect::Policy::limited(5))
            .user_agent("keyhog-web/0.1")
            .no_gzip()
            .no_brotli()
            .no_deflate()
            .build()
            .map_err(|e| SourceError::Other(format!("failed to build HTTP client: {e}")));

        let client = match client {
            Ok(c) => c,
            Err(e) => return vec![Err(e)],
        };

        let mut results = Vec::new();

        for url in &self.urls {
            let chunks = fetch_url(&client, url);
            results.extend(chunks);
        }

        results
    }
}

impl Source for WebSource {
    fn name(&self) -> &str {
        "web"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        Box::new(self.fetch_all().into_iter())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Fetch a single URL and produce one or more chunks based on content type.
fn fetch_url(client: &reqwest::blocking::Client, url: &str) -> Vec<Result<Chunk, SourceError>> {
    let resp = match client.get(url).send() {
        Ok(r) => r,
        Err(e) => {
            return vec![Err(SourceError::Other(format!(
                "failed to fetch {url}: {e}"
            )))];
        }
    };

    let status = resp.status().as_u16();
    if status != 200 {
        tracing::warn!(url, status, "non-200 response, skipping");
        return Vec::new();
    }

    // Route by URL extension
    let lower = url.to_lowercase();
    if lower.ends_with(".wasm") {
        handle_wasm(resp, url)
    } else if lower.ends_with(".map") || lower.contains(".map?") {
        handle_sourcemap(resp, url)
    } else {
        handle_js(resp, url)
    }
}

/// Handle a JavaScript file: return the full text as a single chunk.
fn handle_js(resp: reqwest::blocking::Response, url: &str) -> Vec<Result<Chunk, SourceError>> {
    match read_text_response(resp) {
        Ok(body) => vec![Ok(Chunk {
            data: body.into(),
            metadata: ChunkMetadata {
                    base_offset: 0,
                source_type: "web:js".to_string(),
                path: Some(url.to_string()),
                commit: None,
                author: None,
                date: None,
            },
        })],
        Err(e) => vec![Err(e)],
    }
}

/// Handle a source map: parse JSON and emit each `sourcesContent` entry
/// as a separate chunk tagged with the original filename.
fn handle_sourcemap(
    resp: reqwest::blocking::Response,
    url: &str,
) -> Vec<Result<Chunk, SourceError>> {
    let body = match read_text_response(resp) {
        Ok(b) => b,
        Err(e) => return vec![Err(e)],
    };

    let map: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(url, err = %e, "failed to parse source map JSON");
            // Fall back to treating it as plain JS text
            return vec![Ok(Chunk {
                data: body.into(),
                metadata: ChunkMetadata {
                    base_offset: 0,
                    source_type: "web:sourcemap:raw".to_string(),
                    path: Some(url.to_string()),
                    commit: None,
                    author: None,
                    date: None,
                },
            })];
        }
    };

    let sources: Vec<String> = map["sources"]
        .as_array()
        .unwrap_or(&vec![])
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let contents: Vec<Option<String>> = map["sourcesContent"]
        .as_array()
        .map(|arr| arr.iter().map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default();

    let mut chunks = Vec::new();

    for (i, content) in contents.iter().enumerate() {
        if let Some(code) = content {
            if code.is_empty() {
                continue;
            }
            let source_name = sources
                .get(i)
                .cloned()
                .unwrap_or_else(|| format!("source_{i}"));
            chunks.push(Ok(Chunk {
                data: code.clone().into(),
                metadata: ChunkMetadata {
                    base_offset: 0,
                    source_type: "web:sourcemap".to_string(),
                    path: Some(format!("{url}!{source_name}")),
                    commit: None,
                    author: None,
                    date: None,
                },
            }));
        }
    }

    // If no sourcesContent, treat the raw map as scannable text
    if chunks.is_empty() {
        chunks.push(Ok(Chunk {
            data: body.into(),
            metadata: ChunkMetadata {
                    base_offset: 0,
                source_type: "web:sourcemap:raw".to_string(),
                path: Some(url.to_string()),
                commit: None,
                author: None,
                date: None,
            },
        }));
    }

    chunks
}

/// Handle a WASM binary: extract printable strings and scan as text.
fn handle_wasm(resp: reqwest::blocking::Response, url: &str) -> Vec<Result<Chunk, SourceError>> {
    let bytes = match read_bytes_response(resp) {
        Ok(b) => b,
        Err(e) => return vec![Err(e)],
    };

    // Verify WASM magic bytes
    if bytes.len() < 4 || &bytes[..4] != WASM_MAGIC {
        tracing::warn!(url, "not a valid WASM file (wrong magic bytes)");
        return Vec::new();
    }

    let strings = crate::strings::extract_printable_strings(&bytes, MIN_WASM_STRING_LEN);
    if strings.is_empty() {
        return Vec::new();
    }

    vec![Ok(Chunk {
        data: keyhog_core::SensitiveString::join(&strings, "\n").into(),
        metadata: ChunkMetadata {
                    base_offset: 0,
            source_type: "web:wasm".to_string(),
            path: Some(url.to_string()),
            commit: None,
            author: None,
            date: None,
        },
    })]
}

/// Read an HTTP response body as text, capping at `MAX_RESPONSE_BYTES`.
///
/// Pre-flight Content-Length and streamed cap-aware copy. The previous
/// version called `.text()` (which auto-decompresses gzip/deflate to
/// completion) before checking the size — a 1 MB gzip bomb expanding to
/// 1+ GB would OOM before this check fired. See `audit release-2026-04-26
/// web.rs:287-301`.
fn read_text_response(resp: reqwest::blocking::Response) -> Result<String, SourceError> {
    let bytes = read_bytes_response(resp)?;
    String::from_utf8(bytes).map_err(|e| SourceError::Other(format!("non-UTF-8 response: {e}")))
}

/// Read an HTTP response body as bytes, capping at `MAX_RESPONSE_BYTES`
/// BEFORE decompression to defeat gzip-bomb DoS.
fn read_bytes_response(resp: reqwest::blocking::Response) -> Result<Vec<u8>, SourceError> {
    use std::io::Read;
    let url = resp.url().to_string();

    if let Some(len) = resp.content_length() {
        if len as usize > MAX_RESPONSE_BYTES {
            return Err(SourceError::Other(format!(
                "response from {url} declares {len} bytes (> {} MB limit)",
                MAX_RESPONSE_BYTES / (1024 * 1024)
            )));
        }
    }

    // Stream into a bounded buffer; abort the moment we exceed the cap.
    let mut buf = Vec::with_capacity(MAX_RESPONSE_BYTES.min(64 * 1024));
    let mut taken = resp.take(MAX_RESPONSE_BYTES as u64 + 1);
    taken
        .read_to_end(&mut buf)
        .map_err(|e| SourceError::Other(format!("failed to read bytes from {url}: {e}")))?;
    if buf.len() > MAX_RESPONSE_BYTES {
        return Err(SourceError::Other(format!(
            "response from {url} exceeds {} MB limit",
            MAX_RESPONSE_BYTES / (1024 * 1024)
        )));
    }

    Ok(buf)
}

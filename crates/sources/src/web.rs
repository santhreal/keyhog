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

mod ssrf;
pub(crate) use ssrf::{
    build_web_client, is_autoroute_loopback_calibration_url, is_disallowed_ip,
    is_disallowed_web_host, redact_url, resolve_and_screen,
};

/// Minimum printable string length for WASM binary string extraction.
const MIN_WASM_STRING_LEN: usize = 8;

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
    http: crate::http::HttpClientConfig,
    limits: crate::SourceLimits,
    allow_autoroute_loopback_calibration: bool,
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
        Self {
            urls,
            http: crate::http::HttpClientConfig {
                ua_suffix: Some("web".into()),
                ..Default::default()
            },
            limits: crate::SourceLimits::default(),
            allow_autoroute_loopback_calibration: false,
        }
    }

    /// Override the default HTTP policy (proxy, insecure-TLS,
    /// timeout). Construct from `HttpClientConfig` directly when the
    /// caller already has CLI-derived flags to thread through.
    pub(crate) fn with_http_config(mut self, http: crate::http::HttpClientConfig) -> Self {
        // Preserve the per-source UA suffix so the operator's proxy
        // logs still tag this traffic as `keyhog/<ver> (web)`.
        let mut http = http;
        if http.ua_suffix.is_none() {
            http.ua_suffix = Some("web".into());
        }
        self.http = http;
        self
    }

    pub(crate) fn with_limits(mut self, limits: crate::SourceLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Allow the installer/maintenance autoroute calibration scan to fetch its
    /// numeric loopback HTTP fixture. Normal WebSource scans must leave this
    /// false so SSRF loopback blocks remain fail-closed.
    pub(crate) fn with_autoroute_loopback_calibration(mut self, allow: bool) -> Self {
        self.allow_autoroute_loopback_calibration = allow;
        self
    }

    /// Fetch all URLs and produce chunks.
    ///
    /// Uses `reqwest::blocking` directly; the blocking client internally manages
    /// its own background runtime, so no dedicated thread wrapper is required.
    ///
    /// Each URL gets its own client built via [`build_web_client`] so the
    /// host can be DNS-resolved and pinned (DNS-rebinding defense); the
    /// custom redirect policy re-validates every hop (redirect-to-internal
    /// defense). Both gates mirror the verifier's `resolved_client_for_url`.
    fn fetch_all(&self) -> Vec<Result<Chunk, SourceError>> {
        let proxy_in_use = matches!(
            self.http.effective_proxy().as_deref(),
            Some(p) if !matches!(p, "off" | "none" | "")
        );

        let mut results = Vec::new();

        for url in &self.urls {
            let allow_calibration_url = self.allow_autoroute_loopback_calibration
                && is_autoroute_loopback_calibration_url(url);
            // SSRF defense (host pre-filter): the verifier already has this
            // gate via bogon for live verifications; WebSource was the
            // missing surface. Without it,
            // `WebSource::new(vec!["http://169.254.169.254/latest/meta-data/iam/..."])`
            // would fetch the cloud metadata endpoint and extract IAM creds.
            if is_disallowed_web_host(url) && !allow_calibration_url {
                let safe_url = redact_url(url);
                results.push(Err(SourceError::Other(format!(
                    "refusing to fetch {safe_url}: host resolves to a private / \
                     loopback / link-local / metadata-service address - \
                     WebSource only fetches public URLs"
                ))));
                continue;
            }

            let client =
                match build_web_client(&self.http, url, proxy_in_use, allow_calibration_url) {
                    Ok(c) => c,
                    Err(e) => {
                        results.push(Err(e));
                        continue;
                    }
                };

            let chunks = fetch_url(
                &client,
                url,
                self.limits.web_response_bytes,
                allow_calibration_url,
            );
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
        // `reqwest::blocking` must run off the CLI's `#[tokio::main]` thread:
        // dropping its internal runtime inside an async context aborts the
        // process. `fetch_all` is eager, so run it on a scoped std thread that
        // carries no ambient tokio runtime.
        let all = std::thread::scope(|s| match s.spawn(|| self.fetch_all()).join() {
            Ok(result) => result,
            Err(_panic) => vec![Err(SourceError::Other(
                "web fetch thread panicked".to_string(),
            ))],
        });
        Box::new(all.into_iter())
    }
    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Fetch a single URL and produce one or more chunks based on content type.
///
/// The caller (`fetch_all`) has already screened `url` with
/// `is_disallowed_web_host` and built `client` through `build_web_client`,
/// which pins the resolved (screened) IP and installs the per-hop
/// SSRF-revalidating redirect policy. The pre-filter is repeated here as a
/// cheap defense-in-depth guard so this helper stays safe even if a future
/// caller hands it a client that skipped `build_web_client`.
fn fetch_url(
    client: &reqwest::blocking::Client,
    url: &str,
    max_response_bytes: usize,
    allow_autoroute_loopback_calibration_url: bool,
) -> Vec<Result<Chunk, SourceError>> {
    // SSRF defense (host pre-filter): the verifier already has this gate via
    // bogon for live verifications; WebSource was the missing surface.
    // Without it,
    // `WebSource::new(vec!["http://169.254.169.254/latest/meta-data/iam/..."])`
    // would fetch the cloud metadata endpoint and extract IAM credentials.
    // The redirect-target and DNS-rebinding bypasses of this gate are closed
    // in `build_web_client`. Kimi sources-audit web-source SSRF finding.
    if is_disallowed_web_host(url) && !allow_autoroute_loopback_calibration_url {
        let safe_url = redact_url(url);
        return vec![Err(SourceError::Other(format!(
            "refusing to fetch {safe_url}: host resolves to a private / \
             loopback / link-local / metadata-service address - \
             WebSource only fetches public URLs"
        )))];
    }

    let resp = match client.get(url).send() {
        Ok(r) => r,
        Err(e) => {
            let safe_url = redact_url(url);
            return vec![Err(SourceError::Other(format!(
                "failed to fetch {safe_url}: {e}"
            )))];
        }
    };

    let status = resp.status().as_u16();
    if status != 200 {
        let safe_url = redact_url(url);
        tracing::warn!(url = %safe_url, status, "non-200 response; URL body was NOT scanned");
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        return vec![Err(SourceError::Other(format!(
            "failed to fetch {safe_url}: HTTP status {status}; response body was not scanned"
        )))];
    }

    // Route by URL extension
    let lower = url.to_lowercase();
    if lower.ends_with(".wasm") {
        handle_wasm(resp, url, max_response_bytes)
    } else if lower.ends_with(".map") || lower.contains(".map?") {
        handle_sourcemap(resp, url, max_response_bytes)
    } else {
        handle_js(resp, url, max_response_bytes)
    }
}

/// Handle a JavaScript file: return the full text as a single chunk.
fn handle_js(
    resp: reqwest::blocking::Response,
    url: &str,
    max_response_bytes: usize,
) -> Vec<Result<Chunk, SourceError>> {
    match read_text_response(resp, max_response_bytes) {
        Ok(body) => vec![Ok(Chunk {
            data: body.into(),
            metadata: ChunkMetadata {
                base_offset: 0,
                base_line: 0,
                source_type: "web:js".to_string(),
                path: Some(url.to_string()),
                commit: None,
                author: None,
                date: None,
                mtime_ns: None,
                size_bytes: None,
                decoded_span: None,
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
    max_response_bytes: usize,
) -> Vec<Result<Chunk, SourceError>> {
    let body = match read_text_response(resp, max_response_bytes) {
        Ok(b) => b,
        Err(e) => return vec![Err(e)],
    };

    let map: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(url = %redact_url(url), err = %e, "failed to parse source map JSON");
            // Fall back to treating it as plain JS text
            return vec![Ok(Chunk {
                data: body.into(),
                metadata: ChunkMetadata {
                    base_offset: 0,
                    base_line: 0,
                    source_type: "web:sourcemap:raw".to_string(),
                    path: Some(url.to_string()),
                    commit: None,
                    author: None,
                    date: None,
                    mtime_ns: None,
                    size_bytes: None,
                    decoded_span: None,
                },
            })];
        }
    };

    let sources: Vec<String> = map["sources"]
        .as_array()
        .unwrap_or(&vec![]) // LAW10: a sourcemap with no `sources` array yields empty NAMES; the loop below still scans every `sourcesContent` entry (named `source_{i}`), so no code is dropped
        .iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect();

    let contents: Vec<Option<String>> = map["sourcesContent"]
        .as_array()
        .map(|arr| arr.iter().map(|v| v.as_str().map(String::from)).collect())
        .unwrap_or_default(); // LAW10: missing/non-string field => empty/placeholder; recall-safe

    let mut chunks = Vec::new();

    for (i, content) in contents.iter().enumerate() {
        if let Some(code) = content {
            if code.is_empty() {
                continue;
            }
            let source_name = sources
                .get(i)
                .cloned()
                .unwrap_or_else(|| format!("source_{i}")); // LAW10: synthetic label for an unnamed sourcemap entry; the content is still scanned
            chunks.push(Ok(Chunk {
                data: code.clone().into(),
                metadata: ChunkMetadata {
                    base_offset: 0,
                    base_line: 0,
                    source_type: "web:sourcemap".to_string(),
                    path: Some(format!("{url}!{source_name}")),
                    commit: None,
                    author: None,
                    date: None,
                    mtime_ns: None,
                    size_bytes: None,
                    decoded_span: None,
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
                base_line: 0,
                source_type: "web:sourcemap:raw".to_string(),
                path: Some(url.to_string()),
                commit: None,
                author: None,
                date: None,
                mtime_ns: None,
                size_bytes: None,
                decoded_span: None,
            },
        }));
    }

    chunks
}

/// Handle a WASM binary: extract printable strings and scan as text.
fn handle_wasm(
    resp: reqwest::blocking::Response,
    url: &str,
    max_response_bytes: usize,
) -> Vec<Result<Chunk, SourceError>> {
    let bytes = match read_bytes_response(resp, max_response_bytes) {
        Ok(b) => b,
        Err(e) => return vec![Err(e)],
    };

    // Verify WASM magic bytes
    if bytes.len() < 4 || &bytes[..4] != WASM_MAGIC {
        let safe_url = redact_url(url);
        tracing::warn!(url = %safe_url, "not a valid WASM file; body was NOT scanned as WebAssembly strings");
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        return vec![Err(SourceError::Other(format!(
            "failed to scan {safe_url}: URL ended with .wasm but response did not start with WASM magic bytes"
        )))];
    }

    let strings = crate::strings::extract_printable_strings(&bytes, MIN_WASM_STRING_LEN);
    if strings.is_empty() {
        return Vec::new();
    }

    vec![Ok(Chunk {
        data: keyhog_core::SensitiveString::join(&strings, "\n"),
        metadata: ChunkMetadata {
            base_offset: 0,
            base_line: 0,
            source_type: "web:wasm".to_string(),
            path: Some(url.to_string()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
            decoded_span: None,
        },
    })]
}

/// Read an HTTP response body as text, capping at the resolved source limit.
///
/// Pre-flight Content-Length and streamed cap-aware copy. The previous
/// version called `.text()` (which auto-decompresses gzip/deflate to
/// completion) before checking the size - a 1 MB gzip bomb expanding to
/// 1+ GB would OOM before this check fired. See `audit release-2026-04-26
/// web.rs:287-301`.
fn read_text_response(
    resp: reqwest::blocking::Response,
    max_response_bytes: usize,
) -> Result<String, SourceError> {
    let bytes = read_bytes_response(resp, max_response_bytes)?;
    String::from_utf8(bytes).map_err(|e| {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        SourceError::Other(format!("non-UTF-8 response: {e}"))
    })
}

/// Read an HTTP response body as bytes, capping at the resolved source limit
/// BEFORE decompression to defeat gzip-bomb DoS.
fn read_bytes_response(
    resp: reqwest::blocking::Response,
    max_response_bytes: usize,
) -> Result<Vec<u8>, SourceError> {
    use std::io::Read;
    let url = resp.url().to_string();
    let safe_url = redact_url(&url);

    if let Some(len) = resp.content_length() {
        if len as usize > max_response_bytes {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
            return Err(SourceError::Other(format!(
                "response from {safe_url} declares {len} bytes (> {max_response_bytes} byte limit)"
            )));
        }
    }

    // Stream into a bounded buffer; abort the moment we exceed the cap.
    let mut buf = Vec::with_capacity(max_response_bytes.min(64 * 1024));
    let mut taken = resp.take(max_response_bytes as u64 + 1);
    taken.read_to_end(&mut buf).map_err(|e| {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        SourceError::Other(format!("failed to read bytes from {safe_url}: {e}"))
    })?;
    if buf.len() > max_response_bytes {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        return Err(SourceError::Other(format!(
            "response from {safe_url} exceeds {max_response_bytes} byte limit"
        )));
    }

    Ok(buf)
}

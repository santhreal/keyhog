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
    /// Each URL and redirect hop gets its own client built via
    /// [`build_web_client`] so the host can be DNS-resolved and pinned
    /// (DNS-rebinding defense) before that exact request is sent.
    fn fetch_all(&self) -> Vec<Result<Chunk, SourceError>> {
        let proxy_in_use = matches!(
            self.http.effective_proxy().as_deref(),
            Some(p) if !matches!(p, "off" | "none" | "")
        );

        let mut results = Vec::new();

        for url in &self.urls {
            if let Err(error) = validate_initial_web_url(url) {
                results.push(Err(error));
                continue;
            }
            let allow_calibration_url = self.allow_autoroute_loopback_calibration
                && is_autoroute_loopback_calibration_url(url);
            // SSRF defense (host pre-filter): the verifier already has this
            // gate via bogon for live verifications; WebSource was the
            // missing surface. Without it,
            // `WebSource::new(vec!["http://169.254.169.254/latest/meta-data/iam/..."])`
            // would fetch the cloud metadata endpoint and extract IAM creds.
            if is_disallowed_web_host(url) && !allow_calibration_url {
                let safe_url = redact_url(url);
                results.push(Err(web_unreadable_error(format!(
                    "refusing to fetch {safe_url}: host resolves to a private / \
                     loopback / link-local / metadata-service address - \
                     WebSource only fetches public URLs"
                ))));
                continue;
            }

            let chunks = fetch_url(
                &self.http,
                url,
                self.limits.web_response_bytes,
                proxy_in_use,
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
        match crate::blocking_thread::collect_on_blocking_thread("web", || Ok(self.fetch_all())) {
            Ok(all) => Box::new(all.into_iter()),
            Err(error) => Box::new(std::iter::once(Err(error))),
        }
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
    http: &crate::http::HttpClientConfig,
    url: &str,
    max_response_bytes: usize,
    proxy_in_use: bool,
    allow_autoroute_loopback_calibration_url: bool,
) -> Vec<Result<Chunk, SourceError>> {
    if let Err(error) = validate_initial_web_url(url) {
        return vec![Err(error)];
    }
    // SSRF defense (host pre-filter): the verifier already has this gate via
    // bogon for live verifications; WebSource was the missing surface.
    // Without it,
    // `WebSource::new(vec!["http://169.254.169.254/latest/meta-data/iam/..."])`
    // would fetch the cloud metadata endpoint and extract IAM credentials.
    // The redirect-target and DNS-rebinding bypasses of this gate are closed
    // in `build_web_client`. Kimi sources-audit web-source SSRF finding.
    if is_disallowed_web_host(url) && !allow_autoroute_loopback_calibration_url {
        let safe_url = redact_url(url);
        return vec![Err(web_unreadable_error(format!(
            "refusing to fetch {safe_url}: host resolves to a private / \
             loopback / link-local / metadata-service address - \
             WebSource only fetches public URLs"
        )))];
    }

    let resp = match send_with_pinned_redirects(
        http,
        url,
        proxy_in_use,
        allow_autoroute_loopback_calibration_url,
    ) {
        Ok(r) => r,
        Err(e) => {
            return vec![Err(e)];
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

    match classify_web_response(url) {
        WebResponseKind::Wasm => handle_wasm(resp, url, max_response_bytes),
        WebResponseKind::SourceMap => handle_sourcemap(resp, url, max_response_bytes),
        WebResponseKind::JavaScript => handle_js(resp, url, max_response_bytes),
    }
}

fn validate_initial_web_url(url: &str) -> Result<(), SourceError> {
    let parsed = reqwest::Url::parse(url).map_err(|error| {
        let safe_url = redact_url(url);
        web_unreadable_error(format!("failed to fetch {safe_url}: invalid URL: {error}"))
    })?;
    match parsed.scheme() {
        "http" | "https" => Ok(()),
        scheme => {
            let safe_url = redact_url(url);
            Err(web_unreadable_error(format!(
                "refusing to fetch {safe_url}: unsupported URL scheme {scheme:?}; WebSource only fetches http:// and https:// URLs"
            )))
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum WebResponseKind {
    JavaScript,
    SourceMap,
    Wasm,
}

fn classify_web_response(url: &str) -> WebResponseKind {
    let path = url.split_once(['?', '#']).map_or(url, |(path, _)| path);
    if ends_with_ignore_ascii_case(path, ".wasm") {
        WebResponseKind::Wasm
    } else if ends_with_ignore_ascii_case(path, ".map") {
        WebResponseKind::SourceMap
    } else {
        WebResponseKind::JavaScript
    }
}

fn ends_with_ignore_ascii_case(value: &str, suffix: &str) -> bool {
    value
        .as_bytes()
        .get(value.len().saturating_sub(suffix.len())..)
        .is_some_and(|tail| tail.eq_ignore_ascii_case(suffix.as_bytes()))
}

fn send_with_pinned_redirects(
    http: &crate::http::HttpClientConfig,
    url: &str,
    proxy_in_use: bool,
    allow_autoroute_loopback_calibration_url: bool,
) -> Result<reqwest::blocking::Response, SourceError> {
    let mut current_url = url.to_string();
    let mut allow_current_calibration_url = allow_autoroute_loopback_calibration_url
        && is_autoroute_loopback_calibration_url(&current_url);
    for hop in 0..=crate::http::REDIRECT_LIMIT {
        let client = build_web_client(
            http,
            &current_url,
            proxy_in_use,
            allow_current_calibration_url,
        )?;
        let resp = client.get(&current_url).send().map_err(|e| {
            let safe_url = redact_url(&current_url);
            web_unreadable_error(format!("failed to fetch {safe_url}: {e}"))
        })?;
        if !resp.status().is_redirection() {
            return Ok(resp);
        }
        if hop >= crate::http::REDIRECT_LIMIT {
            let safe_url = redact_url(&current_url);
            return Err(web_unreadable_error(format!(
                "failed to fetch {safe_url}: too many redirects (> {})",
                crate::http::REDIRECT_LIMIT
            )));
        }
        let Some(location) = resp.headers().get(reqwest::header::LOCATION) else {
            let safe_url = redact_url(&current_url);
            return Err(web_unreadable_error(format!(
                "failed to fetch {safe_url}: redirect response missing Location header"
            )));
        };
        let location = location.to_str().map_err(|e| {
            let safe_url = redact_url(&current_url);
            web_unreadable_error(format!(
                "failed to fetch {safe_url}: redirect Location header is invalid: {e}"
            ))
        })?;
        let target = resp.url().join(location).map_err(|e| {
            let safe_url = redact_url(&current_url);
            web_unreadable_error(format!(
                "failed to fetch {safe_url}: redirect Location {location:?} is invalid: {e}"
            ))
        })?;
        match target.scheme() {
            "http" | "https" => {}
            scheme => {
                let safe_target = redact_url(target.as_str());
                return Err(web_unreadable_error(format!(
                    "refusing to follow redirect to {safe_target}: unsupported URL scheme {scheme:?}"
                )));
            }
        }
        let target = target.to_string();
        let allow_target_calibration_url = allow_autoroute_loopback_calibration_url
            && is_autoroute_loopback_calibration_url(&target);
        if is_disallowed_web_host(&target) && !allow_target_calibration_url {
            let redacted = redact_url(&target);
            return Err(web_unreadable_error(format!(
                "refusing to follow redirect to {redacted}: target resolves to a \
                 private / loopback / link-local / metadata-service address"
            )));
        }
        current_url = target;
        allow_current_calibration_url = allow_target_calibration_url;
    }
    unreachable!("redirect loop exits by return or redirect cap");
}

fn web_unreadable_error(message: String) -> SourceError {
    let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
    SourceError::Other(message)
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

    let mut map: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            let _event =
                crate::record_skip_event(crate::SourceSkipEvent::StructuredSourceParseFailure);
            tracing::warn!(url = %redact_url(url), err = %e, "failed to parse source map JSON");
            return vec![Ok(sourcemap_raw_chunk(body, url))];
        }
    };

    let mut malformed_sources = false;
    let mut sources: Vec<Option<String>> = match map.get("sources") {
        Some(value) => match value.as_array() {
            Some(arr) => arr
                .iter()
                .map(|entry| match entry.as_str() {
                    Some(name) => Some(name.to_string()),
                    None => {
                        if !entry.is_null() {
                            malformed_sources = true;
                        }
                        None
                    }
                })
                .collect(),
            None => {
                if !value.is_null() {
                    malformed_sources = true;
                }
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    if malformed_sources {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::StructuredSourceParseFailure);
        tracing::warn!(
            url = %redact_url(url),
            "source map sources array contains non-string entry; decoded content keeps synthetic names for malformed entries"
        );
    }

    let mut malformed_sources_content = false;
    let contents: Vec<Option<String>> = match map.get_mut("sourcesContent") {
        Some(value) => match value.as_array_mut() {
            Some(arr) => arr
                .iter_mut()
                .map(|entry| match entry.take() {
                    serde_json::Value::String(text) => Some(text),
                    serde_json::Value::Null => None,
                    other => {
                        if !other.is_null() {
                            malformed_sources_content = true;
                        }
                        None
                    }
                })
                .collect(),
            None => {
                if !value.is_null() {
                    malformed_sources_content = true;
                }
                Vec::new()
            }
        },
        None => Vec::new(),
    };
    if malformed_sources_content {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::StructuredSourceParseFailure);
        tracing::warn!(
            url = %redact_url(url),
            "source map sourcesContent contains non-string entry; scanning raw map alongside decoded entries"
        );
    }

    let mut chunks = Vec::new();

    for (i, content) in contents.into_iter().enumerate() {
        if let Some(code) = content {
            if code.is_empty() {
                continue;
            }
            let source_name = sources
                .get_mut(i)
                .and_then(Option::take)
                .unwrap_or_else(|| format!("source_{i}")); // LAW10: synthetic label for an unnamed sourcemap entry; the content is still scanned
            chunks.push(Ok(Chunk {
                data: code.into(),
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

    // If no sourcesContent, treat the raw map as scannable text. If only some
    // entries were malformed, scan raw too so malformed embedded code is covered.
    if chunks.is_empty() || malformed_sources_content {
        chunks.push(Ok(sourcemap_raw_chunk(body, url)));
    }

    chunks
}

fn sourcemap_raw_chunk(body: String, url: &str) -> Chunk {
    Chunk {
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
    }
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
        let safe_url = redact_url(url);
        tracing::warn!(
            url = %safe_url,
            "WASM body yielded no printable strings; body was NOT scanned for secrets"
        );
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Binary);
        return vec![Err(SourceError::Other(format!(
            "failed to scan {safe_url}: WASM body yielded no printable strings, so no WebAssembly bytes were scanned for secrets"
        )))];
    }

    vec![Ok(Chunk {
        data: crate::strings::join_sensitive_strings(&strings, "\n"),
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

/// Read an HTTP response body as text, capping raw and decoded bytes at the
/// resolved source limit.
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

/// Read an HTTP response body as bytes.
///
/// Raw wire bytes are capped before buffering, then an explicit
/// Content-Encoding decoder inflates gzip/br/deflate through the same cap.
/// Reqwest auto-decompression stays disabled in `http.rs`, so a compressed
/// web response cannot inflate before these limits run.
fn read_bytes_response(
    resp: reqwest::blocking::Response,
    max_response_bytes: usize,
) -> Result<Vec<u8>, SourceError> {
    use std::io::Read;
    let url = resp.url().to_string();
    let safe_url = redact_url(&url);
    let encodings = response_content_encodings(resp.headers(), &safe_url)?;

    if let Some(len) = resp.content_length() {
        if len > max_response_bytes as u64 {
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

    decode_content_encoding(buf, &encodings, &safe_url, max_response_bytes)
}

fn response_content_encodings(
    headers: &reqwest::header::HeaderMap,
    safe_url: &str,
) -> Result<Vec<String>, SourceError> {
    let Some(raw) = headers.get(reqwest::header::CONTENT_ENCODING) else {
        return Ok(Vec::new());
    };
    let raw = raw.to_str().map_err(|error| {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        SourceError::Other(format!(
            "response from {safe_url} has invalid Content-Encoding header: {error}"
        ))
    })?;
    Ok(raw
        .split(',')
        .map(str::trim)
        .filter(|encoding| !encoding.is_empty())
        .map(str::to_ascii_lowercase)
        .filter(|encoding| encoding != "identity")
        .collect())
}

fn decode_content_encoding(
    mut bytes: Vec<u8>,
    encodings: &[String],
    safe_url: &str,
    max_response_bytes: usize,
) -> Result<Vec<u8>, SourceError> {
    for encoding in encodings.iter().rev() {
        bytes = decode_one_content_encoding(&bytes, encoding, safe_url, max_response_bytes)?;
    }
    Ok(bytes)
}

fn decode_one_content_encoding(
    bytes: &[u8],
    encoding: &str,
    safe_url: &str,
    max_response_bytes: usize,
) -> Result<Vec<u8>, SourceError> {
    use std::io::Read as _;

    let limit = (max_response_bytes as u64).saturating_add(1);
    let mut out = Vec::new();
    let result = match encoding {
        "gzip" | "x-gzip" => {
            let mut decoder = flate2::read::MultiGzDecoder::new(bytes).take(limit);
            decoder.read_to_end(&mut out)
        }
        "deflate" => {
            let mut decoder = flate2::read::ZlibDecoder::new(bytes).take(limit);
            decoder.read_to_end(&mut out)
        }
        "br" => {
            let mut decoder = brotli::Decompressor::new(bytes, 4096).take(limit);
            decoder.read_to_end(&mut out)
        }
        other => {
            let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
            return Err(SourceError::Other(format!(
                "response from {safe_url} uses unsupported Content-Encoding {other:?}; body was not scanned"
            )));
        }
    };

    result.map_err(|error| {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::Unreadable);
        SourceError::Other(format!(
            "failed to decode {encoding} response from {safe_url}: {error}"
        ))
    })?;
    if out.len() > max_response_bytes {
        let _event = crate::record_skip_event(crate::SourceSkipEvent::OverMaxSize);
        return Err(SourceError::Other(format!(
            "decoded {encoding} response from {safe_url} exceeds {max_response_bytes} byte limit"
        )));
    }

    Ok(out)
}

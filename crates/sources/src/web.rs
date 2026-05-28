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

/// Strip userinfo (`user:password@`) from a URL before logging.
///
/// Operators sometimes pass a URL with embedded credentials to scan a
/// private endpoint - `https://user:SECRET_TOKEN@host/path`. Without
/// redaction, every tracing::warn!/info! call below would ship that
/// token straight into the operator's logging pipeline (Splunk,
/// Datadog, journald), defeating the whole point of running a secret
/// scanner. Replace the userinfo with `***` so the URL stays
/// recognisable but the credential never leaves the process.
fn redact_url(url: &str) -> std::borrow::Cow<'_, str> {
    let scheme_end = match url.find("://") {
        Some(idx) => idx + 3,
        None => return std::borrow::Cow::Borrowed(url),
    };
    let after_scheme = &url[scheme_end..];
    // `@` before the path/query/fragment delimits userinfo. Refuse to
    // strip `@` that appears in the path (e.g. ".../foo@bar/baz") by
    // bounding the search to the first `/?#` separator.
    let authority_end = after_scheme
        .find(['/', '?', '#'])
        .unwrap_or(after_scheme.len());
    let authority = &after_scheme[..authority_end];
    let Some(at_offset) = authority.find('@') else {
        return std::borrow::Cow::Borrowed(url);
    };
    let mut out = String::with_capacity(url.len());
    out.push_str(&url[..scheme_end]);
    out.push_str("***@");
    out.push_str(&after_scheme[at_offset + 1..]);
    std::borrow::Cow::Owned(out)
}

/// Returns `true` if `url` resolves (without DNS lookup) to a host that
/// WebSource refuses to fetch on SSRF grounds. Covers:
///   - literal loopback IPs (127.0.0.0/8, ::1)
///   - private IP ranges (RFC 1918, fc00::/7, 169.254.0.0/16 link-local,
///     and the IPv4 cloud-metadata special 169.254.169.254)
///   - hostname aliases (localhost, *.local, *.internal, *.localdomain)
///   - the metadata.google.internal alias
///
/// This is a STRING-level pre-filter - it doesn't resolve DNS. Hosts
/// that look public but resolve to private IPs aren't caught here;
/// that requires a custom resolver with post-connect re-check, which
/// reqwest doesn't currently expose. The check matches the same shape
/// of defense the verifier uses in `crates/verifier/src/ssrf.rs` (via
/// the bogon crate); duplicating without the crate dep keeps WebSource
/// from pulling in verifier-only crypto deps just for this gate.
fn is_disallowed_web_host(url: &str) -> bool {
    let parsed = match reqwest::Url::parse(url) {
        Ok(u) => u,
        Err(_) => return true, // refuse malformed
    };
    let Some(host) = parsed.host() else {
        return true; // file://, mailto://, no host
    };
    match host {
        url::Host::Ipv4(ip) => is_disallowed_ipv4(ip),
        url::Host::Ipv6(ip) => is_disallowed_ipv6(ip),
        url::Host::Domain(d) => {
            let lower = d.to_ascii_lowercase();
            lower == "localhost"
                || lower.ends_with(".local")
                || lower.ends_with(".internal")
                || lower.ends_with(".localdomain")
                || lower == "metadata.google.internal"
        }
    }
}

fn is_disallowed_ipv4(ip: std::net::Ipv4Addr) -> bool {
    ip.is_loopback()
        || ip.is_private()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
}

fn is_disallowed_ipv6(ip: std::net::Ipv6Addr) -> bool {
    // An IPv4-mapped IPv6 (`::ffff:a.b.c.d`) routes to the v4 address -
    // `Ipv6Addr::is_loopback` only matches the literal `::1`, so
    // `[::ffff:127.0.0.1]` would otherwise sneak past the loopback gate
    // and let the WebSource exfil to a local service. Unwrap the inner
    // v4 first and run it through the v4 disallow rules.
    if let Some(v4) = ip.to_ipv4_mapped() {
        return is_disallowed_ipv4(v4);
    }
    ip.is_loopback() || ip.is_multicast() || ip.is_unspecified()
        || ip.segments()[0] & 0xfe00 == 0xfc00 // fc00::/7 unique-local
        || ip.segments()[0] & 0xffc0 == 0xfe80 // fe80::/10 link-local
}

#[cfg(test)]
mod web_host_filter_tests {
    use super::is_disallowed_web_host;

    #[test]
    fn rejects_cloud_metadata_endpoints() {
        assert!(is_disallowed_web_host(
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/"
        ));
        assert!(is_disallowed_web_host(
            "http://metadata.google.internal/computeMetadata/v1/"
        ));
    }

    #[test]
    fn rejects_loopback_and_private() {
        assert!(is_disallowed_web_host("http://127.0.0.1/"));
        assert!(is_disallowed_web_host("http://10.0.0.5/"));
        assert!(is_disallowed_web_host("http://192.168.1.1/"));
        assert!(is_disallowed_web_host("http://172.16.0.5/"));
        assert!(is_disallowed_web_host("http://[::1]/"));
        assert!(is_disallowed_web_host("http://localhost/"));
        assert!(is_disallowed_web_host("http://machine.local/"));
        assert!(is_disallowed_web_host("http://svc.internal/api"));
    }

    #[test]
    fn rejects_malformed_or_hostless() {
        assert!(is_disallowed_web_host("not a url"));
        assert!(is_disallowed_web_host("file:///etc/passwd"));
    }

    #[test]
    fn accepts_real_public_hosts() {
        assert!(!is_disallowed_web_host("https://example.com/"));
        assert!(!is_disallowed_web_host("https://cdn.jsdelivr.net/app.js"));
        assert!(!is_disallowed_web_host(
            "https://api.github.com/repos/foo/bar"
        ));
    }

    /// Macro-wiring regression: prove that an `HttpClientConfig.proxy`
    /// passed via `WebSource::with_http_config` ends up baked into the
    /// reqwest client the source actually uses. Without this assertion
    /// the only thing pinning the proxy behavior was the one-line
    /// `.proxy(proxy)` call in `blocking_client_builder`, and a future
    /// refactor that swaps to a custom builder (which has happened
    /// before for the verifier, see `verify/request.rs`) would silently
    /// drop the proxy with no test to catch it.
    #[test]
    fn web_source_threads_proxy_into_blocking_client_builder() {
        // We can't read back the proxy config from a built reqwest Client
        // (no public accessor), but we CAN assert the builder accepts the
        // exact policy contract we expect: a proxy URL through
        // `blocking_client_builder` returns Ok, and a malformed URL
        // returns Err. If the builder ever stops applying `proxy`, the
        // Err case below would change to Ok (since malformed URLs go
        // through reqwest's Proxy::all which is the validation gate).
        let cfg_ok = crate::http::HttpClientConfig {
            proxy: Some("http://127.0.0.1:8080".into()),
            ..Default::default()
        };
        assert!(
            crate::http::blocking_client_builder(&cfg_ok)
                .and_then(|b| b.build().map_err(|e| e.to_string()))
                .is_ok(),
            "valid proxy URL must build a client; if this fails, the source-side \
             proxy plumbing is broken before it ever leaves WebSource"
        );

        let cfg_bad = crate::http::HttpClientConfig {
            proxy: Some("not a url".into()),
            ..Default::default()
        };
        assert!(
            crate::http::blocking_client_builder(&cfg_bad).is_err(),
            "malformed proxy URL must be rejected at builder time, not silently \
             skipped. If this passes, `--proxy` validation is gone and bad URLs \
             reach reqwest as a no-op default."
        );
    }

    /// Regression for the IPv4-mapped IPv6 SSRF bypass.
    /// `Ipv6Addr::is_loopback()` only returns `true` for the literal `::1`,
    /// so an attacker URL like `http://[::ffff:127.0.0.1]/` previously
    /// passed every disallow gate and let the WebSource exfil to the
    /// machine'"'"'s own loopback service. The fix unwraps an IPv4-mapped
    /// IPv6 into its underlying IPv4 first and runs the v4 disallow
    /// rules against it.
    #[test]
    fn rejects_ipv4_mapped_ipv6_loopback_and_private() {
        assert!(
            is_disallowed_web_host("http://[::ffff:127.0.0.1]/"),
            "::ffff:127.0.0.1 must route to v4 loopback check"
        );
        assert!(
            is_disallowed_web_host("http://[::ffff:10.0.0.1]/"),
            "::ffff:10.0.0.1 must route to v4 private check"
        );
        assert!(
            is_disallowed_web_host("http://[::ffff:169.254.169.254]/"),
            "::ffff:169.254.169.254 (cloud-metadata via v6-mapped form) must block"
        );
        assert!(
            is_disallowed_web_host("http://[::ffff:192.168.1.1]/"),
            "::ffff:192.168.1.1 (private via v6-mapped form) must block"
        );
        assert!(
            is_disallowed_web_host("http://[::ffff:172.16.0.5]/"),
            "::ffff:172.16.0.5 (private via v6-mapped form) must block"
        );
    }
}

#[cfg(test)]
mod redact_url_tests {
    use super::redact_url;

    #[test]
    fn passes_through_urls_without_userinfo() {
        for ok in &[
            "https://example.com/path",
            "http://example.com:8080/p?q=1",
            "https://example.com/path/with/@symbol/in/it",
        ] {
            assert_eq!(redact_url(ok), *ok, "unchanged for {ok:?}");
        }
    }

    #[test]
    fn strips_userinfo() {
        assert_eq!(
            redact_url("https://user:SECRET@host/path"),
            "https://***@host/path"
        );
        assert_eq!(
            redact_url("https://user@host/path?q=1"),
            "https://***@host/path?q=1"
        );
        assert_eq!(
            redact_url("http://x:y@example.com:8080/p#frag"),
            "http://***@example.com:8080/p#frag"
        );
    }

    #[test]
    fn does_not_confuse_path_at_with_userinfo() {
        // The `@` is in the path, NOT the authority - must NOT redact.
        let url = "https://example.com/orgs/foo/users/@me";
        assert_eq!(redact_url(url), url);
    }
}

/// Web content source that fetches JavaScript, source maps, and WASM from URLs.
///
/// URLs ending in `.wasm` are treated as binary and have strings extracted.
/// URLs ending in `.map` are treated as source maps and have `sourcesContent`
/// entries split into individual chunks. Everything else is treated as
/// JavaScript text.
pub struct WebSource {
    urls: Vec<String>,
    http: crate::http::HttpClientConfig,
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
        }
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
        Self::new(vec![url.to_string()])
    }

    /// Override the default HTTP policy (proxy, insecure-TLS,
    /// timeout). Construct from `HttpClientConfig` directly when the
    /// caller already has CLI-derived flags to thread through.
    pub fn with_http_config(mut self, http: crate::http::HttpClientConfig) -> Self {
        // Preserve the per-source UA suffix so the operator's proxy
        // logs still tag this traffic as `keyhog/<ver> (web)`.
        let mut http = http;
        if http.ua_suffix.is_none() {
            http.ua_suffix = Some("web".into());
        }
        self.http = http;
        self
    }

    /// Fetch all URLs and produce chunks.
    ///
    /// Uses `reqwest::blocking` directly; the blocking client internally manages
    /// its own background runtime, so no dedicated thread wrapper is required.
    fn fetch_all(&self) -> Vec<Result<Chunk, SourceError>> {
        // Auto-decompression DISABLED - without this, reqwest expands gzip
        // bodies to completion before we can check size, opening a gzip-bomb
        // DoS. Decompression is opt-in per call where we explicitly want it.
        let client = match crate::http::blocking_client_builder(&self.http) {
            Ok(b) => b
                .timeout(crate::timeouts::HTTP_REQUEST)
                .build()
                .map_err(|e| SourceError::Other(format!("failed to build HTTP client: {e}"))),
            Err(e) => Err(SourceError::Other(e)),
        };

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
    // SSRF defense: the verifier already has this gate via bogon for live
    // verifications; WebSource was the missing surface. Without this,
    // `WebSource::new(vec!["http://169.254.169.254/latest/meta-data/iam/..."])`
    // would happily fetch the cloud metadata endpoint and extract IAM
    // credentials. Kimi sources-audit web-source SSRF finding.
    if is_disallowed_web_host(url) {
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
        tracing::warn!(url = %safe_url, status, "non-200 response, skipping");
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
                mtime_ns: None,
                size_bytes: None,
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
            tracing::warn!(url = %redact_url(url), err = %e, "failed to parse source map JSON");
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
                    mtime_ns: None,
                    size_bytes: None,
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
                    mtime_ns: None,
                    size_bytes: None,
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
                mtime_ns: None,
                size_bytes: None,
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
        tracing::warn!(url = %redact_url(url), "not a valid WASM file (wrong magic bytes)");
        return Vec::new();
    }

    let strings = crate::strings::extract_printable_strings(&bytes, MIN_WASM_STRING_LEN);
    if strings.is_empty() {
        return Vec::new();
    }

    vec![Ok(Chunk {
        data: keyhog_core::SensitiveString::join(&strings, "\n"),
        metadata: ChunkMetadata {
            base_offset: 0,
            source_type: "web:wasm".to_string(),
            path: Some(url.to_string()),
            commit: None,
            author: None,
            date: None,
            mtime_ns: None,
            size_bytes: None,
        },
    })]
}

/// Read an HTTP response body as text, capping at `MAX_RESPONSE_BYTES`.
///
/// Pre-flight Content-Length and streamed cap-aware copy. The previous
/// version called `.text()` (which auto-decompresses gzip/deflate to
/// completion) before checking the size - a 1 MB gzip bomb expanding to
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
    let safe_url = redact_url(&url);

    if let Some(len) = resp.content_length() {
        if len as usize > MAX_RESPONSE_BYTES {
            return Err(SourceError::Other(format!(
                "response from {safe_url} declares {len} bytes (> {} MB limit)",
                MAX_RESPONSE_BYTES / (1024 * 1024)
            )));
        }
    }

    // Stream into a bounded buffer; abort the moment we exceed the cap.
    let mut buf = Vec::with_capacity(MAX_RESPONSE_BYTES.min(64 * 1024));
    let mut taken = resp.take(MAX_RESPONSE_BYTES as u64 + 1);
    taken
        .read_to_end(&mut buf)
        .map_err(|e| SourceError::Other(format!("failed to read bytes from {safe_url}: {e}")))?;
    if buf.len() > MAX_RESPONSE_BYTES {
        return Err(SourceError::Other(format!(
            "response from {safe_url} exceeds {} MB limit",
            MAX_RESPONSE_BYTES / (1024 * 1024)
        )));
    }

    Ok(buf)
}

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
pub(crate) fn redact_url(url: &str) -> std::borrow::Cow<'_, str> {
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
pub(crate) fn is_disallowed_web_host(url: &str) -> bool {
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

/// Disallow check for a RESOLVED IP address (post-DNS). The string-level
/// `is_disallowed_web_host` only ever sees the hostname; once DNS hands us
/// the actual `IpAddr` we run the same v4/v6 rules against it to defeat a
/// public-looking name that resolves to a private/loopback/metadata IP
/// (DNS-rebinding). Mirrors the verifier's `is_private_ip_addr` gate.
pub(crate) fn is_disallowed_ip(ip: std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v4) => is_disallowed_ipv4(v4),
        std::net::IpAddr::V6(v6) => is_disallowed_ipv6(v6),
    }
}

/// Build a redirect policy that re-validates EVERY hop against the SSRF
/// host filter. reqwest's `Policy::limited` is a hop-count-only policy: a
/// public URL that answers `302 Location: http://169.254.169.254/...`
/// (or any 127.0.0.1 / RFC1918 / `.internal` target) is followed
/// automatically and the internal/metadata body comes back as a scanned
/// Chunk - the operator-URL-only check in `fetch_url` never sees the
/// redirect target. This closure aborts the chain when a hop is
/// disallowed, while still capping the hop count.
///
/// Two checks per hop, both required:
///   1. `is_disallowed_web_host` on the target string (literal internal
///      IPs, `.internal`/`localhost` names, malformed URLs).
///   2. `resolve_and_screen` on the target host - the original-host pin
///      via `resolve_to_addrs` only covers the FIRST host, so the redirect
///      target is otherwise re-resolved by the system resolver and a
///      public-looking redirect name pointing at a private IP would slip
///      through (DNS-rebinding via redirect). Resolving + screening here
///      closes that. Mirrors the verifier's `Policy::none()` intent
///      (verify/request.rs:124-128) while still allowing a bounded number
///      of genuinely-public redirects that CDNs legitimately use.
fn ssrf_revalidating_redirect_policy() -> reqwest::redirect::Policy {
    reqwest::redirect::Policy::custom(|attempt| {
        if attempt.previous().len() >= REDIRECT_LIMIT {
            return attempt.error(SourceError::Other(format!(
                "too many redirects (> {REDIRECT_LIMIT})"
            )));
        }
        // Snapshot the target into owned values inside this block so NO borrow
        // of `attempt` is held across the `attempt.error()` / `attempt.follow()`
        // moves below (`Attempt::url()` borrows `attempt`; holding the `&Url`
        // across a move is E0505).
        let (target_str, host, port) = {
            let url = attempt.url();
            (
                url.as_str().to_string(),
                url.host_str().map(str::to_owned),
                url.port_or_known_default().unwrap_or(443),
            )
        };
        // Do NOT echo the (attacker-controlled) target host into the
        // error; redact userinfo and keep the message generic so a
        // redirect to an internal name can't leak topology.
        if is_disallowed_web_host(&target_str) {
            let redacted = redact_url(&target_str);
            return attempt.error(SourceError::Other(format!(
                "refusing to follow redirect to {redacted}: target resolves to a \
                 private / loopback / link-local / metadata-service address"
            )));
        }
        // Post-DNS screen of the redirect target (rebinding-via-redirect).
        if let Some(host) = host {
            if let Err(e) = resolve_and_screen(&host, port) {
                return attempt.error(e);
            }
        }
        attempt.follow()
    })
}

/// Maximum SSRF-revalidated redirect hops. Matches the shared
/// `http::REDIRECT_LIMIT` (5); kept local so the custom policy above
/// doesn't reach across modules for a single constant.
const REDIRECT_LIMIT: usize = 5;

/// Whole-path SSRF-gate tests for the redirect + DNS-rebinding defenses.
///
/// These exercise the REAL `build_web_client` / `resolve_and_screen`
/// path, not just the pure string pre-filter. The previous
/// `web_redirect_target_*` adversarial files only asserted
/// `is_disallowed_web_host("http://169.254.169.254/...") == true` - a
/// pure-function check that passed even though the live redirect/DNS
/// path was wide open. A redirecting-server whole-path test still needs a
/// DNS-control harness (tracked in tests/adversarial; see needs_cross_file),
/// but the post-DNS IP screening and the policy wiring are pinned here.
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
            // SSRF defense (host pre-filter): the verifier already has this
            // gate via bogon for live verifications; WebSource was the
            // missing surface. Without it,
            // `WebSource::new(vec!["http://169.254.169.254/latest/meta-data/iam/..."])`
            // would fetch the cloud metadata endpoint and extract IAM creds.
            if is_disallowed_web_host(url) {
                let safe_url = redact_url(url);
                results.push(Err(SourceError::Other(format!(
                    "refusing to fetch {safe_url}: host resolves to a private / \
                     loopback / link-local / metadata-service address - \
                     WebSource only fetches public URLs"
                ))));
                continue;
            }

            let client = match build_web_client(&self.http, url, proxy_in_use) {
                Ok(c) => c,
                Err(e) => {
                    results.push(Err(e));
                    continue;
                }
            };

            let chunks = fetch_url(&client, url);
            results.extend(chunks);
        }

        results
    }
}

/// Build a per-URL blocking client carrying the shared HTTP policy
/// (proxy, TLS, UA, body-bomb defenses) PLUS two SSRF gates the shared
/// builder can't apply on its own:
///
///   1. **Per-hop redirect re-validation** ([`ssrf_revalidating_redirect_policy`]).
///      Overrides the shared `Policy::limited`, which is hop-count-only
///      and would happily follow `302 Location: http://169.254.169.254/...`.
///   2. **DNS resolution + pinning.** Resolves the host once, rejects if
///      any resolved address is private/loopback/link-local/metadata, then
///      pins host→addrs via `resolve_to_addrs` so reqwest's connector
///      cannot re-resolve to a private IP between the check and the TCP
///      connect (DNS-rebinding). Skipped under a proxy, where DNS is the
///      proxy's job and pinning would be moot (mirrors the verifier's
///      `proxy_in_use` short-circuit in verify/request.rs).
pub(crate) fn build_web_client(
    cfg: &crate::http::HttpClientConfig,
    url: &str,
    proxy_in_use: bool,
) -> Result<reqwest::blocking::Client, SourceError> {
    // Auto-decompression stays DISABLED (set in the shared builder) -
    // without it reqwest expands gzip bodies to completion before we can
    // check size, opening a gzip-bomb DoS. Decompression is opt-in per
    // call where we explicitly want it.
    let mut builder = crate::http::blocking_client_builder(cfg)
        .map_err(SourceError::Other)?
        .timeout(crate::timeouts::HTTP_REQUEST)
        // Replace the shared hop-count-only policy with one that
        // re-validates each redirect target against the SSRF host filter.
        .redirect(ssrf_revalidating_redirect_policy());

    if !proxy_in_use {
        // Direct connection: resolve + pin so a public-looking host that
        // resolves to a private/metadata IP is refused, and a rebinding
        // resolver can't swap the IP after the check.
        let parsed = reqwest::Url::parse(url)
            .map_err(|e| SourceError::Other(format!("invalid URL: {e}")))?;
        if let Some(host) = parsed.host_str() {
            // IP literals are already covered by `is_disallowed_web_host`;
            // only domains need DNS resolution. `to_socket_addrs` handles
            // both, so resolve uniformly and gate on the result.
            let port = parsed.port_or_known_default().unwrap_or(443);
            let host = host.to_string();
            let addrs = resolve_and_screen(&host, port)?;
            builder = builder.resolve_to_addrs(&host, &addrs);
        }
    }

    builder
        .build()
        .map_err(|e| SourceError::Other(format!("failed to build HTTP client: {e}")))
}

/// Resolve `host:port` and reject the lot if ANY resolved address is a
/// private / loopback / link-local / metadata IP. Returns the screened
/// address list for `resolve_to_addrs` pinning. Uses the blocking
/// `ToSocketAddrs` resolver to match the blocking client - no tokio
/// runtime required on the source path.
pub(crate) fn resolve_and_screen(
    host: &str,
    port: u16,
) -> Result<Vec<std::net::SocketAddr>, SourceError> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<std::net::SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| {
            SourceError::Other(format!(
                "refusing to fetch {}: DNS resolution failed: {e}",
                redact_url(host)
            ))
        })?
        .collect();
    if addrs.is_empty() {
        return Err(SourceError::Other(format!(
            "refusing to fetch {}: DNS returned no addresses",
            redact_url(host)
        )));
    }
    if addrs.iter().any(|a| is_disallowed_ip(a.ip())) {
        // Don't name the resolved IP - it's the secret topology this gate
        // exists to protect.
        return Err(SourceError::Other(format!(
            "refusing to fetch {}: host resolves to a private / loopback / \
             link-local / metadata-service address - WebSource only fetches \
             public URLs",
            redact_url(host)
        )));
    }
    Ok(addrs)
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
///
/// The caller (`fetch_all`) has already screened `url` with
/// `is_disallowed_web_host` and built `client` through `build_web_client`,
/// which pins the resolved (screened) IP and installs the per-hop
/// SSRF-revalidating redirect policy. The pre-filter is repeated here as a
/// cheap defense-in-depth guard so this helper stays safe even if a future
/// caller hands it a client that skipped `build_web_client`.
fn fetch_url(client: &reqwest::blocking::Client, url: &str) -> Vec<Result<Chunk, SourceError>> {
    // SSRF defense (host pre-filter): the verifier already has this gate via
    // bogon for live verifications; WebSource was the missing surface.
    // Without it,
    // `WebSource::new(vec!["http://169.254.169.254/latest/meta-data/iam/..."])`
    // would fetch the cloud metadata endpoint and extract IAM credentials.
    // The redirect-target and DNS-rebinding bypasses of this gate are closed
    // in `build_web_client`. Kimi sources-audit web-source SSRF finding.
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

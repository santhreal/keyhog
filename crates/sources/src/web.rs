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

use crate::capped_read::MAX_PREALLOCATED_READ_BYTES;

mod ssrf;
pub(crate) use ssrf::{
    build_web_client, is_autoroute_loopback_calibration_url, is_disallowed_ip,
    is_disallowed_web_host, redact_url, resolve_and_screen,
};

/// Bound on concurrent endpoint fetches inside one [`WebSource`] scan. Eight
/// workers keep a scan of delayed endpoints near one endpoint's latency while
/// capping simultaneous connections a single scan opens (measured on the
/// `perf_web_parallel_fetch` latency harness: 8 delayed endpoints complete in
/// ~1x endpoint delay instead of ~8x; larger bounds showed no further median
/// gain once every endpoint had a worker).
const WEB_FETCH_THREADS: usize = 8;

/// SSRF-pinned clients shared across the endpoints (and redirect hops) of one
/// streamed scan, keyed by `(redirect_pin_key, calibration-flag)`. A cached
/// client already pins its host:port to the screened resolution, so reuse
/// across same-host endpoints is exactly the per-hop reuse
/// `send_with_pinned_redirects` already did, extended across URLs: N
/// endpoints on one host pay one DNS resolve + screen + TLS connector build.
/// Bounded by the scan's URL count and dropped with the scan.
///
/// Acquisition is SINGLE-FLIGHT per key: the first worker needing a key
/// builds while later workers wait on `BuildSignal`, so N same-host workers
/// never race to build N duplicate clients (a measured ~300ms storm for 8
/// same-host endpoints). When the leader's build FAILS, the slot is cleared
/// and each waiter retries (and constructs) its own build error, so per-URL
/// skip/error accounting stays identical to the serial fetch.
#[derive(Default)]
struct PinnedWebClientCache {
    slots: std::sync::Mutex<std::collections::HashMap<(String, bool), PinnedWebClientSlot>>,
}

enum PinnedWebClientSlot {
    Building(std::sync::Arc<BuildSignal>),
    Ready(reqwest::blocking::Client),
}

impl PinnedWebClientCache {
    /// Return the shared client for `(pin_key, calibration)`, building it
    /// single-flight when absent. A build failure clears the slot and is
    /// returned to the building worker; each waiter then retries as the new
    /// builder, so every URL on an unbuildable host constructs its own error
    /// (identical per-URL error accounting to the serial fetch).
    fn acquire(
        &self,
        pin_key: &str,
        calibration: bool,
        build: impl FnOnce() -> Result<reqwest::blocking::Client, SourceError>,
    ) -> Result<reqwest::blocking::Client, SourceError> {
        let key = (pin_key.to_string(), calibration);
        let mut build = Some(build);
        loop {
            let mut slots = self
                .slots
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner()); // LAW10: poisoned cache-lock recovery retains the existing client/build state; fetch errors still propagate.
            match slots.get(&key) {
                Some(PinnedWebClientSlot::Ready(client)) => return Ok(client.clone()),
                Some(PinnedWebClientSlot::Building(signal)) => {
                    let signal = signal.clone();
                    drop(slots);
                    signal.wait();
                }
                None => {
                    let signal = std::sync::Arc::new(BuildSignal::default());
                    slots.insert(key.clone(), PinnedWebClientSlot::Building(signal.clone()));
                    drop(slots);
                    // The `None` arm always returns, so the builder is taken at
                    // most once. Fail closed rather than panic if that ever
                    // stops holding: a scan must not die inside a client cache.
                    let Some(build) = build.take() else {
                        return Err(SourceError::Other(
                            "pinned web client builder was already consumed. Fix: rerun the scan; \
                             report this if it repeats"
                                .to_string(),
                        ));
                    };
                    return match build() {
                        Ok(client) => {
                            let mut slots = self
                                .slots
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner()); // LAW10: poisoned cache-lock recovery installs the successfully built client without changing fetch results.
                            slots.insert(key, PinnedWebClientSlot::Ready(client.clone()));
                            drop(slots);
                            signal.finish();
                            Ok(client)
                        }
                        Err(error) => {
                            let mut slots = self
                                .slots
                                .lock()
                                .unwrap_or_else(|poisoned| poisoned.into_inner()); // LAW10: poisoned cache-lock recovery removes the failed build slot while returning the original build error.
                            slots.remove(&key);
                            drop(slots);
                            signal.finish();
                            Err(error)
                        }
                    };
                }
            }
        }
    }
}

/// Completion signal for one in-flight pinned-client build; waiters park here
/// instead of racing a duplicate build.
#[derive(Default)]
struct BuildSignal {
    done: std::sync::Mutex<bool>,
    cond: std::sync::Condvar,
}

impl BuildSignal {
    fn wait(&self) {
        let mut done = self
            .done
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()); // LAW10: poisoned build-signal recovery reads the same completion flag; client construction errors remain explicit.
        while !*done {
            done = self
                .cond
                .wait(done)
                .unwrap_or_else(|poisoned| poisoned.into_inner()); // LAW10: poisoned build-signal recovery resumes waiting on the same completion flag; no fetch result is discarded.
        }
    }

    fn finish(&self) {
        let mut done = self
            .done
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()); // LAW10: poisoned build-signal recovery sets completion and wakes waiters; the associated client result remains authoritative.
        *done = true;
        self.cond.notify_all();
    }
}

/// Web content source that fetches JavaScript, source maps, and WASM from URLs.
///
/// URLs ending in `.wasm` are treated as binary and have strings extracted.
/// URLs ending in `.map` are treated as source maps and have `sourcesContent`
/// entries split into individual chunks. Everything else is treated as
/// JavaScript text.
#[derive(Clone)]
pub struct WebSource {
    urls: Vec<String>,
    http: crate::http::HttpClientConfig,
    limits: crate::SourceLimits,
    allow_autoroute_loopback_calibration: bool,
}

struct WebChunkStream {
    receiver: Option<std::sync::mpsc::Receiver<Result<Chunk, SourceError>>>,
    worker: Option<std::thread::JoinHandle<()>>,
    reported_worker_failure: bool,
}

impl Iterator for WebChunkStream {
    type Item = Result<Chunk, SourceError>;

    fn next(&mut self) -> Option<Self::Item> {
        let received = self.receiver.as_ref()?.recv();
        match received {
            Ok(row) => Some(row),
            Err(_) => {
                // LAW10: result-channel closure triggers the worker join below, which surfaces the first worker panic as a SourceError.
                self.receiver.take();
                let worker = self.worker.take()?;
                match worker.join() {
                    Ok(()) => None,
                    Err(_) if !self.reported_worker_failure => {
                        self.reported_worker_failure = true;
                        Some(Err(SourceError::Other(
                            "web: bounded fetch worker panicked".to_string(),
                        )))
                    }
                    Err(_) => None, // LAW10: a worker panic is emitted at most once above; a later iterator call terminates without duplicating the same error.
                }
            }
        }
    }
}

impl Drop for WebChunkStream {
    fn drop(&mut self) {
        self.receiver.take();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join(); // LAW10: Drop means the fetch consumer abandoned the stream; joining only reclaims the worker and cannot report to a recipient.
        }
    }
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

    /// Fetch all URLs concurrently and stream ordered chunks through a bounded
    /// channel. At most one result row plus one result per fetch worker is
    /// retained, rather than every response body across the full URL list.
    fn stream_all(
        self,
        output: std::sync::mpsc::SyncSender<Result<Chunk, SourceError>>,
        lease: crate::skip::ScanReadLease,
    ) {
        let _attributed = lease.enter();
        let proxy_in_use = matches!(
            self.http.effective_proxy().as_deref(),
            Some(p) if !matches!(p, "off" | "none" | "")
        );
        let _acquire = crate::profile::acquire_span();
        let shared_clients = PinnedWebClientCache::default();
        let profile_runtime = crate::profile::current_runtime();
        let cancelled = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let next_job = std::sync::atomic::AtomicUsize::new(0);
        let (completed, completions) = std::sync::mpsc::sync_channel::<(
            usize,
            Vec<Result<Chunk, SourceError>>,
        )>(WEB_FETCH_THREADS);
        let (release_slot, available_slots) = crossbeam_channel::bounded::<()>(WEB_FETCH_THREADS);
        for _ in 0..WEB_FETCH_THREADS {
            let _ = release_slot.send(()); // LAW10: the bounded slot receiver is retained throughout initialization, so seeding this channel cannot fail.
        }

        std::thread::scope(|scope| {
            for _ in 0..WEB_FETCH_THREADS.min(self.urls.len()) {
                let completed = completed.clone();
                let cancelled = std::sync::Arc::clone(&cancelled);
                let profile_runtime = profile_runtime.clone();
                let worker_lease = lease.clone();
                let source = &self;
                let shared_clients = &shared_clients;
                let next_job = &next_job;
                let available_slots = available_slots.clone();
                scope.spawn(move || {
                    let _attributed = worker_lease.enter();
                    let _profile_guard = profile_runtime.as_ref().map(|runtime| runtime.enter());
                    loop {
                        if cancelled.load(std::sync::atomic::Ordering::Relaxed) {
                            break;
                        }
                        if available_slots.recv().is_err() {
                            break;
                        }
                        let index = next_job.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(url) = source.urls.get(index) else {
                            break;
                        };
                        let rows = source.fetch_one(url, proxy_in_use, shared_clients);
                        if completed.send((index, rows)).is_err() {
                            break;
                        }
                    }
                });
            }
            drop(completed);

            let mut pending = std::collections::BTreeMap::new();
            let mut next_output = 0;
            while let Ok((index, rows)) = completions.recv() {
                pending.insert(index, rows);
                while let Some(rows) = pending.remove(&next_output) {
                    for row in rows {
                        if output.send(row).is_err() {
                            cancelled.store(true, std::sync::atomic::Ordering::Relaxed);
                            return;
                        }
                    }
                    next_output += 1;
                    let _ = release_slot.send(()); // LAW10: slot release failure only occurs after the scoped scheduler receiver closes; no further fetch can consume it.
                }
            }
        });
    }

    /// Validate, SSRF-screen, and fetch one configured URL, recording per-chunk
    /// emission counters. Runs on a bounded fetch worker.
    fn fetch_one(
        &self,
        url: &str,
        proxy_in_use: bool,
        shared_clients: &PinnedWebClientCache,
    ) -> Vec<Result<Chunk, SourceError>> {
        if let Err(error) = validate_initial_web_url(url) {
            return vec![Err(error)];
        }
        let allow_calibration_url =
            self.allow_autoroute_loopback_calibration && is_autoroute_loopback_calibration_url(url);
        // SSRF defense (host pre-filter): the verifier already has this
        // gate via bogon for live verifications; WebSource was the
        // missing surface. Without it,
        // `WebSource::new(vec!["http://169.254.169.254/latest/meta-data/iam/..."])`
        // would fetch the cloud metadata endpoint and extract IAM creds.
        if is_disallowed_web_host(url)
            && !self.http.allow_private_endpoint
            && !allow_calibration_url
        {
            let safe_url = redact_url(url);
            return vec![Err(web_unreadable_error(format!(
                "refusing to fetch {safe_url}: host resolves to a private / \
                 loopback / link-local / metadata-service address - \
                 WebSource only fetches public URLs"
            )))];
        }

        let chunks = fetch_url(
            &self.http,
            url,
            self.limits.web_response_bytes,
            proxy_in_use,
            self.http.allow_private_endpoint,
            allow_calibration_url,
            shared_clients,
        );
        for row in &chunks {
            crate::profile::record_emitted_chunk(row);
        }
        chunks
    }
}

impl Source for WebSource {
    fn name(&self) -> &str {
        "web"
    }

    fn chunks(&self) -> Box<dyn Iterator<Item = Result<Chunk, SourceError>> + '_> {
        let lease = crate::acquire_scan_read_lease();
        let source = self.clone();
        let worker_lease = lease.clone();
        let profile_runtime = crate::profile::current_runtime();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let worker = std::thread::Builder::new()
            .name("keyhog-web-fetch".to_string())
            .spawn(move || {
                let _profile_guard = profile_runtime.as_ref().map(|runtime| runtime.enter());
                source.stream_all(sender, worker_lease);
            });

        let inner: Box<dyn Iterator<Item = Result<Chunk, SourceError>>> = match worker {
            Ok(worker) => Box::new(WebChunkStream {
                receiver: Some(receiver),
                worker: Some(worker),
                reported_worker_failure: false,
            }),
            Err(error) => Box::new(std::iter::once(Err(SourceError::Other(format!(
                "web: failed to spawn bounded fetch worker: {error}"
            ))))),
        };
        crate::attach_scan_lease(lease, inner)
    }

    fn as_any(&self) -> &dyn std::any::Any {
        self
    }
}

/// Fetch a single URL and produce one or more chunks based on content type.
///
/// The bounded fetch worker has already screened `url` with
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
    allow_private_endpoint: bool,
    allow_autoroute_loopback_calibration_url: bool,
    shared_clients: &PinnedWebClientCache,
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
    if is_disallowed_web_host(url)
        && !allow_private_endpoint
        && !allow_autoroute_loopback_calibration_url
    {
        let safe_url = redact_url(url);
        return vec![Err(web_unreadable_error(format!(
            "refusing to fetch {safe_url}: host resolves to a private / \
             loopback / link-local / metadata-service address - \
             WebSource only fetches public URLs"
        )))];
    }

    // HTTP wire capture and response-body streaming for one endpoint.
    let _wire = crate::profile::read_span();
    let resp = match send_with_pinned_redirects(
        http,
        url,
        proxy_in_use,
        allow_private_endpoint,
        allow_autoroute_loopback_calibration_url,
        shared_clients,
    ) {
        Ok(r) => r,
        Err(e) => {
            return vec![Err(e)];
        }
    };

    let status = resp.status();
    if !status.is_success() {
        let safe_url = redact_url(url);
        tracing::warn!(url = %safe_url, %status, "non-success response; URL body was NOT scanned");
        return vec![Err(web_unreadable_error(format!(
            "failed to fetch {safe_url}: HTTP status {status}; response body was not scanned"
        )))];
    }

    match classify_web_response_with_headers(url, resp.headers()) {
        WebResponseKind::Wasm => handle_wasm(resp, url, max_response_bytes),
        WebResponseKind::Json => handle_json(resp, url, max_response_bytes),
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
    Json,
    SourceMap,
    Wasm,
}

fn classify_web_response(url: &str) -> WebResponseKind {
    let path = url.split_once(['?', '#']).map_or(url, |(path, _)| path);
    use keyhog_core::ascii_ci::ends_with_ignore_ascii_case;
    if ends_with_ignore_ascii_case(path.as_bytes(), b".wasm") {
        WebResponseKind::Wasm
    } else if ends_with_ignore_ascii_case(path.as_bytes(), b".map") {
        WebResponseKind::SourceMap
    } else {
        WebResponseKind::JavaScript
    }
}

fn classify_web_response_with_headers(
    url: &str,
    headers: &reqwest::header::HeaderMap,
) -> WebResponseKind {
    let url_kind = classify_web_response(url);
    if url_kind != WebResponseKind::JavaScript {
        return url_kind;
    }
    match web_response_kind_from_content_type(headers) {
        Some(kind) => kind,
        None => url_kind,
    }
}

fn web_response_kind_from_content_type(
    headers: &reqwest::header::HeaderMap,
) -> Option<WebResponseKind> {
    let raw = match headers.get(reqwest::header::CONTENT_TYPE)?.to_str() {
        Ok(raw) => raw,
        Err(_error) => {
            // LAW10: invalid Content-Type is only a routing hint failure;
            // recall-preserving, the URL-extension classifier below still
            // chooses a scannable path.
            return None;
        }
    };
    let media_type = crate::http::media_type(raw);
    if media_type.eq_ignore_ascii_case("application/wasm") {
        Some(WebResponseKind::Wasm)
    } else if media_type.eq_ignore_ascii_case("application/source-map") {
        Some(WebResponseKind::SourceMap)
    } else if media_type.eq_ignore_ascii_case("application/json") {
        Some(WebResponseKind::Json)
    } else {
        None
    }
}

/// Stable `host:port` identity a redirect client is pinned to. Two URLs share a
/// client only when this matches, because the SSRF `resolve_to_addrs` pin is
/// host:port-specific (a redirect that keeps the host but changes the port must
/// be re-screened and re-pinned). `None` on an unparseable URL forces a rebuild
/// so `build_web_client` surfaces the real parse error rather than silently
/// reusing a stale client.
pub(crate) fn redirect_pin_key(url: &str) -> Option<String> {
    let parsed = match reqwest::Url::parse(url) {
        Ok(parsed) => parsed,
        Err(_invalid_url) => return None,
    };
    let host = parsed.host_str()?;
    let port = parsed.port_or_known_default().map_or(443, |port| port);
    Some(format!("{host}:{port}"))
}

fn send_with_pinned_redirects(
    http: &crate::http::HttpClientConfig,
    url: &str,
    proxy_in_use: bool,
    allow_private_endpoint: bool,
    allow_autoroute_loopback_calibration_url: bool,
    shared_clients: &PinnedWebClientCache,
) -> Result<reqwest::blocking::Response, SourceError> {
    let mut current_url = url.to_string();
    let mut allow_current_private_url = allow_private_endpoint
        || (allow_autoroute_loopback_calibration_url
            && is_autoroute_loopback_calibration_url(&current_url));
    // Reuse one client (and its TLS config + connection pool) across hops and
    // endpoints whose pinned host:port and calibration flag are unchanged, a
    // same-host redirect (only the path changes) and same-host endpoint lists
    // are the common cases. Rebuilding paid a fresh DNS resolve + screen +
    // TLS/connector setup up to REDIRECT_LIMIT+1 times per URL, times the URL
    // count (Law 7). A client is only rebuilt when the target host:port
    // differs, since the SSRF-screened `resolve_to_addrs` pin is
    // host:port-specific. `Client` clones share the same inner Arc, so the
    // cached clone reuses the live pool. Failed builds are not cached: every
    // URL on an unbuildable host constructs (and counts) its own error,
    // identical to the serial fetch.
    for hop in 0..=crate::http::REDIRECT_LIMIT {
        let pin_key = redirect_pin_key(&current_url);
        let client = match pin_key {
            Some(key) => {
                match shared_clients.acquire(&key, allow_current_private_url, || {
                    build_web_client(http, &current_url, proxy_in_use, allow_current_private_url)
                }) {
                    Ok(client) => client,
                    Err(error) => return Err(error),
                }
            }
            // Unparseable URL: force a fresh build so `build_web_client`
            // surfaces the real parse error rather than reusing a stale client.
            None => build_web_client(http, &current_url, proxy_in_use, allow_current_private_url)?,
        };
        let resp = client.get(&current_url).send().map_err(|e| {
            let safe_url = redact_url(&current_url);
            // `{e}` alone would undo `safe_url`: `reqwest::Error`'s Display
            // re-appends the request URL verbatim, userinfo and query included.
            web_unreadable_error(format!(
                "failed to fetch {safe_url}: {}",
                crate::url_redaction::redact_http_error(e)
            ))
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
        let allow_target_private_url = allow_private_endpoint
            || (allow_autoroute_loopback_calibration_url
                && is_autoroute_loopback_calibration_url(&target));
        if is_disallowed_web_host(&target) && !allow_target_private_url {
            let redacted = redact_url(&target);
            return Err(web_unreadable_error(format!(
                "refusing to follow redirect to {redacted}: target resolves to a \
                 private / loopback / link-local / metadata-service address"
            )));
        }
        current_url = target;
        allow_current_private_url = allow_target_private_url;
    }
    unreachable!("redirect loop exits by return or redirect cap");
}

fn web_unreadable_error(message: String) -> SourceError {
    web_skip_error(crate::SourceSkipEvent::Unreadable, message)
}

fn web_over_max_error(message: String) -> SourceError {
    web_skip_error(crate::SourceSkipEvent::OverMaxSize, message)
}

fn web_skip_error(event: crate::SourceSkipEvent, message: String) -> SourceError {
    let _event = crate::record_skip_event(event);
    SourceError::Other(message)
}

/// Handle a JavaScript file through bounded, gapless scan chunks.
fn handle_js(
    resp: reqwest::blocking::Response,
    url: &str,
    max_response_bytes: usize,
) -> Vec<Result<Chunk, SourceError>> {
    match read_text_response(resp, max_response_bytes) {
        Ok(body) => web_text_rows(body, "web:js", chunk_path(url)),
        Err(e) => vec![Err(e)],
    }
}

fn handle_json(
    resp: reqwest::blocking::Response,
    url: &str,
    max_response_bytes: usize,
) -> Vec<Result<Chunk, SourceError>> {
    let body = match read_text_response(resp, max_response_bytes) {
        Ok(body) => body,
        Err(e) => return vec![Err(e)],
    };
    // Parse the JSON body ONCE: if it is source-map-shaped, expand it from the
    // already-parsed value; otherwise scan it as text. Previously the body was
    // parsed twice here, once by `is_sourcemap_shaped_json` to classify it and
    // again inside `expand_sourcemap_body` to walk it.
    match serde_json::from_str::<serde_json::Value>(&body) {
        Ok(value) if is_sourcemap_shaped_value(&value) => expand_sourcemap_value(value, body, url),
        _ => web_text_rows(body, "web:js", chunk_path(url)),
    }
}

/// Chunk-path form of a fetched URL.
///
/// The operator-supplied `--url` (and any redirect target derived from it) can
/// carry `user:password@` userinfo or a credential query parameter
/// (`?access_token=`, `?api_key=`, a presigned `?sig=`/`X-Amz-Signature`). This
/// string becomes `file_path` on every finding from the fetch and is printed
/// verbatim by text, JSON, SARIF, CSV, HTML, and JUnit output, so it is masked
/// here, at the boundary that mints it, by the same owner every WebSource log
/// line and error already routes through. A URL with nothing sensitive in it is
/// returned unchanged.
fn chunk_path(url: &str) -> std::sync::Arc<str> {
    redact_url(url).as_ref().into()
}

fn web_text_rows(
    body: String,
    source_type: &'static str,
    path: std::sync::Arc<str>,
) -> Vec<Result<Chunk, SourceError>> {
    bounded_web_text_chunks(body, source_type, path)
        .into_iter()
        .map(Ok)
        .collect()
}

fn bounded_web_text_chunks(
    body: String,
    source_type: &'static str,
    path: std::sync::Arc<str>,
) -> Vec<Chunk> {
    let chunk_bytes = crate::strings::BOUNDED_DERIVED_TEXT_CHUNK_BYTES;
    if body.len() <= chunk_bytes {
        return vec![Chunk {
            data: body.into(),
            metadata: ChunkMetadata {
                source_type: keyhog_core::intern_source_type(source_type),
                path: Some(path),
                ..Default::default()
            },
        }];
    }

    let bytes = body.into_bytes();
    let mut chunks = Vec::with_capacity(bytes.len().div_ceil(chunk_bytes));
    let mut start = 0;
    let mut base_line = 0;
    while start < bytes.len() {
        let mut end = (start + chunk_bytes).min(bytes.len());
        while end > start && std::str::from_utf8(&bytes[start..end]).is_err() {
            end -= 1;
        }
        if end == start {
            end = (start + chunk_bytes).min(bytes.len());
        }
        let data = String::from_utf8_lossy(&bytes[start..end]).into_owned();
        let line_count = data
            .as_bytes()
            .iter()
            .filter(|&&byte| byte == b'\n')
            .count();
        chunks.push(Chunk {
            data: data.into(),
            metadata: ChunkMetadata {
                base_offset: start,
                base_line,
                source_type: keyhog_core::intern_source_type(source_type),
                path: Some(path.clone()),
                ..Default::default()
            },
        });
        base_line += line_count;
        start = end;
    }
    chunks
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
    expand_sourcemap_body(body, url)
}

fn expand_sourcemap_body(body: String, url: &str) -> Vec<Result<Chunk, SourceError>> {
    let map: serde_json::Value = match serde_json::from_str(&body) {
        Ok(v) => v,
        Err(e) => {
            let _event =
                crate::record_skip_event(crate::SourceSkipEvent::StructuredSourceParseFailure);
            tracing::warn!(url = %redact_url(url), err = %e, "failed to parse source map JSON");
            return sourcemap_raw_rows(body, url);
        }
    };
    expand_sourcemap_value(map, body, url)
}

/// Expand an ALREADY-PARSED source map value into per-`sourcesContent` chunks
/// (plus the raw map when there is no embedded content or some entries are
/// malformed). Split out of [`expand_sourcemap_body`] so `handle_json`: which
/// must parse the body anyway to decide it is source-map-shaped, reuses that
/// single parse instead of re-parsing the same JSON.
fn expand_sourcemap_value(
    mut map: serde_json::Value,
    body: String,
    url: &str,
) -> Vec<Result<Chunk, SourceError>> {
    let mut malformed_sources = false;
    let mut sources: Vec<Option<String>> = match map.get_mut("sources") {
        Some(value) => match value.as_array_mut() {
            Some(arr) => arr
                .iter_mut()
                .map(|entry| match entry.take() {
                    serde_json::Value::String(name) => Some(name),
                    serde_json::Value::Null => None,
                    other => {
                        if !other.is_null() {
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

    let has_decoded_content = contents
        .iter()
        .any(|content| content.as_ref().is_some_and(|code| !code.is_empty()));
    let raw_body = (!has_decoded_content || malformed_sources_content).then_some(body);
    drop(map);

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
            let path: std::sync::Arc<str> = format!("{}!{source_name}", redact_url(url)).into();
            chunks.extend(web_text_rows(code, "web:sourcemap", path));
        }
    }

    // If no sourcesContent, treat the raw map as scannable text. If only some
    // entries were malformed, scan raw too so malformed embedded code is covered.
    if let Some(body) = raw_body {
        chunks.extend(sourcemap_raw_rows(body, url));
    }

    chunks
}

fn is_sourcemap_shaped_value(value: &serde_json::Value) -> bool {
    value.get("sourcesContent").is_some()
        || (value.get("version").is_some()
            && value.get("sources").is_some()
            && value.get("mappings").is_some())
}

fn sourcemap_raw_rows(body: String, url: &str) -> Vec<Result<Chunk, SourceError>> {
    web_text_rows(body, "web:sourcemap:raw", chunk_path(url))
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
    if !crate::magic::starts_with_wasm_module(&bytes) {
        let safe_url = redact_url(url);
        tracing::warn!(url = %safe_url, "not a valid WASM file; body was NOT scanned as WebAssembly strings");
        return vec![Err(web_unreadable_error(format!(
            "failed to scan {safe_url}: response was classified as WebAssembly but did not start with WASM magic bytes"
        )))];
    }

    let strings = crate::strings::extract_printable_string_chunks(
        &bytes,
        crate::strings::MIN_PRINTABLE_STRING_LEN,
        crate::strings::BOUNDED_DERIVED_TEXT_CHUNK_BYTES,
    );
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

    let path = chunk_path(url);
    let mut base_offset = 0;
    let mut base_line = 0;
    strings
        .into_iter()
        .map(|data| {
            let data_len = data.len();
            let line_count = data
                .as_bytes()
                .iter()
                .filter(|&&byte| byte == b'\n')
                .count();
            let chunk = Chunk {
                data,
                metadata: ChunkMetadata {
                    base_offset,
                    base_line,
                    source_type: keyhog_core::intern_source_type("web:wasm"),
                    path: Some(path.clone()),
                    commit: None,
                    author: None,
                    date: None,
                    mtime_ns: None,
                    size_bytes: None,
                    decoded_span: None,
                },
            };
            base_offset += data_len;
            base_line += line_count;
            Ok(chunk)
        })
        .collect()
}

/// Read an HTTP response body as text, capping raw and decoded bytes at the
/// resolved source limit.
fn read_text_response(
    resp: reqwest::blocking::Response,
    max_response_bytes: usize,
) -> Result<String, SourceError> {
    let bytes = read_bytes_response(resp, max_response_bytes)?;
    String::from_utf8(bytes).map_err(|e| web_unreadable_error(format!("non-UTF-8 response: {e}")))
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
    let url = resp.url().to_string();
    let safe_url = redact_url(&url);
    let encodings = response_content_encodings(resp.headers(), &safe_url)?;
    let cap = u64::try_from(max_response_bytes).map_err(|_| {
        web_over_max_error(format!(
            "response byte limit for {safe_url} exceeds this platform's supported range"
        ))
    })?;

    if let Some(len) = resp.content_length() {
        if len > cap {
            return Err(web_over_max_error(format!(
                "response from {safe_url} declares {len} bytes (> {max_response_bytes} byte limit)"
            )));
        }
    }

    // Stream into a bounded buffer; abort the moment we exceed the cap.
    let capacity_hint = max_response_bytes.min(MAX_PREALLOCATED_READ_BYTES as usize);
    let read = crate::capped_read::read_to_cap(resp, cap, Some(capacity_hint as u64))
        .map_err(|e| web_unreadable_error(format!("failed to read bytes from {safe_url}: {e}")))?;
    if read.truncated {
        return Err(web_over_max_error(format!(
            "response from {safe_url} exceeds {max_response_bytes} byte limit"
        )));
    }

    decode_content_encoding(read.bytes, &encodings, &safe_url, max_response_bytes)
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum WebContentEncoding {
    Gzip,
    XGzip,
    Deflate,
    Brotli,
    Unsupported(String),
}

impl WebContentEncoding {
    fn parse(raw: &str) -> Option<Self> {
        let encoding = raw.trim();
        if encoding.is_empty() || encoding.eq_ignore_ascii_case("identity") {
            return None;
        }
        if encoding.eq_ignore_ascii_case("gzip") {
            Some(Self::Gzip)
        } else if encoding.eq_ignore_ascii_case("x-gzip") {
            Some(Self::XGzip)
        } else if encoding.eq_ignore_ascii_case("deflate") {
            Some(Self::Deflate)
        } else if encoding.eq_ignore_ascii_case("br") {
            Some(Self::Brotli)
        } else {
            Some(Self::Unsupported(encoding.to_owned()))
        }
    }

    fn label(&self) -> &str {
        match self {
            Self::Gzip => "gzip",
            Self::XGzip => "x-gzip",
            Self::Deflate => "deflate",
            Self::Brotli => "br",
            Self::Unsupported(encoding) => encoding.as_str(),
        }
    }
}

fn response_content_encodings(
    headers: &reqwest::header::HeaderMap,
    safe_url: &str,
) -> Result<Vec<WebContentEncoding>, SourceError> {
    let Some(raw) = headers.get(reqwest::header::CONTENT_ENCODING) else {
        return Ok(Vec::new());
    };
    let raw = raw.to_str().map_err(|error| {
        web_unreadable_error(format!(
            "response from {safe_url} has invalid Content-Encoding header: {error}"
        ))
    })?;
    Ok(raw
        .split(',')
        .filter_map(WebContentEncoding::parse)
        .collect())
}

fn decode_content_encoding(
    mut bytes: Vec<u8>,
    encodings: &[WebContentEncoding],
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
    encoding: &WebContentEncoding,
    safe_url: &str,
    max_response_bytes: usize,
) -> Result<Vec<u8>, SourceError> {
    let label = encoding.label();
    let cap = u64::try_from(max_response_bytes).map_err(|_| {
        web_over_max_error(format!(
            "decoded {label} response byte limit for {safe_url} exceeds this platform's supported range"
        ))
    })?;
    let read = match encoding {
        WebContentEncoding::Gzip | WebContentEncoding::XGzip => {
            crate::capped_read::read_to_cap(flate2::read::MultiGzDecoder::new(bytes), cap, None)
        }
        WebContentEncoding::Deflate => {
            crate::capped_read::read_to_cap(flate2::read::ZlibDecoder::new(bytes), cap, None)
        }
        WebContentEncoding::Brotli => {
            crate::capped_read::read_to_cap(brotli::Decompressor::new(bytes, 4096), cap, None)
        }
        WebContentEncoding::Unsupported(other) => {
            return Err(web_unreadable_error(format!(
                "response from {safe_url} uses unsupported Content-Encoding {other:?}; body was not scanned"
            )));
        }
    };

    let read = read.map_err(|error| {
        web_unreadable_error(format!(
            "failed to decode {label} response from {safe_url}: {error}"
        ))
    })?;
    if read.truncated {
        return Err(web_over_max_error(format!(
            "decoded {label} response from {safe_url} exceeds {max_response_bytes} byte limit"
        )));
    }

    Ok(read.bytes)
}

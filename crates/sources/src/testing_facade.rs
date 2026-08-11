//! Hidden test facade for source crate internals.

pub mod testing {
    pub use crate::ScanCounterScope;

    pub struct TestApi;

    // ── magic byte-signature classifiers (src/magic.rs) ──────────────────────
    // Free `for_test` wrappers over the `pub(crate)` binary-format detectors that
    // drive `filesystem/read/decode.rs`'s binary-vs-text classification. The
    // `src` no-inline-tests contract keeps unit coverage out of `src`, so these
    // expose the pure functions to `tests/` without widening their visibility.

    /// [`crate::magic::has_unambiguous_binary_prefix`].
    pub fn has_unambiguous_binary_prefix_for_test(bytes: &[u8]) -> bool {
        crate::magic::has_unambiguous_binary_prefix(bytes)
    }
    /// [`crate::magic::has_bmp_header`].
    pub fn has_bmp_header_for_test(bytes: &[u8]) -> bool {
        crate::magic::has_bmp_header(bytes)
    }
    /// [`crate::magic::has_pe_header`].
    pub fn has_pe_header_for_test(bytes: &[u8]) -> bool {
        crate::magic::has_pe_header(bytes)
    }
    /// [`crate::magic::has_bzip2_header`].
    pub fn has_bzip2_header_for_test(bytes: &[u8]) -> bool {
        crate::magic::has_bzip2_header(bytes)
    }
    /// [`crate::magic::starts_with_pdf`].
    pub fn starts_with_pdf_for_test(bytes: &[u8]) -> bool {
        crate::magic::starts_with_pdf(bytes)
    }
    /// [`crate::magic::starts_with_zip_container_prefix`].
    pub fn starts_with_zip_container_prefix_for_test(bytes: &[u8]) -> bool {
        crate::magic::starts_with_zip_container_prefix(bytes)
    }
    /// [`crate::magic::starts_with_python_pickle_protocol2`].
    pub fn starts_with_python_pickle_protocol2_for_test(bytes: &[u8]) -> bool {
        crate::magic::starts_with_python_pickle_protocol2(bytes)
    }
    /// [`crate::magic::starts_with_gzip`].
    pub fn starts_with_gzip_for_test(bytes: &[u8]) -> bool {
        crate::magic::starts_with_gzip(bytes)
    }
    /// [`crate::magic::starts_with_zstd_frame`].
    pub fn starts_with_zstd_frame_for_test(bytes: &[u8]) -> bool {
        crate::magic::starts_with_zstd_frame(bytes)
    }
    /// [`crate::magic::starts_with_wasm_module`] (web feature).
    #[cfg(feature = "web")]
    pub fn starts_with_wasm_module_for_test(bytes: &[u8]) -> bool {
        crate::magic::starts_with_wasm_module(bytes)
    }

    /// Drive [`crate::blocking_thread::collect_on_blocking_thread`] with a closure
    /// that PANICS, returning the surfaced error message (or `None` if it somehow
    /// succeeded). Pins the panic-safety contract: a fetch thread panic must be
    /// converted to a counted `SourceError::Other("… fetch thread panicked")`,
    /// never unwind into / abort the caller.
    pub fn blocking_thread_panic_error_message_for_test(source: &'static str) -> Option<String> {
        match crate::blocking_thread::collect_on_blocking_thread::<(), _>(source, || {
            panic!("simulated fetch-thread panic for the panic-safety test")
        }) {
            Ok(()) => None,
            Err(err) => Some(err.to_string()),
        }
    }

    // ── default-excludes rule-list validation (src/filesystem/filter.rs) ──────
    // The `filter.rs` normalizers reject malformed `default_excludes` config
    // (empty, non-lowercase, control chars, wrong dot/separator shape per kind,
    // duplicates). Kind is named by a label so the private `RuleListKind` enum
    // stays crate-internal while `tests/` can exercise every branch.

    fn rule_list_kind_from_label(label: &str) -> crate::filesystem::filter::RuleListKind {
        use crate::filesystem::filter::RuleListKind;
        match label {
            "extension" => RuleListKind::Extension,
            "path_segment" => RuleListKind::PathSegment,
            "suffix" => RuleListKind::Suffix,
            "filename" => RuleListKind::Filename,
            "infix" => RuleListKind::Infix,
            other => panic!("unknown RuleListKind label {other:?} in test helper"),
        }
    }

    /// [`crate::filesystem::filter::validate_rule_value`] for the named kind.
    /// `kind` is one of `extension` / `path_segment` / `suffix` / `filename` /
    /// `infix`. Returns `Ok(())` for an acceptable entry, else the refusal reason.
    pub fn validate_rule_value_for_test(name: &str, value: &str, kind: &str) -> Result<(), String> {
        crate::filesystem::filter::validate_rule_value(name, value, rule_list_kind_from_label(kind))
    }

    /// [`crate::filesystem::filter::normalize_rule_list`] for the named kind
    /// trims, validates every entry, and rejects duplicates, returning the
    /// normalized list or the first refusal reason.
    pub fn normalize_rule_list_for_test(
        name: &str,
        values: Vec<String>,
        kind: &str,
    ) -> Result<Vec<String>, String> {
        crate::filesystem::filter::normalize_rule_list(
            name,
            values,
            rule_list_kind_from_label(kind),
        )
    }

    impl TestApi {
        /// Enter an exclusive scan scope for a counter-asserting test. Held for
        /// the whole `reset → scan → read skip_counts()` window, it serializes
        /// against every other gated scan so concurrent tests cannot pollute the
        /// process-global skip counters this test is about to assert on.
        pub fn skip_counter_guard(&self) -> ScanCounterScope {
            crate::enter_exclusive_scan_scope()
        }

        /// Return whether no scan currently holds the shared counter-isolation
        /// lease. Used to prove first-scope serialization before any guard runs.
        pub fn scan_gate_exclusive_available(&self) -> bool {
            crate::skip::scan_gate_exclusive_available_for_test()
        }

        /// Archive entry-name path-traversal validator (test accessor; the
        /// `src/filesystem/extract/**` no-inline-tests contract keeps the unit
        /// coverage out of `src`). Returns `Ok(())` for a safe relative entry
        /// name and `Err(reason)` naming the refusal for traversal / absolute /
        /// backslash / NUL / over-encoded names.
        pub fn validate_archive_entry_name(&self, name: &str) -> Result<(), String> {
            crate::filesystem::validate_scan_archive_entry_name(name).map_err(str::to_string)
        }

        #[cfg(feature = "docker")]
        /// OCI/Docker manifest-vs-index classification (test accessor so the
        /// `src/docker/**` no-inline-tests contract holds; coverage lives in
        /// `tests/docker_oci_classification.rs`).
        pub fn oci_descriptor_points_to_index(
            &self,
            media_type: Option<&str>,
            body: &[u8],
        ) -> bool {
            crate::docker::oci::descriptor_points_to_index_for_test(media_type, body)
        }

        #[cfg(feature = "docker")]
        /// OCI blob sha256 verification through the crate's safe opener
        /// (O_NOFOLLOW): returns whether the blob at `path` matches `digest`.
        /// Critically REFUSES a symlink blob a raw `File::open` would follow (test
        /// accessor so the `src/docker/**` no-inline-tests contract holds; coverage
        /// lives in `tests/regression_docker_oci_safe_open.rs`).
        pub fn verify_oci_blob_sha256_ok(&self, path: &std::path::Path, digest: &str) -> bool {
            crate::docker::oci::verify_oci_blob_sha256(path, digest).is_ok()
        }

        pub fn set_skip_counts(&self, counts: crate::SkipCounts) {
            crate::skip::store_skip_counts(counts);
        }

        pub fn reset_skip_counters(&self) {
            crate::reset_skip_counters();
        }

        /// Source-side default window size, so the limits guard can assert its
        /// ordering against the scanner's decode ceiling.
        pub fn source_default_window_size(&self) -> usize {
            crate::filesystem::default_window_size_for_test()
        }

        pub fn bump_skipped_over_max_size(&self, delta: usize) {
            let _event = crate::record_skip_events(crate::SourceSkipEvent::OverMaxSize, delta);
        }

        pub fn bump_git_object_unreadable(&self, delta: usize) {
            let _event =
                crate::record_skip_events(crate::SourceSkipEvent::GitObjectUnreadable, delta);
        }

        pub fn read_stdin_test_input_with_limit(
            &self,
            input: &[u8],
            max_bytes: usize,
        ) -> std::io::Result<String> {
            let mut reader = std::io::Cursor::new(input);
            crate::stdin::read_to_string_limited(&mut reader, max_bytes)
        }

        #[cfg(any(
            feature = "git",
            feature = "docker",
            feature = "github",
            feature = "gitlab",
            feature = "bitbucket"
        ))]
        pub fn drain_process_stderr_excerpt(&self, reader: &mut dyn std::io::Read) -> String {
            crate::process_excerpt::drain_stderr_excerpt(reader)
        }

        pub fn expand_har(
            &self,
            bytes: &[u8],
            path_str: &str,
            max_size: u64,
        ) -> Option<Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>>> {
            crate::har::try_expand_har(bytes, path_str, max_size)
        }

        pub fn compact_har_base64_text(&self, text: &str) -> String {
            crate::har::compact_base64_text(text).into_owned()
        }

        pub fn reader_pool_thread_count(&self, scanner_threads: usize) -> usize {
            crate::filesystem::reader_pool_thread_count_for_test(scanner_threads)
        }

        pub fn reader_panic_rows(
            &self,
        ) -> Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>> {
            crate::filesystem::reader_panic_rows_for_test()
        }

        pub fn reader_process_entry_panic_rows(
            &self,
        ) -> Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>> {
            crate::filesystem::reader_process_entry_panic_rows_for_test()
        }

        pub fn process_entry_with_recorded_size(
            &self,
            path: std::path::PathBuf,
            recorded_size: u64,
            max_size: u64,
        ) -> Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>> {
            crate::filesystem::process_entry_with_recorded_size_for_test(
                path,
                recorded_size,
                max_size,
            )
        }

        pub fn process_entry_with_merkle(
            &self,
            path: std::path::PathBuf,
            recorded_size: u64,
            max_size: u64,
            merkle: std::sync::Arc<keyhog_core::MerkleIndex>,
        ) -> (
            Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>>,
            usize,
        ) {
            crate::filesystem::process_entry_with_merkle_for_test(
                path,
                recorded_size,
                max_size,
                merkle,
            )
        }

        pub fn configured_reader_pool_thread_count(
            &self,
            scanner_threads: usize,
            configured: std::num::NonZeroUsize,
        ) -> usize {
            crate::filesystem::reader_pool_thread_count_with_config_for_test(
                scanner_threads,
                configured,
            )
        }

        pub fn filesystem_with_window_config(
            &self,
            root: std::path::PathBuf,
            window_size: usize,
            overlap: usize,
        ) -> crate::FilesystemSource {
            crate::FilesystemSource::new(root).with_window_config(window_size, overlap)
        }

        pub fn filesystem_skipped_count(&self, source: &crate::FilesystemSource) -> usize {
            source
                .skipped_counter()
                .load(std::sync::atomic::Ordering::Relaxed)
        }

        pub fn max_buffered_read_bytes(&self) -> u64 {
            crate::filesystem::max_buffered_read_bytes_for_test()
        }

        pub fn mmap_toctou_sanity_cap_bytes(&self) -> u64 {
            crate::filesystem::mmap_toctou_sanity_cap_bytes_for_test()
        }

        pub fn read_file_safe_capped(
            &self,
            path: &std::path::Path,
            cap: u64,
        ) -> std::io::Result<Vec<u8>> {
            crate::filesystem::read_file_safe_capped_for_test(path, cap)
        }

        pub fn read_file_mmap(&self, path: &std::path::Path) -> Option<String> {
            crate::filesystem::read_file_mmap_for_test(path)
        }

        pub fn read_file_for_compressed_input(
            &self,
            path: &std::path::Path,
            size_cap: u64,
        ) -> Option<Vec<u8>> {
            crate::filesystem::read_file_for_compressed_input_for_test(path, size_cap)
        }

        pub fn read_file_windowed_mmap_len(
            &self,
            path: &std::path::Path,
            window_size: usize,
            overlap: usize,
        ) -> Option<usize> {
            crate::filesystem::read_file_windowed_mmap_len_for_test(path, window_size, overlap)
        }

        pub fn slice_into_windows(
            &self,
            bytes: &[u8],
            window_size: usize,
            overlap: usize,
        ) -> Vec<String> {
            crate::filesystem::slice_into_windows_for_test(bytes, window_size, overlap)
        }

        pub fn decode_utf16(&self, bytes: &[u8]) -> Option<String> {
            crate::filesystem::decode_utf16_for_test(bytes)
        }

        pub fn decode_text_file(&self, bytes: &[u8]) -> Option<String> {
            crate::filesystem::decode_text_file_for_test(bytes)
        }

        pub fn decode_text_file_owned_or_bytes(&self, bytes: Vec<u8>) -> Result<String, Vec<u8>> {
            crate::filesystem::decode_text_file_owned_or_bytes_for_test(bytes)
        }

        pub fn looks_binary(&self, bytes: &[u8]) -> bool {
            crate::filesystem::looks_binary_for_test(bytes)
        }

        pub fn looks_binary_prefix(&self, bytes: &[u8]) -> bool {
            crate::filesystem::looks_binary_prefix_for_test(bytes)
        }

        pub fn slice_into_windows_with_offsets(
            &self,
            bytes: &[u8],
            window_size: usize,
            overlap: usize,
        ) -> Vec<(usize, String)> {
            crate::filesystem::slice_into_windows_with_offsets_for_test(bytes, window_size, overlap)
        }

        pub fn read_file_windowed_mmap(
            &self,
            path: &std::path::Path,
            window_size: usize,
            overlap: usize,
        ) -> Option<Vec<(usize, String)>> {
            crate::filesystem::read_file_windowed_mmap_for_test(path, window_size, overlap)
        }

        pub fn read_file_buffered_text(
            &self,
            path: &std::path::Path,
            size_hint: u64,
        ) -> Option<String> {
            crate::filesystem::read_file_buffered_text_for_test(path, size_hint)
        }

        pub fn read_file_prefix_safe(
            &self,
            path: &std::path::Path,
            buf: &mut [u8],
        ) -> std::io::Result<usize> {
            crate::filesystem::read_file_prefix_safe_for_test(path, buf)
        }

        pub fn open_file_safe(&self, path: &std::path::Path) -> std::io::Result<std::fs::File> {
            crate::filesystem::open_file_safe(path)
        }

        pub fn open_file_safe_with_metadata(
            &self,
            path: &std::path::Path,
        ) -> std::io::Result<(std::fs::File, std::fs::Metadata)> {
            crate::filesystem::open_file_safe_with_metadata(path)
        }

        pub fn duplicate_zip_central_entries_error(
            &self,
            path: &std::path::Path,
        ) -> Result<String, String> {
            crate::filesystem::duplicate_zip_central_entries_error_for_test(path)
        }

        pub fn duplicate_zip_local_entry_data_error(
            &self,
            path: &std::path::Path,
            compressed_size: u64,
        ) -> Result<String, String> {
            crate::filesystem::duplicate_zip_local_entry_data_error_for_test(path, compressed_size)
        }

        pub fn duplicate_zip_reopen_error(&self, path: &std::path::Path) -> Option<String> {
            crate::filesystem::duplicate_zip_reopen_error_for_test(path)
        }

        pub fn filesystem_default_max_file_size(&self) -> u64 {
            crate::filesystem::default_max_file_size_for_test()
        }

        #[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
        pub fn cloud_is_probably_text_object_key(&self, key: &str) -> bool {
            crate::cloud::is_probably_text_object_key(key)
        }

        #[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
        pub fn cloud_is_binary_content_type(&self, content_type: &str) -> bool {
            crate::cloud::is_binary_content_type(content_type)
        }

        #[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
        pub fn cloud_read_text_object_body_from_url(
            &self,
            url: &str,
            max_bytes: u64,
        ) -> Result<Option<String>, keyhog_core::SourceError> {
            let response = reqwest::blocking::Client::new()
                .get(url)
                .send()
                .map_err(|error| {
                    keyhog_core::SourceError::Other(format!(
                        "failed to fetch cloud test object {url}: {error}"
                    ))
                })?;
            crate::cloud::read_text_object_body(
                response,
                crate::cloud::TextObjectBodyContext {
                    source: "unit-cloud",
                    item_kind: "object",
                    item_name: url,
                    display_path: url.to_string(),
                    max_bytes,
                },
            )
        }

        #[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
        pub fn cloud_record_unreadable_object_skip(
            &self,
            source: &str,
            item_kind: &str,
            display_path: &str,
            reason: &str,
        ) -> keyhog_core::SourceError {
            crate::cloud::record_unreadable_object_skip(source, item_kind, display_path, reason)
        }

        #[cfg(any(
            feature = "azure",
            feature = "web",
            feature = "slack",
            feature = "s3",
            feature = "github",
            feature = "gitlab",
            feature = "bitbucket",
            feature = "gcs"
        ))]
        pub fn http_request_timeout(&self) -> std::time::Duration {
            crate::timeouts::HTTP_REQUEST
        }

        #[cfg(any(
            feature = "azure",
            feature = "web",
            feature = "slack",
            feature = "s3",
            feature = "github",
            feature = "gitlab",
            feature = "bitbucket",
            feature = "gcs"
        ))]
        pub fn http_effective_proxy(&self, http: &crate::http::HttpClientConfig) -> Option<String> {
            http.effective_proxy()
        }

        #[cfg(any(
            feature = "azure",
            feature = "web",
            feature = "slack",
            feature = "s3",
            feature = "github",
            feature = "gitlab",
            feature = "bitbucket",
            feature = "gcs"
        ))]
        pub fn http_effective_insecure_tls(&self, http: &crate::http::HttpClientConfig) -> bool {
            http.effective_insecure_tls()
        }

        #[cfg(any(
            feature = "azure",
            feature = "web",
            feature = "slack",
            feature = "s3",
            feature = "github",
            feature = "gitlab",
            feature = "bitbucket",
            feature = "gcs"
        ))]
        pub fn http_blocking_client_builder(
            &self,
            http: &crate::http::HttpClientConfig,
        ) -> Result<reqwest::blocking::ClientBuilder, String> {
            crate::http::blocking_client_builder(http)
        }

        #[cfg(any(
            feature = "azure",
            feature = "web",
            feature = "slack",
            feature = "s3",
            feature = "github",
            feature = "gitlab",
            feature = "bitbucket",
            feature = "gcs"
        ))]
        pub fn http_async_client_builder(
            &self,
            http: &crate::http::HttpClientConfig,
        ) -> Result<reqwest::ClientBuilder, String> {
            crate::http::async_client_builder(http)
        }

        #[cfg(feature = "gcs")]
        pub fn gcs_endpoint_is_google(&self, endpoint: &str) -> bool {
            crate::gcs::endpoint_is_google(endpoint)
        }

        #[cfg(feature = "gcs")]
        pub fn gcs_credential_forward_allowed(&self, allow_explicit: bool) -> bool {
            crate::cloud::credential_forward_allowed(allow_explicit)
        }

        #[cfg(feature = "gcs")]
        pub fn gcs_source_with_endpoint<B, E>(&self, bucket: B, endpoint: E) -> crate::GcsSource
        where
            B: Into<String>,
            E: Into<String>,
        {
            crate::GcsSource::new(bucket)
                .with_endpoint(endpoint)
                .with_http_config(crate::http::HttpClientConfig::allowing_private_endpoint())
        }

        #[cfg(feature = "gcs")]
        pub fn gcs_source_with_endpoint_and_limits<B, E>(
            &self,
            bucket: B,
            endpoint: E,
            limits: crate::SourceLimits,
        ) -> crate::GcsSource
        where
            B: Into<String>,
            E: Into<String>,
        {
            crate::GcsSource::new(bucket)
                .with_endpoint(endpoint)
                .with_limits(limits)
                .with_http_config(crate::http::HttpClientConfig::allowing_private_endpoint())
        }

        #[cfg(feature = "gcs")]
        pub fn gcs_source_with_endpoint_max_objects<B, E>(
            &self,
            bucket: B,
            endpoint: E,
            max_objects: usize,
        ) -> crate::GcsSource
        where
            B: Into<String>,
            E: Into<String>,
        {
            crate::GcsSource::new(bucket)
                .with_endpoint(endpoint)
                .with_max_objects(max_objects)
                .with_http_config(crate::http::HttpClientConfig::allowing_private_endpoint())
        }

        #[cfg(feature = "s3")]
        pub fn s3_endpoint_is_aws(&self, endpoint: &str) -> bool {
            crate::s3::endpoint_is_aws(endpoint)
        }

        #[cfg(feature = "s3")]
        pub fn s3_credential_forward_allowed(&self, allow_explicit: bool) -> bool {
            crate::cloud::credential_forward_allowed(allow_explicit)
        }

        #[cfg(feature = "s3")]
        /// Build an `S3Source` at a custom (typically loopback httpmock) endpoint.
        ///
        /// SECURITY NOTE: every `*_with_endpoint*` loopback-mock builder OPTS INTO
        /// private endpoints (`allow_private_endpoint = true`) so the mock at
        /// `127.0.0.1` is reachable, i.e. it DISABLES the cloud SSRF endpoint
        /// screen. A test that must exercise the ACTIVE screen (private/metadata
        /// refusal, public-host acceptance) MUST instead use
        /// `s3_source_with_endpoint_allow_private(bucket, endpoint, false)`, or it
        /// silently passes with the screen off.
        pub fn s3_source_with_endpoint<B, E>(&self, bucket: B, endpoint: E) -> crate::S3Source
        where
            B: Into<String>,
            E: Into<String>,
        {
            crate::S3Source::new(bucket)
                .with_endpoint(endpoint)
                .with_http_config(crate::http::HttpClientConfig::allowing_private_endpoint())
        }

        #[cfg(feature = "s3")]
        pub fn s3_source_with_endpoint_and_limits<B, E>(
            &self,
            bucket: B,
            endpoint: E,
            limits: crate::SourceLimits,
        ) -> crate::S3Source
        where
            B: Into<String>,
            E: Into<String>,
        {
            crate::S3Source::new(bucket)
                .with_endpoint(endpoint)
                .with_limits(limits)
                .with_http_config(crate::http::HttpClientConfig::allowing_private_endpoint())
        }

        #[cfg(feature = "s3")]
        pub fn s3_source_with_endpoint_max_objects<B, E>(
            &self,
            bucket: B,
            endpoint: E,
            max_objects: usize,
        ) -> crate::S3Source
        where
            B: Into<String>,
            E: Into<String>,
        {
            crate::S3Source::new(bucket)
                .with_endpoint(endpoint)
                .with_max_objects(max_objects)
                .with_http_config(crate::http::HttpClientConfig::allowing_private_endpoint())
        }

        #[cfg(feature = "s3")]
        /// Build an S3 source whose SSRF endpoint screen is either default-on
        /// (`allow_private = false`) or opted-out (`true`), the config-flag
        /// replacement for the retired `KEYHOG_ALLOW_PRIVATE_CLOUD_ENDPOINT` env,
        /// used by the SSRF-refusal regression tests to drive both paths.
        pub fn s3_source_with_endpoint_allow_private<B, E>(
            &self,
            bucket: B,
            endpoint: E,
            allow_private: bool,
        ) -> crate::S3Source
        where
            B: Into<String>,
            E: Into<String>,
        {
            crate::S3Source::new(bucket)
                .with_endpoint(endpoint)
                .with_http_config(crate::http::HttpClientConfig {
                    allow_private_endpoint: allow_private,
                    ..Default::default()
                })
        }

        #[cfg(feature = "gcs")]
        /// GCS counterpart of [`s3_source_with_endpoint_allow_private`].
        pub fn gcs_source_with_endpoint_allow_private<B, E>(
            &self,
            bucket: B,
            endpoint: E,
            allow_private: bool,
        ) -> crate::GcsSource
        where
            B: Into<String>,
            E: Into<String>,
        {
            crate::GcsSource::new(bucket)
                .with_endpoint(endpoint)
                .with_http_config(crate::http::HttpClientConfig {
                    allow_private_endpoint: allow_private,
                    ..Default::default()
                })
        }

        #[cfg(feature = "azure")]
        /// Build an Azure Blob source whose container URL is permitted to be a
        /// private / loopback endpoint (httpmock binds 127.0.0.1), the loopback
        /// config-flag replacement used by the azure listing/drop regressions.
        pub fn azure_blob_source<U>(&self, container_url: U) -> crate::AzureBlobSource
        where
            U: Into<String>,
        {
            crate::AzureBlobSource::new(container_url)
                .with_http_config(crate::http::HttpClientConfig::allowing_private_endpoint())
        }

        #[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
        pub fn git_clone_timeout(&self) -> std::time::Duration {
            crate::timeouts::GIT_CLONE
        }

        #[cfg(feature = "binary")]
        pub fn ghidra_analysis_timeout(&self) -> std::time::Duration {
            crate::timeouts::GHIDRA_ANALYSIS
        }

        #[cfg(feature = "docker")]
        pub fn docker_export_timeout(&self) -> std::time::Duration {
            crate::timeouts::DOCKER_EXPORT
        }

        #[cfg(feature = "binary")]
        pub fn binary_strings_only<P>(&self, path: P) -> crate::BinarySource
        where
            P: Into<std::path::PathBuf>,
        {
            crate::BinarySource::strings_only(path)
        }

        pub fn user_agent(&self, suffix: Option<&str>) -> String {
            crate::http::user_agent(suffix)
        }

        #[cfg(feature = "binary")]
        pub fn extract_string_literals(&self, line: &str) -> Vec<String> {
            let mut out = Vec::new();
            crate::binary::literals::extract_string_literals(line, &mut out);
            out
        }

        #[cfg(feature = "binary")]
        pub fn extract_sections(
            &self,
            bytes: &[u8],
            path: &str,
        ) -> Option<Vec<keyhog_core::Chunk>> {
            crate::binary::sections::extract_sections(bytes, path)
        }

        #[cfg(feature = "binary")]
        pub fn resolve_binary_section_name<'a>(
            &self,
            resolved: Option<&'a str>,
            sh_name: usize,
        ) -> &'a str {
            crate::binary::sections::resolve_section_name(resolved, sh_name)
        }

        #[cfg(feature = "github")]
        pub fn validate_repo_name(&self, name: &str) -> Result<(), keyhog_core::SourceError> {
            crate::github_org::validate_repo_name(name)
        }

        #[cfg(feature = "github")]
        pub fn github_collaboration_source_with_endpoint(
            &self,
            repository: &str,
            endpoint: &str,
            selection: crate::GitHubCollaborationSelection,
            limits: crate::SourceLimits,
        ) -> Result<crate::GitHubCollaborationSource, keyhog_core::SourceError> {
            Ok(
                crate::GitHubCollaborationSource::new(repository, "test-token", selection)?
                    .with_endpoint(endpoint)
                    .with_limits(limits)
                    .with_http_config(crate::http::HttpClientConfig {
                        allow_private_endpoint: true,
                        ua_suffix: Some("github-collaboration-test".into()),
                        ..Default::default()
                    }),
            )
        }

        #[cfg(feature = "github")]
        pub fn github_collaboration_wiki_chunks_from_repo(
            &self,
            repo: &std::path::Path,
            limits: crate::SourceLimits,
        ) -> Result<Vec<keyhog_core::Chunk>, keyhog_core::SourceError> {
            crate::github_collaboration::collect_wiki_repo_for_test(repo, limits)
        }

        #[cfg(feature = "github")]
        pub fn validate_org_name(&self, name: &str) -> Result<(), keyhog_core::SourceError> {
            crate::github_org::validate_org_name(name)
        }

        #[cfg(feature = "github")]
        pub fn validate_clone_url(&self, url: &str) -> Result<(), keyhog_core::SourceError> {
            crate::github_org::validate_clone_url(url)
        }

        #[cfg(feature = "github")]
        pub fn github_org_rewrite_chunk_path(
            &self,
            chunk: keyhog_core::Chunk,
            org: &str,
            repo_name: &str,
            clone_path: &std::path::Path,
        ) -> Result<keyhog_core::Chunk, keyhog_core::SourceError> {
            crate::github_org::rewrite_chunk_path_for_test(chunk, org, repo_name, clone_path)
        }

        #[cfg(feature = "github")]
        pub fn github_org_scan_repo_chunks<I>(
            &self,
            chunks: I,
            org: &str,
            repo_name: &str,
            clone_path: &std::path::Path,
        ) -> Result<Vec<keyhog_core::Chunk>, keyhog_core::SourceError>
        where
            I: IntoIterator<Item = Result<keyhog_core::Chunk, keyhog_core::SourceError>>,
        {
            crate::github_org::scan_repo_chunks_for_test(chunks, org, repo_name, clone_path)
        }

        #[cfg(feature = "github")]
        pub fn github_org_listing_truncated_error(
            &self,
            org: &str,
            repo_count: usize,
            max_pages: usize,
        ) -> keyhog_core::SourceError {
            crate::github_org::github_listing_truncated_error_for_test(org, repo_count, max_pages)
        }

        #[cfg(feature = "gitlab")]
        pub fn validate_gitlab_group_path(
            &self,
            group: &str,
        ) -> Result<(), keyhog_core::SourceError> {
            crate::gitlab_group::validate_group_path(group)
        }

        #[cfg(feature = "gitlab")]
        pub fn gitlab_group_listing_truncated_error(
            &self,
            group: &str,
            repo_count: usize,
            max_pages: usize,
        ) -> keyhog_core::SourceError {
            crate::gitlab_group::listing_truncated_error_for_test(group, repo_count, max_pages)
        }

        #[cfg(feature = "bitbucket")]
        pub fn validate_bitbucket_workspace(
            &self,
            workspace: &str,
        ) -> Result<(), keyhog_core::SourceError> {
            crate::bitbucket_workspace::validate_workspace(workspace)
        }

        #[cfg(feature = "bitbucket")]
        pub fn bitbucket_workspace_listing_truncated_error(
            &self,
            workspace: &str,
            repo_count: usize,
            max_pages: usize,
        ) -> keyhog_core::SourceError {
            crate::bitbucket_workspace::listing_truncated_error_for_test(
                workspace, repo_count, max_pages,
            )
        }

        #[cfg(feature = "docker")]
        pub fn export_docker_image_archive(
            &self,
            docker_bin: &std::path::Path,
            image: &str,
            archive_path: &std::path::Path,
        ) -> Result<(), keyhog_core::SourceError> {
            crate::docker::export_docker_image_archive_for_test(docker_bin, image, archive_path)
        }

        #[cfg(feature = "docker")]
        pub fn docker_manifest_layer_archives(
            &self,
            root_path: &std::path::Path,
        ) -> Result<Vec<std::path::PathBuf>, keyhog_core::SourceError> {
            crate::docker::manifest_layer_archives_for_test(root_path)
        }

        #[cfg(feature = "docker")]
        pub fn docker_fallback_layer_archives_from_rows(
            &self,
            rows: Vec<Result<std::path::PathBuf, keyhog_core::SourceError>>,
        ) -> Vec<std::path::PathBuf> {
            crate::docker::fallback_layer_archives_from_rows_for_test(rows)
        }

        #[cfg(feature = "docker")]
        pub fn docker_manifest_config_chunks(
            &self,
            root_path: &std::path::Path,
            image: &str,
        ) -> Result<Vec<keyhog_core::Chunk>, keyhog_core::SourceError> {
            crate::docker::manifest_config_chunks_for_test(root_path, image)
        }

        #[cfg(feature = "docker")]
        pub fn docker_archive_metadata_chunks(
            &self,
            root_path: &std::path::Path,
            image: &str,
        ) -> Result<Vec<keyhog_core::Chunk>, keyhog_core::SourceError> {
            crate::docker::archive_metadata_chunks_for_test(root_path, image)
        }

        #[cfg(feature = "docker")]
        pub fn unpack_docker_layer_archive(
            &self,
            archive_path: &std::path::Path,
            destination: &std::path::Path,
        ) -> Result<Vec<keyhog_core::SourceError>, keyhog_core::SourceError> {
            crate::docker::unpack_layer_archive_for_test(archive_path, destination)
        }

        #[cfg(feature = "docker")]
        pub fn stream_docker_layer_archive_chunks(
            &self,
            archive_path: &std::path::Path,
            limits: crate::SourceLimits,
            total_cap: u64,
            respect_default_excludes: bool,
        ) -> Result<
            Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>>,
            keyhog_core::SourceError,
        > {
            crate::docker::stream_layer_archive_chunks_for_test(
                archive_path,
                limits,
                total_cap,
                respect_default_excludes,
            )
        }

        #[cfg(feature = "docker")]
        pub fn unpack_docker_layer_archive_with_total_cap(
            &self,
            archive_path: &std::path::Path,
            destination: &std::path::Path,
            total_cap: u64,
        ) -> Result<Vec<keyhog_core::SourceError>, keyhog_core::SourceError> {
            crate::docker::unpack_layer_archive_with_total_cap_for_test(
                archive_path,
                destination,
                total_cap,
            )
        }

        #[cfg(feature = "docker")]
        pub fn unpack_docker_layer_archive_with_entry_cap(
            &self,
            archive_path: &std::path::Path,
            destination: &std::path::Path,
            entry_cap: u64,
        ) -> Result<Vec<keyhog_core::SourceError>, keyhog_core::SourceError> {
            crate::docker::unpack_layer_archive_with_entry_cap_for_test(
                archive_path,
                destination,
                entry_cap,
            )
        }

        #[cfg(feature = "docker")]
        pub fn unpack_docker_layer_archive_with_caps(
            &self,
            archive_path: &std::path::Path,
            destination: &std::path::Path,
            entry_cap: u64,
            total_cap: u64,
        ) -> Result<Vec<keyhog_core::SourceError>, keyhog_core::SourceError> {
            crate::docker::unpack_layer_archive_with_caps_for_test(
                archive_path,
                destination,
                entry_cap,
                total_cap,
            )
        }

        #[cfg(feature = "docker")]
        pub fn unpack_docker_image_archive_with_entry_cap(
            &self,
            archive_path: &std::path::Path,
            destination: &std::path::Path,
            entry_cap: u64,
        ) -> Result<Vec<keyhog_core::SourceError>, keyhog_core::SourceError> {
            crate::docker::unpack_image_archive_with_entry_cap_for_test(
                archive_path,
                destination,
                entry_cap,
            )
        }

        #[cfg(feature = "docker")]
        /// Unpack several layer tars through ONE image-scoped unpack budget, so
        /// the image-wide ceiling is reachable without a docker daemon.
        pub fn unpack_docker_layers_with_shared_budget(
            &self,
            archives: &[(&std::path::Path, &std::path::Path)],
            total_cap: u64,
        ) -> Result<Vec<keyhog_core::SourceError>, keyhog_core::SourceError> {
            crate::docker::unpack_layers_with_shared_budget_for_test(archives, total_cap)
        }

        #[cfg(feature = "docker")]
        pub fn stream_docker_layers_with_shared_budget(
            &self,
            archives: &[&std::path::Path],
            total_cap: u64,
            respect_default_excludes: bool,
        ) -> Result<
            Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>>,
            keyhog_core::SourceError,
        > {
            crate::docker::stream_layers_with_shared_budget_for_test(
                archives,
                total_cap,
                respect_default_excludes,
            )
        }

        #[cfg(feature = "docker")]
        pub fn rewrite_streamed_docker_layer_chunk(
            &self,
            chunk: keyhog_core::Chunk,
            image: &str,
            layer_name: &str,
        ) -> Result<keyhog_core::Chunk, keyhog_core::SourceError> {
            crate::docker::rewrite_streamed_layer_chunk_for_test(chunk, image, layer_name)
        }

        #[cfg(feature = "docker")]
        pub fn docker_rewrite_layer_chunks<I>(
            &self,
            chunks: I,
            image: &str,
            layer_root: &std::path::Path,
            layer_name: &str,
        ) -> Result<
            Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>>,
            keyhog_core::SourceError,
        >
        where
            I: IntoIterator<Item = Result<keyhog_core::Chunk, keyhog_core::SourceError>>,
        {
            crate::docker::rewrite_layer_chunks_for_test(chunks, image, layer_root, layer_name)
        }

        #[cfg(feature = "docker")]
        pub fn validate_docker_tar_archive(
            &self,
            archive_path: &std::path::Path,
        ) -> Result<(), keyhog_core::SourceError> {
            crate::docker::validate_tar_archive_for_test(archive_path)
        }

        #[cfg(feature = "docker")]
        pub fn validate_docker_tar_archive_with_total_cap(
            &self,
            archive_path: &std::path::Path,
            total_cap: u64,
        ) -> Result<(), keyhog_core::SourceError> {
            crate::docker::validate_tar_archive_with_total_cap_for_test(archive_path, total_cap)
        }

        #[cfg(feature = "azure")]
        pub fn azure_blob_source_with_max_objects<U>(
            &self,
            container_url: U,
            max_objects: usize,
        ) -> crate::AzureBlobSource
        where
            U: Into<String>,
        {
            crate::AzureBlobSource::new(container_url)
                .with_max_objects(max_objects)
                .with_http_config(crate::http::HttpClientConfig::allowing_private_endpoint())
        }

        #[cfg(feature = "azure")]
        pub fn azure_blob_source_with_limits<U>(
            &self,
            container_url: U,
            limits: crate::SourceLimits,
        ) -> crate::AzureBlobSource
        where
            U: Into<String>,
        {
            crate::AzureBlobSource::new(container_url)
                .with_limits(limits)
                .with_http_config(crate::http::HttpClientConfig::allowing_private_endpoint())
        }

        pub fn extract_printable_strings(
            &self,
            bytes: &[u8],
            min_len: usize,
        ) -> Vec<keyhog_core::SensitiveString> {
            crate::strings::extract_printable_strings(bytes, min_len)
        }

        pub fn join_sensitive_strings(
            &self,
            parts: &[keyhog_core::SensitiveString],
            sep: &str,
        ) -> keyhog_core::SensitiveString {
            crate::strings::join_sensitive_strings(parts, sep)
        }

        /// The exact separator `join_printable_runs` places between two
        /// independent printable runs, so a test can split a binary-strings
        /// chunk body back into its run list without restating the literal.
        pub fn printable_run_separator(&self) -> &'static str {
            crate::strings::RUN_SEPARATOR
        }

        #[cfg(feature = "git")]
        pub fn git_max_commits_limit(&self, cap: usize) -> Option<usize> {
            crate::git::max_commits_limit(cap)
        }

        #[cfg(feature = "git")]
        pub fn git_source_configured_max_commits(&self, cap: usize) -> Option<usize> {
            crate::git::GitSource::new(std::path::PathBuf::from("."))
                .with_max_commits(cap)
                .max_commits
        }

        #[cfg(feature = "git")]
        pub fn git_history_source_configured_max_commits(&self, cap: usize) -> Option<usize> {
            crate::git::GitHistorySource::new(std::path::PathBuf::from("."))
                .with_max_commits(cap)
                .max_commits
        }

        #[cfg(all(feature = "git", debug_assertions))]
        pub fn reset_max_buffered_git_blob_chunks(&self) {
            crate::git::reset_max_buffered_git_blob_chunks();
        }

        #[cfg(all(feature = "git", debug_assertions))]
        pub fn max_buffered_git_blob_chunks(&self) -> usize {
            crate::git::max_buffered_git_blob_chunks()
        }

        #[cfg(feature = "web")]
        pub fn redact_url(&self, url: &str) -> String {
            crate::web::redact_url(url).into_owned()
        }

        #[cfg(feature = "web")]
        pub fn redirect_pin_key(&self, url: &str) -> Option<String> {
            crate::web::redirect_pin_key(url)
        }

        #[cfg(feature = "github")]
        pub fn github_rate_limit_backoff_secs(
            &self,
            retry_after: Option<u64>,
            attempt: usize,
        ) -> u64 {
            crate::github_org::rate_limit_backoff_secs(retry_after, attempt)
        }

        #[cfg(feature = "github")]
        pub fn github_max_backoff_secs(&self) -> u64 {
            crate::github_org::MAX_BACKOFF_SECS
        }

        #[cfg(feature = "github")]
        pub fn github_repos_per_page(&self) -> usize {
            crate::github_org::REPOS_PER_PAGE
        }

        #[cfg(feature = "web")]
        pub fn is_disallowed_web_host(&self, url: &str) -> bool {
            crate::web::is_disallowed_web_host(url)
        }

        #[cfg(feature = "web")]
        pub fn is_disallowed_ip(&self, ip: std::net::IpAddr) -> bool {
            crate::web::is_disallowed_ip(ip)
        }

        #[cfg(feature = "web")]
        pub fn resolve_and_screen(
            &self,
            host: &str,
            port: u16,
            timeout: std::time::Duration,
        ) -> Result<Vec<std::net::SocketAddr>, keyhog_core::SourceError> {
            crate::web::resolve_and_screen(host, port, timeout)
        }

        #[cfg(feature = "web")]
        pub fn build_web_client(
            &self,
            http: &crate::http::HttpClientConfig,
            original_url: &str,
            use_proxy: bool,
            allow_autoroute_loopback_calibration_url: bool,
        ) -> Result<reqwest::blocking::Client, keyhog_core::SourceError> {
            crate::web::build_web_client(
                http,
                original_url,
                use_proxy,
                allow_autoroute_loopback_calibration_url,
            )
        }

        #[cfg(feature = "web")]
        pub fn web_source_with_autoroute_loopback_calibration(
            &self,
            urls: Vec<String>,
            allow: bool,
        ) -> crate::WebSource {
            crate::WebSource::new(urls).with_autoroute_loopback_calibration(allow)
        }

        #[cfg(feature = "slack")]
        pub fn slack_conversations_list_len_for_test(&self, body: &str) -> Result<usize, String> {
            crate::slack::conversations_list_len_for_test(body).map_err(|error| error.to_string())
        }

        #[cfg(feature = "slack")]
        pub fn slack_history_len_for_test(
            &self,
            body: &str,
            channel_id: &str,
        ) -> Result<usize, String> {
            crate::slack::history_len_for_test(body, channel_id).map_err(|error| error.to_string())
        }

        #[cfg(feature = "slack")]
        pub fn slack_conversations_list_next_cursor_for_test(
            &self,
            body: &str,
        ) -> Result<Option<String>, String> {
            crate::slack::conversations_list_next_cursor_for_test(body)
                .map_err(|error| error.to_string())
        }

        #[cfg(feature = "slack")]
        pub fn slack_history_next_cursor_for_test(
            &self,
            body: &str,
            channel_id: &str,
        ) -> Result<Option<String>, String> {
            crate::slack::history_next_cursor_for_test(body, channel_id)
                .map_err(|error| error.to_string())
        }

        #[cfg(feature = "slack")]
        pub fn slack_source_with_endpoint<T, E>(&self, token: T, endpoint: E) -> crate::SlackSource
        where
            T: Into<String>,
            E: Into<String>,
        {
            crate::SlackSource::new(token).with_endpoint(endpoint)
        }

        #[cfg(feature = "slack")]
        pub fn slack_source_with_endpoint_and_limits<T, E>(
            &self,
            token: T,
            endpoint: E,
            limits: crate::SourceLimits,
        ) -> crate::SlackSource
        where
            T: Into<String>,
            E: Into<String>,
        {
            crate::SlackSource::new(token)
                .with_endpoint(endpoint)
                .with_limits(limits)
        }

        #[cfg(feature = "slack")]
        pub fn slack_source_with_endpoint_and_lookback<T, E>(
            &self,
            token: T,
            endpoint: E,
            lookback_messages: usize,
        ) -> crate::SlackSource
        where
            T: Into<String>,
            E: Into<String>,
        {
            crate::SlackSource::new(token)
                .with_endpoint(endpoint)
                .with_lookback_messages(lookback_messages)
        }
    }
    /// Outcome of [`for_each_file_windowed_mmap_for_test`].
    pub enum ForEachWindowedMmapOutcome {
        Consumed,
        Fallback,
    }

    /// Stream a file through the windowed-mmap path, calling `emit` for each
    /// decoded `(offset, text)` window. The bool return value of `emit` stops
    /// further emission when `false`.
    pub fn for_each_file_windowed_mmap_for_test<F>(
        path: &std::path::Path,
        window_size: usize,
        overlap: usize,
        mut emit: F,
    ) -> ForEachWindowedMmapOutcome
    where
        F: FnMut(Result<(usize, String), String>) -> bool,
    {
        match crate::filesystem::for_each_file_windowed_mmap_for_test(
            path,
            window_size,
            overlap,
            |row| emit(row),
        ) {
            crate::filesystem::ForEachWindowedMmapTestOutcome::Consumed => {
                ForEachWindowedMmapOutcome::Consumed
            }
            crate::filesystem::ForEachWindowedMmapTestOutcome::Fallback => {
                ForEachWindowedMmapOutcome::Fallback
            }
        }
    }

    /// Canonical zstd frame magic bytes used by the filesystem text decoder's
    /// binary-magic rejection path.
    pub fn zstd_frame_magic_for_test() -> &'static [u8] {
        crate::magic::ZSTD_FRAME_MAGIC
    }

    #[cfg(feature = "git")]
    pub fn oversized_staged_header_path_outcome_for_test(
        input: &[u8],
        path_limit: usize,
    ) -> (String, bool, Vec<u8>) {
        let mut reader = std::io::Cursor::new(input);
        let mut raw_path = Vec::new();
        let outcome = crate::git::consume_oversized_staged_header_path(
            &mut reader,
            &mut raw_path,
            path_limit,
        );
        let remainder = input[reader.position() as usize..].to_vec();
        (
            outcome.error.to_string(),
            outcome.continue_later_records,
            remainder,
        )
    }
}

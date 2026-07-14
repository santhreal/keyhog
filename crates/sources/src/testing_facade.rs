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

    pub trait SourceTestApi {
        /// Enter an exclusive scan scope for a counter-asserting test. Held for
        /// the whole `reset → scan → read skip_counts()` window, it serializes
        /// against every other gated scan so concurrent tests cannot pollute the
        /// process-global skip counters this test is about to assert on.
        fn skip_counter_guard(&self) -> ScanCounterScope;
        /// Archive entry-name path-traversal validator (test accessor; the
        /// `src/filesystem/extract/**` no-inline-tests contract keeps the unit
        /// coverage out of `src`). Returns `Ok(())` for a safe relative entry
        /// name and `Err(reason)` naming the refusal for traversal / absolute /
        /// backslash / NUL / over-encoded names.
        fn validate_archive_entry_name(&self, name: &str) -> Result<(), String>;
        /// OCI/Docker manifest-vs-index classification (test accessor so the
        /// `src/docker/**` no-inline-tests contract holds; coverage lives in
        /// `tests/docker_oci_classification.rs`).
        #[cfg(feature = "docker")]
        fn oci_descriptor_points_to_index(&self, media_type: Option<&str>, body: &[u8]) -> bool;
        /// OCI blob sha256 verification through the crate's safe opener
        /// (O_NOFOLLOW): returns whether the blob at `path` matches `digest`.
        /// Critically REFUSES a symlink blob a raw `File::open` would follow (test
        /// accessor so the `src/docker/**` no-inline-tests contract holds; coverage
        /// lives in `tests/regression_docker_oci_safe_open.rs`).
        #[cfg(feature = "docker")]
        fn verify_oci_blob_sha256_ok(&self, path: &std::path::Path, digest: &str) -> bool;
        fn set_skip_counts(&self, counts: crate::SkipCounts);
        fn reset_skip_counters(&self);
        fn bump_skipped_over_max_size(&self, delta: usize);
        fn bump_git_object_unreadable(&self, delta: usize);
        fn read_stdin_test_input_with_limit(
            &self,
            input: &[u8],
            max_bytes: usize,
        ) -> std::io::Result<String>;
        #[cfg(any(
            feature = "git",
            feature = "docker",
            feature = "github",
            feature = "gitlab",
            feature = "bitbucket"
        ))]
        fn drain_process_stderr_excerpt(&self, reader: &mut dyn std::io::Read) -> String;
        fn expand_har(
            &self,
            bytes: &[u8],
            path_str: &str,
            max_size: u64,
        ) -> Option<Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>>>;
        fn compact_har_base64_text(&self, text: &str) -> String;
        fn reader_pool_thread_count(&self, scanner_threads: usize) -> usize;
        fn reader_panic_rows(&self) -> Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>>;
        fn reader_process_entry_panic_rows(
            &self,
        ) -> Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>>;
        fn process_entry_with_recorded_size(
            &self,
            path: std::path::PathBuf,
            recorded_size: u64,
            max_size: u64,
        ) -> Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>>;
        fn process_entry_with_merkle(
            &self,
            path: std::path::PathBuf,
            recorded_size: u64,
            max_size: u64,
            merkle: std::sync::Arc<keyhog_core::MerkleIndex>,
        ) -> (
            Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>>,
            usize,
        );
        fn configured_reader_pool_thread_count(
            &self,
            scanner_threads: usize,
            configured: std::num::NonZeroUsize,
        ) -> usize;
        fn filesystem_with_window_config(
            &self,
            root: std::path::PathBuf,
            window_size: usize,
            overlap: usize,
        ) -> crate::FilesystemSource;
        fn filesystem_skipped_count(&self, source: &crate::FilesystemSource) -> usize;
        fn max_buffered_read_bytes(&self) -> u64;
        fn mmap_toctou_sanity_cap_bytes(&self) -> u64;
        fn read_file_safe_capped(
            &self,
            path: &std::path::Path,
            cap: u64,
        ) -> std::io::Result<Vec<u8>>;
        fn read_file_mmap(&self, path: &std::path::Path) -> Option<String>;
        fn read_file_for_compressed_input(
            &self,
            path: &std::path::Path,
            size_cap: u64,
        ) -> Option<Vec<u8>>;
        fn read_file_windowed_mmap_len(
            &self,
            path: &std::path::Path,
            window_size: usize,
            overlap: usize,
        ) -> Option<usize>;
        fn slice_into_windows(
            &self,
            bytes: &[u8],
            window_size: usize,
            overlap: usize,
        ) -> Vec<String>;
        fn decode_utf16(&self, bytes: &[u8]) -> Option<String>;
        fn looks_binary(&self, bytes: &[u8]) -> bool;
        fn duplicate_zip_central_entries_error(
            &self,
            path: &std::path::Path,
        ) -> Result<String, String>;
        fn duplicate_zip_local_entry_data_error(
            &self,
            path: &std::path::Path,
            compressed_size: u64,
        ) -> Result<String, String>;
        fn duplicate_zip_reopen_error(&self, path: &std::path::Path) -> Option<String>;
        fn filesystem_default_max_file_size(&self) -> u64;
        #[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
        fn cloud_is_probably_text_object_key(&self, key: &str) -> bool;
        #[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
        fn cloud_is_binary_content_type(&self, content_type: &str) -> bool;
        #[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
        fn cloud_read_text_object_body_from_url(
            &self,
            url: &str,
            max_bytes: u64,
        ) -> Result<Option<String>, keyhog_core::SourceError>;
        #[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
        fn cloud_record_unreadable_object_skip(
            &self,
            source: &str,
            item_kind: &str,
            display_path: &str,
            reason: &str,
        ) -> keyhog_core::SourceError;

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
        fn http_request_timeout(&self) -> std::time::Duration;
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
        fn http_effective_proxy(&self, http: &crate::http::HttpClientConfig) -> Option<String>;
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
        fn http_effective_insecure_tls(&self, http: &crate::http::HttpClientConfig) -> bool;
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
        fn http_blocking_client_builder(
            &self,
            http: &crate::http::HttpClientConfig,
        ) -> Result<reqwest::blocking::ClientBuilder, String>;
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
        fn http_async_client_builder(
            &self,
            http: &crate::http::HttpClientConfig,
        ) -> Result<reqwest::ClientBuilder, String>;

        #[cfg(feature = "gcs")]
        fn gcs_endpoint_is_google(&self, endpoint: &str) -> bool;
        #[cfg(feature = "gcs")]
        fn gcs_credential_forward_allowed(&self, allow_explicit: bool) -> bool;
        #[cfg(feature = "gcs")]
        fn gcs_source_with_endpoint<B, E>(&self, bucket: B, endpoint: E) -> crate::GcsSource
        where
            B: Into<String>,
            E: Into<String>;
        #[cfg(feature = "gcs")]
        fn gcs_source_with_endpoint_and_limits<B, E>(
            &self,
            bucket: B,
            endpoint: E,
            limits: crate::SourceLimits,
        ) -> crate::GcsSource
        where
            B: Into<String>,
            E: Into<String>;
        #[cfg(feature = "gcs")]
        fn gcs_source_with_endpoint_max_objects<B, E>(
            &self,
            bucket: B,
            endpoint: E,
            max_objects: usize,
        ) -> crate::GcsSource
        where
            B: Into<String>,
            E: Into<String>;
        #[cfg(feature = "s3")]
        fn s3_endpoint_is_aws(&self, endpoint: &str) -> bool;
        #[cfg(feature = "s3")]
        fn s3_credential_forward_allowed(&self, allow_explicit: bool) -> bool;
        /// Build an `S3Source` at a custom (typically loopback httpmock) endpoint.
        ///
        /// SECURITY NOTE: every `*_with_endpoint*` loopback-mock builder OPTS INTO
        /// private endpoints (`allow_private_endpoint = true`) so the mock at
        /// `127.0.0.1` is reachable, i.e. it DISABLES the cloud SSRF endpoint
        /// screen. A test that must exercise the ACTIVE screen (private/metadata
        /// refusal, public-host acceptance) MUST instead use
        /// `s3_source_with_endpoint_allow_private(bucket, endpoint, false)`, or it
        /// silently passes with the screen off.
        #[cfg(feature = "s3")]
        fn s3_source_with_endpoint<B, E>(&self, bucket: B, endpoint: E) -> crate::S3Source
        where
            B: Into<String>,
            E: Into<String>;
        #[cfg(feature = "s3")]
        fn s3_source_with_endpoint_and_limits<B, E>(
            &self,
            bucket: B,
            endpoint: E,
            limits: crate::SourceLimits,
        ) -> crate::S3Source
        where
            B: Into<String>,
            E: Into<String>;
        #[cfg(feature = "s3")]
        fn s3_source_with_endpoint_max_objects<B, E>(
            &self,
            bucket: B,
            endpoint: E,
            max_objects: usize,
        ) -> crate::S3Source
        where
            B: Into<String>,
            E: Into<String>;
        /// Build an S3 source whose SSRF endpoint screen is either default-on
        /// (`allow_private = false`) or opted-out (`true`), the config-flag
        /// replacement for the retired `KEYHOG_ALLOW_PRIVATE_CLOUD_ENDPOINT` env,
        /// used by the SSRF-refusal regression tests to drive both paths.
        #[cfg(feature = "s3")]
        fn s3_source_with_endpoint_allow_private<B, E>(
            &self,
            bucket: B,
            endpoint: E,
            allow_private: bool,
        ) -> crate::S3Source
        where
            B: Into<String>,
            E: Into<String>;
        /// GCS counterpart of [`s3_source_with_endpoint_allow_private`].
        #[cfg(feature = "gcs")]
        fn gcs_source_with_endpoint_allow_private<B, E>(
            &self,
            bucket: B,
            endpoint: E,
            allow_private: bool,
        ) -> crate::GcsSource
        where
            B: Into<String>,
            E: Into<String>;
        /// Build an Azure Blob source whose container URL is permitted to be a
        /// private / loopback endpoint (httpmock binds 127.0.0.1), the loopback
        /// config-flag replacement used by the azure listing/drop regressions.
        #[cfg(feature = "azure")]
        fn azure_blob_source<U>(&self, container_url: U) -> crate::AzureBlobSource
        where
            U: Into<String>;
        #[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
        fn git_clone_timeout(&self) -> std::time::Duration;
        #[cfg(feature = "binary")]
        fn ghidra_analysis_timeout(&self) -> std::time::Duration;
        #[cfg(feature = "docker")]
        fn docker_export_timeout(&self) -> std::time::Duration;
        #[cfg(feature = "binary")]
        fn binary_strings_only<P>(&self, path: P) -> crate::BinarySource
        where
            P: Into<std::path::PathBuf>;

        fn user_agent(&self, suffix: Option<&str>) -> String;

        #[cfg(feature = "binary")]
        fn extract_string_literals(&self, line: &str) -> Vec<String>;
        #[cfg(feature = "binary")]
        fn extract_sections(&self, bytes: &[u8], path: &str) -> Option<Vec<keyhog_core::Chunk>>;
        #[cfg(feature = "binary")]
        fn resolve_binary_section_name<'a>(
            &self,
            resolved: Option<&'a str>,
            sh_name: usize,
        ) -> &'a str;

        #[cfg(feature = "github")]
        fn validate_repo_name(&self, name: &str) -> Result<(), keyhog_core::SourceError>;
        #[cfg(feature = "github")]
        fn github_collaboration_source_with_endpoint(
            &self,
            repository: &str,
            endpoint: &str,
            selection: crate::GitHubCollaborationSelection,
            limits: crate::SourceLimits,
        ) -> Result<crate::GitHubCollaborationSource, keyhog_core::SourceError>;
        #[cfg(feature = "github")]
        fn github_collaboration_wiki_chunks_from_repo(
            &self,
            repo: &std::path::Path,
            limits: crate::SourceLimits,
        ) -> Result<Vec<keyhog_core::Chunk>, keyhog_core::SourceError>;
        #[cfg(feature = "github")]
        fn validate_org_name(&self, name: &str) -> Result<(), keyhog_core::SourceError>;
        #[cfg(feature = "github")]
        fn validate_clone_url(&self, url: &str) -> Result<(), keyhog_core::SourceError>;
        #[cfg(feature = "github")]
        fn github_org_rewrite_chunk_path(
            &self,
            chunk: keyhog_core::Chunk,
            org: &str,
            repo_name: &str,
            clone_path: &std::path::Path,
        ) -> Result<keyhog_core::Chunk, keyhog_core::SourceError>;
        #[cfg(feature = "github")]
        fn github_org_scan_repo_chunks<I>(
            &self,
            chunks: I,
            org: &str,
            repo_name: &str,
            clone_path: &std::path::Path,
        ) -> Result<Vec<keyhog_core::Chunk>, keyhog_core::SourceError>
        where
            I: IntoIterator<Item = Result<keyhog_core::Chunk, keyhog_core::SourceError>>;
        #[cfg(feature = "github")]
        fn github_org_listing_truncated_error(
            &self,
            org: &str,
            repo_count: usize,
            max_pages: usize,
        ) -> keyhog_core::SourceError;

        #[cfg(feature = "gitlab")]
        fn validate_gitlab_group_path(&self, group: &str) -> Result<(), keyhog_core::SourceError>;
        #[cfg(feature = "gitlab")]
        fn gitlab_group_listing_truncated_error(
            &self,
            group: &str,
            repo_count: usize,
            max_pages: usize,
        ) -> keyhog_core::SourceError;

        #[cfg(feature = "bitbucket")]
        fn validate_bitbucket_workspace(
            &self,
            workspace: &str,
        ) -> Result<(), keyhog_core::SourceError>;
        #[cfg(feature = "bitbucket")]
        fn bitbucket_workspace_listing_truncated_error(
            &self,
            workspace: &str,
            repo_count: usize,
            max_pages: usize,
        ) -> keyhog_core::SourceError;

        #[cfg(feature = "docker")]
        fn export_docker_image_archive(
            &self,
            docker_bin: &std::path::Path,
            image: &str,
            archive_path: &std::path::Path,
        ) -> Result<(), keyhog_core::SourceError>;
        #[cfg(feature = "docker")]
        fn docker_manifest_layer_archives(
            &self,
            root_path: &std::path::Path,
        ) -> Result<Vec<std::path::PathBuf>, keyhog_core::SourceError>;
        #[cfg(feature = "docker")]
        fn docker_manifest_config_chunks(
            &self,
            root_path: &std::path::Path,
            image: &str,
        ) -> Result<Vec<keyhog_core::Chunk>, keyhog_core::SourceError>;
        #[cfg(feature = "docker")]
        fn docker_archive_metadata_chunks(
            &self,
            root_path: &std::path::Path,
            image: &str,
        ) -> Result<Vec<keyhog_core::Chunk>, keyhog_core::SourceError>;
        #[cfg(feature = "docker")]
        fn unpack_docker_layer_archive(
            &self,
            archive_path: &std::path::Path,
            destination: &std::path::Path,
        ) -> Result<Vec<keyhog_core::SourceError>, keyhog_core::SourceError>;
        #[cfg(feature = "docker")]
        fn unpack_docker_layer_archive_with_total_cap(
            &self,
            archive_path: &std::path::Path,
            destination: &std::path::Path,
            total_cap: u64,
        ) -> Result<Vec<keyhog_core::SourceError>, keyhog_core::SourceError>;
        #[cfg(feature = "docker")]
        fn unpack_docker_layer_archive_with_entry_cap(
            &self,
            archive_path: &std::path::Path,
            destination: &std::path::Path,
            entry_cap: u64,
        ) -> Result<Vec<keyhog_core::SourceError>, keyhog_core::SourceError>;
        #[cfg(feature = "docker")]
        fn unpack_docker_image_archive_with_entry_cap(
            &self,
            archive_path: &std::path::Path,
            destination: &std::path::Path,
            entry_cap: u64,
        ) -> Result<Vec<keyhog_core::SourceError>, keyhog_core::SourceError>;
        #[cfg(feature = "docker")]
        fn docker_rewrite_layer_chunks<I>(
            &self,
            chunks: I,
            image: &str,
            layer_root: &std::path::Path,
            layer_name: &str,
        ) -> Result<Vec<keyhog_core::Chunk>, keyhog_core::SourceError>
        where
            I: IntoIterator<Item = Result<keyhog_core::Chunk, keyhog_core::SourceError>>;
        #[cfg(feature = "docker")]
        fn validate_docker_tar_archive(
            &self,
            archive_path: &std::path::Path,
        ) -> Result<(), keyhog_core::SourceError>;
        #[cfg(feature = "docker")]
        fn validate_docker_tar_archive_with_total_cap(
            &self,
            archive_path: &std::path::Path,
            total_cap: u64,
        ) -> Result<(), keyhog_core::SourceError>;

        #[cfg(feature = "azure")]
        fn azure_blob_source_with_max_objects<U>(
            &self,
            container_url: U,
            max_objects: usize,
        ) -> crate::AzureBlobSource
        where
            U: Into<String>;
        #[cfg(feature = "azure")]
        fn azure_blob_source_with_limits<U>(
            &self,
            container_url: U,
            limits: crate::SourceLimits,
        ) -> crate::AzureBlobSource
        where
            U: Into<String>;

        fn extract_printable_strings(
            &self,
            bytes: &[u8],
            min_len: usize,
        ) -> Vec<keyhog_core::SensitiveString>;
        fn join_sensitive_strings(
            &self,
            parts: &[keyhog_core::SensitiveString],
            sep: &str,
        ) -> keyhog_core::SensitiveString;
        #[cfg(feature = "git")]
        fn git_max_commits_limit(&self, cap: usize) -> Option<usize>;
        #[cfg(feature = "git")]
        fn git_source_configured_max_commits(&self, cap: usize) -> Option<usize>;
        #[cfg(feature = "git")]
        fn git_history_source_configured_max_commits(&self, cap: usize) -> Option<usize>;
        #[cfg(feature = "web")]
        fn redact_url(&self, url: &str) -> String;
        #[cfg(feature = "web")]
        fn redirect_pin_key(&self, url: &str) -> Option<String>;
        #[cfg(feature = "github")]
        fn github_rate_limit_backoff_secs(&self, retry_after: Option<u64>, attempt: usize) -> u64;
        #[cfg(feature = "github")]
        fn github_max_backoff_secs(&self) -> u64;
        #[cfg(feature = "github")]
        fn github_repos_per_page(&self) -> usize;
        #[cfg(feature = "web")]
        fn is_disallowed_web_host(&self, url: &str) -> bool;
        #[cfg(feature = "web")]
        fn is_disallowed_ip(&self, ip: std::net::IpAddr) -> bool;
        #[cfg(feature = "web")]
        fn resolve_and_screen(
            &self,
            host: &str,
            port: u16,
            timeout: std::time::Duration,
        ) -> Result<Vec<std::net::SocketAddr>, keyhog_core::SourceError>;
        #[cfg(feature = "web")]
        fn build_web_client(
            &self,
            http: &crate::http::HttpClientConfig,
            original_url: &str,
            use_proxy: bool,
            allow_autoroute_loopback_calibration_url: bool,
        ) -> Result<reqwest::blocking::Client, keyhog_core::SourceError>;
        #[cfg(feature = "web")]
        fn web_source_with_autoroute_loopback_calibration(
            &self,
            urls: Vec<String>,
            allow: bool,
        ) -> crate::WebSource;

        #[cfg(feature = "slack")]
        fn slack_conversations_list_len_for_test(&self, body: &str) -> Result<usize, String>;
        #[cfg(feature = "slack")]
        fn slack_history_len_for_test(&self, body: &str, channel_id: &str)
            -> Result<usize, String>;
        #[cfg(feature = "slack")]
        fn slack_conversations_list_next_cursor_for_test(
            &self,
            body: &str,
        ) -> Result<Option<String>, String>;
        #[cfg(feature = "slack")]
        fn slack_history_next_cursor_for_test(
            &self,
            body: &str,
            channel_id: &str,
        ) -> Result<Option<String>, String>;
        #[cfg(feature = "slack")]
        fn slack_source_with_endpoint<T, E>(&self, token: T, endpoint: E) -> crate::SlackSource
        where
            T: Into<String>,
            E: Into<String>;
        #[cfg(feature = "slack")]
        fn slack_source_with_endpoint_and_limits<T, E>(
            &self,
            token: T,
            endpoint: E,
            limits: crate::SourceLimits,
        ) -> crate::SlackSource
        where
            T: Into<String>,
            E: Into<String>;
        #[cfg(feature = "slack")]
        fn slack_source_with_endpoint_and_lookback<T, E>(
            &self,
            token: T,
            endpoint: E,
            lookback_messages: usize,
        ) -> crate::SlackSource
        where
            T: Into<String>,
            E: Into<String>;
    }

    impl SourceTestApi for TestApi {
        fn skip_counter_guard(&self) -> ScanCounterScope {
            crate::enter_exclusive_scan_scope()
        }

        fn validate_archive_entry_name(&self, name: &str) -> Result<(), String> {
            crate::filesystem::validate_scan_archive_entry_name(name).map_err(str::to_string)
        }

        #[cfg(feature = "docker")]
        fn oci_descriptor_points_to_index(&self, media_type: Option<&str>, body: &[u8]) -> bool {
            crate::docker::oci::descriptor_points_to_index_for_test(media_type, body)
        }

        #[cfg(feature = "docker")]
        fn verify_oci_blob_sha256_ok(&self, path: &std::path::Path, digest: &str) -> bool {
            crate::docker::oci::verify_oci_blob_sha256(path, digest).is_ok()
        }

        fn set_skip_counts(&self, counts: crate::SkipCounts) {
            crate::skip::set_skip_counts_for_test(counts);
        }

        fn reset_skip_counters(&self) {
            crate::reset_skip_counters();
        }

        fn bump_skipped_over_max_size(&self, delta: usize) {
            let _event = crate::record_skip_events(crate::SourceSkipEvent::OverMaxSize, delta);
        }

        fn bump_git_object_unreadable(&self, delta: usize) {
            let _event =
                crate::record_skip_events(crate::SourceSkipEvent::GitObjectUnreadable, delta);
        }

        fn read_stdin_test_input_with_limit(
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
        fn drain_process_stderr_excerpt(&self, reader: &mut dyn std::io::Read) -> String {
            crate::process_excerpt::drain_stderr_excerpt(reader)
        }

        fn expand_har(
            &self,
            bytes: &[u8],
            path_str: &str,
            max_size: u64,
        ) -> Option<Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>>> {
            crate::har::try_expand_har(bytes, path_str, max_size)
        }

        fn compact_har_base64_text(&self, text: &str) -> String {
            crate::har::compact_base64_text(text).into_owned()
        }

        fn reader_pool_thread_count(&self, scanner_threads: usize) -> usize {
            crate::filesystem::reader_pool_thread_count_for_test(scanner_threads)
        }

        fn reader_panic_rows(&self) -> Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>> {
            crate::filesystem::reader_panic_rows_for_test()
        }

        fn reader_process_entry_panic_rows(
            &self,
        ) -> Vec<Result<keyhog_core::Chunk, keyhog_core::SourceError>> {
            crate::filesystem::reader_process_entry_panic_rows_for_test()
        }

        fn process_entry_with_recorded_size(
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

        fn process_entry_with_merkle(
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

        fn configured_reader_pool_thread_count(
            &self,
            scanner_threads: usize,
            configured: std::num::NonZeroUsize,
        ) -> usize {
            crate::filesystem::reader_pool_thread_count_with_config_for_test(
                scanner_threads,
                configured,
            )
        }

        fn filesystem_with_window_config(
            &self,
            root: std::path::PathBuf,
            window_size: usize,
            overlap: usize,
        ) -> crate::FilesystemSource {
            crate::FilesystemSource::new(root).with_window_config(window_size, overlap)
        }

        fn filesystem_skipped_count(&self, source: &crate::FilesystemSource) -> usize {
            source
                .skipped_counter()
                .load(std::sync::atomic::Ordering::Relaxed)
        }

        fn max_buffered_read_bytes(&self) -> u64 {
            crate::filesystem::max_buffered_read_bytes_for_test()
        }

        fn mmap_toctou_sanity_cap_bytes(&self) -> u64 {
            crate::filesystem::mmap_toctou_sanity_cap_bytes_for_test()
        }

        fn read_file_safe_capped(
            &self,
            path: &std::path::Path,
            cap: u64,
        ) -> std::io::Result<Vec<u8>> {
            crate::filesystem::read_file_safe_capped_for_test(path, cap)
        }

        fn read_file_mmap(&self, path: &std::path::Path) -> Option<String> {
            crate::filesystem::read_file_mmap_for_test(path)
        }

        fn read_file_for_compressed_input(
            &self,
            path: &std::path::Path,
            size_cap: u64,
        ) -> Option<Vec<u8>> {
            crate::filesystem::read_file_for_compressed_input_for_test(path, size_cap)
        }

        fn read_file_windowed_mmap_len(
            &self,
            path: &std::path::Path,
            window_size: usize,
            overlap: usize,
        ) -> Option<usize> {
            crate::filesystem::read_file_windowed_mmap_len_for_test(path, window_size, overlap)
        }

        fn slice_into_windows(
            &self,
            bytes: &[u8],
            window_size: usize,
            overlap: usize,
        ) -> Vec<String> {
            crate::filesystem::slice_into_windows_for_test(bytes, window_size, overlap)
        }

        fn decode_utf16(&self, bytes: &[u8]) -> Option<String> {
            crate::filesystem::decode_utf16_for_test(bytes)
        }

        fn looks_binary(&self, bytes: &[u8]) -> bool {
            crate::filesystem::looks_binary_for_test(bytes)
        }

        fn duplicate_zip_central_entries_error(
            &self,
            path: &std::path::Path,
        ) -> Result<String, String> {
            crate::filesystem::duplicate_zip_central_entries_error_for_test(path)
        }

        fn duplicate_zip_local_entry_data_error(
            &self,
            path: &std::path::Path,
            compressed_size: u64,
        ) -> Result<String, String> {
            crate::filesystem::duplicate_zip_local_entry_data_error_for_test(path, compressed_size)
        }

        fn duplicate_zip_reopen_error(&self, path: &std::path::Path) -> Option<String> {
            crate::filesystem::duplicate_zip_reopen_error_for_test(path)
        }

        fn filesystem_default_max_file_size(&self) -> u64 {
            crate::filesystem::default_max_file_size_for_test()
        }

        #[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
        fn cloud_is_probably_text_object_key(&self, key: &str) -> bool {
            crate::cloud::is_probably_text_object_key(key)
        }

        #[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
        fn cloud_is_binary_content_type(&self, content_type: &str) -> bool {
            crate::cloud::is_binary_content_type(content_type)
        }

        #[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
        fn cloud_read_text_object_body_from_url(
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
        fn cloud_record_unreadable_object_skip(
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
        fn http_request_timeout(&self) -> std::time::Duration {
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
        fn http_effective_proxy(&self, http: &crate::http::HttpClientConfig) -> Option<String> {
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
        fn http_effective_insecure_tls(&self, http: &crate::http::HttpClientConfig) -> bool {
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
        fn http_blocking_client_builder(
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
        fn http_async_client_builder(
            &self,
            http: &crate::http::HttpClientConfig,
        ) -> Result<reqwest::ClientBuilder, String> {
            crate::http::async_client_builder(http)
        }

        #[cfg(feature = "gcs")]
        fn gcs_endpoint_is_google(&self, endpoint: &str) -> bool {
            crate::gcs::endpoint_is_google(endpoint)
        }

        #[cfg(feature = "gcs")]
        fn gcs_credential_forward_allowed(&self, allow_explicit: bool) -> bool {
            crate::cloud::credential_forward_allowed(allow_explicit)
        }

        #[cfg(feature = "gcs")]
        fn gcs_source_with_endpoint<B, E>(&self, bucket: B, endpoint: E) -> crate::GcsSource
        where
            B: Into<String>,
            E: Into<String>,
        {
            crate::GcsSource::new(bucket)
                .with_endpoint(endpoint)
                .with_http_config(crate::http::HttpClientConfig::allowing_private_endpoint())
        }

        #[cfg(feature = "gcs")]
        fn gcs_source_with_endpoint_and_limits<B, E>(
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
        fn gcs_source_with_endpoint_max_objects<B, E>(
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
        fn s3_endpoint_is_aws(&self, endpoint: &str) -> bool {
            crate::s3::endpoint_is_aws(endpoint)
        }

        #[cfg(feature = "s3")]
        fn s3_credential_forward_allowed(&self, allow_explicit: bool) -> bool {
            crate::cloud::credential_forward_allowed(allow_explicit)
        }

        #[cfg(feature = "s3")]
        fn s3_source_with_endpoint<B, E>(&self, bucket: B, endpoint: E) -> crate::S3Source
        where
            B: Into<String>,
            E: Into<String>,
        {
            crate::S3Source::new(bucket)
                .with_endpoint(endpoint)
                .with_http_config(crate::http::HttpClientConfig::allowing_private_endpoint())
        }

        #[cfg(feature = "s3")]
        fn s3_source_with_endpoint_and_limits<B, E>(
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
        fn s3_source_with_endpoint_max_objects<B, E>(
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
        fn s3_source_with_endpoint_allow_private<B, E>(
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
        fn gcs_source_with_endpoint_allow_private<B, E>(
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
        fn azure_blob_source<U>(&self, container_url: U) -> crate::AzureBlobSource
        where
            U: Into<String>,
        {
            crate::AzureBlobSource::new(container_url)
                .with_http_config(crate::http::HttpClientConfig::allowing_private_endpoint())
        }

        #[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
        fn git_clone_timeout(&self) -> std::time::Duration {
            crate::timeouts::GIT_CLONE
        }

        #[cfg(feature = "binary")]
        fn ghidra_analysis_timeout(&self) -> std::time::Duration {
            crate::timeouts::GHIDRA_ANALYSIS
        }

        #[cfg(feature = "docker")]
        fn docker_export_timeout(&self) -> std::time::Duration {
            crate::timeouts::DOCKER_EXPORT
        }

        #[cfg(feature = "binary")]
        fn binary_strings_only<P>(&self, path: P) -> crate::BinarySource
        where
            P: Into<std::path::PathBuf>,
        {
            crate::BinarySource::strings_only(path)
        }

        fn user_agent(&self, suffix: Option<&str>) -> String {
            crate::http::user_agent(suffix)
        }

        #[cfg(feature = "binary")]
        fn extract_string_literals(&self, line: &str) -> Vec<String> {
            let mut out = Vec::new();
            crate::binary::literals::extract_string_literals(line, &mut out);
            out
        }

        #[cfg(feature = "binary")]
        fn extract_sections(&self, bytes: &[u8], path: &str) -> Option<Vec<keyhog_core::Chunk>> {
            crate::binary::sections::extract_sections(bytes, path)
        }

        #[cfg(feature = "binary")]
        fn resolve_binary_section_name<'a>(
            &self,
            resolved: Option<&'a str>,
            sh_name: usize,
        ) -> &'a str {
            crate::binary::sections::resolve_section_name(resolved, sh_name)
        }

        #[cfg(feature = "github")]
        fn validate_repo_name(&self, name: &str) -> Result<(), keyhog_core::SourceError> {
            crate::github_org::validate_repo_name(name)
        }

        #[cfg(feature = "github")]
        fn github_collaboration_source_with_endpoint(
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
        fn github_collaboration_wiki_chunks_from_repo(
            &self,
            repo: &std::path::Path,
            limits: crate::SourceLimits,
        ) -> Result<Vec<keyhog_core::Chunk>, keyhog_core::SourceError> {
            crate::github_collaboration::collect_wiki_repo_for_test(repo, limits)
        }

        #[cfg(feature = "github")]
        fn validate_org_name(&self, name: &str) -> Result<(), keyhog_core::SourceError> {
            crate::github_org::validate_org_name(name)
        }

        #[cfg(feature = "github")]
        fn validate_clone_url(&self, url: &str) -> Result<(), keyhog_core::SourceError> {
            crate::github_org::validate_clone_url(url)
        }

        #[cfg(feature = "github")]
        fn github_org_rewrite_chunk_path(
            &self,
            chunk: keyhog_core::Chunk,
            org: &str,
            repo_name: &str,
            clone_path: &std::path::Path,
        ) -> Result<keyhog_core::Chunk, keyhog_core::SourceError> {
            crate::github_org::rewrite_chunk_path_for_test(chunk, org, repo_name, clone_path)
        }

        #[cfg(feature = "github")]
        fn github_org_scan_repo_chunks<I>(
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
        fn github_org_listing_truncated_error(
            &self,
            org: &str,
            repo_count: usize,
            max_pages: usize,
        ) -> keyhog_core::SourceError {
            crate::github_org::github_listing_truncated_error_for_test(org, repo_count, max_pages)
        }

        #[cfg(feature = "gitlab")]
        fn validate_gitlab_group_path(&self, group: &str) -> Result<(), keyhog_core::SourceError> {
            crate::gitlab_group::validate_group_path(group)
        }

        #[cfg(feature = "gitlab")]
        fn gitlab_group_listing_truncated_error(
            &self,
            group: &str,
            repo_count: usize,
            max_pages: usize,
        ) -> keyhog_core::SourceError {
            crate::gitlab_group::listing_truncated_error_for_test(group, repo_count, max_pages)
        }

        #[cfg(feature = "bitbucket")]
        fn validate_bitbucket_workspace(
            &self,
            workspace: &str,
        ) -> Result<(), keyhog_core::SourceError> {
            crate::bitbucket_workspace::validate_workspace(workspace)
        }

        #[cfg(feature = "bitbucket")]
        fn bitbucket_workspace_listing_truncated_error(
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
        fn export_docker_image_archive(
            &self,
            docker_bin: &std::path::Path,
            image: &str,
            archive_path: &std::path::Path,
        ) -> Result<(), keyhog_core::SourceError> {
            crate::docker::export_docker_image_archive_for_test(docker_bin, image, archive_path)
        }

        #[cfg(feature = "docker")]
        fn docker_manifest_layer_archives(
            &self,
            root_path: &std::path::Path,
        ) -> Result<Vec<std::path::PathBuf>, keyhog_core::SourceError> {
            crate::docker::manifest_layer_archives_for_test(root_path)
        }

        #[cfg(feature = "docker")]
        fn docker_manifest_config_chunks(
            &self,
            root_path: &std::path::Path,
            image: &str,
        ) -> Result<Vec<keyhog_core::Chunk>, keyhog_core::SourceError> {
            crate::docker::manifest_config_chunks_for_test(root_path, image)
        }

        #[cfg(feature = "docker")]
        fn docker_archive_metadata_chunks(
            &self,
            root_path: &std::path::Path,
            image: &str,
        ) -> Result<Vec<keyhog_core::Chunk>, keyhog_core::SourceError> {
            crate::docker::archive_metadata_chunks_for_test(root_path, image)
        }

        #[cfg(feature = "docker")]
        fn unpack_docker_layer_archive(
            &self,
            archive_path: &std::path::Path,
            destination: &std::path::Path,
        ) -> Result<Vec<keyhog_core::SourceError>, keyhog_core::SourceError> {
            crate::docker::unpack_layer_archive_for_test(archive_path, destination)
        }

        #[cfg(feature = "docker")]
        fn unpack_docker_layer_archive_with_total_cap(
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
        fn unpack_docker_layer_archive_with_entry_cap(
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
        fn unpack_docker_image_archive_with_entry_cap(
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
        fn docker_rewrite_layer_chunks<I>(
            &self,
            chunks: I,
            image: &str,
            layer_root: &std::path::Path,
            layer_name: &str,
        ) -> Result<Vec<keyhog_core::Chunk>, keyhog_core::SourceError>
        where
            I: IntoIterator<Item = Result<keyhog_core::Chunk, keyhog_core::SourceError>>,
        {
            crate::docker::rewrite_layer_chunks_for_test(chunks, image, layer_root, layer_name)
        }

        #[cfg(feature = "docker")]
        fn validate_docker_tar_archive(
            &self,
            archive_path: &std::path::Path,
        ) -> Result<(), keyhog_core::SourceError> {
            crate::docker::validate_tar_archive_for_test(archive_path)
        }

        #[cfg(feature = "docker")]
        fn validate_docker_tar_archive_with_total_cap(
            &self,
            archive_path: &std::path::Path,
            total_cap: u64,
        ) -> Result<(), keyhog_core::SourceError> {
            crate::docker::validate_tar_archive_with_total_cap_for_test(archive_path, total_cap)
        }

        #[cfg(feature = "azure")]
        fn azure_blob_source_with_max_objects<U>(
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
        fn azure_blob_source_with_limits<U>(
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

        fn extract_printable_strings(
            &self,
            bytes: &[u8],
            min_len: usize,
        ) -> Vec<keyhog_core::SensitiveString> {
            crate::strings::extract_printable_strings(bytes, min_len)
        }

        fn join_sensitive_strings(
            &self,
            parts: &[keyhog_core::SensitiveString],
            sep: &str,
        ) -> keyhog_core::SensitiveString {
            crate::strings::join_sensitive_strings(parts, sep)
        }

        #[cfg(feature = "git")]
        fn git_max_commits_limit(&self, cap: usize) -> Option<usize> {
            crate::git::max_commits_limit(cap)
        }

        #[cfg(feature = "git")]
        fn git_source_configured_max_commits(&self, cap: usize) -> Option<usize> {
            crate::git::GitSource::new(std::path::PathBuf::from("."))
                .with_max_commits(cap)
                .max_commits
        }

        #[cfg(feature = "git")]
        fn git_history_source_configured_max_commits(&self, cap: usize) -> Option<usize> {
            crate::git::GitHistorySource::new(std::path::PathBuf::from("."))
                .with_max_commits(cap)
                .max_commits
        }

        #[cfg(feature = "web")]
        fn redact_url(&self, url: &str) -> String {
            crate::web::redact_url(url).into_owned()
        }

        #[cfg(feature = "web")]
        fn redirect_pin_key(&self, url: &str) -> Option<String> {
            crate::web::redirect_pin_key(url)
        }

        #[cfg(feature = "github")]
        fn github_rate_limit_backoff_secs(&self, retry_after: Option<u64>, attempt: usize) -> u64 {
            crate::github_org::rate_limit_backoff_secs(retry_after, attempt)
        }

        #[cfg(feature = "github")]
        fn github_max_backoff_secs(&self) -> u64 {
            crate::github_org::MAX_BACKOFF_SECS
        }

        #[cfg(feature = "github")]
        fn github_repos_per_page(&self) -> usize {
            crate::github_org::REPOS_PER_PAGE
        }

        #[cfg(feature = "web")]
        fn is_disallowed_web_host(&self, url: &str) -> bool {
            crate::web::is_disallowed_web_host(url)
        }

        #[cfg(feature = "web")]
        fn is_disallowed_ip(&self, ip: std::net::IpAddr) -> bool {
            crate::web::is_disallowed_ip(ip)
        }

        #[cfg(feature = "web")]
        fn resolve_and_screen(
            &self,
            host: &str,
            port: u16,
            timeout: std::time::Duration,
        ) -> Result<Vec<std::net::SocketAddr>, keyhog_core::SourceError> {
            crate::web::resolve_and_screen(host, port, timeout)
        }

        #[cfg(feature = "web")]
        fn build_web_client(
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
        fn web_source_with_autoroute_loopback_calibration(
            &self,
            urls: Vec<String>,
            allow: bool,
        ) -> crate::WebSource {
            crate::WebSource::new(urls).with_autoroute_loopback_calibration(allow)
        }

        #[cfg(feature = "slack")]
        fn slack_conversations_list_len_for_test(&self, body: &str) -> Result<usize, String> {
            crate::slack::conversations_list_len_for_test(body).map_err(|error| error.to_string())
        }

        #[cfg(feature = "slack")]
        fn slack_history_len_for_test(
            &self,
            body: &str,
            channel_id: &str,
        ) -> Result<usize, String> {
            crate::slack::history_len_for_test(body, channel_id).map_err(|error| error.to_string())
        }

        #[cfg(feature = "slack")]
        fn slack_conversations_list_next_cursor_for_test(
            &self,
            body: &str,
        ) -> Result<Option<String>, String> {
            crate::slack::conversations_list_next_cursor_for_test(body)
                .map_err(|error| error.to_string())
        }

        #[cfg(feature = "slack")]
        fn slack_history_next_cursor_for_test(
            &self,
            body: &str,
            channel_id: &str,
        ) -> Result<Option<String>, String> {
            crate::slack::history_next_cursor_for_test(body, channel_id)
                .map_err(|error| error.to_string())
        }

        #[cfg(feature = "slack")]
        fn slack_source_with_endpoint<T, E>(&self, token: T, endpoint: E) -> crate::SlackSource
        where
            T: Into<String>,
            E: Into<String>,
        {
            crate::SlackSource::new(token).with_endpoint(endpoint)
        }

        #[cfg(feature = "slack")]
        fn slack_source_with_endpoint_and_limits<T, E>(
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
        fn slack_source_with_endpoint_and_lookback<T, E>(
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
}

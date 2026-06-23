//! Hidden test facade for source crate internals.

pub mod testing {
    pub struct TestApi;

    pub trait SourceTestApi {
        fn set_skip_counts(&self, counts: crate::SkipCounts);
        fn reset_skip_counters(&self);
        fn bump_skipped_over_max_size(&self, delta: usize);
        fn read_stdin_test_input_with_limit(
            &self,
            input: &[u8],
            max_bytes: usize,
        ) -> std::io::Result<String>;
        fn reader_pool_thread_count(&self, scanner_threads: usize) -> usize;
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
        fn filesystem_default_max_file_size(&self) -> u64;
        #[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
        fn cloud_is_probably_text_object_key(&self, key: &str) -> bool;
        #[cfg(any(feature = "azure", feature = "s3", feature = "gcs"))]
        fn cloud_is_binary_content_type(&self, content_type: &str) -> bool;

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
        #[cfg(feature = "s3")]
        fn s3_source_with_endpoint<B, E>(&self, bucket: B, endpoint: E) -> crate::S3Source
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
        #[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
        fn git_clone_timeout(&self) -> std::time::Duration;
        #[cfg(feature = "binary")]
        fn ghidra_analysis_timeout(&self) -> std::time::Duration;
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
        fn unpack_docker_layer_archive(
            &self,
            archive_path: &std::path::Path,
            destination: &std::path::Path,
        ) -> Result<(), keyhog_core::SourceError>;
        #[cfg(feature = "docker")]
        fn unpack_docker_layer_archive_with_total_cap(
            &self,
            archive_path: &std::path::Path,
            destination: &std::path::Path,
            total_cap: u64,
        ) -> Result<(), keyhog_core::SourceError>;
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

        #[cfg(feature = "web")]
        fn redact_url(&self, url: &str) -> String;
        #[cfg(feature = "web")]
        fn is_disallowed_web_host(&self, url: &str) -> bool;
        #[cfg(feature = "web")]
        fn is_disallowed_ip(&self, ip: std::net::IpAddr) -> bool;
        #[cfg(feature = "web")]
        fn resolve_and_screen(
            &self,
            host: &str,
            port: u16,
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
    }

    impl SourceTestApi for TestApi {
        fn set_skip_counts(&self, counts: crate::SkipCounts) {
            crate::skip::set_skip_counts_for_test(counts);
        }

        fn reset_skip_counters(&self) {
            crate::reset_skip_counters();
        }

        fn bump_skipped_over_max_size(&self, delta: usize) {
            let _event = crate::record_skip_events(crate::SourceSkipEvent::OverMaxSize, delta);
        }

        fn read_stdin_test_input_with_limit(
            &self,
            input: &[u8],
            max_bytes: usize,
        ) -> std::io::Result<String> {
            let mut reader = std::io::Cursor::new(input);
            crate::stdin::read_to_string_limited(&mut reader, max_bytes)
        }

        fn reader_pool_thread_count(&self, scanner_threads: usize) -> usize {
            crate::filesystem::reader_pool_thread_count_for_test(scanner_threads)
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
            crate::GcsSource::new(bucket).with_endpoint(endpoint)
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
            crate::S3Source::new(bucket).with_endpoint(endpoint)
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
        }

        #[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
        fn git_clone_timeout(&self) -> std::time::Duration {
            crate::timeouts::GIT_CLONE
        }

        #[cfg(feature = "binary")]
        fn ghidra_analysis_timeout(&self) -> std::time::Duration {
            crate::timeouts::GHIDRA_ANALYSIS
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
        fn unpack_docker_layer_archive(
            &self,
            archive_path: &std::path::Path,
            destination: &std::path::Path,
        ) -> Result<(), keyhog_core::SourceError> {
            crate::docker::unpack_layer_archive_for_test(archive_path, destination)
        }

        #[cfg(feature = "docker")]
        fn unpack_docker_layer_archive_with_total_cap(
            &self,
            archive_path: &std::path::Path,
            destination: &std::path::Path,
            total_cap: u64,
        ) -> Result<(), keyhog_core::SourceError> {
            crate::docker::unpack_layer_archive_with_total_cap_for_test(
                archive_path,
                destination,
                total_cap,
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
            crate::AzureBlobSource::new(container_url).with_max_objects(max_objects)
        }

        #[cfg(feature = "web")]
        fn redact_url(&self, url: &str) -> String {
            crate::web::redact_url(url).into_owned()
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
        ) -> Result<Vec<std::net::SocketAddr>, keyhog_core::SourceError> {
            crate::web::resolve_and_screen(host, port)
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
    }
}

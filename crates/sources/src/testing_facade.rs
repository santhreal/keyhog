//! Hidden test facade for source crate internals.

pub mod testing {
    pub fn set_skip_counts(counts: crate::SkipCounts) {
        use std::sync::atomic::Ordering::Relaxed;

        crate::SKIPPED_OVER_MAX_SIZE.store(counts.over_max_size, Relaxed);
        crate::SKIPPED_BINARY.store(counts.binary, Relaxed);
        crate::SKIPPED_EXCLUDED.store(counts.excluded, Relaxed);
        crate::SKIPPED_UNREADABLE.store(counts.unreadable, Relaxed);
        crate::SKIPPED_ARCHIVE_TRUNCATED.store(counts.archive_truncated, Relaxed);
        crate::BINARY_SECTION_NAME_UNRESOLVED.store(counts.binary_section_name_unresolved, Relaxed);
        crate::SOURCE_TRUNCATED.store(counts.source_truncated, Relaxed);
        crate::STRUCTURED_SOURCE_PARSE_FAILURES
            .store(counts.structured_source_parse_failures, Relaxed);
    }

    pub fn reset_skip_counters() {
        crate::reset_skip_counters();
    }

    pub fn bump_skipped_over_max_size(delta: usize) {
        let _event = crate::record_skip_events(crate::SourceSkipEvent::OverMaxSize, delta);
    }

    pub fn reader_pool_thread_count(scanner_threads: usize) -> usize {
        crate::filesystem::reader_pool_thread_count_for_test(scanner_threads)
    }

    pub fn filesystem_with_window_config(
        root: std::path::PathBuf,
        window_size: usize,
        overlap: usize,
    ) -> crate::FilesystemSource {
        crate::FilesystemSource::new(root).with_window_config(window_size, overlap)
    }

    pub fn filesystem_skipped_count(source: &crate::FilesystemSource) -> usize {
        source
            .skipped_counter()
            .load(std::sync::atomic::Ordering::Relaxed)
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
    pub fn http_request_timeout() -> std::time::Duration {
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
    pub fn http_effective_proxy(http: &crate::http::HttpClientConfig) -> Option<String> {
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
    pub fn http_effective_insecure_tls(http: &crate::http::HttpClientConfig) -> bool {
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
        http: &crate::http::HttpClientConfig,
    ) -> Result<crate::reqwest::blocking::ClientBuilder, String> {
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
        http: &crate::http::HttpClientConfig,
    ) -> Result<crate::reqwest::ClientBuilder, String> {
        crate::http::async_client_builder(http)
    }

    #[cfg(feature = "gcs")]
    pub fn gcs_endpoint_is_google(endpoint: &str) -> bool {
        crate::gcs::endpoint_is_google(endpoint)
    }

    #[cfg(feature = "gcs")]
    pub fn gcs_credential_forward_allowed() -> bool {
        crate::gcs::credential_forward_allowed()
    }

    #[cfg(feature = "s3")]
    pub fn s3_endpoint_is_aws(endpoint: &str) -> bool {
        crate::s3::endpoint_is_aws(endpoint)
    }

    #[cfg(feature = "s3")]
    pub fn s3_credential_forward_allowed() -> bool {
        crate::s3::credential_forward_allowed()
    }

    #[cfg(feature = "git")]
    pub fn record_git_history_cap_for_test(total_bytes: usize, chunk_count: usize) -> bool {
        crate::git::record_git_history_cap_for_test(total_bytes, chunk_count)
    }

    #[cfg(any(feature = "github", feature = "gitlab", feature = "bitbucket"))]
    pub fn git_clone_timeout() -> std::time::Duration {
        crate::timeouts::GIT_CLONE
    }

    #[cfg(feature = "binary")]
    pub fn ghidra_analysis_timeout() -> std::time::Duration {
        crate::timeouts::GHIDRA_ANALYSIS
    }

    #[cfg(feature = "binary")]
    pub fn binary_strings_only(path: impl Into<std::path::PathBuf>) -> crate::BinarySource {
        crate::BinarySource::strings_only(path)
    }

    pub fn user_agent(suffix: Option<&str>) -> String {
        crate::http::user_agent(suffix)
    }

    #[cfg(feature = "binary")]
    pub fn extract_string_literals(line: &str) -> Vec<String> {
        let mut out = Vec::new();
        crate::binary::literals::extract_string_literals(line, &mut out);
        out
    }

    #[cfg(feature = "binary")]
    pub fn extract_sections(bytes: &[u8], path: &str) -> Option<Vec<keyhog_core::Chunk>> {
        crate::binary::sections::extract_sections(bytes, path)
    }

    #[cfg(feature = "binary")]
    pub fn resolve_binary_section_name<'a>(resolved: Option<&'a str>, sh_name: usize) -> &'a str {
        crate::binary::sections::resolve_section_name(resolved, sh_name)
    }

    #[cfg(feature = "github")]
    pub fn validate_repo_name(name: &str) -> Result<(), keyhog_core::SourceError> {
        crate::github_org::validate_repo_name(name)
    }

    #[cfg(feature = "github")]
    pub fn validate_org_name(name: &str) -> Result<(), keyhog_core::SourceError> {
        crate::github_org::validate_org_name(name)
    }

    #[cfg(feature = "github")]
    pub fn validate_clone_url(url: &str) -> Result<(), keyhog_core::SourceError> {
        crate::github_org::validate_clone_url(url)
    }

    #[cfg(feature = "github")]
    pub fn github_org_rewrite_chunk_path(
        chunk: keyhog_core::Chunk,
        org: &str,
        repo_name: &str,
        clone_path: &std::path::Path,
    ) -> Result<keyhog_core::Chunk, keyhog_core::SourceError> {
        crate::github_org::rewrite_chunk_path_for_test(chunk, org, repo_name, clone_path)
    }

    #[cfg(feature = "github")]
    pub fn github_org_scan_repo_chunks<I>(
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
        org: &str,
        repo_count: usize,
        max_pages: usize,
    ) -> keyhog_core::SourceError {
        crate::github_org::github_listing_truncated_error_for_test(org, repo_count, max_pages)
    }

    #[cfg(feature = "gitlab")]
    pub fn validate_gitlab_group_path(group: &str) -> Result<(), keyhog_core::SourceError> {
        crate::gitlab_group::validate_group_path(group)
    }

    #[cfg(feature = "gitlab")]
    pub fn gitlab_group_listing_truncated_error(
        group: &str,
        repo_count: usize,
        max_pages: usize,
    ) -> keyhog_core::SourceError {
        crate::gitlab_group::listing_truncated_error_for_test(group, repo_count, max_pages)
    }

    #[cfg(feature = "bitbucket")]
    pub fn validate_bitbucket_workspace(workspace: &str) -> Result<(), keyhog_core::SourceError> {
        crate::bitbucket_workspace::validate_workspace(workspace)
    }

    #[cfg(feature = "bitbucket")]
    pub fn bitbucket_workspace_listing_truncated_error(
        workspace: &str,
        repo_count: usize,
        max_pages: usize,
    ) -> keyhog_core::SourceError {
        crate::bitbucket_workspace::listing_truncated_error_for_test(
            workspace, repo_count, max_pages,
        )
    }

    #[cfg(feature = "docker")]
    pub fn docker_manifest_layer_archives(
        root_path: &std::path::Path,
    ) -> Result<Vec<std::path::PathBuf>, keyhog_core::SourceError> {
        crate::docker::manifest_layer_archives_for_test(root_path)
    }

    #[cfg(feature = "docker")]
    pub fn docker_manifest_config_chunks(
        root_path: &std::path::Path,
        image: &str,
    ) -> Result<Vec<keyhog_core::Chunk>, keyhog_core::SourceError> {
        crate::docker::manifest_config_chunks_for_test(root_path, image)
    }

    #[cfg(feature = "docker")]
    pub fn unpack_docker_layer_archive(
        archive_path: &std::path::Path,
        destination: &std::path::Path,
    ) -> Result<(), keyhog_core::SourceError> {
        crate::docker::unpack_layer_archive_for_test(archive_path, destination)
    }

    #[cfg(feature = "docker")]
    pub fn docker_rewrite_layer_chunks<I>(
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
    pub fn validate_docker_tar_archive(
        archive_path: &std::path::Path,
    ) -> Result<(), keyhog_core::SourceError> {
        crate::docker::validate_tar_archive_for_test(archive_path)
    }

    #[cfg(feature = "docker")]
    pub fn validate_docker_tar_archive_with_total_cap(
        archive_path: &std::path::Path,
        total_cap: u64,
    ) -> Result<(), keyhog_core::SourceError> {
        crate::docker::validate_tar_archive_with_total_cap_for_test(archive_path, total_cap)
    }

    #[cfg(feature = "web")]
    pub fn redact_url(url: &str) -> String {
        crate::web::redact_url(url).into_owned()
    }

    #[cfg(feature = "web")]
    pub fn is_disallowed_web_host(url: &str) -> bool {
        crate::web::is_disallowed_web_host(url)
    }

    #[cfg(feature = "web")]
    pub fn is_disallowed_ip(ip: std::net::IpAddr) -> bool {
        crate::web::is_disallowed_ip(ip)
    }

    #[cfg(feature = "web")]
    pub fn resolve_and_screen(
        host: &str,
        port: u16,
    ) -> Result<Vec<std::net::SocketAddr>, keyhog_core::SourceError> {
        crate::web::resolve_and_screen(host, port)
    }

    #[cfg(feature = "web")]
    pub fn build_web_client(
        http: &crate::http::HttpClientConfig,
        original_url: &str,
        use_proxy: bool,
    ) -> Result<crate::reqwest::blocking::Client, keyhog_core::SourceError> {
        crate::web::build_web_client(http, original_url, use_proxy)
    }
}

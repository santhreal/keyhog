//! Explicit integration-test API for CLI internals.

use crate::args::ScanArgs;
use anyhow::Result;
use keyhog_core::{DetectorSpec, RawMatch, Source, VerifiedFinding};
use keyhog_scanner::{CompiledScanner, ScannerConfig};
use std::future::Future;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};

/// Zero-sized handle for integration tests that need crate-internal seams.
pub struct TestApi;

/// Integration-test handle. Import [`CliTestApi`] to call its methods.
pub const API: TestApi = TestApi;

static SCAN_RUNTIME_TEST_LOCK: Mutex<()> = Mutex::new(());

pub struct ScanRuntimeGuard {
    _guard: MutexGuard<'static, ()>,
}

/// Public baseline shape used by tests without exposing the production cache.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct Baseline {
    pub version: u32,
    pub created: String,
    pub entries: Vec<BaselineEntry>,
}

/// Public baseline-entry shape used by tests.
#[derive(Debug, Clone, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
pub struct BaselineEntry {
    pub detector_id: String,
    pub credential_hash: String,
    pub file_path: Option<String>,
    pub line: Option<usize>,
    pub status: String,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ScanRuntimeSnapshot {
    pub scanned_chunks: usize,
    pub total_chunks: usize,
    pub findings_count: usize,
    pub gpu_scanned_chunks: usize,
    pub source_errors: usize,
    pub failed_sources: usize,
    pub incremental_cache_errors: usize,
    pub scanner_panicked: bool,
    pub dogfood_enabled: bool,
    pub example_suppressions: usize,
    pub decode_truncations: usize,
}

/// Opaque test-fixture suppression wrapper.
pub struct TestFixtureSuppressions(crate::test_fixture_suppressions::TestFixtureSuppressions);

impl std::fmt::Debug for TestFixtureSuppressions {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TestFixtureSuppressions")
            .field("exact_count", &self.0.exact_count())
            .finish_non_exhaustive()
    }
}

/// Opaque scan-system finding sink wrapper.
pub struct FindingSink(crate::subcommands::scan_system::testing::FindingSink);

/// Opaque orchestrator wrapper.
pub struct ScanOrchestrator(crate::orchestrator::ScanOrchestrator);

pub type DownloadFuture<'a> = Pin<Box<dyn Future<Output = Result<Vec<u8>>> + 'a>>;

/// Integration-test operations that would otherwise force implementation
/// modules into the production public API.
pub trait CliTestApi {
    fn parse_min_confidence(&self, s: &str) -> std::result::Result<f64, String>;
    fn parse_verify_rate(&self, s: &str) -> std::result::Result<f64, String>;
    fn parse_ml_threshold(&self, s: &str) -> std::result::Result<f64, String>;
    fn parse_decode_depth(&self, s: &str) -> std::result::Result<usize, String>;
    fn parse_min_secret_len(&self, s: &str) -> std::result::Result<usize, String>;
    fn parse_positive_thread_count(&self, s: &str) -> std::result::Result<usize, String>;
    fn parse_positive_usize(&self, s: &str) -> std::result::Result<usize, String>;
    fn parse_byte_size(&self, s: &str) -> std::result::Result<usize, String>;
    fn parse_detectors_verb(&self, s: &str) -> std::result::Result<String, String>;
    fn parse_severity_filter(&self, s: &str) -> Option<crate::args::SeverityFilter>;
    fn parse_output_format(&self, s: &str) -> Option<crate::args::OutputFormat>;
    fn parse_dedup_scope(&self, s: &str) -> Option<crate::args::CliDedupScope>;

    fn format_gpu_summary(&self) -> String;
    fn format_gpu_max_buffer(&self, max_buffer_mb: u64) -> String;
    fn format_backend_probe_count_metric(&self, value: Option<usize>) -> String;
    fn format_backend_probe_mb_metric(&self, value: Option<u64>) -> String;
    fn find_config_file(&self, start: Option<&Path>) -> Option<PathBuf>;
    fn apply_config_file_quiet(&self, args: &mut ScanArgs);
    fn build_sources(
        &self,
        args: &ScanArgs,
        allowlist_paths: Vec<String>,
        merkle: Option<Arc<keyhog_core::MerkleIndex>>,
    ) -> Result<Vec<Box<dyn Source>>>;
    fn merge_scan_ignore_paths(&self, args: &ScanArgs, allowlist_paths: Vec<String>)
        -> Vec<String>;
    fn validate_cli_path_arg(&self, path: &Path, name: &str) -> Result<()>;
    fn report_findings(&self, findings: &[VerifiedFinding], args: &ScanArgs) -> Result<()>;
    fn filter_inline_suppressions(&self, matches: Vec<RawMatch>) -> Vec<RawMatch>;
    fn format_bytes(&self, n: u64) -> String;
    fn ensure_private_socket_dir(&self, parent: &Path) -> Result<()>;
    fn remove_stale_socket_if_trusted(&self, socket_path: &Path) -> Result<()>;
    fn validate_socket_for_connect(&self, socket_path: &Path) -> Result<()>;
    fn current_uid(&self) -> libc::uid_t;
    fn connected_peer_uid(&self, stream: &tokio::net::UnixStream) -> Result<libc::uid_t>;
    fn daemon_client_version<'a>(&self, client: &'a crate::daemon::client::Client) -> &'a str;
    fn daemon_client_is_stale(&self, client: &crate::daemon::client::Client) -> bool;
    fn daemon_client_round_trip<'a>(
        &self,
        client: &'a mut crate::daemon::client::Client,
        request: &'a crate::daemon::protocol::Request,
    ) -> Pin<Box<dyn Future<Output = Result<crate::daemon::protocol::Response>> + 'a>>;

    fn baseline_version(&self) -> u32;
    fn baseline_empty(&self) -> Baseline;
    fn baseline_load(&self, path: &Path) -> Result<Baseline>;
    fn baseline_save(&self, baseline: &Baseline, path: &Path) -> Result<()>;
    fn baseline_from_findings(&self, findings: &[VerifiedFinding]) -> Baseline;
    fn baseline_merge(&self, baseline: &mut Baseline, findings: &[VerifiedFinding]);
    fn baseline_contains(&self, baseline: &Baseline, finding: &VerifiedFinding) -> bool;
    fn baseline_filter_new(
        &self,
        baseline: &Baseline,
        findings: &[VerifiedFinding],
    ) -> Vec<VerifiedFinding>;
    fn baseline_looks_like_findings_report(&self, content: &str) -> bool;

    fn bundled_test_fixture_suppressions(&self) -> TestFixtureSuppressions;
    fn empty_test_fixture_suppressions(&self) -> TestFixtureSuppressions;
    fn test_fixture_suppressions_from_toml(
        &self,
        raw: &str,
    ) -> std::result::Result<TestFixtureSuppressions, String>;
    fn test_fixture_suppresses(&self, suppressions: &TestFixtureSuppressions, cred: &str) -> bool;
    fn test_fixture_exact_count(&self, suppressions: &TestFixtureSuppressions) -> usize;

    fn asset_name(&self, os: &str, arch: &str, cuda: bool) -> Option<String>;
    fn select_release_asset_name(
        &self,
        tag_name: &str,
        asset_names: &[&str],
        want_cuda: bool,
    ) -> Result<String>;
    fn default_wants_cuda_variant_for_host(
        &self,
        os: &str,
        arch: &str,
        nvidia_gpu: bool,
        libcuda: bool,
        cuda_toolkit: bool,
    ) -> bool;
    fn wants_cuda_variant(&self, explicit: Option<&str>) -> Result<bool>;
    fn parse_semver(&self, tag: &str) -> Option<(u64, u64, u64)>;
    fn is_newer(&self, current: &str, latest: &str) -> bool;
    fn looks_like_native_executable(&self, bytes: &[u8]) -> bool;
    fn looks_like_native_executable_for_os(&self, bytes: &[u8], os: &str) -> bool;
    fn verify_release_signature(&self, data: &[u8], signature: &str) -> Result<()>;
    fn release_api_base(&self) -> String;
    fn release_api_base_with_override(&self, base: &str) -> String;
    fn release_public_key(&self) -> &'static str;
    fn release_repo(&self) -> &'static str;
    fn scan_engine_self_test(&self) -> Result<bool>;
    fn verify_via_doctor(&self, exe: &Path) -> bool;
    fn http_client(&self) -> Result<reqwest::Client>;
    fn download_verified_asset<'a>(
        &self,
        client: &'a reqwest::Client,
        name: &'a str,
        browser_download_url: String,
    ) -> DownloadFuture<'a>;
    fn current_binary(&self) -> Result<PathBuf>;
    fn replace_running_binary<F>(
        &self,
        exe: &Path,
        bytes: &[u8],
        verify: F,
    ) -> Result<Option<PathBuf>>
    where
        F: FnOnce(&Path) -> bool;
    fn reap_stale_binaries(&self, exe: &Path);
    fn backup_path(&self, exe: &Path) -> PathBuf;
    fn verify_candidate_release(
        &self,
        exe: &Path,
        expected_release_tag: &str,
        current_version: &str,
        allow_explicit_downgrade: bool,
    ) -> Result<()>;
    fn install_with_rollback<F>(&self, exe: &Path, bytes: &[u8], verify: F) -> Result<()>
    where
        F: FnOnce(&Path) -> bool;
    fn install_with_rollback_checked<F>(&self, exe: &Path, bytes: &[u8], verify: F) -> Result<()>
    where
        F: FnOnce(&Path) -> Result<()>;

    fn rewrite_detector_braces(&self, s: &str) -> (String, usize);
    fn fix_single_brace_in_verify_blocks(&self, toml_text: &str) -> (String, usize);
    fn fix_verify_braces(&self, toml_text: &str) -> (String, usize);
    fn rewrite_braces_in_string_literals(&self, line: &str) -> (String, usize);
    fn canonical_for_hot_id(&self, id: &str) -> Option<&'static str>;
    fn explain_not_found(
        &self,
        detectors: &[DetectorSpec],
        requested: &str,
        lowered: &str,
    ) -> anyhow::Error;
    fn render_failing_ac_probe_json(&self) -> Result<String>;
    fn doctor_canonicalize_for_shadow_check(&self, path: PathBuf) -> PathBuf;
    fn canonical_scan_args(&self) -> &'static str;
    fn hook_content(&self) -> &'static str;

    fn max_resident_findings(&self) -> usize;
    fn finding_sink_new(&self) -> FindingSink;
    fn finding_sink_with_cap(&self, cap: usize) -> FindingSink;
    fn finding_sink_record_skipped_chunk(&self, sink: &mut FindingSink);
    fn finding_sink_skipped_chunks(&self, sink: &FindingSink) -> u64;
    fn finding_sink_absorb(&self, sink: &mut FindingSink, matches: Vec<RawMatch>);
    fn finding_sink_is_empty(&self, sink: &FindingSink) -> bool;
    fn finding_sink_total(&self, sink: &FindingSink) -> u64;
    fn finding_sink_retained_len(&self, sink: &FindingSink) -> usize;
    fn finding_sink_cap(&self, sink: &FindingSink) -> usize;
    fn finding_sink_capped_warned(&self, sink: &FindingSink) -> bool;
    fn finding_sink_retained_hash(
        &self,
        sink: &FindingSink,
        index: usize,
    ) -> Option<keyhog_core::CredentialHash>;
    fn finding_sink_retained_json(&self, sink: &FindingSink) -> serde_json::Result<String>;

    fn sanitise_thread_count(
        &self,
        requested: usize,
        physical_cores: usize,
        source: &'static str,
    ) -> usize;
    fn max_threads_cap(&self) -> usize;
    fn load_detectors_or_embedded(&self, path: &Path) -> Result<Vec<DetectorSpec>>;
    fn load_detectors_from_dir_with_cache(
        &self,
        source_dir: &Path,
        cache_path: &Path,
    ) -> Result<Vec<DetectorSpec>>;
    fn build_scanner_config(&self, args: &ScanArgs) -> ScannerConfig;
    fn resolve_scan_config(&self, args: &mut ScanArgs) -> Result<()>;
    fn resolve_scan_config_aws_canary_accounts(&self, args: &mut ScanArgs) -> Result<Vec<String>>;
    fn render_effective_config_for_scanner(&self, scanner: ScannerConfig) -> String;
    fn autoroute_config_digest_for_args(&self, args: &mut ScanArgs) -> Result<u64>;
    fn autoroute_config_digest_for_scanner(&self, scanner: ScannerConfig) -> u64;
    fn autoroute_config_digest_for_scanner_with_autoroute_gpu(
        &self,
        scanner: ScannerConfig,
        autoroute_gpu: bool,
    ) -> u64;
    fn ml_threshold_default(&self) -> f64;

    fn explicit_backend_override(
        &self,
        raw: Option<&str>,
    ) -> Result<Option<keyhog_scanner::ScanBackend>>;
    fn allowlist_root_for_test(&self, path: &Path) -> PathBuf;
    fn backend_requires_coalesced_batch_pipeline_for_test(
        &self,
        explicit: Option<keyhog_scanner::ScanBackend>,
    ) -> bool;
    fn gpu_init_policy_for_args_for_test(&self, args: &ScanArgs) -> keyhog_scanner::GpuInitPolicy;
    fn gpu_init_policy_for_resolved_autoroute_for_test(
        &self,
        args: &ScanArgs,
        autoroute_cache_path: Option<&Path>,
        autoroute_gpu: bool,
        autoroute_calibration: bool,
    ) -> keyhog_scanner::GpuInitPolicy;
    fn scanner_panic_notice_for_test(&self, panicked: bool) -> Option<String>;
    fn scan_orchestrator_from_parts_for_test(
        &self,
        args: ScanArgs,
        detectors: Vec<DetectorSpec>,
        scanner: Arc<CompiledScanner>,
        signatures: std::collections::HashSet<Arc<str>>,
        test_fixture_suppressions: TestFixtureSuppressions,
    ) -> ScanOrchestrator;
    fn scan_orchestrator_scanner<'a>(
        &self,
        orchestrator: &'a ScanOrchestrator,
    ) -> &'a CompiledScanner;
    fn scan_orchestrator_args<'a>(&self, orchestrator: &'a ScanOrchestrator) -> &'a ScanArgs;
    fn scan_orchestrator_scan_sources_for_test(
        &self,
        orchestrator: &ScanOrchestrator,
        sources: Vec<Box<dyn Source>>,
        show_progress: bool,
        merkle: Option<Arc<keyhog_core::MerkleIndex>>,
    ) -> Result<Vec<RawMatch>>;

    fn scan_runtime_guard_for_test(&self) -> ScanRuntimeGuard;
    fn seed_scan_runtime_state_for_test(&self, _guard: &ScanRuntimeGuard);
    fn reset_scan_runtime_state_for_test(&self, _guard: &ScanRuntimeGuard);
    fn scan_runtime_snapshot(&self, _guard: &ScanRuntimeGuard) -> ScanRuntimeSnapshot;
    fn scanned_chunks(&self, _guard: &ScanRuntimeGuard) -> usize;
    fn scanner_panicked(&self, _guard: &ScanRuntimeGuard) -> bool;
}

impl CliTestApi for TestApi {
    fn parse_min_confidence(&self, s: &str) -> std::result::Result<f64, String> {
        crate::value_parsers::parse_min_confidence(s)
    }
    fn parse_verify_rate(&self, s: &str) -> std::result::Result<f64, String> {
        crate::value_parsers::parse_verify_rate(s)
    }
    fn parse_ml_threshold(&self, s: &str) -> std::result::Result<f64, String> {
        crate::value_parsers::parse_ml_threshold(s)
    }
    fn parse_decode_depth(&self, s: &str) -> std::result::Result<usize, String> {
        crate::value_parsers::parse_decode_depth(s)
    }
    fn parse_min_secret_len(&self, s: &str) -> std::result::Result<usize, String> {
        crate::value_parsers::parse_min_secret_len(s)
    }
    fn parse_positive_thread_count(&self, s: &str) -> std::result::Result<usize, String> {
        crate::value_parsers::parse_positive_thread_count(s)
    }
    fn parse_positive_usize(&self, s: &str) -> std::result::Result<usize, String> {
        crate::value_parsers::parse_positive_usize(s)
    }
    fn parse_byte_size(&self, s: &str) -> std::result::Result<usize, String> {
        crate::value_parsers::parse_byte_size(s)
    }
    fn parse_detectors_verb(&self, s: &str) -> std::result::Result<String, String> {
        crate::value_parsers::parse_detectors_verb(s)
    }
    fn parse_severity_filter(&self, s: &str) -> Option<crate::args::SeverityFilter> {
        crate::value_parsers::parse_severity_filter(s)
    }
    fn parse_output_format(&self, s: &str) -> Option<crate::args::OutputFormat> {
        crate::value_parsers::parse_output_format(s)
    }
    fn parse_dedup_scope(&self, s: &str) -> Option<crate::args::CliDedupScope> {
        crate::value_parsers::parse_dedup_scope(s)
    }

    fn format_gpu_summary(&self) -> String {
        crate::benchmark::format_gpu_summary()
    }
    fn format_gpu_max_buffer(&self, max_buffer_mb: u64) -> String {
        crate::subcommands::backend::testing::format_gpu_max_buffer(max_buffer_mb)
    }
    fn format_backend_probe_count_metric(&self, value: Option<usize>) -> String {
        crate::subcommands::backend::testing::format_probe_count_metric(value)
    }
    fn format_backend_probe_mb_metric(&self, value: Option<u64>) -> String {
        crate::subcommands::backend::testing::format_probe_mb_metric(value)
    }
    fn find_config_file(&self, start: Option<&Path>) -> Option<PathBuf> {
        crate::config::find_config_file(start)
    }
    fn apply_config_file_quiet(&self, args: &mut ScanArgs) {
        let _outcome = crate::config::apply_config_file_quiet(args);
    }
    fn build_sources(
        &self,
        args: &ScanArgs,
        allowlist_paths: Vec<String>,
        merkle: Option<Arc<keyhog_core::MerkleIndex>>,
    ) -> Result<Vec<Box<dyn Source>>> {
        crate::sources::build_sources(args, allowlist_paths, merkle)
    }
    fn merge_scan_ignore_paths(
        &self,
        args: &ScanArgs,
        allowlist_paths: Vec<String>,
    ) -> Vec<String> {
        crate::sources::merge_scan_ignore_paths(args, allowlist_paths)
    }
    fn validate_cli_path_arg(&self, path: &Path, name: &str) -> Result<()> {
        crate::path_validation::validate_cli_path_arg(path, name)
    }
    fn report_findings(&self, findings: &[VerifiedFinding], args: &ScanArgs) -> Result<()> {
        crate::reporting::report_findings(findings, args)
    }
    fn filter_inline_suppressions(&self, matches: Vec<RawMatch>) -> Vec<RawMatch> {
        crate::inline_suppression::filter_inline_suppressions(matches)
    }
    fn format_bytes(&self, n: u64) -> String {
        crate::format::format_bytes(n)
    }
    fn ensure_private_socket_dir(&self, parent: &Path) -> Result<()> {
        crate::daemon::server::testing::ensure_private_socket_dir(parent)
    }
    fn remove_stale_socket_if_trusted(&self, socket_path: &Path) -> Result<()> {
        crate::daemon::server::testing::remove_stale_socket_if_trusted(socket_path)
    }
    fn validate_socket_for_connect(&self, socket_path: &Path) -> Result<()> {
        crate::daemon::client::testing::validate_socket_for_connect(socket_path)
    }
    fn current_uid(&self) -> libc::uid_t {
        crate::daemon::client::testing::current_uid()
    }
    fn connected_peer_uid(&self, stream: &tokio::net::UnixStream) -> Result<libc::uid_t> {
        crate::daemon::client::testing::connected_peer_uid(stream)
    }
    fn daemon_client_version<'a>(&self, client: &'a crate::daemon::client::Client) -> &'a str {
        client.daemon_version()
    }
    fn daemon_client_is_stale(&self, client: &crate::daemon::client::Client) -> bool {
        client.is_stale()
    }
    fn daemon_client_round_trip<'a>(
        &self,
        client: &'a mut crate::daemon::client::Client,
        request: &'a crate::daemon::protocol::Request,
    ) -> Pin<Box<dyn Future<Output = Result<crate::daemon::protocol::Response>> + 'a>> {
        Box::pin(async move { client.round_trip(request).await })
    }

    fn baseline_version(&self) -> u32 {
        crate::baseline::testing::baseline_version()
    }
    fn baseline_empty(&self) -> Baseline {
        expose_baseline(crate::baseline::Baseline::empty())
    }
    fn baseline_load(&self, path: &Path) -> Result<Baseline> {
        crate::baseline::Baseline::load(path).map(expose_baseline)
    }
    fn baseline_save(&self, baseline: &Baseline, path: &Path) -> Result<()> {
        baseline.to_internal().save(path)
    }
    fn baseline_from_findings(&self, findings: &[VerifiedFinding]) -> Baseline {
        expose_baseline(crate::baseline::Baseline::from_findings(findings))
    }
    fn baseline_merge(&self, baseline: &mut Baseline, findings: &[VerifiedFinding]) {
        let mut inner = baseline.to_internal();
        inner.merge(findings);
        *baseline = expose_baseline(inner);
    }
    fn baseline_contains(&self, baseline: &Baseline, finding: &VerifiedFinding) -> bool {
        baseline.to_internal().contains(finding)
    }
    fn baseline_filter_new(
        &self,
        baseline: &Baseline,
        findings: &[VerifiedFinding],
    ) -> Vec<VerifiedFinding> {
        baseline.to_internal().filter_new(findings)
    }
    fn baseline_looks_like_findings_report(&self, content: &str) -> bool {
        crate::baseline::testing::looks_like_findings_report(content)
    }

    fn bundled_test_fixture_suppressions(&self) -> TestFixtureSuppressions {
        TestFixtureSuppressions(
            crate::test_fixture_suppressions::TestFixtureSuppressions::bundled(),
        )
    }
    fn empty_test_fixture_suppressions(&self) -> TestFixtureSuppressions {
        TestFixtureSuppressions(crate::test_fixture_suppressions::TestFixtureSuppressions::empty())
    }
    fn test_fixture_suppressions_from_toml(
        &self,
        raw: &str,
    ) -> std::result::Result<TestFixtureSuppressions, String> {
        crate::test_fixture_suppressions::TestFixtureSuppressions::from_toml(raw)
            .map(TestFixtureSuppressions)
    }
    fn test_fixture_suppresses(&self, suppressions: &TestFixtureSuppressions, cred: &str) -> bool {
        suppressions.0.suppresses(cred)
    }
    fn test_fixture_exact_count(&self, suppressions: &TestFixtureSuppressions) -> usize {
        suppressions.0.exact_count()
    }

    fn asset_name(&self, os: &str, arch: &str, cuda: bool) -> Option<String> {
        crate::installer::asset_name(os, arch, cuda)
    }
    fn select_release_asset_name(
        &self,
        tag_name: &str,
        asset_names: &[&str],
        want_cuda: bool,
    ) -> Result<String> {
        let release = crate::installer::Release {
            tag_name: tag_name.to_string(),
            assets: asset_names
                .iter()
                .map(|name| crate::installer::Asset {
                    name: (*name).to_string(),
                    browser_download_url: format!("https://example.invalid/{name}"),
                })
                .collect(),
        };
        crate::installer::select_asset(&release, want_cuda).map(|asset| asset.name.clone())
    }
    fn default_wants_cuda_variant_for_host(
        &self,
        os: &str,
        arch: &str,
        nvidia_gpu: bool,
        libcuda: bool,
        cuda_toolkit: bool,
    ) -> bool {
        crate::installer::default_wants_cuda_variant_for_host(
            os,
            arch,
            nvidia_gpu,
            libcuda,
            cuda_toolkit,
        )
    }
    fn wants_cuda_variant(&self, explicit: Option<&str>) -> Result<bool> {
        crate::installer::wants_cuda_variant(explicit)
    }
    fn parse_semver(&self, tag: &str) -> Option<(u64, u64, u64)> {
        crate::installer::parse_semver(tag)
    }
    fn is_newer(&self, current: &str, latest: &str) -> bool {
        crate::installer::is_newer(current, latest)
    }
    fn looks_like_native_executable(&self, bytes: &[u8]) -> bool {
        crate::installer::looks_like_native_executable(bytes)
    }
    fn looks_like_native_executable_for_os(&self, bytes: &[u8], os: &str) -> bool {
        crate::installer::looks_like_native_executable_for_os(bytes, os)
    }
    fn verify_release_signature(&self, data: &[u8], signature: &str) -> Result<()> {
        crate::installer::verify_release_signature(data, signature)
    }
    fn release_api_base(&self) -> String {
        crate::installer::release_api_base(None)
    }
    fn release_api_base_with_override(&self, base: &str) -> String {
        crate::installer::release_api_base(Some(base))
    }
    fn release_public_key(&self) -> &'static str {
        crate::installer::RELEASE_PUBLIC_KEY
    }
    fn release_repo(&self) -> &'static str {
        crate::installer::REPO
    }
    fn scan_engine_self_test(&self) -> Result<bool> {
        crate::installer::scan_engine_self_test()
    }
    fn verify_via_doctor(&self, exe: &Path) -> bool {
        crate::installer::verify_via_doctor(exe)
    }
    fn http_client(&self) -> Result<reqwest::Client> {
        crate::installer::http_client()
    }
    fn download_verified_asset<'a>(
        &self,
        client: &'a reqwest::Client,
        name: &'a str,
        browser_download_url: String,
    ) -> DownloadFuture<'a> {
        Box::pin(async move {
            let asset = crate::installer::Asset {
                name: name.to_string(),
                browser_download_url,
            };
            crate::installer::download_verified_asset(client, &asset).await
        })
    }
    fn current_binary(&self) -> Result<PathBuf> {
        crate::installer::current_binary()
    }
    fn replace_running_binary<F>(
        &self,
        exe: &Path,
        bytes: &[u8],
        verify: F,
    ) -> Result<Option<PathBuf>>
    where
        F: FnOnce(&Path) -> bool,
    {
        crate::installer::replace_running_binary(exe, bytes, verify)
    }
    fn reap_stale_binaries(&self, exe: &Path) {
        crate::installer::reap_stale_binaries(exe)
    }
    fn backup_path(&self, exe: &Path) -> PathBuf {
        crate::installer::backup_path(exe)
    }
    fn verify_candidate_release(
        &self,
        exe: &Path,
        expected_release_tag: &str,
        current_version: &str,
        allow_explicit_downgrade: bool,
    ) -> Result<()> {
        crate::installer::verify_candidate_release(
            exe,
            expected_release_tag,
            current_version,
            allow_explicit_downgrade,
        )
    }
    fn install_with_rollback<F>(&self, exe: &Path, bytes: &[u8], verify: F) -> Result<()>
    where
        F: FnOnce(&Path) -> bool,
    {
        crate::installer::install_with_rollback(exe, bytes, verify)
    }
    fn install_with_rollback_checked<F>(&self, exe: &Path, bytes: &[u8], verify: F) -> Result<()>
    where
        F: FnOnce(&Path) -> Result<()>,
    {
        crate::installer::install_with_rollback_checked(exe, bytes, verify)
    }

    fn rewrite_detector_braces(&self, s: &str) -> (String, usize) {
        crate::subcommands::detectors::testing::rewrite_braces(s)
    }
    fn fix_single_brace_in_verify_blocks(&self, toml_text: &str) -> (String, usize) {
        crate::subcommands::detectors::testing::fix_single_brace_in_verify_blocks(toml_text)
    }
    fn fix_verify_braces(&self, toml_text: &str) -> (String, usize) {
        crate::subcommands::detectors::testing::fix_verify_braces_for_test(toml_text)
    }
    fn rewrite_braces_in_string_literals(&self, line: &str) -> (String, usize) {
        crate::subcommands::detectors::testing::rewrite_braces_in_string_literals(line)
    }
    fn canonical_for_hot_id(&self, id: &str) -> Option<&'static str> {
        crate::subcommands::explain::testing::canonical_for_hot_id(id)
    }
    fn explain_not_found(
        &self,
        detectors: &[DetectorSpec],
        requested: &str,
        lowered: &str,
    ) -> anyhow::Error {
        crate::subcommands::explain::testing::explain_not_found(detectors, requested, lowered)
    }
    fn render_failing_ac_probe_json(&self) -> Result<String> {
        crate::subcommands::backend::testing::render_failing_ac_probe_json()
    }
    fn doctor_canonicalize_for_shadow_check(&self, path: PathBuf) -> PathBuf {
        crate::subcommands::doctor::testing::canonicalize_for_shadow_check(path)
    }
    fn canonical_scan_args(&self) -> &'static str {
        crate::subcommands::hook::testing::CANONICAL_SCAN_ARGS
    }
    fn hook_content(&self) -> &'static str {
        crate::subcommands::hook::testing::HOOK_CONTENT
    }

    fn max_resident_findings(&self) -> usize {
        crate::subcommands::scan_system::testing::MAX_RESIDENT_FINDINGS
    }
    fn finding_sink_new(&self) -> FindingSink {
        FindingSink(crate::subcommands::scan_system::testing::FindingSink::new())
    }
    fn finding_sink_with_cap(&self, cap: usize) -> FindingSink {
        FindingSink(crate::subcommands::scan_system::testing::FindingSink::with_cap(cap))
    }
    fn finding_sink_record_skipped_chunk(&self, sink: &mut FindingSink) {
        sink.0.record_skipped_chunk();
    }
    fn finding_sink_skipped_chunks(&self, sink: &FindingSink) -> u64 {
        sink.0.skipped_chunks()
    }
    fn finding_sink_absorb(&self, sink: &mut FindingSink, matches: Vec<RawMatch>) {
        sink.0.absorb(matches);
    }
    fn finding_sink_is_empty(&self, sink: &FindingSink) -> bool {
        sink.0.is_empty()
    }
    fn finding_sink_total(&self, sink: &FindingSink) -> u64 {
        sink.0.total()
    }
    fn finding_sink_retained_len(&self, sink: &FindingSink) -> usize {
        sink.0.retained_len()
    }
    fn finding_sink_cap(&self, sink: &FindingSink) -> usize {
        sink.0.cap()
    }
    fn finding_sink_capped_warned(&self, sink: &FindingSink) -> bool {
        sink.0.capped_warned()
    }
    fn finding_sink_retained_hash(
        &self,
        sink: &FindingSink,
        index: usize,
    ) -> Option<keyhog_core::CredentialHash> {
        sink.0.retained_hash(index)
    }
    fn finding_sink_retained_json(&self, sink: &FindingSink) -> serde_json::Result<String> {
        sink.0.retained_json()
    }

    fn sanitise_thread_count(
        &self,
        requested: usize,
        physical_cores: usize,
        source: &'static str,
    ) -> usize {
        crate::orchestrator_config::testing::sanitise_thread_count(
            requested,
            physical_cores,
            source,
        )
    }
    fn max_threads_cap(&self) -> usize {
        crate::orchestrator_config::MAX_THREADS_CAP
    }
    fn load_detectors_or_embedded(&self, path: &Path) -> Result<Vec<DetectorSpec>> {
        crate::orchestrator_config::load_detectors_or_embedded(path)
    }
    fn load_detectors_from_dir_with_cache(
        &self,
        source_dir: &Path,
        cache_path: &Path,
    ) -> Result<Vec<DetectorSpec>> {
        crate::orchestrator_config::testing::load_detectors_from_dir_with_cache(
            source_dir, cache_path,
        )
    }
    fn build_scanner_config(&self, args: &ScanArgs) -> ScannerConfig {
        crate::orchestrator_config::build_scanner_config(args)
    }
    fn resolve_scan_config(&self, args: &mut ScanArgs) -> Result<()> {
        crate::orchestrator_config::resolve_scan_config(args).map(|_| ())
    }
    fn resolve_scan_config_aws_canary_accounts(&self, args: &mut ScanArgs) -> Result<Vec<String>> {
        crate::orchestrator_config::resolve_scan_config(args)
            .map(|resolved| resolved.aws_canary_accounts)
    }
    fn render_effective_config_for_scanner(&self, scanner: ScannerConfig) -> String {
        let resolved = crate::orchestrator_config::resolved_scan_config_for_scanner(scanner);
        crate::orchestrator_config::render_effective_config(&resolved)
    }
    fn autoroute_config_digest_for_args(&self, args: &mut ScanArgs) -> Result<u64> {
        let resolved = crate::orchestrator_config::resolve_scan_config(args)?;
        Ok(crate::orchestrator_config::autoroute_config_digest(
            &resolved,
        ))
    }
    fn autoroute_config_digest_for_scanner(&self, scanner: ScannerConfig) -> u64 {
        let resolved = crate::orchestrator_config::resolved_scan_config_for_scanner(scanner);
        crate::orchestrator_config::autoroute_config_digest(&resolved)
    }
    fn autoroute_config_digest_for_scanner_with_autoroute_gpu(
        &self,
        scanner: ScannerConfig,
        autoroute_gpu: bool,
    ) -> u64 {
        let mut resolved = crate::orchestrator_config::resolved_scan_config_for_scanner(scanner);
        resolved.autoroute_gpu = autoroute_gpu;
        crate::orchestrator_config::autoroute_config_digest(&resolved)
    }
    fn ml_threshold_default(&self) -> f64 {
        crate::orchestrator_config::ML_THRESHOLD_DEFAULT
    }

    fn explicit_backend_override(
        &self,
        raw: Option<&str>,
    ) -> Result<Option<keyhog_scanner::ScanBackend>> {
        crate::orchestrator::explicit_backend_override(raw)
    }
    fn allowlist_root_for_test(&self, path: &Path) -> PathBuf {
        crate::orchestrator::allowlist_root_for_test(path)
    }
    fn backend_requires_coalesced_batch_pipeline_for_test(
        &self,
        explicit: Option<keyhog_scanner::ScanBackend>,
    ) -> bool {
        crate::orchestrator::backend_requires_coalesced_batch_pipeline_for_test(explicit)
    }
    fn gpu_init_policy_for_args_for_test(&self, args: &ScanArgs) -> keyhog_scanner::GpuInitPolicy {
        crate::orchestrator::gpu_init_policy_for_args_for_test(args)
    }
    fn gpu_init_policy_for_resolved_autoroute_for_test(
        &self,
        args: &ScanArgs,
        autoroute_cache_path: Option<&Path>,
        autoroute_gpu: bool,
        autoroute_calibration: bool,
    ) -> keyhog_scanner::GpuInitPolicy {
        crate::orchestrator::gpu_init_policy_for_resolved_autoroute_for_test(
            args,
            autoroute_cache_path,
            autoroute_gpu,
            autoroute_calibration,
        )
    }
    fn scanner_panic_notice_for_test(&self, panicked: bool) -> Option<String> {
        crate::orchestrator::scanner_panic_notice_for_test(panicked)
    }
    fn scan_orchestrator_from_parts_for_test(
        &self,
        args: ScanArgs,
        detectors: Vec<DetectorSpec>,
        scanner: Arc<CompiledScanner>,
        signatures: std::collections::HashSet<Arc<str>>,
        test_fixture_suppressions: TestFixtureSuppressions,
    ) -> ScanOrchestrator {
        ScanOrchestrator(crate::orchestrator::ScanOrchestrator::from_parts_for_test(
            args,
            detectors,
            scanner,
            signatures,
            test_fixture_suppressions.0,
        ))
    }
    fn scan_orchestrator_scanner<'a>(
        &self,
        orchestrator: &'a ScanOrchestrator,
    ) -> &'a CompiledScanner {
        orchestrator.0.scanner()
    }
    fn scan_orchestrator_args<'a>(&self, orchestrator: &'a ScanOrchestrator) -> &'a ScanArgs {
        orchestrator.0.args()
    }
    fn scan_orchestrator_scan_sources_for_test(
        &self,
        orchestrator: &ScanOrchestrator,
        sources: Vec<Box<dyn Source>>,
        show_progress: bool,
        merkle: Option<Arc<keyhog_core::MerkleIndex>>,
    ) -> Result<Vec<RawMatch>> {
        orchestrator
            .0
            .scan_sources_for_test(sources, show_progress, merkle)
    }

    fn scan_runtime_guard_for_test(&self) -> ScanRuntimeGuard {
        let guard = match SCAN_RUNTIME_TEST_LOCK.lock() {
            Ok(guard) => guard,
            // LAW10: test-only lock poisoning would cascade unrelated failures;
            // keep the guard held so shared scan-runtime state remains serialized.
            Err(poisoned) => poisoned.into_inner(),
        };
        ScanRuntimeGuard { _guard: guard }
    }

    fn seed_scan_runtime_state_for_test(&self, _guard: &ScanRuntimeGuard) {
        use std::sync::atomic::Ordering::Relaxed;

        crate::SCANNED_CHUNKS.store(11, Relaxed);
        crate::TOTAL_CHUNKS.store(13, Relaxed);
        crate::FINDINGS_COUNT.store(17, Relaxed);
        crate::GPU_SCANNED_CHUNKS.store(19, Relaxed);
        let _source_error_receipt = crate::record_source_error();
        let _failed_source_receipt = crate::record_failed_source();
        let _incremental_cache_receipt = crate::record_incremental_cache_persist_failed();
        let _scanner_panic_receipt = crate::record_scanner_panic();
        keyhog_scanner::telemetry::enable_dogfood();
        keyhog_scanner::telemetry::add_example_suppressions(23);
    }

    fn reset_scan_runtime_state_for_test(&self, _guard: &ScanRuntimeGuard) {
        crate::reset_scan_runtime_state();
    }

    fn scan_runtime_snapshot(&self, _guard: &ScanRuntimeGuard) -> ScanRuntimeSnapshot {
        use std::sync::atomic::Ordering::Relaxed;

        ScanRuntimeSnapshot {
            scanned_chunks: crate::SCANNED_CHUNKS.load(Relaxed),
            total_chunks: crate::TOTAL_CHUNKS.load(Relaxed),
            findings_count: crate::FINDINGS_COUNT.load(Relaxed),
            gpu_scanned_chunks: crate::GPU_SCANNED_CHUNKS.load(Relaxed),
            source_errors: crate::SOURCE_ERRORS.load(Relaxed),
            failed_sources: crate::FAILED_SOURCES.load(Relaxed),
            incremental_cache_errors: crate::INCREMENTAL_CACHE_ERRORS.load(Relaxed),
            scanner_panicked: crate::SCANNER_PANICKED.load(Relaxed),
            dogfood_enabled: keyhog_scanner::telemetry::is_dogfood_enabled(),
            example_suppressions: keyhog_scanner::telemetry::example_suppression_count(),
            decode_truncations: keyhog_scanner::telemetry::decode_truncation_count(),
        }
    }

    fn scanned_chunks(&self, _guard: &ScanRuntimeGuard) -> usize {
        crate::SCANNED_CHUNKS.load(std::sync::atomic::Ordering::Relaxed)
    }
    fn scanner_panicked(&self, _guard: &ScanRuntimeGuard) -> bool {
        crate::SCANNER_PANICKED.load(std::sync::atomic::Ordering::Relaxed)
    }
}

fn expose_baseline(inner: crate::baseline::Baseline) -> Baseline {
    Baseline {
        version: inner.version,
        created: inner.created,
        entries: inner
            .entries
            .into_iter()
            .map(|entry| BaselineEntry {
                detector_id: entry.detector_id,
                credential_hash: entry.credential_hash,
                file_path: entry.file_path,
                line: entry.line,
                status: entry.status,
            })
            .collect(),
    }
}

impl Baseline {
    fn to_internal(&self) -> crate::baseline::Baseline {
        let mut baseline = crate::baseline::Baseline::empty();
        baseline.version = self.version;
        baseline.created = self.created.clone();
        baseline.entries = self
            .entries
            .iter()
            .map(|entry| crate::baseline::BaselineEntry {
                detector_id: entry.detector_id.clone(),
                credential_hash: entry.credential_hash.clone(),
                file_path: entry.file_path.clone(),
                line: entry.line,
                status: entry.status.clone(),
            })
            .collect();
        baseline
    }
}

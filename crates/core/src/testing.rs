use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::allowlist::Allowlist;
use crate::calibration::{BetaCounters, Calibration};
use crate::config::ScanConfig;
use crate::credential::Credential;
use crate::merkle_index::MerkleIndex;
use crate::registry::{CustomVerifier, SourceRegistry, VerifierRegistry};
use crate::report::ReportError;
use crate::{
    DetectorSpec, RawMatch, RuleSuppressor, RuleSuppressorError, Severity, SpecError,
    VerifiedFinding,
};

pub fn seed_calibration_counters(calibration: &Calibration, id: &str, alpha: u32, beta: u32) {
    calibration.test_seed_counters(id, alpha, beta);
}

pub fn calibration_confidence_multiplier(calibration: &Calibration, detector_id: &str) -> f64 {
    calibration.confidence_multiplier(detector_id)
}

pub fn beta_posterior_mean(counters: &BetaCounters) -> f64 {
    counters.posterior_mean()
}

pub fn beta_observations(counters: &BetaCounters) -> u32 {
    counters.observations()
}

pub fn credential_expose_str(credential: &Credential) -> Option<&str> {
    credential.expose_str()
}

pub const MAX_STANDARD_BASE64_INPUT_BYTES: usize = crate::encoding::MAX_STANDARD_BASE64_INPUT_BYTES;

pub fn encode_standard_base64(input: &[u8]) -> String {
    crate::encoding::encode_standard_base64(input)
}

pub fn calibration_record_true_positive(calibration: &Calibration, detector_id: &str) {
    calibration.record_true_positive(detector_id);
}

pub fn calibration_record_false_positive(calibration: &Calibration, detector_id: &str) {
    calibration.record_false_positive(detector_id);
}

pub fn load_detectors_with_gate(
    dir: &Path,
    enforce_gate: bool,
) -> Result<Vec<DetectorSpec>, SpecError> {
    crate::spec::load::load_detectors_with_gate(dir, enforce_gate)
}

pub fn load_detectors_from_str(toml_str: &str) -> Result<Vec<DetectorSpec>, SpecError> {
    crate::spec::load::load_detectors_from_str(toml_str)
}

pub fn max_standard_base64_input_bytes() -> usize {
    crate::encoding::MAX_STANDARD_BASE64_INPUT_BYTES
}

pub fn merkle_empty() -> MerkleIndex {
    MerkleIndex::default()
}

pub fn merkle_with_max_entries(max_entries: usize) -> MerkleIndex {
    MerkleIndex::with_max_entries(max_entries)
}

pub fn merkle_max_entries(index: &MerkleIndex) -> usize {
    index.max_entries()
}

pub fn merkle_load(path: &Path) -> MerkleIndex {
    MerkleIndex::load(path)
}

pub fn merkle_save(index: &MerkleIndex, path: &Path) -> std::io::Result<()> {
    index.save(path)
}

pub fn merkle_lookup(index: &MerkleIndex, path: &Path) -> Option<(u64, u64, [u8; 32])> {
    index.lookup(path)
}

pub fn merkle_record(index: &MerkleIndex, path: PathBuf, content_hash: [u8; 32]) {
    index.record(path, content_hash);
}

pub fn merkle_is_empty(index: &MerkleIndex) -> bool {
    index.is_empty()
}

pub fn merkle_hash_content(content: &[u8]) -> [u8; 32] {
    MerkleIndex::hash_content(content)
}

pub fn merkle_unchanged(index: &MerkleIndex, path: &Path, content_hash: &[u8; 32]) -> bool {
    index.unchanged(path, content_hash)
}

pub fn merkle_metadata_unchanged(
    index: &MerkleIndex,
    path: &Path,
    mtime_ns: u64,
    size: u64,
) -> bool {
    index.metadata_unchanged(path, mtime_ns, size)
}

pub fn merkle_record_with_metadata(
    index: &MerkleIndex,
    path: PathBuf,
    mtime_ns: u64,
    size: u64,
    content_hash: [u8; 32],
) {
    index.record_with_metadata(path, mtime_ns, size, content_hash);
}

pub fn merkle_len(index: &MerkleIndex) -> usize {
    index.len()
}

pub fn merkle_default_cache_path() -> Option<PathBuf> {
    crate::merkle_index::default_cache_path()
}

pub fn default_cache_path() -> Option<PathBuf> {
    crate::merkle_index::default_cache_path()
}

pub fn lockdown_disk_cache_violations() -> Vec<PathBuf> {
    crate::hardening::lockdown_disk_cache_violations()
}

pub fn lockdown_cache_entry_error_is_violation() -> bool {
    crate::hardening::lockdown_cache_entry_error_is_violation_for_test()
}

pub fn allowlist_parse(content: &str) -> Allowlist {
    Allowlist::parse(content)
}

pub fn allowlist_is_allowed(allowlist: &Allowlist, finding: &VerifiedFinding) -> bool {
    allowlist.is_allowed(finding)
}

pub fn allowlist_is_hash_allowed(allowlist: &Allowlist, credential: &str) -> bool {
    allowlist.is_hash_allowed(credential)
}

pub fn allowlist_is_raw_hash_ignored(allowlist: &Allowlist, hash_hex: &str) -> bool {
    allowlist.is_raw_hash_ignored(hash_hex)
}

pub fn rule_suppressor_parse(toml_text: &str) -> Result<RuleSuppressor, RuleSuppressorError> {
    RuleSuppressor::parse(toml_text)
}

pub fn raw_match_sanitize_floats(raw_match: RawMatch) -> RawMatch {
    raw_match.sanitize_floats()
}

pub fn raw_match_deduplication_key(raw_match: &RawMatch) -> (&str, &str) {
    raw_match.deduplication_key()
}

pub fn dedup_lost_singleton_load(ordering: std::sync::atomic::Ordering) -> u64 {
    crate::dedup::DEDUP_LOST_SINGLETON.load(ordering)
}

pub struct DedupLostSingleton;

impl DedupLostSingleton {
    pub fn load(&self, ordering: std::sync::atomic::Ordering) -> u64 {
        crate::dedup::DEDUP_LOST_SINGLETON.load(ordering)
    }
}

pub static DEDUP_LOST_SINGLETON: DedupLostSingleton = DedupLostSingleton;

pub fn scan_config_validate(config: &ScanConfig) -> Result<(), String> {
    config.validate().map_err(|error| error.to_string())
}

pub fn max_decode_depth_limit() -> usize {
    crate::config::MAX_DECODE_DEPTH_LIMIT
}

pub fn secret_filenames() -> Vec<String> {
    crate::config::secret_filenames()
}

pub fn severity_to_severity(severity: Severity) -> Severity {
    severity.to_severity()
}

pub struct SourceRegistryProbe(SourceRegistry);

impl SourceRegistryProbe {
    pub fn register(&self, source: std::sync::Arc<dyn crate::Source + Send + Sync>) {
        self.0.register(source);
    }

    pub fn get(&self, name: &str) -> Option<std::sync::Arc<dyn crate::Source + Send + Sync>> {
        self.0.get(name)
    }
}

pub struct VerifierRegistryProbe(VerifierRegistry);

impl VerifierRegistryProbe {
    pub fn register(&self, verifier: std::sync::Arc<dyn CustomVerifier>) {
        self.0.register(verifier);
    }

    pub fn get(&self, name: &str) -> Option<std::sync::Arc<dyn CustomVerifier>> {
        self.0.get(name)
    }
}

pub fn source_registry() -> SourceRegistryProbe {
    SourceRegistryProbe(SourceRegistry::new())
}

pub fn verifier_registry() -> VerifierRegistryProbe {
    VerifierRegistryProbe(VerifierRegistry::new())
}

pub fn auto_fix_env_var_name_for_service(service: &str) -> String {
    crate::auto_fix::env_var_name_for_service(service)
}

pub fn auto_fix_replacement_text(service: &str) -> String {
    crate::auto_fix::fix_replacement_text(service)
}

pub fn report_banner<W: Write>(
    writer: &mut W,
    color: bool,
    art: bool,
    detector_count: usize,
) -> std::io::Result<()> {
    crate::report::banner::print_banner(writer, color, art, detector_count)
}

pub fn file_path_to_sarif_uri(path: &str) -> String {
    crate::report::sarif_uri::file_path_to_sarif_uri(path)
}

pub fn sarif_relative_to(path: &str, root: &Path) -> Option<String> {
    crate::report::sarif_uri::relative_to(path, root)
}

pub fn apply_code_scanning_props(
    props: &mut serde_json::Map<String, serde_json::Value>,
    severity: Severity,
) {
    crate::report::sarif_uri::apply_code_scanning_props(props, severity);
}

pub fn credential_fingerprints(credential_hash: &[u8; 32]) -> Option<BTreeMap<String, String>> {
    crate::report::sarif_uri::credential_fingerprints(credential_hash)
}

pub fn aws_account_from_key_id(key_id: &str) -> Option<String> {
    crate::aws::aws_account_from_key_id(key_id)
}

pub fn aws_account_is_canary(account_id: &str) -> bool {
    crate::aws::account_is_canary(account_id)
}

pub fn parse_aws_canary_accounts_for_test(
    raw: &str,
) -> Result<std::collections::HashSet<String>, String> {
    crate::aws::parse_canary_accounts(raw)
}

pub fn aws_canary_message() -> &'static str {
    crate::aws::CANARY_MESSAGE
}

pub trait Reporter {
    fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError>;
    fn finish(&mut self) -> Result<(), ReportError>;
}

macro_rules! reporter_wrapper {
    ($name:ident, $inner:path) => {
        pub struct $name<W: Write + Send> {
            inner: $inner,
            _writer: std::marker::PhantomData<W>,
        }

        impl<W: Write + Send> Reporter for $name<W> {
            fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
                crate::report::Reporter::report(&mut self.inner, finding)
            }

            fn finish(&mut self) -> Result<(), ReportError> {
                crate::report::Reporter::finish(&mut self.inner)
            }
        }

        impl<W: Write + Send> $name<W> {
            pub fn report(&mut self, finding: &VerifiedFinding) -> Result<(), ReportError> {
                crate::report::Reporter::report(&mut self.inner, finding)
            }

            pub fn finish(&mut self) -> Result<(), ReportError> {
                crate::report::Reporter::finish(&mut self.inner)
            }
        }
    };
}

reporter_wrapper!(TextReporter, crate::report::text::TextReporter<W>);
impl<W: Write + Send> TextReporter<W> {
    pub fn with_color(writer: W, color: bool) -> Self {
        Self {
            inner: crate::report::text::TextReporter::with_color(writer, color),
            _writer: std::marker::PhantomData,
        }
    }

    pub fn set_example_suppressions(&mut self, count: usize) {
        self.inner.set_example_suppressions(count);
    }

    pub fn set_dogfood_active(&mut self, active: bool) {
        self.inner.set_dogfood_active(active);
    }
}

reporter_wrapper!(JsonlReporter, crate::report::json::JsonlReporter<W>);
impl<W: Write + Send> JsonlReporter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            inner: crate::report::json::JsonlReporter::new(writer),
            _writer: std::marker::PhantomData,
        }
    }
}

reporter_wrapper!(JsonArrayReporter, crate::report::json::JsonArrayReporter<W>);
impl<W: Write + Send> JsonArrayReporter<W> {
    pub fn new(writer: W) -> Result<Self, ReportError> {
        Ok(Self {
            inner: crate::report::json::JsonArrayReporter::new(writer)?,
            _writer: std::marker::PhantomData,
        })
    }
}
pub type JsonReporter<W> = JsonArrayReporter<W>;

reporter_wrapper!(SarifReporter, crate::report::sarif::SarifReporter<W>);
impl<W: Write + Send> SarifReporter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            inner: crate::report::sarif::SarifReporter::new(writer),
            _writer: std::marker::PhantomData,
        }
    }

    pub fn with_skip_summary(mut self, skip_summary: Vec<(String, usize)>) -> Self {
        self.inner = self.inner.with_skip_summary(skip_summary);
        self
    }
}

reporter_wrapper!(CsvReporter, crate::report::csv::CsvReporter<W>);
impl<W: Write + Send> CsvReporter<W> {
    pub fn new(writer: W) -> Result<Self, ReportError> {
        Ok(Self {
            inner: crate::report::csv::CsvReporter::new(writer)?,
            _writer: std::marker::PhantomData,
        })
    }
}

reporter_wrapper!(HtmlReporter, crate::report::html::HtmlReporter<W>);
impl<W: Write + Send> HtmlReporter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            inner: crate::report::html::HtmlReporter::new(writer),
            _writer: std::marker::PhantomData,
        }
    }
}

reporter_wrapper!(JunitReporter, crate::report::junit::JunitReporter<W>);
impl<W: Write + Send> JunitReporter<W> {
    pub fn new(writer: W) -> Self {
        Self {
            inner: crate::report::junit::JunitReporter::new(writer),
            _writer: std::marker::PhantomData,
        }
    }
}

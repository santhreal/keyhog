use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::allowlist::Allowlist;
use crate::calibration::{BetaCounters, Calibration};
use crate::config::ScanConfig;
use crate::credential::Credential;
use crate::merkle_index::MerkleIndex;
use crate::registry::{CustomVerifier, SourceRegistry, VerifierRegistry};
use crate::{
    DetectorSpec, RawMatch, RuleSuppressor, RuleSuppressorError, Severity, SpecError,
    VerifiedFinding,
};

pub struct TestApi;

pub trait CoreTestApi {
    fn seed_calibration_counters(&self, calibration: &Calibration, id: &str, alpha: u32, beta: u32);
    fn calibration_confidence_multiplier(
        &self,
        calibration: &Calibration,
        detector_id: &str,
    ) -> f64;
    fn beta_posterior_mean(&self, counters: &BetaCounters) -> f64;
    fn beta_observations(&self, counters: &BetaCounters) -> u32;
    fn credential_expose_str<'a>(&self, credential: &'a Credential) -> Option<&'a str>;
    fn encode_standard_base64(&self, input: &[u8]) -> String;
    fn calibration_record_true_positive(&self, calibration: &Calibration, detector_id: &str);
    fn calibration_record_false_positive(&self, calibration: &Calibration, detector_id: &str);
    fn load_detectors_with_gate(
        &self,
        dir: &Path,
        enforce_gate: bool,
    ) -> Result<Vec<DetectorSpec>, SpecError>;
    fn load_detectors_from_str(&self, toml_str: &str) -> Result<Vec<DetectorSpec>, SpecError>;
    fn embedded_detector_tomls(&self) -> &'static [(&'static str, &'static str)];
    fn max_standard_base64_input_bytes(&self) -> usize;
    fn merkle_empty(&self) -> MerkleIndex;
    fn merkle_with_max_entries(&self, max_entries: usize) -> MerkleIndex;
    fn merkle_max_entries(&self, index: &MerkleIndex) -> usize;
    fn merkle_load(&self, path: &Path) -> MerkleIndex;
    fn merkle_save(&self, index: &MerkleIndex, path: &Path) -> std::io::Result<()>;
    fn merkle_lookup(&self, index: &MerkleIndex, path: &Path) -> Option<(u64, u64, [u8; 32])>;
    fn merkle_record(&self, index: &MerkleIndex, path: PathBuf, content_hash: [u8; 32]);
    fn merkle_is_empty(&self, index: &MerkleIndex) -> bool;
    fn merkle_hash_content(&self, content: &[u8]) -> [u8; 32];
    fn merkle_unchanged(&self, index: &MerkleIndex, path: &Path, content_hash: &[u8; 32]) -> bool;
    fn merkle_metadata_unchanged(
        &self,
        index: &MerkleIndex,
        path: &Path,
        mtime_ns: u64,
        size: u64,
    ) -> bool;
    fn merkle_record_with_metadata(
        &self,
        index: &MerkleIndex,
        path: PathBuf,
        mtime_ns: u64,
        size: u64,
        content_hash: [u8; 32],
    );
    fn merkle_len(&self, index: &MerkleIndex) -> usize;
    fn merkle_default_cache_path(&self) -> Option<PathBuf>;
    fn default_cache_path(&self) -> Option<PathBuf>;
    fn lockdown_disk_cache_violations(&self) -> Vec<PathBuf>;
    fn lockdown_disk_cache_violations_for_paths(
        &self,
        persistence_paths: Vec<PathBuf>,
    ) -> Vec<PathBuf>;
    fn lockdown_cache_entry_error_is_violation(&self) -> bool;
    fn allowlist_parse(&self, content: &str) -> Allowlist;
    fn allowlist_is_allowed(&self, allowlist: &Allowlist, finding: &VerifiedFinding) -> bool;
    fn allowlist_is_hash_allowed(&self, allowlist: &Allowlist, credential: &str) -> bool;
    fn allowlist_is_raw_hash_ignored(&self, allowlist: &Allowlist, hash_hex: &str) -> bool;
    fn rule_suppressor_parse(&self, toml_text: &str)
        -> Result<RuleSuppressor, RuleSuppressorError>;
    fn raw_match_sanitize_floats(&self, raw_match: RawMatch) -> RawMatch;
    fn raw_match_deduplication_key<'a>(&self, raw_match: &'a RawMatch) -> (&'a str, &'a str);
    fn dedup_lost_singleton_load(&self, ordering: std::sync::atomic::Ordering) -> u64;
    fn scan_config_validate(&self, config: &ScanConfig) -> Result<(), String>;
    fn max_decode_depth_limit(&self) -> usize;
    fn secret_filenames(&self) -> Vec<String>;
    fn source_registry_registered_name(
        &self,
        source: std::sync::Arc<dyn crate::Source + Send + Sync>,
        name: &str,
    ) -> Option<String>;
    fn source_registry_missing(&self, name: &str) -> bool;
    fn source_registry_register_twice_has(
        &self,
        first: std::sync::Arc<dyn crate::Source + Send + Sync>,
        second: std::sync::Arc<dyn crate::Source + Send + Sync>,
        name: &str,
    ) -> bool;
    fn verifier_registry_registered_name(&self, name: &str) -> Option<String>;
    fn auto_fix_env_var_name_for_service(&self, service: &str) -> String;
    fn auto_fix_replacement_text(&self, service: &str) -> String;
    fn remediation_action_for(
        &self,
        detector_id: &str,
        service: &str,
        severity: Severity,
    ) -> String;
    fn remediation_docs_for(
        &self,
        detector_id: &str,
        service: &str,
        severity: Severity,
    ) -> Option<String>;
    fn report_banner<W: Write>(
        &self,
        writer: &mut W,
        color: bool,
        art: bool,
        detector_count: usize,
    ) -> std::io::Result<()>;
    fn file_path_to_sarif_uri(&self, path: &str) -> String;
    fn sarif_relative_to(&self, path: &str, root: &Path) -> Option<String>;
    fn apply_code_scanning_props(
        &self,
        props: &mut serde_json::Map<String, serde_json::Value>,
        severity: Severity,
    );
    fn credential_fingerprints(
        &self,
        credential_hash: &[u8; 32],
    ) -> Option<BTreeMap<String, String>>;
    fn aws_account_from_key_id(&self, key_id: &str) -> Option<String>;
    fn aws_account_is_canary(&self, account_id: &str) -> bool;
    fn parse_aws_canary_accounts_for_test(
        &self,
        raw: &str,
    ) -> Result<std::collections::HashSet<String>, String>;
    fn aws_canary_message(&self) -> &'static str;
}

impl CoreTestApi for TestApi {
    fn seed_calibration_counters(
        &self,
        calibration: &Calibration,
        id: &str,
        alpha: u32,
        beta: u32,
    ) {
        calibration.test_seed_counters(id, alpha, beta);
    }

    fn calibration_confidence_multiplier(
        &self,
        calibration: &Calibration,
        detector_id: &str,
    ) -> f64 {
        calibration.confidence_multiplier(detector_id)
    }

    fn beta_posterior_mean(&self, counters: &BetaCounters) -> f64 {
        counters.posterior_mean()
    }

    fn beta_observations(&self, counters: &BetaCounters) -> u32 {
        counters.observations()
    }

    fn credential_expose_str<'a>(&self, credential: &'a Credential) -> Option<&'a str> {
        credential.expose_str()
    }

    fn encode_standard_base64(&self, input: &[u8]) -> String {
        crate::encoding::encode_standard_base64(input)
    }

    fn calibration_record_true_positive(&self, calibration: &Calibration, detector_id: &str) {
        calibration.record_true_positive(detector_id);
    }

    fn calibration_record_false_positive(&self, calibration: &Calibration, detector_id: &str) {
        calibration.record_false_positive(detector_id);
    }

    fn load_detectors_with_gate(
        &self,
        dir: &Path,
        enforce_gate: bool,
    ) -> Result<Vec<DetectorSpec>, SpecError> {
        crate::spec::load::load_detectors_with_gate(dir, enforce_gate)
    }

    fn load_detectors_from_str(&self, toml_str: &str) -> Result<Vec<DetectorSpec>, SpecError> {
        crate::spec::load::load_detectors_from_str(toml_str)
    }

    fn embedded_detector_tomls(&self) -> &'static [(&'static str, &'static str)] {
        crate::embedded_detector_tomls()
    }

    fn max_standard_base64_input_bytes(&self) -> usize {
        crate::encoding::MAX_STANDARD_BASE64_INPUT_BYTES
    }

    fn merkle_empty(&self) -> MerkleIndex {
        MerkleIndex::default()
    }

    fn merkle_with_max_entries(&self, max_entries: usize) -> MerkleIndex {
        MerkleIndex::with_max_entries(max_entries)
    }

    fn merkle_max_entries(&self, index: &MerkleIndex) -> usize {
        index.max_entries()
    }

    fn merkle_load(&self, path: &Path) -> MerkleIndex {
        MerkleIndex::load(path)
    }

    fn merkle_save(&self, index: &MerkleIndex, path: &Path) -> std::io::Result<()> {
        index.save(path)
    }

    fn merkle_lookup(&self, index: &MerkleIndex, path: &Path) -> Option<(u64, u64, [u8; 32])> {
        index.lookup(path)
    }

    fn merkle_record(&self, index: &MerkleIndex, path: PathBuf, content_hash: [u8; 32]) {
        index.record(path, content_hash);
    }

    fn merkle_is_empty(&self, index: &MerkleIndex) -> bool {
        index.is_empty()
    }

    fn merkle_hash_content(&self, content: &[u8]) -> [u8; 32] {
        MerkleIndex::hash_content(content)
    }

    fn merkle_unchanged(&self, index: &MerkleIndex, path: &Path, content_hash: &[u8; 32]) -> bool {
        index.unchanged(path, content_hash)
    }

    fn merkle_metadata_unchanged(
        &self,
        index: &MerkleIndex,
        path: &Path,
        mtime_ns: u64,
        size: u64,
    ) -> bool {
        index.metadata_unchanged(path, mtime_ns, size)
    }

    fn merkle_record_with_metadata(
        &self,
        index: &MerkleIndex,
        path: PathBuf,
        mtime_ns: u64,
        size: u64,
        content_hash: [u8; 32],
    ) {
        index.record_with_metadata(path, mtime_ns, size, content_hash);
    }

    fn merkle_len(&self, index: &MerkleIndex) -> usize {
        index.len()
    }

    fn merkle_default_cache_path(&self) -> Option<PathBuf> {
        crate::merkle_index::default_cache_path()
    }

    fn default_cache_path(&self) -> Option<PathBuf> {
        crate::merkle_index::default_cache_path()
    }

    fn lockdown_disk_cache_violations(&self) -> Vec<PathBuf> {
        crate::hardening::lockdown_disk_cache_violations()
    }

    fn lockdown_disk_cache_violations_for_paths(
        &self,
        persistence_paths: Vec<PathBuf>,
    ) -> Vec<PathBuf> {
        crate::hardening::lockdown_disk_cache_violations_for_paths(persistence_paths)
    }

    fn lockdown_cache_entry_error_is_violation(&self) -> bool {
        crate::hardening::lockdown_cache_entry_error_is_violation_for_test()
    }

    fn allowlist_parse(&self, content: &str) -> Allowlist {
        Allowlist::parse(content)
    }

    fn allowlist_is_allowed(&self, allowlist: &Allowlist, finding: &VerifiedFinding) -> bool {
        allowlist.is_allowed(finding)
    }

    fn allowlist_is_hash_allowed(&self, allowlist: &Allowlist, credential: &str) -> bool {
        allowlist.is_hash_allowed(credential)
    }

    fn allowlist_is_raw_hash_ignored(&self, allowlist: &Allowlist, hash_hex: &str) -> bool {
        allowlist.is_raw_hash_ignored(hash_hex)
    }

    fn rule_suppressor_parse(
        &self,
        toml_text: &str,
    ) -> Result<RuleSuppressor, RuleSuppressorError> {
        RuleSuppressor::parse(toml_text)
    }

    fn raw_match_sanitize_floats(&self, raw_match: RawMatch) -> RawMatch {
        raw_match.sanitize_floats()
    }

    fn raw_match_deduplication_key<'a>(&self, raw_match: &'a RawMatch) -> (&'a str, &'a str) {
        raw_match.deduplication_key()
    }

    fn dedup_lost_singleton_load(&self, ordering: std::sync::atomic::Ordering) -> u64 {
        crate::dedup::DEDUP_LOST_SINGLETON.load(ordering)
    }

    fn scan_config_validate(&self, config: &ScanConfig) -> Result<(), String> {
        config.validate().map_err(|error| error.to_string())
    }

    fn max_decode_depth_limit(&self) -> usize {
        crate::config::MAX_DECODE_DEPTH_LIMIT
    }

    fn secret_filenames(&self) -> Vec<String> {
        crate::config::secret_filenames()
    }

    fn source_registry_registered_name(
        &self,
        source: std::sync::Arc<dyn crate::Source + Send + Sync>,
        name: &str,
    ) -> Option<String> {
        let registry = SourceRegistry::new();
        registry.register(source);
        registry.get(name).map(|source| source.name().to_string())
    }

    fn source_registry_missing(&self, name: &str) -> bool {
        SourceRegistry::new().get(name).is_none()
    }

    fn source_registry_register_twice_has(
        &self,
        first: std::sync::Arc<dyn crate::Source + Send + Sync>,
        second: std::sync::Arc<dyn crate::Source + Send + Sync>,
        name: &str,
    ) -> bool {
        let registry = SourceRegistry::new();
        registry.register(first);
        registry.register(second);
        registry.get(name).is_some()
    }

    fn verifier_registry_registered_name(&self, name: &str) -> Option<String> {
        let registry = VerifierRegistry::new();
        let verifier = std::sync::Arc::new(NamedVerifier {
            name: name.to_string(),
        });
        registry.register(verifier);
        registry
            .get(name)
            .map(|verifier| verifier.name().to_string())
    }

    fn auto_fix_env_var_name_for_service(&self, service: &str) -> String {
        crate::auto_fix::env_var_name_for_service(service)
    }

    fn auto_fix_replacement_text(&self, service: &str) -> String {
        crate::auto_fix::fix_replacement_text(service)
    }

    fn remediation_action_for(
        &self,
        detector_id: &str,
        service: &str,
        severity: Severity,
    ) -> String {
        crate::auto_fix::remediation_for(detector_id, service, severity).action
    }

    fn remediation_docs_for(
        &self,
        detector_id: &str,
        service: &str,
        severity: Severity,
    ) -> Option<String> {
        let remediation = crate::auto_fix::remediation_for(detector_id, service, severity);
        remediation.revoke_url.or(remediation.docs_url)
    }

    fn report_banner<W: Write>(
        &self,
        writer: &mut W,
        color: bool,
        art: bool,
        detector_count: usize,
    ) -> std::io::Result<()> {
        crate::report::banner::print_banner(writer, color, art, detector_count)
    }

    fn file_path_to_sarif_uri(&self, path: &str) -> String {
        crate::report::sarif_uri::file_path_to_sarif_uri(path)
    }

    fn sarif_relative_to(&self, path: &str, root: &Path) -> Option<String> {
        crate::report::sarif_uri::relative_to(path, root)
    }

    fn apply_code_scanning_props(
        &self,
        props: &mut serde_json::Map<String, serde_json::Value>,
        severity: Severity,
    ) {
        crate::report::sarif_uri::apply_code_scanning_props(props, severity);
    }

    fn credential_fingerprints(
        &self,
        credential_hash: &[u8; 32],
    ) -> Option<BTreeMap<String, String>> {
        crate::report::sarif_uri::credential_fingerprints(credential_hash)
    }

    fn aws_account_from_key_id(&self, key_id: &str) -> Option<String> {
        crate::aws::aws_account_from_key_id(key_id)
    }

    fn aws_account_is_canary(&self, account_id: &str) -> bool {
        crate::aws::account_is_canary(account_id)
    }

    fn parse_aws_canary_accounts_for_test(
        &self,
        raw: &str,
    ) -> Result<std::collections::HashSet<String>, String> {
        crate::aws::parse_canary_accounts(raw)
    }

    fn aws_canary_message(&self) -> &'static str {
        crate::aws::CANARY_MESSAGE
    }
}

struct NamedVerifier {
    name: String,
}

impl CustomVerifier for NamedVerifier {
    fn name(&self) -> &str {
        &self.name
    }
}

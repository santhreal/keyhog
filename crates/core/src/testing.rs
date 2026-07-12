use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::allowlist::Allowlist;
use crate::calibration::{BetaCounters, Calibration};
use crate::config::ScanConfig;
use crate::credential::Credential;
use crate::merkle_index::{MerkleIndex, MerkleLoadReport};
use crate::{
    CredentialHash, DetectorSpec, RawMatch, RawMatchDedupKey, RuleSuppressor, RuleSuppressorError,
    Severity, SpecError, VerifiedFinding,
};

/// The absolute path to a source file given a path **relative to this crate's
/// manifest root** (`crates/core/`). Anchored to the compile-time
/// `CARGO_MANIFEST_DIR`, so it is independent of the process working directory.
/// Accepts crate-escaping relatives (e.g. `"../cli/src/..."`) for the few tests
/// that introspect a sibling crate's source. Pairs with [`read_crate_source`]
/// for callers that need the path itself rather than the contents.
pub fn crate_source_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

/// Read a source file by its manifest-root-relative path, independent of the
/// process working directory.
///
/// Source-introspection tests read crate source off disk. A bare
/// `read_to_string` of a `"src/..."` literal resolves against the *process*
/// CWD, which only equals the package root under a plain `cargo test`; it
/// `NotFound`-flakes under `cargo-nextest` (CWD = workspace root), a raw
/// test-binary run, or a sibling test that mutates the global CWD. Anchoring to
/// [`crate_source_path`] (compile-time `CARGO_MANIFEST_DIR`) makes the read
/// deterministic from any CWD and runner. This is the ONE canonical
/// crate-source reader for core tests; the `no_cwd_relative_source_reads` gate
/// forbids re-open-coding the CWD-relative form.
///
/// Panics with the resolved absolute path when the file is missing, so a typo
/// in `rel` is an obvious failure rather than a silent empty string.
pub fn read_crate_source(rel: &str) -> String {
    let path = crate_source_path(rel);
    match std::fs::read_to_string(&path) {
        Ok(source) => source,
        Err(error) => panic!("read crate source {}: {error}", path.display()),
    }
}

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
    fn credential_expose_secret<'a>(&self, credential: &'a Credential) -> &'a [u8];
    fn credential_expose_str<'a>(&self, credential: &'a Credential) -> Option<&'a str>;
    fn encode_standard_base64(&self, input: &[u8]) -> String;
    fn calibration_load_tolerant(&self, path: &Path) -> Calibration;
    fn read_capped(&self, path: &Path, cap: u64, kind: &str) -> std::io::Result<Vec<u8>>;
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
    fn merkle_load_with_max_entries(&self, path: &Path, max_entries: usize) -> MerkleIndex;
    fn merkle_load_report(&self, path: &Path) -> MerkleLoadReport;
    fn merkle_load_with_spec(&self, path: &Path, expected_spec_hash: &[u8; 32]) -> MerkleIndex;
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
    fn merkle_record_chunk_at_offset_and_check_unchanged(
        &self,
        index: &MerkleIndex,
        path: PathBuf,
        chunk_offset: u64,
        mtime_ns: u64,
        size: u64,
        content: &[u8],
    ) -> bool;
    fn merkle_len(&self, index: &MerkleIndex) -> usize;
    fn merkle_default_cache_path(&self) -> Option<PathBuf>;
    fn lockdown_disk_cache_violations(&self) -> Vec<PathBuf>;
    fn lockdown_disk_cache_violations_for_paths(
        &self,
        persistence_paths: Vec<PathBuf>,
    ) -> Vec<PathBuf>;
    fn lockdown_cache_entry_error_is_violation(&self) -> bool;
    fn allowlist_parse(&self, content: &str) -> Allowlist;
    fn allowlist_days_since_epoch_for_test(
        &self,
        now: std::time::SystemTime,
    ) -> Result<i64, String>;
    fn allowlist_is_allowed(&self, allowlist: &Allowlist, finding: &VerifiedFinding) -> bool;
    fn allowlist_is_hash_allowed(&self, allowlist: &Allowlist, credential: &str) -> bool;
    fn allowlist_is_raw_hash_ignored(&self, allowlist: &Allowlist, hash_hex: &str) -> bool;
    fn rule_suppressor_parse(&self, toml_text: &str)
        -> Result<RuleSuppressor, RuleSuppressorError>;
    fn rule_suppressor_load(&self, path: &Path) -> Result<RuleSuppressor, RuleSuppressorError>;
    fn raw_match_sanitize_floats(&self, raw_match: RawMatch) -> RawMatch;
    fn raw_match_deduplication_key<'a>(&self, raw_match: &'a RawMatch) -> RawMatchDedupKey<'a>;
    fn dedup_lost_singleton_load(&self, ordering: std::sync::atomic::Ordering) -> u64;
    fn scan_config_validate(&self, config: &ScanConfig) -> Result<(), String>;
    fn max_decode_depth_limit(&self) -> usize;
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
    fn parse_remediation_file_for_test(&self, raw: &str) -> Result<(), String>;
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
        credential_hash: CredentialHash,
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

    fn credential_expose_secret<'a>(&self, credential: &'a Credential) -> &'a [u8] {
        credential.expose_secret()
    }

    fn credential_expose_str<'a>(&self, credential: &'a Credential) -> Option<&'a str> {
        credential.expose_str()
    }

    fn encode_standard_base64(&self, input: &[u8]) -> String {
        crate::encoding::encode_standard_base64(input)
    }

    fn calibration_load_tolerant(&self, path: &Path) -> Calibration {
        Calibration::load(path)
    }
    fn read_capped(&self, path: &Path, cap: u64, kind: &str) -> std::io::Result<Vec<u8>> {
        crate::state_file::read_capped(path, cap, kind)
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

    fn merkle_load_with_max_entries(&self, path: &Path, max_entries: usize) -> MerkleIndex {
        MerkleIndex::load_with_max_entries(path, max_entries)
    }

    fn merkle_load_report(&self, path: &Path) -> MerkleLoadReport {
        MerkleIndex::load_report(path)
    }

    fn merkle_load_with_spec(&self, path: &Path, expected_spec_hash: &[u8; 32]) -> MerkleIndex {
        MerkleIndex::load_with_spec(path, expected_spec_hash)
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

    fn merkle_record_chunk_at_offset_and_check_unchanged(
        &self,
        index: &MerkleIndex,
        path: PathBuf,
        chunk_offset: u64,
        mtime_ns: u64,
        size: u64,
        content: &[u8],
    ) -> bool {
        index.record_chunk_at_offset_and_check_unchanged(
            path,
            chunk_offset,
            mtime_ns,
            size,
            content,
        )
    }

    fn merkle_len(&self, index: &MerkleIndex) -> usize {
        index.len()
    }

    fn merkle_default_cache_path(&self) -> Option<PathBuf> {
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

    fn allowlist_days_since_epoch_for_test(
        &self,
        now: std::time::SystemTime,
    ) -> Result<i64, String> {
        crate::allowlist::allowlist_days_since_epoch_for_test(now)
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

    fn rule_suppressor_load(&self, path: &Path) -> Result<RuleSuppressor, RuleSuppressorError> {
        RuleSuppressor::load(path)
    }

    fn raw_match_sanitize_floats(&self, raw_match: RawMatch) -> RawMatch {
        raw_match.sanitize_floats()
    }

    fn raw_match_deduplication_key<'a>(&self, raw_match: &'a RawMatch) -> RawMatchDedupKey<'a> {
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

    fn parse_remediation_file_for_test(&self, raw: &str) -> Result<(), String> {
        crate::auto_fix::validate_remediation_file_for_test(raw)
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
        props.insert(
            "security-severity".to_string(),
            serde_json::Value::String(
                crate::report::sarif_uri::code_scanning_security_severity(severity).to_string(),
            ),
        );
        props.insert(
            "tags".to_string(),
            serde_json::Value::Array(vec![serde_json::Value::String(
                crate::report::sarif_uri::CODE_SCANNING_SECURITY_TAG.to_string(),
            )]),
        );
    }

    fn credential_fingerprints(
        &self,
        credential_hash: CredentialHash,
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

// ── report::escape security-sanitizer facades (property-test surface) ──
// The `report::escape` sanitizers are `pub(crate)` and reached today only
// through the report FORMATTERS with fixed crafted inputs. These facades expose
// them directly so an integration proptest can pin the SECURITY INVARIANTS that
// must hold for ALL inputs (never just the sampled ones): no CDATA-terminator
// survives `escape_cdata`, no raw XML metacharacter survives `escape_xml_attr`,
// the sanitizers strip their whole control class, clean input is BORROWED (no
// alloc), and every sanitizer is idempotent. Each returns an owned `String` so
// tests need not thread `Cow` lifetimes; the `*_borrows` variants report whether
// the zero-copy `Cow::Borrowed` fast path was taken.

/// Escape a value for an XML attribute (`report::escape::escape_xml_attr`).
pub fn escape_xml_attr_for_test(value: &str) -> String {
    crate::report::escape::escape_xml_attr(value).into_owned()
}

/// Whether `escape_xml_attr` took the zero-copy borrowed path for `value`.
pub fn escape_xml_attr_borrows_for_test(value: &str) -> bool {
    matches!(
        crate::report::escape::escape_xml_attr(value),
        std::borrow::Cow::Borrowed(_)
    )
}

/// Neutralize a value for a `<![CDATA[…]]>` body (`report::escape::escape_cdata`).
pub fn escape_cdata_for_test(value: &str) -> String {
    crate::report::escape::escape_cdata(value).into_owned()
}

/// Replace XML-1.0-illegal control bytes (`report::escape::sanitize_xml`).
pub fn sanitize_xml_for_test(value: &str) -> String {
    crate::report::escape::sanitize_xml(value).into_owned()
}

/// Whether `sanitize_xml` took the zero-copy borrowed path for `value`.
pub fn sanitize_xml_borrows_for_test(value: &str) -> bool {
    matches!(
        crate::report::escape::sanitize_xml(value),
        std::borrow::Cow::Borrowed(_)
    )
}

/// Replace terminal-control bytes (`report::escape::sanitize_terminal`).
pub fn sanitize_terminal_for_test(value: &str) -> String {
    crate::report::escape::sanitize_terminal(value).into_owned()
}

/// Whether `sanitize_terminal` took the zero-copy borrowed path for `value`.
pub fn sanitize_terminal_borrows_for_test(value: &str) -> bool {
    matches!(
        crate::report::escape::sanitize_terminal(value),
        std::borrow::Cow::Borrowed(_)
    )
}

/// Escape a value for a CSV field (`report::escape::escape_csv`).
pub fn escape_csv_for_test(value: &str) -> String {
    crate::report::escape::escape_csv(value).into_owned()
}

/// The terminal-control predicate (`report::escape::is_terminal_control`).
pub fn is_terminal_control_for_test(c: char) -> bool {
    crate::report::escape::is_terminal_control(c)
}

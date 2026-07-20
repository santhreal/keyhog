//! Post-scan filtering, deduplication, and optional live verification.

use super::ScanOrchestrator;
use anyhow::Context;
use anyhow::Result;
use keyhog_core::{DedupScope, DedupedMatch, RawMatch, VerificationResult, VerifiedFinding};

/// Offline (no-verify, no-network) structural metadata for a finding's
/// credential, surfaced on every scan-output route.
///
/// This is the single merge point for the analyzers that derive evidence from
/// the credential string alone:
///   - [`keyhog_scanner::jwt::finding_metadata`]: `jwt.alg` / `jwt.iss` / … and
///     the `jwt.alg_none` security anomaly for JWT-shaped tokens.
///   - [`keyhog_scanner::aws::finding_metadata`], the offline-decoded
///     `account_id` for `AKIA…` / `ASIA…` AWS access-key IDs.
///
/// A credential is at most one of these shapes, so the maps never collide;
/// merging keeps the contract simple and means a future analyzer is one more
/// `extend` here rather than another divergent construction site. Returns an
/// empty map when no analyzer matched (the common case).
/// Offline structural metadata for a finding's credential. JWT iss/sub/aud
/// follow `show_secrets` (KH-1458); default redacts those claims (KH-1350).
pub(crate) fn offline_finding_metadata(
    credential: &str,
    show_secrets: bool,
) -> std::collections::HashMap<String, String> {
    let mut meta = keyhog_scanner::jwt::finding_metadata_with_secrets(credential, show_secrets)
        .unwrap_or_default(); // LAW10: missing/non-string field => empty/placeholder; recall-safe
    if let Some(aws_meta) = keyhog_scanner::aws::finding_metadata(credential) {
        meta.extend(aws_meta);
    }
    meta
}

/// Detect whether a given file path lives inside keyhog's own source repository.
///
/// The segment-based suppression below (detectors/tests/fixtures/benches) is
/// intended ONLY for keyhog-developer self-scans where those dirs hold
/// intentional test secrets that shouldn't be reported. Applied unconditionally,
/// it silently drops real leaks from any user repo whose tree contains a
/// `tests/` or `fixtures/` directory: and that is "every repo with tests."
///
/// The marker is keyhog's own root `Cargo.toml`: it lists `crates/scanner` plus
/// `crates/cli` as workspace members and contains the literal `"keyhog` (from
/// the embedded crate names). We resolve the keyhog repo root ONCE per process
/// by walking up from the binary's CWD, then for each finding check whether
/// its file path is a descendant of that root. A finding scanned from
/// `/tmp/some-other-project/` stays unsuppressed even if the user happens to
/// be running `keyhog` while CWD is inside the keyhog repo.
fn keyhog_repo_root() -> Option<&'static std::path::Path> {
    static CACHED: std::sync::OnceLock<Option<std::path::PathBuf>> = std::sync::OnceLock::new();
    CACHED
        .get_or_init(|| {
            let mut dir = std::env::current_dir().ok()?; // LAW10: optional env/cwd probe; absent => None (intended config/probe), recall-irrelevant
            loop {
                let cargo = dir.join("Cargo.toml");
                if cargo.is_file() {
                    // Read just the first 4 KiB. KeyHog's root Cargo.toml
                    // declares `members = ["crates/core", "crates/scanner", ...]`
                    // in the first dozen lines. Anything bigger is almost
                    // certainly not the keyhog manifest.
                    if let Ok(text) = std::fs::read_to_string(&cargo) {
                        // LAW10: optional self-repo marker probe; unreadable manifest disables only keyhog-fixture self-suppression, so findings stay emitted.
                        let head: String = text.chars().take(4096).collect();
                        if head.contains("crates/scanner")
                            && head.contains("crates/cli")
                            && head.contains("\"keyhog")
                        {
                            return Some(match std::fs::canonicalize(&dir) {
                                Ok(canonical) => canonical,
                                Err(_) => dir, // LAW10: canonicalize failure => original path (best-effort normalization); recall-safe
                            });
                        }
                    }
                }
                if !dir.pop() {
                    break;
                }
            }
            None
        })
        .as_deref()
}

struct SelfScanPathScope {
    keyhog_root: Option<&'static std::path::Path>,
    canonicalized_parent_dirs: std::collections::HashMap<std::path::PathBuf, std::path::PathBuf>,
}

impl SelfScanPathScope {
    fn new() -> Self {
        Self {
            keyhog_root: keyhog_repo_root(),
            canonicalized_parent_dirs: std::collections::HashMap::new(),
        }
    }

    fn canonical_parent_dir(&mut self, parent: &std::path::Path) -> &std::path::Path {
        self.canonicalized_parent_dirs
            .entry(parent.to_path_buf())
            .or_insert_with(|| {
                std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf())
                // LAW10: canonicalize failure => original parent path (best-effort normalization); recall-safe
            })
            .as_path()
    }

    /// True when the given finding's file path is a descendant of keyhog's own
    /// source tree. Returns false when no keyhog repo root was found.
    fn finding_inside_keyhog_repo(&mut self, file_path: &str) -> bool {
        let Some(root) = self.keyhog_root else {
            return false;
        };
        let path = std::path::Path::new(file_path);
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or_else(|| std::path::Path::new(".")); // LAW10: bare relative file has CWD as parent for self-scan scoping; recall-safe
        let Some(file_name) = path.file_name() else {
            return self.canonical_parent_dir(parent).starts_with(root);
        };
        let canonical_parent = self.canonical_parent_dir(parent);
        canonical_parent.join(file_name).starts_with(root)
    }
}

pub(crate) fn suppresses_test_fixture(
    fixtures: &crate::test_fixture_suppressions::TestFixtureSuppressions,
    m: &RawMatch,
) -> bool {
    if fixtures.suppresses(&m.credential) {
        keyhog_scanner::telemetry::record_example_suppression(
            m.detector_id.as_ref(),
            m.location.file_path.as_deref(),
            &m.credential,
            "test_fixture_suppression",
        );
        return true;
    }
    false
}

pub(crate) fn suppresses_allowlist_match(allowlist: &keyhog_core::Allowlist, m: &RawMatch) -> bool {
    if let Some(path) = m.location.file_path.as_deref() {
        if allowlist.is_path_ignored(path) {
            return true;
        }
    }
    allowlist.credential_hashes.contains(&m.credential_hash)
        || allowlist.ignored_detectors.contains(&*m.detector_id)
}

pub(crate) fn dedup_for_report(
    mut matches: Vec<RawMatch>,
    scope: &DedupScope,
) -> Vec<DedupedMatch> {
    matches.sort_by_key(|m| std::cmp::Reverse(m.severity));
    let deduped = keyhog_core::dedup_matches(matches, scope);
    keyhog_core::dedup_cross_detector(deduped)
}

/// One owner for the redact-vs-plaintext rendering of a finding's credential, so
/// a `Skipped` finding renders identically whether it came from the verify path
/// (`verify_findings`) or the non-verify path (`skipped_findings_from_deduped`).
/// `--show-secrets` prints plaintext; otherwise the credential is redacted.
pub(crate) fn render_credential(
    credential: &keyhog_core::SensitiveString,
    show_secrets: bool,
) -> std::borrow::Cow<'static, str> {
    if show_secrets {
        // Display redacts (KH-1424); intentional reveal uses as_str.
        credential.as_str().to_owned().into()
    } else {
        keyhog_core::redact(credential)
    }
}

pub(crate) fn skipped_findings_from_deduped(
    deduped: Vec<DedupedMatch>,
    show_secrets: bool,
) -> Vec<VerifiedFinding> {
    deduped
        .into_iter()
        .map(|m| {
            let severity = m.severity;
            let credential_redacted = render_credential(&m.credential, show_secrets);
            let metadata = offline_finding_metadata(m.credential.as_str(), show_secrets);
            let mut finding =
                VerifiedFinding::from_deduped(m, severity, VerificationResult::Skipped, metadata);
            finding.credential_redacted = credential_redacted;
            finding
        })
        .collect()
}

/// The scan-time filtering policy shared by EVERY scan-output route, borrowed
/// from whichever owner holds it (`ScanOrchestrator` for `keyhog scan`, the
/// `DefaultScanRuntime`'s resolved filter for `keyhog watch`). Extracting it into
/// one struct + one free function ([`filter_and_resolve_matches`]) is the ONE
/// PLACE that guarantees `scan` and `watch` apply an IDENTICAL pipeline
/// (signatures, disabled detectors, test-fixture + self-scan suppression,
/// allowlist, per-detector / global confidence floors, severity, match
/// resolution, inline suppression) (they can no longer drift).
pub(crate) struct MatchFilter<'a> {
    pub(crate) scanner: &'a keyhog_scanner::CompiledScanner,
    pub(crate) signatures: &'a std::collections::HashSet<std::sync::Arc<str>>,
    pub(crate) disabled_detectors: &'a std::collections::HashSet<String>,
    pub(crate) test_fixture_suppressions:
        &'a crate::test_fixture_suppressions::TestFixtureSuppressions,
    pub(crate) no_suppress_test_fixtures: bool,
    pub(crate) detector_min_confidence: &'a std::collections::HashMap<String, f64>,
    pub(crate) min_confidence: f64,
    pub(crate) min_severity: Option<keyhog_core::Severity>,
}

/// Apply the shared scan-time filter + resolution pipeline. Owner-agnostic: both
/// `keyhog scan` and `keyhog watch` route through this, so a finding suppressed
/// by one is suppressed by the other.
pub(crate) fn filter_and_resolve_matches(
    filter: &MatchFilter<'_>,
    matches: Vec<RawMatch>,
    allowlist: &keyhog_core::Allowlist,
) -> Result<Vec<RawMatch>> {
    let mut self_scan_path_scope = SelfScanPathScope::new();
    let mut filtered = matches
        .into_iter()
        .filter(|m| {
            let cred = m.credential.as_ref();

            if filter.signatures.contains(cred) {
                return false;
            }
            // `.keyhog.toml` `[detector.<id>] enabled = false`. Detectors are
            // already dropped at load; this exact-id guard keeps alternate
            // runtime surfaces aligned with the compiled corpus.
            if !filter.disabled_detectors.is_empty()
                && filter.disabled_detectors.contains(m.detector_id.as_ref())
            {
                return false;
            }
            if suppresses_test_fixture(filter.test_fixture_suppressions, m) {
                return false;
            }

            // Self-scan test-data path suppression. Three gates must
            // be true to suppress:
            //   1. `--no-suppress-test-fixtures` was NOT passed.
            //   2. The finding's file path lives inside keyhog's own repo.
            //   3. The path has a test-data-marker segment.
            if !filter.no_suppress_test_fixtures {
                if let Some(file_path) = m.location.file_path.as_deref() {
                    if self_scan_path_scope.finding_inside_keyhog_repo(file_path) {
                        let mut segs = file_path.split(['/', '\\']);
                        let suppressed = segs.any(|seg| {
                            seg.eq_ignore_ascii_case("detectors")
                                || seg.eq_ignore_ascii_case("tests")
                                || seg.eq_ignore_ascii_case("fixtures")
                                || seg.eq_ignore_ascii_case("benches")
                        });
                        if suppressed {
                            keyhog_scanner::telemetry::record_example_suppression(
                                m.detector_id.as_ref(),
                                m.location.file_path.as_deref(),
                                cred,
                                "self_scan_test_data_path",
                            );
                            return false;
                        }
                    }
                }
            }

            if suppresses_allowlist_match(allowlist, m) {
                return false;
            }
            // Missing/NaN confidence is 0.0 for the floor (KH-1351): unknown
            // quality must not bypass --min-confidence or per-detector floors.
            let conf = match m.confidence.filter(|confidence| confidence.is_finite()) {
                Some(confidence) => confidence,
                None => {
                    tracing::warn!(
                        detector = %m.detector_id,
                        "finding has no finite confidence; applying the conservative zero-confidence floor"
                    );
                    0.0
                }
            };
            if let Some(floor) = filter.detector_min_confidence.get(m.detector_id.as_ref()) {
                if conf < *floor {
                    return false;
                }
            } else if conf < filter.min_confidence {
                return false;
            }
            if let Some(min_severity) = filter.min_severity {
                if m.severity < min_severity {
                    return false;
                }
            }
            true
        })
        .collect::<Vec<_>>();

    filtered = filter
        .scanner
        .try_resolve_matches(filtered)
        .map_err(anyhow::Error::msg)
        .context("failed to resolve matches; fix the detector definitions")?;
    Ok(crate::inline_suppression::filter_inline_suppressions(
        filtered,
    ))
}

impl ScanOrchestrator {
    pub(crate) fn filter_and_resolve(
        &self,
        matches: Vec<RawMatch>,
        allowlist: &keyhog_core::Allowlist,
    ) -> Result<Vec<RawMatch>> {
        // Build the shared filter from the orchestrator's resolved config and
        // delegate to the ONE PLACE `keyhog watch` also uses.
        let filter = MatchFilter {
            scanner: &self.scanner,
            signatures: &self.signatures,
            disabled_detectors: &self.disabled_detectors,
            test_fixture_suppressions: &self.test_fixture_suppressions,
            no_suppress_test_fixtures: self.effective_config.report.no_suppress_test_fixtures,
            detector_min_confidence: &self.detector_min_confidence,
            min_confidence: self.effective_config.min_confidence,
            min_severity: self
                .effective_config
                .report
                .severity
                .as_ref()
                .map(|s| s.to_severity()),
        };
        filter_and_resolve_matches(&filter, matches, allowlist)
    }

    pub(crate) async fn finalize(&self, matches: Vec<RawMatch>) -> Result<Vec<VerifiedFinding>> {
        let scope = self.effective_config.report.dedup.to_core();
        let deduped = dedup_for_report(matches, &scope);

        #[cfg(feature = "verify")]
        if self.effective_config.report.verify {
            if self.effective_config.report.lockdown {
                anyhow::bail!(
                    "lockdown mode forbids --verify (would send credentials \
                     to outbound HTTPS endpoints). Drop --verify or drop --lockdown."
                );
            }
            return self
                .verify_findings(deduped, self.effective_config.report.show_secrets)
                .await;
        }

        if self.effective_config.report.lockdown && self.effective_config.report.show_secrets {
            anyhow::bail!(
                "lockdown mode forbids --show-secrets (would print plaintext credentials \
                 to stdout/stderr). Drop --show-secrets or drop --lockdown."
            );
        }

        Ok(skipped_findings_from_deduped(
            deduped,
            self.effective_config.report.show_secrets,
        ))
    }

    #[cfg(feature = "verify")]
    async fn verify_findings(
        &self,
        groups: Vec<DedupedMatch>,
        show_secrets: bool,
    ) -> Result<Vec<VerifiedFinding>> {
        use keyhog_verifier::{VerificationEngine, VerifyConfig};
        use std::io::IsTerminal;
        use std::time::Duration;

        const MIN_VERIFY_CONFIDENCE: f64 = 0.3;
        let (verify_candidates, skip_candidates): (Vec<_>, Vec<_>) = groups
            .into_iter()
            .partition(|m| m.confidence.unwrap_or(0.0) >= MIN_VERIFY_CONFIDENCE); // LAW10: absent confidence => 0.0 for sort/partition ordering only; recall-safe

        let skipped_count = skip_candidates.len();
        if skipped_count > 0 {
            tracing::info!(
                skipped = skipped_count,
                threshold = MIN_VERIFY_CONFIDENCE,
                "skipping low-confidence findings from verification"
            );
            eprintln!(
                "warning: --verify skipped {skipped_count} low-confidence finding(s) below \
                 verifier confidence floor {MIN_VERIFY_CONFIDENCE:.2}; they remain in output \
                 as verification=skipped."
            );
        }

        let verify = &self.effective_config.verify;
        let rate = verify.rate;
        if !rate.is_finite() || rate <= 0.0 {
            tracing::warn!(
                requested = rate,
                effective_rps = 1.0,
                "--verify-rate must be finite and > 0; \
                 clamping to 1 rps (one request per service per second)"
            );
        }
        keyhog_verifier::rate_limit::set_global_default_rps(rate);

        if verify.allow_script_verify {
            eprintln!(
                "warning: --allow-script-verify is active; trusted detector scripts may execute during verification"
            );
        }

        let mut verifier = VerificationEngine::new(
            &self.detectors,
            VerifyConfig {
                timeout: Duration::from_secs(verify.timeout_secs),
                max_concurrent_per_service: verify.max_concurrent_per_service,
                proxy: verify.proxy.clone(),
                insecure_tls: verify.insecure_tls,
                allow_script_verify: verify.allow_script_verify,
                ..Default::default()
            },
        )
        .context("initializing verification engine")?;

        if verify.oob.enabled {
            use keyhog_verifier::oob::OobConfig;
            let oob_config = OobConfig {
                server: verify.oob.server.clone(),
                default_timeout: Duration::from_secs(verify.oob.timeout_secs),
                max_timeout: Duration::from_secs(verify.oob.timeout_secs.max(120)),
                ..OobConfig::default()
            };
            if let Err(e) = verifier.enable_oob(oob_config).await {
                tracing::warn!(
                    error = %e,
                    server = %verify.oob.server,
                    "OOB verification unavailable: collector handshake failed; \
                     detectors that require [detector.verify.oob] will return \
                     verification errors while non-OOB detectors continue"
                );
                eprintln!(
                    "warning: --verify-oob collector handshake failed for {}: {e}; \
                     detectors that require OOB verification will report verification errors \
                     while non-OOB detectors continue.",
                    verify.oob.server
                );
            }
        }

        let progress_enabled =
            (self.args.progress || std::io::stderr().is_terminal()) && !self.args.stream;
        let progress_guard = if progress_enabled && !verify_candidates.is_empty() {
            let verify_candidate_count = verify_candidates.len();
            Some(super::reporting::TickerGuard::spawn(
                "verification",
                move |done, started| {
                    super::reporting::verification_ticker(done, started, verify_candidate_count)
                },
            ))
        } else {
            None
        };

        // KH-1487: retain offline JWT/AWS metadata by credential_hash before
        // verify_all consumes DedupedMatch plaintext; merge after so Live/Dead
        // rows get jwt.* under --show-secrets the same as Skipped.
        let offline_by_hash: std::collections::HashMap<_, _> = verify_candidates
            .iter()
            .map(|m| {
                (
                    m.credential_hash,
                    offline_finding_metadata(m.credential.as_str(), show_secrets),
                )
            })
            .collect();
        let mut findings = verifier.verify_all(verify_candidates).await;
        if let Some(guard) = progress_guard {
            guard.stop();
        }
        verifier.shutdown_oob().await;
        for finding in &mut findings {
            if let Some(offline) = offline_by_hash.get(&finding.credential_hash) {
                for (key, value) in offline {
                    finding
                        .metadata
                        .entry(key.clone())
                        .or_insert_with(|| value.clone());
                }
            }
        }

        for m in skip_candidates {
            let severity = m.severity;
            let credential_redacted = render_credential(&m.credential, show_secrets);
            let metadata = offline_finding_metadata(m.credential.as_str(), show_secrets);
            let mut finding = keyhog_core::VerifiedFinding::from_deduped(
                m,
                severity,
                keyhog_core::VerificationResult::Skipped,
                metadata,
            );
            finding.credential_redacted = credential_redacted;
            findings.push(finding);
        }

        Ok(findings)
    }
}

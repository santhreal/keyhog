//! Post-scan filtering, deduplication, and optional live verification.

use super::ScanOrchestrator;
use anyhow::{Context, Result};
#[cfg(feature = "verify")]
use keyhog_core::DedupedMatch;
use keyhog_core::{dedup_matches, RawMatch, VerificationResult, VerifiedFinding};

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
            let mut dir = std::env::current_dir().ok()?;
            loop {
                let cargo = dir.join("Cargo.toml");
                if cargo.is_file() {
                    // Read just the first 4 KiB. Keyhog's root Cargo.toml
                    // declares `members = ["crates/core", "crates/scanner", ...]`
                    // in the first dozen lines. Anything bigger is almost
                    // certainly not the keyhog manifest.
                    if let Ok(text) = std::fs::read_to_string(&cargo) {
                        let head: String = text.chars().take(4096).collect();
                        if head.contains("crates/scanner")
                            && head.contains("crates/cli")
                            && head.contains("\"keyhog")
                        {
                            return std::fs::canonicalize(&dir).ok().or(Some(dir));
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

/// True when the given finding's file path is a descendant of keyhog's
/// own source tree. Returns false when the path can't be canonicalized
/// or no keyhog repo root was found.
fn finding_inside_keyhog_repo(file_path: &str) -> bool {
    let Some(root) = keyhog_repo_root() else {
        return false;
    };
    let canonical =
        std::fs::canonicalize(file_path).unwrap_or_else(|_| std::path::PathBuf::from(file_path));
    canonical.starts_with(root)
}

impl ScanOrchestrator {
    pub(crate) fn filter_and_resolve(
        &self,
        matches: Vec<RawMatch>,
        allowlist: &keyhog_core::allowlist::Allowlist,
    ) -> Vec<RawMatch> {
        let mut filtered = matches
            .into_iter()
            .filter(|m| {
                let cred = m.credential.as_ref();

                if self.signatures.contains(cred) {
                    return false;
                }
                // `.keyhog.toml` `[detector.<id>] enabled = false`. TOML
                // detectors are already dropped at load; this also catches the
                // hardcoded hot-pattern fast path (ids like `hot-aws_key`),
                // which is not part of the loaded corpus.
                if !self.disabled_detectors.is_empty()
                    && self.disabled_detectors.contains(m.detector_id.as_ref())
                {
                    return false;
                }
                if self.test_fixture_suppressions.suppresses(cred) {
                    keyhog_scanner::telemetry::record_example_suppression(
                        m.detector_id.as_ref(),
                        m.location.file_path.as_deref(),
                        cred,
                        "test_fixture_suppression",
                    );
                    return false;
                }

                // Self-scan test-data path suppression. Three gates must
                // be true to suppress:
                //   1. `--no-suppress-test-fixtures` was NOT passed
                //      (it explicitly opts out of bundled suppression,
                //      and a user auditing the suppression list wants
                //      to see segment-filtered findings too).
                //   2. The finding's file path lives inside keyhog's
                //      own source repo (root Cargo.toml marker check).
                //   3. The path has a segment matching a test-data
                //      marker (detectors/tests/fixtures/benches).
                //
                // Without the path-scoping gate, every user with a
                // `tests/` directory in their tree would have findings
                // silently dropped, even when scanning a totally
                // unrelated project. The CWD-only check landed earlier
                // was the right idea but the wrong dimension: scoping
                // on FINDING path (not CWD) means a developer who runs
                // keyhog from inside its own repo against an external
                // target still gets real findings from that target.
                //
                // The previous iteration also matched any segment literally
                // equal to "keyhog", which dropped findings from any folder
                // named keyhog/ (forks, docs paths, Reddit demo trees).
                if !self.args.no_suppress_test_fixtures {
                    if let Some(file_path) = m.location.file_path.as_deref() {
                        if finding_inside_keyhog_repo(file_path) {
                            let mut segs = file_path.split(['/', '\\']);
                            let suppressed = segs.any(|seg| {
                                seg.eq_ignore_ascii_case("detectors")
                                    || seg.eq_ignore_ascii_case("tests")
                                    || seg.eq_ignore_ascii_case("fixtures")
                                    || seg.eq_ignore_ascii_case("benches")
                            });
                            if suppressed {
                                return false;
                            }
                        }
                    }
                }

                if let Some(path) = m.location.file_path.as_deref() {
                    if allowlist.is_path_ignored(path) {
                        return false;
                    }
                }
                if allowlist.is_hash_ignored(&m.credential_hash) {
                    return false;
                }
                if allowlist.ignored_detectors.contains(&*m.detector_id) {
                    return false;
                }
                if let Some(conf) = m.confidence {
                    // Per-detector floor from `.keyhog.toml`
                    // `[detector.<id>] min_confidence` takes precedence and
                    // applies unconditionally (it is an explicit per-detector
                    // policy, not the ML gate). Falls back to the global
                    // `--min-confidence` floor, which stays gated on `!no_ml`.
                    if let Some(floor) = self.detector_min_confidence.get(m.detector_id.as_ref()) {
                        if conf < *floor {
                            return false;
                        }
                    } else if !self.args.no_ml
                        && conf
                            < self
                                .args
                                .min_confidence
                                .unwrap_or(keyhog_core::ScanConfig::default().min_confidence)
                    {
                        // When `--min-confidence` is unset the floor falls back to the
                        // canonical `ScanConfig::default().min_confidence` (single source
                        // of truth in crates/core/src/config.rs), NOT a bare literal. This
                        // is the post-scan confidence gate for named-detector / entropy
                        // findings; its sibling is the scan-time generic-fallback gate at
                        // crates/scanner/src/engine/fallback_generic.rs (`confidence <
                        // self.config.min_confidence`). Both now resolve to the same value
                        // so the tuned == benched == shipped floor stays coherent.
                        return false;
                    }
                }
                if let Some(min_severity) = &self.args.severity {
                    if m.severity < min_severity.to_severity() {
                        return false;
                    }
                }
                true
            })
            .collect::<Vec<_>>();

        filtered = keyhog_scanner::resolution::resolve_matches(filtered);
        crate::inline_suppression::filter_inline_suppressions(filtered)
    }

    pub(crate) async fn finalize(
        &self,
        mut matches: Vec<RawMatch>,
    ) -> Result<Vec<VerifiedFinding>> {
        matches.sort_by_key(|m| std::cmp::Reverse(m.severity));
        let scope = self.args.dedup.to_core();
        let deduped = dedup_matches(matches, &scope);
        let deduped = keyhog_core::dedup_cross_detector(deduped);

        #[cfg(feature = "verify")]
        if self.args.verify {
            if self.args.lockdown {
                anyhow::bail!(
                    "lockdown mode forbids --verify (would send credentials \
                     to outbound HTTPS endpoints). Drop --verify or drop --lockdown."
                );
            }
            return self.verify_findings(deduped).await;
        }

        if self.args.lockdown && self.args.show_secrets {
            anyhow::bail!(
                "lockdown mode forbids --show-secrets (would print plaintext credentials \
                 to stdout/stderr). Drop --show-secrets or drop --lockdown."
            );
        }

        Ok(deduped
            .into_iter()
            .map(|m| VerifiedFinding {
                detector_id: m.detector_id,
                detector_name: m.detector_name,
                service: m.service,
                severity: m.severity,
                credential_redacted: if self.args.show_secrets {
                    m.credential.to_string().into()
                } else {
                    keyhog_core::redact(&m.credential)
                },
                credential_hash: m.credential_hash,
                location: m.primary_location,
                verification: VerificationResult::Skipped,
                metadata: std::collections::HashMap::new(),
                additional_locations: m.additional_locations,
                confidence: m.confidence,
            })
            .collect())
    }

    #[cfg(feature = "verify")]
    async fn verify_findings(&self, groups: Vec<DedupedMatch>) -> Result<Vec<VerifiedFinding>> {
        use keyhog_verifier::{VerificationEngine, VerifyConfig};
        use std::time::Duration;

        const MIN_VERIFY_CONFIDENCE: f64 = 0.3;
        let (verify_candidates, skip_candidates): (Vec<_>, Vec<_>) = groups
            .into_iter()
            .partition(|m| m.confidence.unwrap_or(0.0) >= MIN_VERIFY_CONFIDENCE);

        let skipped_count = skip_candidates.len();
        if skipped_count > 0 {
            tracing::info!(
                skipped = skipped_count,
                threshold = MIN_VERIFY_CONFIDENCE,
                "skipping low-confidence findings from verification"
            );
        }

        let rate = self.args.verify_rate;
        if !rate.is_finite() || rate <= 0.0 {
            tracing::warn!(
                requested = rate,
                effective_rps = 1.0,
                "--verify-rate must be finite and > 0; \
                 clamping to 1 rps (one request per service per second)"
            );
        }
        keyhog_verifier::rate_limit::set_global_default_rps(rate);

        let per_service_concurrency = if self.args.verify_batch {
            1
        } else {
            self.args.rate
        };

        let mut verifier = VerificationEngine::new(
            &self.detectors,
            VerifyConfig {
                timeout: Duration::from_secs(self.args.timeout),
                max_concurrent_per_service: per_service_concurrency,
                proxy: self.args.proxy.clone(),
                insecure_tls: self.args.insecure,
                ..Default::default()
            },
        )
        .context("initializing verification engine")?;

        if self.args.verify_oob {
            use keyhog_verifier::oob::OobConfig;
            let oob_config = OobConfig {
                server: self.args.oob_server.clone(),
                default_timeout: Duration::from_secs(self.args.oob_timeout),
                max_timeout: Duration::from_secs(self.args.oob_timeout.max(120)),
                ..OobConfig::default()
            };
            if let Err(e) = verifier.enable_oob(oob_config).await {
                tracing::warn!(
                    error = %e,
                    server = %self.args.oob_server,
                    "OOB verification disabled: collector handshake failed; continuing with HTTP-only verification"
                );
            }
        }

        let mut findings = verifier.verify_all(verify_candidates).await;
        verifier.shutdown_oob().await;

        for m in skip_candidates {
            findings.push(keyhog_core::VerifiedFinding {
                detector_id: m.detector_id,
                detector_name: m.detector_name,
                service: m.service,
                severity: m.severity,
                credential_redacted: keyhog_core::redact(&m.credential),
                credential_hash: m.credential_hash,
                location: m.primary_location,
                additional_locations: m.additional_locations,
                verification: keyhog_core::VerificationResult::Skipped,
                metadata: std::collections::HashMap::new(),
                confidence: m.confidence,
            });
        }

        Ok(findings)
    }
}

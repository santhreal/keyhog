//! Post-scan filtering, deduplication, and optional live verification.

use super::ScanOrchestrator;
use anyhow::{Context, Result};
#[cfg(feature = "verify")]
use keyhog_core::DedupedMatch;
use keyhog_core::{dedup_matches, RawMatch, VerificationResult, VerifiedFinding};

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
                if self.test_fixture_suppressions.suppresses(cred) {
                    keyhog_scanner::telemetry::record_example_suppression(
                        m.detector_id.as_ref(),
                        m.location.file_path.as_deref(),
                        cred,
                        "test_fixture_suppression",
                    );
                    return false;
                }

                if let Some(file_path) = m.location.file_path.as_deref() {
                    let mut segs = file_path.split(['/', '\\']);
                    let suppressed = segs.any(|seg| {
                        seg.eq_ignore_ascii_case("keyhog")
                            || seg.eq_ignore_ascii_case("detectors")
                            || seg.eq_ignore_ascii_case("tests")
                            || seg.eq_ignore_ascii_case("fixtures")
                            || seg.eq_ignore_ascii_case("benches")
                    });
                    if suppressed {
                        return false;
                    }
                }

                if let Some(path) = m.location.file_path.as_deref() {
                    if allowlist.is_path_ignored(path) {
                        return false;
                    }
                }
                if allowlist.is_raw_hash_ignored(&m.credential_hash) {
                    return false;
                }
                if allowlist.ignored_detectors.contains(&*m.detector_id) {
                    return false;
                }
                if let Some(conf) = m.confidence {
                    if !self.args.no_ml && conf < self.args.min_confidence.unwrap_or(0.3) {
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
                    "OOB verification disabled — collector handshake failed; continuing with HTTP-only verification"
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

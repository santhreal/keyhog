use crate::args::{CliDedupScope, ScanArgs, SeverityFilter};
use crate::orchestrator_config::{VERIFY_MAX_CONCURRENT_DEFAULT, VERIFY_TIMEOUT_DEFAULT_SECS};
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub(crate) struct ResolvedAllowlistConfig {
    pub(crate) file: Option<PathBuf>,
    pub(crate) require_reason: bool,
    pub(crate) require_approved_by: bool,
    pub(crate) max_expires_days: Option<u64>,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedReportPolicy {
    pub(crate) severity: Option<SeverityFilter>,
    pub(crate) dedup: CliDedupScope,
    pub(crate) verify: bool,
    pub(crate) lockdown: bool,
    pub(crate) show_secrets: bool,
    pub(crate) no_suppress_test_fixtures: bool,
    pub(crate) hide_client_safe: bool,
}

impl ResolvedReportPolicy {
    pub(super) fn from_scan_args(args: &ScanArgs) -> Self {
        Self {
            severity: args.severity.clone(),
            dedup: args.dedup.clone(),
            verify: scan_verify_enabled(args),
            lockdown: args.lockdown,
            show_secrets: args.show_secrets,
            no_suppress_test_fixtures: args.no_suppress_test_fixtures,
            hide_client_safe: args.hide_client_safe,
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedVerifyPolicy {
    pub(crate) rate: f64,
    pub(crate) max_concurrent_per_service: usize,
    pub(crate) timeout_secs: u64,
    pub(crate) proxy: Option<String>,
    pub(crate) insecure_tls: bool,
    pub(crate) allow_script_verify: bool,
    pub(crate) oob: ResolvedOobPolicy,
}

#[derive(Debug, Clone)]
pub(crate) struct ResolvedOobPolicy {
    pub(crate) enabled: bool,
    pub(crate) server: String,
    pub(crate) timeout_secs: u64,
}

impl ResolvedVerifyPolicy {
    #[cfg(feature = "verify")]
    pub(super) fn from_scan_args(args: &ScanArgs) -> Self {
        Self {
            rate: args.verify_rate,
            max_concurrent_per_service: if args.verify_batch {
                1
            } else {
                args.verify_concurrency
                    .unwrap_or(VERIFY_MAX_CONCURRENT_DEFAULT) // LAW10: absent verify concurrency => documented default; explicit CLI/TOML values remain Some and win
            },
            timeout_secs: args.timeout.unwrap_or(VERIFY_TIMEOUT_DEFAULT_SECS), // LAW10: absent verify timeout => documented default; explicit CLI/TOML values remain Some and win
            proxy: args.proxy.clone(),
            insecure_tls: args.insecure,
            allow_script_verify: args.allow_script_verify,
            oob: ResolvedOobPolicy {
                enabled: args.verify_oob,
                server: args.oob_server.clone(),
                timeout_secs: args.oob_timeout,
            },
        }
    }

    #[cfg(all(
        not(feature = "verify"),
        any(
            feature = "web",
            feature = "github",
            feature = "gitlab",
            feature = "bitbucket",
            feature = "s3",
            feature = "gcs",
            feature = "azure"
        )
    ))]
    pub(super) fn from_scan_args(args: &ScanArgs) -> Self {
        // HTTP transport policy also belongs to remote sources. A build without
        // live verification must still report and honor it.
        Self {
            proxy: args.proxy.clone(),
            insecure_tls: args.insecure,
            ..Self::disabled()
        }
    }

    #[cfg(all(
        not(feature = "verify"),
        not(any(
            feature = "web",
            feature = "github",
            feature = "gitlab",
            feature = "bitbucket",
            feature = "s3",
            feature = "gcs",
            feature = "azure"
        ))
    ))]
    pub(super) fn from_scan_args(_args: &ScanArgs) -> Self {
        Self::disabled()
    }

    pub(crate) fn disabled() -> Self {
        Self {
            rate: 1.0,
            max_concurrent_per_service: VERIFY_MAX_CONCURRENT_DEFAULT,
            timeout_secs: VERIFY_TIMEOUT_DEFAULT_SECS,
            proxy: None,
            insecure_tls: false,
            allow_script_verify: false,
            oob: ResolvedOobPolicy {
                enabled: false,
                server: "https://oob.invalid".into(),
                timeout_secs: 30,
            },
        }
    }
}

#[cfg(feature = "verify")]
fn scan_verify_enabled(args: &ScanArgs) -> bool {
    args.verify
}

#[cfg(not(feature = "verify"))]
fn scan_verify_enabled(_args: &ScanArgs) -> bool {
    false
}

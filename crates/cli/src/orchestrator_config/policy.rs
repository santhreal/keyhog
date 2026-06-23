use crate::args::{CliDedupScope, ScanArgs, SeverityFilter};
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
            verify: args.verify,
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
    pub(super) fn from_scan_args(args: &ScanArgs) -> Self {
        Self {
            rate: args.verify_rate,
            max_concurrent_per_service: if args.verify_batch { 1 } else { args.rate },
            timeout_secs: args.timeout,
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

    pub(crate) fn disabled() -> Self {
        Self {
            rate: 1.0,
            max_concurrent_per_service: 5,
            timeout_secs: 5,
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

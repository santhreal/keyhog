//! CLI exit-code contract.
//!
//! Keep every numeric code here. Subcommands may expose semantic aliases, but
//! the underlying numbers and help text live in this module so docs, help, and
//! behavior cannot drift independently.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitCodeDefinition {
    pub code: u8,
    pub label: &'static str,
    pub scan_reachable: bool,
}

pub const EXIT_SUCCESS: u8 = 0;
pub const EXIT_FINDINGS: u8 = 1;
pub const EXIT_USER_ERROR: u8 = 2;
pub const EXIT_SYSTEM_ERROR: u8 = 3;
pub const EXIT_HEALTH_FAILURE: u8 = 4;
pub const EXIT_LIVE_CREDENTIALS: u8 = 10;
pub const EXIT_SCANNER_PANIC: u8 = 11;
pub const EXIT_REQUIRE_GPU_UNMET: u8 = 12;
pub const EXIT_SOURCE_FAILED: u8 = 13;
pub const EXIT_INTERRUPTED: u8 = 130;

pub const EXIT_BACKEND_SELF_TEST_FAILED: u8 = EXIT_HEALTH_FAILURE;
pub const EXIT_DETECTOR_AUDIT_FAILED: u8 = EXIT_SYSTEM_ERROR;
pub const EXIT_DOCTOR_UNHEALTHY: u8 = EXIT_HEALTH_FAILURE;
pub const EXIT_REPAIR_FAILED: u8 = EXIT_HEALTH_FAILURE;
pub const EXIT_UPDATE_AVAILABLE: u8 = EXIT_LIVE_CREDENTIALS;
pub const EXIT_CREDENTIALS_FOUND: u8 = EXIT_FINDINGS;

pub const DEFINITIONS: &[ExitCodeDefinition] = &[
    ExitCodeDefinition {
        code: EXIT_SUCCESS,
        label: "Success",
        scan_reachable: true,
    },
    ExitCodeDefinition {
        code: EXIT_FINDINGS,
        label: "Findings present",
        scan_reachable: true,
    },
    ExitCodeDefinition {
        code: EXIT_USER_ERROR,
        label: "User error",
        scan_reachable: true,
    },
    ExitCodeDefinition {
        code: EXIT_SYSTEM_ERROR,
        label: "System error",
        scan_reachable: true,
    },
    ExitCodeDefinition {
        code: EXIT_HEALTH_FAILURE,
        label: "Health/self-test failure",
        scan_reachable: false,
    },
    ExitCodeDefinition {
        code: EXIT_LIVE_CREDENTIALS,
        label: "Live credentials found",
        scan_reachable: true,
    },
    ExitCodeDefinition {
        code: EXIT_SCANNER_PANIC,
        label: "Scanner thread panicked",
        scan_reachable: true,
    },
    ExitCodeDefinition {
        code: EXIT_REQUIRE_GPU_UNMET,
        label: "Required GPU unavailable",
        scan_reachable: true,
    },
    ExitCodeDefinition {
        code: EXIT_SOURCE_FAILED,
        label: "Requested source produced no data",
        scan_reachable: true,
    },
    ExitCodeDefinition {
        code: EXIT_INTERRUPTED,
        label: "Interrupted",
        scan_reachable: true,
    },
];

pub const HELP: &str = "EXIT CODES:\n  \
0   Success (no secrets found)\n  \
1   Secrets found, none confirmed live (unverified, skipped, or verified-inactive: dead/revoked)\n  \
2   User error (bad flag/config, missing path/baseline, detector-load failure, not-found/permission-denied path)\n  \
3   System error (local environment failure: low-level I/O that is not not-found/permission-denied, or GPU/hardware init)\n  \
4   Health/self-test failure (doctor unhealthy / repair could not restore a working binary / backend --self-test failed)\n  \
10  Live credentials found (requires --verify)\n  \
11  Scanner thread panicked mid-scan (state is unreliable)\n  \
12  Required GPU unavailable (--require-gpu)\n  \
13  Requested source failed before producing scan data\n  \
130 Interrupted (SIGINT / Ctrl-C)";

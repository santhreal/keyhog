//! CLI exit-code contract.
//!
//! Keep every numeric code here. Subcommands may expose semantic aliases, but
//! the underlying numbers and help text live in this module so docs, help, and
//! behavior cannot drift independently.

use std::sync::LazyLock;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExitCodeDefinition {
    pub code: u8,
    /// Short label (used by structured/diagnostic surfaces).
    pub label: &'static str,
    /// Full one-line description rendered in the `EXIT CODES:` help block. The
    /// generated [`help`] view renders these, so `DEFINITIONS` is the single source
    /// of truth for the printed help (the numbers and the docs cannot drift).
    pub help: &'static str,
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
        help: "Success (no secrets found)",
        scan_reachable: true,
    },
    ExitCodeDefinition {
        code: EXIT_FINDINGS,
        label: "Findings present",
        help: "Secrets found, none confirmed live (unverified, skipped, or verified-inactive: dead/revoked)",
        scan_reachable: true,
    },
    ExitCodeDefinition {
        code: EXIT_USER_ERROR,
        label: "User error",
        help: "User error (bad flag/config, missing path/baseline, detector-load failure, invalid autoroute calibration, not-found/permission-denied path)",
        scan_reachable: true,
    },
    ExitCodeDefinition {
        code: EXIT_SYSTEM_ERROR,
        label: "System error",
        help: "System error (local environment failure: low-level I/O, fatal daemon service failure, or selected SIMD/Hyperscan unavailable)",
        scan_reachable: true,
    },
    ExitCodeDefinition {
        code: EXIT_HEALTH_FAILURE,
        label: "Health/self-test failure",
        help: "Health/self-test failure (doctor unhealthy / repair could not restore a working binary / backend --self-test failed)",
        scan_reachable: false,
    },
    ExitCodeDefinition {
        code: EXIT_LIVE_CREDENTIALS,
        label: "Live credentials found",
        help: "Live credentials found (requires --verify)",
        scan_reachable: true,
    },
    ExitCodeDefinition {
        code: EXIT_SCANNER_PANIC,
        label: "Scanner thread panicked",
        help: "Scanner thread panicked mid-scan (state is unreliable)",
        scan_reachable: true,
    },
    ExitCodeDefinition {
        code: EXIT_REQUIRE_GPU_UNMET,
        label: "Selected GPU unavailable",
        help: "Selected GPU unavailable (--require-gpu, explicit gpu, or autoroute gpu dispatch)",
        scan_reachable: true,
    },
    ExitCodeDefinition {
        code: EXIT_SOURCE_FAILED,
        label: "Requested source failed or coverage incomplete",
        help: "Requested source failed or input coverage was incomplete",
        scan_reachable: true,
    },
    ExitCodeDefinition {
        code: EXIT_INTERRUPTED,
        label: "Interrupted",
        help: "Interrupted (SIGINT / Ctrl-C)",
        scan_reachable: true,
    },
];

/// The `EXIT CODES:` help block shown under `--help`, GENERATED from
/// [`DEFINITIONS`] so the numeric constants, the table, and the printed help can
/// never drift apart (the table is the single source of truth). Rendered once and
/// cached. Each row is `  {code:<3} {help}`, matching the historical hand-written
/// layout byte-for-byte.
pub fn help() -> &'static str {
    static RENDERED: LazyLock<String> = LazyLock::new(|| {
        let mut out = String::from("EXIT CODES:");
        for def in DEFINITIONS {
            out.push_str(&format!("\n  {:<3} {}", def.code, def.help));
        }
        out
    });
    &RENDERED
}

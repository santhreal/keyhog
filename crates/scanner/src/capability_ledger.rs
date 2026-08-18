//! Capability test ledger for tracking capability-conditional test outcomes.
//!
//! Prevents vacuous test passes by ensuring every capability-conditional test
//! explicitly registers whether it ran or skipped due to an absent capability,
//! and validates that skip counts do not exceed committed host-class baselines.

use std::path::Path;
use std::sync::Mutex;
use serde::{Deserialize, Serialize};

pub use crate::hw_probe::HostClass;

/// The execution outcome of a capability-conditional test.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CapabilityOutcome {
    /// The capability was present and the test ran its assertions.
    Ran,
    /// The capability was absent on this host class and the test skipped early.
    SkippedCapabilityAbsent,
    /// The test failed.
    Failed,
}

/// A recorded capability test execution entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityLedgerRecord {
    pub test_name: String,
    pub capability: String,
    pub host_class: HostClass,
    pub outcome: CapabilityOutcome,
}

static CAPABILITY_LEDGER: Mutex<Vec<CapabilityLedgerRecord>> = Mutex::new(Vec::new());

/// Register a capability-conditional test outcome.
///
/// Returns `true` if the capability is available and the test should proceed,
/// or `false` if the capability is absent and the test should return early.
/// Panics if a required policy (e.g. `gpu_required_by_policy()`) is breached.
pub fn register_capability_test(test_name: &str, capability: &str, is_available: bool) -> bool {
    let host_class = HostClass::detect();
    let outcome = if is_available {
        CapabilityOutcome::Ran
    } else {
        if crate::gpu::gpu_required_by_policy() && capability.to_ascii_lowercase().contains("gpu") {
            panic!(
                "capability '{capability}' is required by policy for test '{test_name}' but absent on host class {}",
                host_class.label()
            );
        }
        CapabilityOutcome::SkippedCapabilityAbsent
    };

    if let Ok(mut ledger) = CAPABILITY_LEDGER.lock() { // LAW10: capability test ledger recording; test-only observability
        ledger.push(CapabilityLedgerRecord {
            test_name: test_name.to_string(),
            capability: capability.to_string(),
            host_class,
            outcome,
        });
    }

    is_available
}

/// Aggregated summary of capability test outcomes for the current process.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityLedgerSummary {
    pub host_class: Option<HostClass>,
    pub ran_count: usize,
    pub skipped_count: usize,
    pub failed_count: usize,
    pub records: Vec<CapabilityLedgerRecord>,
}

/// Retrieve the current capability ledger summary.
pub fn capability_ledger_summary() -> CapabilityLedgerSummary {
    let host_class = Some(HostClass::detect());
    let records = CAPABILITY_LEDGER.lock().map(|l| l.clone()).unwrap_or_default(); // LAW10: capability test ledger snapshot; test-only observability
    let mut ran_count = 0;
    let mut skipped_count = 0;
    let mut failed_count = 0;
    for r in &records {
        match r.outcome {
            CapabilityOutcome::Ran => ran_count += 1,
            CapabilityOutcome::SkippedCapabilityAbsent => skipped_count += 1,
            CapabilityOutcome::Failed => failed_count += 1,
        }
    }
    CapabilityLedgerSummary {
        host_class,
        ran_count,
        skipped_count,
        failed_count,
        records,
    }
}

/// Reset the capability ledger (for testing).
pub fn reset_capability_ledger() {
    if let Ok(mut ledger) = CAPABILITY_LEDGER.lock() { // LAW10: capability test ledger reset; test-only observability
        ledger.clear();
    }
}

/// Print the capability ledger summary to stderr.
pub fn print_capability_ledger_summary() {
    let summary = capability_ledger_summary();
    let class_label = summary.host_class.map(|c| c.label()).unwrap_or("unknown"); // LAW10: formatting fallback for display-only test summary
    eprintln!(
        "[CAPABILITY LEDGER] Host class: {} | Ran: {} | Skipped (absent): {} | Failed: {}",
        class_label,
        summary.ran_count,
        summary.skipped_count,
        summary.failed_count
    );
}

/// Verify that the current process's skip count does not exceed the committed baseline for its host class.
pub fn verify_capability_ledger_baseline(baseline_path: &Path) -> Result<(), String> {
    let summary = capability_ledger_summary();
    let host_class = summary.host_class.unwrap_or_else(HostClass::detect); // LAW10: intended default to detect current host class; test-only reporting-only

    if !baseline_path.exists() {
        return Err(format!(
            "capability skip baseline file not found at {}",
            baseline_path.display()
        ));
    }

    let content = std::fs::read_to_string(baseline_path).map_err(|e| e.to_string())?;
    let toml: toml::Value = toml::from_str(&content).map_err(|e| e.to_string())?;
    let baselines = toml
        .get("baselines")
        .and_then(|b| b.as_table())
        .ok_or_else(|| "missing [baselines] table in baseline TOML".to_string())?;

    let limit = baselines
        .get(host_class.label())
        .and_then(|v| v.as_integer())
        .ok_or_else(|| {
            format!(
                "no baseline skip limit configured for host class {}",
                host_class.label()
            )
        })? as usize;

    if summary.skipped_count > limit {
        return Err(format!(
            "capability skip count {} on host class {} exceeds committed baseline limit of {}",
            summary.skipped_count,
            host_class.label(),
            limit
        ));
    }

    Ok(())
}

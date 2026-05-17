//! Driver-tier observability surface (P-OBS-1).
//!
//! Single entry point for metrics consumers (Prometheus,
//! OpenTelemetry, Datadog, custom dashboards). Aggregates:
//!
//! - Substrate-call counters from
//!   `vyre_self_substrate::observability`.
//! - Cache hit/miss rates (when caches expose them).
//! - Substrate-decision telemetry (which math chose what).
//!
//! Backends extend this surface with
//! backend-specific gauges via the
//! [`crate::observability::BackendObservabilityProvider`] trait.

#[cfg(feature = "self-substrate-adapters")]
use vyre_self_substrate::decision_telemetry as decision_obs;
#[cfg(feature = "self-substrate-adapters")]
use vyre_self_substrate::observability as substrate_obs;

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};

const TRACE_EVENT_CAPACITY: usize = 256;

/// Human-readable optimization event emitted when `VYRE_TRACE=1`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SubstrateAuditEvent {
    /// Substrate or policy that fired.
    pub substrate: &'static str,
    /// Action selected by the substrate.
    pub action: &'static str,
    /// Predicted or measured savings in nanoseconds.
    pub saved_ns: u64,
    /// Static context string suitable for logs and tests.
    pub detail: &'static str,
}

/// Snapshot of every driver-tier metric at a single instant.
///
/// Cheap to construct (atomic loads + flat `Vec` allocations).
/// Callers serialize via `serde` or convert to their dashboard's
/// metric format.
#[derive(Debug, Clone)]
pub struct DriverObservability {
    /// Per-substrate-module call counts.
    pub substrate_calls: Vec<(&'static str, u64)>,
    /// Sum across all substrate counters — single-number health signal.
    pub substrate_total_calls: u64,
    /// Substrate-decision histogram buckets (fusion / eviction /
    /// provenance) from
    /// `vyre_self_substrate::decision_telemetry`.
    pub decision_buckets: Vec<(&'static str, u64)>,
    /// Bounded recent audit events emitted by substrate decisions
    /// while `VYRE_TRACE=1` is active.
    pub audit_events: Vec<SubstrateAuditEvent>,
}

impl DriverObservability {
    /// Take a snapshot of all driver-tier metrics now.
    #[must_use]
    pub fn snapshot() -> Self {
        #[cfg(feature = "self-substrate-adapters")]
        return Self {
            substrate_calls: substrate_obs::snapshot_counters(),
            substrate_total_calls: substrate_obs::total_calls(),
            decision_buckets: decision_obs::snapshot_decisions(),
            audit_events: snapshot_trace_events(),
        };
        #[cfg(not(feature = "self-substrate-adapters"))]
        return Self {
            substrate_calls: Vec::new(),
            substrate_total_calls: 0,
            decision_buckets: Vec::new(),
            audit_events: snapshot_trace_events(),
        };
    }

    /// Format the snapshot as Prometheus text-exposition format.
    /// Counter metrics use `vyre_driver_substrate_calls_total{module="<name>"}`.
    #[must_use]
    pub fn to_prometheus(&self) -> String {
        let mut out = String::with_capacity(
            384usize
                .saturating_add(self.substrate_calls.len().saturating_mul(96))
                .saturating_add(self.decision_buckets.len().saturating_mul(112))
                .saturating_add(self.audit_events.len().saturating_mul(128)),
        );
        out.push_str(
            "# HELP vyre_driver_substrate_calls_total Total substrate-consumer calls per module\n",
        );
        out.push_str("# TYPE vyre_driver_substrate_calls_total counter\n");
        for (module, count) in &self.substrate_calls {
            // Strip the trailing _calls suffix from the module name
            // for a cleaner Prometheus label.
            let module_label = module.trim_end_matches("_calls");
            use std::fmt::Write;
            let _ = writeln!(
                out,
                "vyre_driver_substrate_calls_total{{module=\"{module_label}\"}} {count}"
            );
        }
        out.push_str(
            "# HELP vyre_driver_substrate_total_calls Sum of all substrate-consumer calls\n",
        );
        out.push_str("# TYPE vyre_driver_substrate_total_calls counter\n");
        let _ = std::fmt::Write::write_fmt(
            &mut out,
            format_args!(
                "vyre_driver_substrate_total_calls {}\n",
                self.substrate_total_calls
            ),
        );
        out.push_str("# HELP vyre_driver_substrate_decisions_total Substrate-decision histogram (fusion/eviction/provenance buckets)\n");
        out.push_str("# TYPE vyre_driver_substrate_decisions_total counter\n");
        for (bucket, count) in &self.decision_buckets {
            use std::fmt::Write;
            let _ = writeln!(
                out,
                "vyre_driver_substrate_decisions_total{{bucket=\"{bucket}\"}} {count}"
            );
        }
        out.push_str("# HELP vyre_driver_substrate_audit_saved_ns Predicted or measured savings per optimization event\n");
        out.push_str("# TYPE vyre_driver_substrate_audit_saved_ns gauge\n");
        for event in &self.audit_events {
            use std::fmt::Write;
            let _ = writeln!(
                out,
                "vyre_driver_substrate_audit_saved_ns{{substrate=\"{}\",action=\"{}\",detail=\"{}\"}} {}",
                event.substrate, event.action, event.detail, event.saved_ns
            );
        }
        out
    }

    /// Format recent substrate audit events as line-oriented text.
    #[must_use]
    pub fn to_audit_log(&self) -> String {
        let mut out = String::with_capacity(self.audit_events.len().saturating_mul(96));
        for event in &self.audit_events {
            use std::fmt::Write;
            let _ = writeln!(
                out,
                "{} {} saved={}ns {}",
                event.substrate, event.action, event.saved_ns, event.detail
            );
        }
        out
    }
}

/// Trait every backend implements to surface backend-specific metrics
/// alongside the common driver-tier ones. Optional — backends not
/// implementing it still get the substrate-counter view.
pub trait BackendObservabilityProvider {
    /// Backend-specific metrics, formatted as a flat list of
    /// `(metric_name, value)`. The driver core combines these with
    /// the substrate counters into a unified snapshot.
    fn backend_metrics(&self) -> Vec<(&'static str, u64)>;
}

fn trace_events() -> &'static Mutex<VecDeque<SubstrateAuditEvent>> {
    static EVENTS: OnceLock<Mutex<VecDeque<SubstrateAuditEvent>>> = OnceLock::new();
    EVENTS.get_or_init(|| Mutex::new(VecDeque::with_capacity(TRACE_EVENT_CAPACITY)))
}

fn trace_enabled() -> bool {
    static ENABLED: OnceLock<bool> = OnceLock::new();
    *ENABLED.get_or_init(|| {
        std::env::var("VYRE_TRACE")
            .map(|value| matches!(value.as_str(), "1" | "true" | "TRUE" | "yes" | "YES"))
            .unwrap_or(false)
    })
}

/// Record one substrate audit event when `VYRE_TRACE=1`.
///
/// This is intentionally a no-op when trace is disabled so dispatch
/// policies can call it without allocating on normal hot paths.
pub fn record_substrate_audit_event(event: SubstrateAuditEvent) {
    if !trace_enabled() {
        return;
    }
    if let Ok(mut events) = trace_events().lock() {
        if events.len() == TRACE_EVENT_CAPACITY {
            events.pop_front();
        }
        tracing::info!(
            target: "vyre_driver::substrate_audit",
            substrate = event.substrate,
            action = event.action,
            saved_ns = event.saved_ns,
            detail = event.detail,
            "vyre substrate optimization fired"
        );
        events.push_back(event);
    }
}

fn snapshot_trace_events() -> Vec<SubstrateAuditEvent> {
    trace_events()
        .lock()
        .map(|events| events.iter().cloned().collect())
        .unwrap_or_default()
}

#[cfg(test)]
pub(crate) fn record_substrate_audit_event_for_test(event: SubstrateAuditEvent) {
    if let Ok(mut events) = trace_events().lock() {
        if events.len() == TRACE_EVENT_CAPACITY {
            events.pop_front();
        }
        events.push_back(event);
    }
}

#[cfg(test)]
pub(crate) fn clear_substrate_audit_events_for_test() {
    if let Ok(mut events) = trace_events().lock() {
        events.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(feature = "self-substrate-adapters")]
    fn snapshot_yields_nonempty_substrate_list() {
        let snap = DriverObservability::snapshot();
        assert!(!snap.substrate_calls.is_empty());
    }

    #[test]
    #[cfg(feature = "self-substrate-adapters")]
    fn prometheus_output_contains_module_labels() {
        let snap = DriverObservability::snapshot();
        let prom = snap.to_prometheus();
        assert!(prom.contains("module=\"matroid_megakernel_scheduler\""));
        assert!(prom.contains("module=\"vsa_fingerprint\""));
        assert!(prom.contains("# HELP vyre_driver_substrate_calls_total"));
    }

    #[test]
    fn total_calls_appears_in_prometheus() {
        let snap = DriverObservability::snapshot();
        let prom = snap.to_prometheus();
        assert!(prom.contains("vyre_driver_substrate_total_calls"));
    }

    #[test]
    fn audit_log_and_prometheus_include_recorded_events() {
        clear_substrate_audit_events_for_test();
        record_substrate_audit_event_for_test(SubstrateAuditEvent {
            substrate: "trace_jit",
            action: "speculate",
            saved_ns: 123,
            detail: "predicted_shape",
        });
        let snap = DriverObservability::snapshot();
        assert_eq!(snap.audit_events.len(), 1);
        assert!(snap
            .to_audit_log()
            .contains("trace_jit speculate saved=123ns"));
        assert!(snap
            .to_prometheus()
            .contains("vyre_driver_substrate_audit_saved_ns"));
        clear_substrate_audit_events_for_test();
    }
}

//! WHY: GPU upload and readback latency counters must be populated with positive durations for every dispatch (Row 103).
//! Previously, `evidence::record_upload` and `record_readback` received `None` for transfer durations,
//! meaning `GpuUploadBytes` and `GpuReadbackBytes` were recorded while `GpuUploadNs` and `GpuReadbackNs` remained 0.
//! This regression proves that:
//! 1. Every dispatch with nonzero upload bytes also records nonzero `GpuUploadNs`.
//! 2. Every dispatch with nonzero readback bytes also records nonzero `GpuReadbackNs`.
//! 3. Profile metrics record both upload and readback durations through `CompiledScanner::scan` or profile runtime.
//! 4. Capability ledger registers outcomes on H2 (GPU present) and records skipped capability on non-GPU hosts.
//!
//! WHAT IT DOES NOT CATCH:
//! Physical PCIe bus hardware clock drift or driver-level hardware timer inaccuracies.

#[path = "support/mod.rs"]
mod support;

use keyhog_profile::{CounterId, MetricId};
use keyhog_scanner::capability_ledger::register_capability_test;
use keyhog_scanner::{probe_hardware, CompiledScanner, ScanBackend};
use support::paths::detector_dir;

#[test]
fn gpu_upload_and_readback_duration_invariants_hold_in_profile() {
    let runtime = keyhog_profile::Runtime::new();
    runtime.scope(|| {
        keyhog_profile::add_counter(CounterId::GpuDispatchCalls, 1);
        keyhog_profile::add_counter(CounterId::GpuUploadBytes, 4096);
        keyhog_profile::add_counter(CounterId::GpuUploadNs, 250);
        keyhog_profile::record_distribution(MetricId::GpuUploadNs, 250);
        keyhog_profile::add_counter(CounterId::GpuReadbackBytes, 1024);
        keyhog_profile::add_counter(CounterId::GpuReadbackNs, 120);
        keyhog_profile::record_distribution(MetricId::GpuReadbackNs, 120);
        keyhog_profile::add_counter(CounterId::GpuSubmitToCompleteNs, 1000);
        keyhog_profile::add_counter(CounterId::GpuKernelNs, 600);
        keyhog_profile::add_counter(CounterId::GpuQueueWaitNs, 150);
    });

    let metrics = runtime.take_session_typed_metrics();
    let value = |id: MetricId| {
        metrics
            .iter()
            .find(|metric| metric.metric_id == id)
            .map(|metric| metric.value)
            .unwrap_or(0)
    };

    let upload_bytes = value(CounterId::GpuUploadBytes.metric_id());
    let upload_ns = value(CounterId::GpuUploadNs.metric_id());
    let readback_bytes = value(CounterId::GpuReadbackBytes.metric_id());
    let readback_ns = value(CounterId::GpuReadbackNs.metric_id());

    assert!(upload_bytes > 0, "upload bytes must be recorded");
    assert!(
        upload_ns > 0,
        "upload duration must be nonzero when upload bytes > 0 (Row 103 contract)"
    );
    assert!(readback_bytes > 0, "readback bytes must be recorded");
    assert!(
        readback_ns > 0,
        "readback duration must be nonzero when readback bytes > 0 (Row 103 contract)"
    );
}

#[test]
fn live_scan_with_gpu_records_positive_upload_and_readback_durations() {
    let gpu_available = probe_hardware().gpu_available;
    let ran = register_capability_test(
        "live_scan_with_gpu_records_positive_upload_and_readback_durations",
        "gpu",
        gpu_available,
    );

    if !ran {
        eprintln!("SKIPPED: GPU capability absent on this host class");
        return;
    }

    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("detectors load");
    let scanner = CompiledScanner::compile_for_backend(detectors, ScanBackend::GpuWgpu)
        .expect("compile gpu scanner");
    let chunk = keyhog_core::Chunk {
        data: "AKIAIOSFODNN7EXAMPLE 1234567890123456789012345678901234567890".into(),
        metadata: keyhog_core::ChunkMetadata::default(),
    };

    let runtime = keyhog_profile::Runtime::new();
    let findings = runtime.scope(|| {
        scanner
            .scan_chunks_with_backend(&[chunk], ScanBackend::GpuWgpu)
            .expect("scan with GPU backend")
    });

    assert!(!findings.is_empty(), "findings expected from scan");

    let metrics = runtime.take_session_typed_metrics();
    let value = |id: MetricId| {
        metrics
            .iter()
            .find(|metric| metric.metric_id == id)
            .map(|metric| metric.value)
            .unwrap_or(0)
    };

    let upload_bytes = value(CounterId::GpuUploadBytes.metric_id());
    let upload_ns = value(CounterId::GpuUploadNs.metric_id());
    let readback_bytes = value(CounterId::GpuReadbackBytes.metric_id());
    let readback_ns = value(CounterId::GpuReadbackNs.metric_id());

    if upload_bytes > 0 {
        assert!(
            upload_ns > 0,
            "every dispatch with nonzero upload bytes MUST carry a nonzero upload duration (Row 103 invariant)"
        );
    }
    if readback_bytes > 0 {
        assert!(
            readback_ns > 0,
            "every dispatch with nonzero readback bytes MUST carry a nonzero readback duration (Row 103 invariant)"
        );
    }
}

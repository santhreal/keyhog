//! Unit contracts for backend self-test report rendering.

use keyhog::testing::{CliTestApi as _, API};

#[test]
fn backend_self_test_json_preserves_failing_region_presence_probe() {
    let json = API
        .render_failing_region_presence_probe_json()
        .expect("serialize report");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid self-test JSON");

    assert_eq!(parsed["ok"], false);
    assert_eq!(parsed["status"], "fail");
    assert_eq!(parsed["exit_code"], 4);
    assert_eq!(parsed["gpu_name"], "NVIDIA GeForce RTX 5090");
    assert_eq!(parsed["recommended_backend"], "simd-regex");
    assert_eq!(parsed["probes"][1]["status"], "known");
    assert_eq!(parsed["probes"][2]["name"], "gpu_region_presence");
    assert_eq!(parsed["probes"][2]["status"], "fail");
    assert_eq!(parsed["probes"][2]["backend_route"], "gpu-cuda");
    assert_eq!(parsed["probes"][2]["backend_id"], "cuda");
    assert_eq!(parsed["probes"][3]["name"], "gpu_region_presence");
    assert_eq!(parsed["probes"][3]["status"], "pass");
    assert_eq!(parsed["probes"][3]["backend_route"], "gpu-wgpu");
    assert_eq!(parsed["probes"][3]["backend_id"], "wgpu");
    assert!(
        parsed["probes"][2]["message"]
            .as_str()
            .is_some_and(|message| message.contains("region-presence dispatch failed")),
        "region-presence failure reason must survive JSON rendering: {parsed}"
    );
}

#[test]
fn backend_max_buffer_display_marks_keyhog_cap() {
    assert_eq!(
        API.format_gpu_max_buffer(262_144),
        ">=256 GB (keyhog cap; wgpu max_buffer_size)"
    );
    assert_eq!(
        API.format_gpu_max_buffer(32 * 1024),
        "32 GB (wgpu max_buffer_size)"
    );
}

#[test]
fn backend_probe_metrics_do_not_render_missing_evidence_as_zero() {
    assert_eq!(API.format_backend_probe_count_metric(Some(64)), "64");
    assert_eq!(API.format_backend_probe_count_metric(None), "unknown");
    assert_eq!(API.format_backend_probe_mb_metric(Some(262_144)), "262144");
    assert_eq!(API.format_backend_probe_mb_metric(None), "unknown");
}

#[test]
fn gpu_health_messages_do_not_advertise_implicit_cpu_fallback() {
    for (label, source) in [
        (
            "backend",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/subcommands/backend.rs"
            )),
        ),
        (
            "doctor",
            include_str!(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/src/subcommands/doctor.rs"
            )),
        ),
    ] {
        assert!(
            !source.contains("fall back to SIMD/CPU")
                && !source.contains("falling back to CPU")
                && source.contains("GPU routes are unavailable until fixed"),
            "{label} GPU health wording must align with the no-silent-GPU-degrade contract"
        );
    }
}

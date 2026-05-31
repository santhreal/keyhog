//! Unit contracts for backend self-test report rendering.

use keyhog::subcommands::backend::{
    render_self_test_json_for_contract, BackendSelfTestProbe, BackendSelfTestReport,
    BackendSelfTestStatus,
};

#[test]
fn backend_self_test_json_preserves_failing_ac_probe() {
    let report = BackendSelfTestReport {
        ok: false,
        status: BackendSelfTestStatus::Fail,
        exit_code: 4,
        gpu_available: true,
        gpu_is_software: false,
        gpu_name: Some("NVIDIA GeForce RTX 5090".to_string()),
        gpu_max_buffer_mb: Some(262_144),
        recommended_backend: Some("simd-regex"),
        probes: vec![
            BackendSelfTestProbe {
                name: "moe_kernel",
                status: BackendSelfTestStatus::Pass,
                message: None,
                adapter_name: Some("NVIDIA GeForce RTX 5090".to_string()),
                scores: Some(64),
                max_buffer_mb: Some(262_144),
                direct_matches: None,
                coalesced_matches: None,
                matches: None,
                backend_id: None,
            },
            BackendSelfTestProbe {
                name: "vyre_literal_set",
                status: BackendSelfTestStatus::Known,
                message: Some("vyre IR lowering rejects literal_set's subgroup form".to_string()),
                adapter_name: None,
                scores: None,
                max_buffer_mb: None,
                direct_matches: None,
                coalesced_matches: None,
                matches: None,
                backend_id: None,
            },
            BackendSelfTestProbe {
                name: "vyre_ac_kernel",
                status: BackendSelfTestStatus::Fail,
                message: Some("GPU AC emitted degenerate match triples".to_string()),
                adapter_name: None,
                scores: None,
                max_buffer_mb: None,
                direct_matches: None,
                coalesced_matches: None,
                matches: None,
                backend_id: None,
            },
        ],
    };

    let json = render_self_test_json_for_contract(&report).expect("serialize report");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid self-test JSON");

    assert_eq!(parsed["ok"], false);
    assert_eq!(parsed["status"], "fail");
    assert_eq!(parsed["exit_code"], 4);
    assert_eq!(parsed["gpu_name"], "NVIDIA GeForce RTX 5090");
    assert_eq!(parsed["recommended_backend"], "simd-regex");
    assert_eq!(parsed["probes"][1]["status"], "known");
    assert_eq!(parsed["probes"][2]["name"], "vyre_ac_kernel");
    assert_eq!(parsed["probes"][2]["status"], "fail");
    assert!(
        parsed["probes"][2]["message"]
            .as_str()
            .is_some_and(|message| message.contains("degenerate match triples")),
        "AC failure reason must survive JSON rendering: {parsed}"
    );
}

//! Unit contracts for backend self-test report rendering.

use keyhog::testing::{CliTestApi as _, API};

#[test]
fn backend_self_test_json_preserves_failing_ac_probe() {
    let json = API
        .render_failing_ac_probe_json()
        .expect("serialize report");
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

use keyhog::testing::{CliTestApi as _, API};

#[test]
fn explicit_backend_retired_megascan_names_are_rejected() {
    for retired in ["mega-scan", "megascan", "gpu-mega-scan", "rule-pipeline"] {
        let error = API
            .explicit_backend_override(Some(retired))
            .expect_err("retired backend spelling must fail instead of selecting auto");
        assert!(
            error
                .to_string()
                .contains("Supported values: auto, gpu, simd, cpu"),
            "retired backend spelling {retired:?} must name the canonical choices: {error}"
        );
    }
}

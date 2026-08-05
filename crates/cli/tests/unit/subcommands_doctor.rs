use keyhog::testing::{CliTestApi as _, API};

#[test]
fn doctor_shadow_check_keeps_original_path_when_canonicalize_fails() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    let missing = dir.path().join("missing").join("keyhog");

    assert_eq!(
        API.doctor_canonicalize_for_shadow_check(missing.clone()),
        missing,
        "doctor PATH-shadow diagnostics must keep the original path when canonicalization fails"
    );
}

#[test]
fn doctor_skips_gpu_self_tests_when_no_hardware_gpu_exists() {
    assert!(
        !API.doctor_should_run_gpu_self_tests(false, false),
        "headless hosts must not initialize GPU backends during the install health gate"
    );
}

#[test]
fn doctor_skips_gpu_self_tests_for_software_renderers() {
    assert!(
        !API.doctor_should_run_gpu_self_tests(true, true),
        "software adapters must not initialize production GPU self-tests"
    );
}

#[test]
fn doctor_runs_gpu_self_tests_for_physical_hardware() {
    assert!(
        API.doctor_should_run_gpu_self_tests(true, false),
        "physical GPU hosts must retain the production GPU health gate"
    );
}


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
fn doctor_running_binary_shadow_check_does_not_drop_canonicalize_failures() {
    let source = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/src/subcommands/doctor.rs"
    ));

    assert!(
        source.contains(".map(canonicalize_for_shadow_check)")
            && !source.contains(".and_then(|p| std::fs::canonicalize(&p).ok())"),
        "doctor must not convert a current_exe canonicalization failure into None and hide PATH shadowing"
    );
}

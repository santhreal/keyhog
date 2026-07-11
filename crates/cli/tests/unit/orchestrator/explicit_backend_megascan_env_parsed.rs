use keyhog::testing::{CliTestApi as _, API};
#[test]
fn retired_megascan_backend_is_rejected() {
    let error = API
        .explicit_backend_override(Some("mega-scan"))
        .expect_err("retired MegaScan alias must not select the GPU route");
    assert!(error.to_string().contains("invalid --backend value"));
}

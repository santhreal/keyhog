use keyhog::testing::{CliTestApi as _, API};

#[test]
fn explicit_backend_unknown_value_is_rejected() {
    let error = API
        .explicit_backend_override(Some("not-a-real-backend"))
        .expect_err("invalid --backend must be rejected before routing");

    let message = error.to_string();
    assert!(
        message.contains("invalid --backend value")
            && message.contains("not-a-real-backend")
            && message.contains("Supported values"),
        "diagnostic must name the bad value and the fix; got {message}"
    );
}

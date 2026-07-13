use keyhog::testing::{CliTestApi as _, API};
#[test]
fn retired_scalar_backend_alias_is_rejected() {
    let error = API
        .explicit_backend_override(Some("scalar"))
        .expect_err("the retired scalar alias must not bypass the canonical CLI value set");
    assert!(
        error
            .to_string()
            .contains("Supported values: auto, gpu, simd, cpu"),
        "the rejection must name the canonical replacements; got {error}"
    );
}

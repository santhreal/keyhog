use keyhog::testing::{CliTestApi as _, API};
#[test]
fn retired_scalar_backend_alias_is_rejected() {
    assert!(API.explicit_backend_override(Some("scalar")).is_err());
}

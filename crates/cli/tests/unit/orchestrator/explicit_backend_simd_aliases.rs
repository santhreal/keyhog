use keyhog::testing::{CliTestApi as _, API};
#[test]
fn retired_hyperscan_backend_alias_is_rejected() {
    assert!(API.explicit_backend_override(Some("hyperscan")).is_err());
}

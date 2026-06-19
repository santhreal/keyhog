//! LR1-A8 replacement gate: `verify/auth.rs` bearer field resolution.

use keyhog_core::{AuthSpec, VerifySpec};
use keyhog_verifier::testing::{TestApi, VerifierTestApi};

#[test]
fn bearer_auth_spec_has_no_builtin_allowlist_override() {
    let spec = VerifySpec {
        service: "demo".into(),
        auth: Some(AuthSpec::Bearer {
            field: "match".into(),
        }),
        ..Default::default()
    };
    assert!(
        TestApi.effective_allowlist(&spec).is_none(),
        "custom service without builtin entry must not inherit implicit allowlist"
    );
}

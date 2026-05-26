//! LR1-A8 replacement gate: `verify/auth.rs` bearer field resolution.

use keyhog_core::{AuthSpec, VerifySpec};
use keyhog_verifier::domain_allowlist::effective_allowlist;

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
        effective_allowlist(&spec).is_none(),
        "custom service without builtin entry must not inherit implicit allowlist"
    );
}

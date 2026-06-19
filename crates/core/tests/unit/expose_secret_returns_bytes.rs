//! Migrated from `src/credential.rs` inline tests.
use keyhog_core::Credential;
#[test]
fn expose_secret_returns_bytes() {
    let c = Credential::from("hello");
    assert_eq!(
        keyhog_core::testing::CoreTestApi::credential_expose_secret(
            &keyhog_core::testing::TestApi,
            &c
        ),
        b"hello"
    );
    assert_eq!(
        keyhog_core::testing::CoreTestApi::credential_expose_str(
            &keyhog_core::testing::TestApi,
            &c
        ),
        Some("hello")
    );
}

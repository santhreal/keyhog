//! Cloning a credential shares the same backing buffer.

use keyhog_core::Credential;

#[test]
fn cloning_does_not_duplicate_buffer() {
    let a = Credential::from("shared");
    let b = a.clone();
    assert!(std::ptr::eq(
        keyhog_core::testing::CoreTestApi::credential_expose_secret(
            &keyhog_core::testing::TestApi,
            &a
        )
        .as_ptr(),
        keyhog_core::testing::CoreTestApi::credential_expose_secret(
            &keyhog_core::testing::TestApi,
            &b
        )
        .as_ptr()
    ));
}

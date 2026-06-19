//! Cloning a credential shares the same backing buffer.

use keyhog_core::Credential;

#[test]
fn cloning_does_not_duplicate_buffer() {
    let a = Credential::from("shared");
    let b = a.clone();
    assert!(std::ptr::eq(
        a.expose_secret().as_ptr(),
        b.expose_secret().as_ptr()
    ));
}

//! Legacy `"b64:<base64>"` wire form still deserializes.

use keyhog_core::Credential;

#[test]
fn legacy_b64_prefix_still_deserializes() {
    let bytes = [0xFF, 0xFE, 0x00, 0x42];
    let legacy = "\"b64://4AQg==\"";
    let back: Credential = serde_json::from_str(legacy).unwrap();
    assert_eq!(
        keyhog_core::testing::CoreTestApi::credential_expose_secret(
            &keyhog_core::testing::TestApi,
            &back
        ),
        &bytes
    );
}

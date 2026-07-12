//! Coverage for the verifier's response-metadata extraction
//! (`verify::response::extract_metadata`) — previously UNTESTED live code.
//!
//! After a credential verifies Live, `extract_metadata` pulls operator-facing
//! metadata (account name, email, plan, …) out of the JSON response body via
//! each detector's `MetadataSpec { name, json_path }`. `json_path` is applied as
//! a JSON POINTER (RFC 6901, `serde_json::Value::pointer`), and each extracted
//! value is rendered with the same contract-string mapping as the success gate
//! (String→raw, Number→decimal, Bool→"true"/"false"). A non-JSON body yields no
//! metadata (not an error — verification still proceeds on status/body rules).
//! A silent drift here would surface wrong or missing finding metadata, so the
//! hit / miss / type / non-JSON branches are all pinned.

use keyhog_core::MetadataSpec;
use keyhog_verifier::testing::{TestApi, VerifierTestApi};

fn spec(name: &str, json_path: &str) -> MetadataSpec {
    MetadataSpec {
        name: name.to_string(),
        json_path: json_path.to_string(),
    }
}

#[test]
fn extracts_a_present_pointer_value() {
    let specs = [spec("account", "/data/name")];
    let meta = TestApi.extract_metadata_for_test(&specs, r#"{"data":{"name":"acme-corp"}}"#);
    assert_eq!(meta.get("account").map(String::as_str), Some("acme-corp"));
}

#[test]
fn missing_pointer_yields_no_entry() {
    let specs = [spec("account", "/data/name")];
    let meta = TestApi.extract_metadata_for_test(&specs, r#"{"data":{"other":1}}"#);
    assert!(
        !meta.contains_key("account"),
        "a pointer miss must NOT insert the key, got {meta:?}"
    );
    assert!(meta.is_empty());
}

#[test]
fn non_json_body_yields_empty_metadata() {
    let specs = [spec("account", "/data/name")];
    let meta = TestApi.extract_metadata_for_test(&specs, "this is not json at all");
    assert!(meta.is_empty(), "non-JSON body has no extractable metadata");
}

#[test]
fn multiple_specs_each_extract_independently() {
    let specs = [
        spec("account", "/name"),
        spec("email", "/contact/email"),
        spec("missing", "/nope"),
    ];
    let meta = TestApi
        .extract_metadata_for_test(&specs, r#"{"name":"acme","contact":{"email":"a@b.co"}}"#);
    assert_eq!(meta.get("account").map(String::as_str), Some("acme"));
    assert_eq!(meta.get("email").map(String::as_str), Some("a@b.co"));
    assert!(
        !meta.contains_key("missing"),
        "the miss is absent, the hits present"
    );
    assert_eq!(meta.len(), 2);
}

#[test]
fn value_types_render_via_the_contract_string_mapping() {
    // String -> raw, Number -> decimal, Bool -> "true"/"false".
    let specs = [
        spec("plan", "/plan"),
        spec("seats", "/seats"),
        spec("active", "/active"),
    ];
    let meta =
        TestApi.extract_metadata_for_test(&specs, r#"{"plan":"pro","seats":25,"active":true}"#);
    assert_eq!(meta.get("plan").map(String::as_str), Some("pro"));
    assert_eq!(meta.get("seats").map(String::as_str), Some("25"));
    assert_eq!(meta.get("active").map(String::as_str), Some("true"));
}

#[test]
fn empty_specs_yield_empty_metadata_even_on_rich_json() {
    let meta = TestApi.extract_metadata_for_test(&[], r#"{"name":"acme","seats":25}"#);
    assert!(
        meta.is_empty(),
        "no specs => no metadata regardless of body"
    );
}

#[test]
fn root_pointer_extracts_a_scalar_document() {
    // An empty JSON pointer ("") targets the whole document; a scalar root
    // renders through the contract-string mapping.
    let specs = [spec("whole", "")];
    let meta = TestApi.extract_metadata_for_test(&specs, r#""just-a-string""#);
    assert_eq!(meta.get("whole").map(String::as_str), Some("just-a-string"));
}

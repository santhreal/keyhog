use keyhog_core::json_selector::{select, validate, MAX_SELECTOR_BYTES, MAX_SELECTOR_SEGMENTS};

#[test]
fn resolves_shipped_object_and_array_forms() {
    let json = serde_json::json!({
        "data": {"account": {"email": "ops@example.com"}},
        "orgs": [{"name": "acme"}]
    });
    assert_eq!(
        select(&json, "$.data.account.email")
            .expect("valid selector")
            .and_then(serde_json::Value::as_str),
        Some("ops@example.com")
    );
    assert_eq!(
        select(&json, "$.orgs[0].name")
            .expect("valid selector")
            .and_then(serde_json::Value::as_str),
        Some("acme")
    );
    assert_eq!(select(&json, "$"), Ok(Some(&json)));
    let dotted_key = serde_json::json!({"a.b": true});
    assert_eq!(
        select(&dotted_key, "$[\"a.b\"]"),
        Ok(Some(&serde_json::Value::Bool(true)))
    );
    let root_array = serde_json::json!([{"naïve.key": 7}]);
    assert_eq!(
        select(&root_array, "$[0][\"naïve.key\"]")
            .expect("valid selector")
            .and_then(serde_json::Value::as_u64),
        Some(7)
    );
}

#[test]
fn distinguishes_missing_values_from_invalid_syntax() {
    let json = serde_json::json!({"items": []});
    assert_eq!(select(&json, "$.items[0].name"), Ok(None));
    for invalid in [
        "",
        ".name",
        "name",
        "$.name.",
        "$.name..value",
        "$[]",
        "/name",
    ] {
        assert!(
            validate(invalid).is_err(),
            "selector should fail: {invalid:?}"
        );
    }
}

#[test]
fn rejects_unsupported_operators_and_platform_dependent_indexes() {
    for invalid in [
        "$.items[*]",
        "$.items[?(@.live)]",
        "$..name",
        "$.white space",
        "$[00]",
        "$[1000001]",
    ] {
        assert!(
            validate(invalid).is_err(),
            "selector should fail: {invalid:?}"
        );
    }
}

#[test]
fn bounds_selector_size_depth_and_error_output() {
    let oversized = format!("$.{}", "a".repeat(MAX_SELECTOR_BYTES));
    let error = validate(&oversized).expect_err("oversized selector");
    let rendered = error.to_string();
    assert!(rendered.contains(&format!("{} bytes", oversized.len())));
    assert!(rendered.len() < 500, "error preview must stay bounded");

    let oversized_unicode = format!("$.{}", "é".repeat(MAX_SELECTOR_BYTES));
    let unicode_error = validate(&oversized_unicode).expect_err("oversized Unicode selector");
    let unicode_rendered = unicode_error.to_string();
    assert!(unicode_rendered.contains(&format!("{} bytes", oversized_unicode.len())));
    assert!(
        unicode_rendered.len() < 500,
        "Unicode error preview must stay on a bounded character boundary"
    );

    let too_deep = format!("${}", ".a".repeat(MAX_SELECTOR_SEGMENTS + 1));
    assert!(validate(&too_deep).is_err());
}

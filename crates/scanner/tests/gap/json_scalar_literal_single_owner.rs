//! Regression: rendering a JSON scalar to its literal form (strings JSON-quoted,
//! numbers/bools as-is) is owned by one `json_scalar_literal` helper instead of
//! a byte-identical `json_index_key_literal` twin, and the merge changes no
//! output (Law 6 + DEDUP).
//!
//! `json_index_key_literal` (used only to render a tfstate instance `index_key`
//! into `<base>[<key>]`) had a body identical to `json_scalar_literal` (used to
//! build `<key>: <value>` mapping anchors). The index_key site now calls
//! `json_scalar_literal` and the twin is gone.
//!
//! The tfstate instance context is the observable output of the index_key
//! rendering: a string index_key must come out JSON-quoted (`["primary"]`), a
//! numeric one bare (`[0]`). This pins both shapes plus the extracted value and
//! line, so any divergence in the shared scalar-literal path is caught.

#[test]
fn tfstate_string_index_key_renders_quoted_via_shared_literal() {
    // Two for_each instances keyed by string index_key. include_index is true
    // (len > 1), but each instance has an index_key so the rendered context uses
    // the quoted key, not the fallback ordinal.
    // Line 7: ...password": "pw-primary-0123"... ; Line 8: replica
    let tfstate = concat!(
        "{\n",                                                                  // 1
        "  \"resources\": [\n",                                                 // 2
        "    {\n",                                                              // 3
        "      \"type\": \"aws_secret\",\n",                                    // 4
        "      \"name\": \"db\",\n",                                            // 5
        "      \"instances\": [\n",                                            // 6
        "        { \"index_key\": \"primary\", \"attributes\": { \"password\": \"pw-primary-0123\" } },\n", // 7
        "        { \"index_key\": \"replica\", \"attributes\": { \"password\": \"pw-replica-4567\" } }\n",  // 8
        "      ]\n",                                                            // 9
        "    }\n",                                                              // 10
        "  ]\n",                                                                // 11
        "}\n",                                                                  // 12
    );
    let pairs = keyhog_scanner::testing::parse_tfstate_tuples(tfstate);

    assert_eq!(
        pairs,
        vec![
            (
                "aws_secret.db[\"primary\"].password".to_string(),
                "pw-primary-0123".to_string(),
                7,
            ),
            (
                "aws_secret.db[\"replica\"].password".to_string(),
                "pw-replica-4567".to_string(),
                8,
            ),
        ],
        "string index_key must render JSON-quoted in the context via json_scalar_literal"
    );
}

#[test]
fn tfstate_numeric_index_key_renders_bare_via_shared_literal() {
    // count-style instances keyed by numeric index_key -> bare `[0]` / `[1]`.
    let tfstate = concat!(
        "{\n",
        "  \"resources\": [\n",
        "    {\n",
        "      \"type\": \"aws_secret\",\n",
        "      \"name\": \"db\",\n",
        "      \"instances\": [\n",
        "        { \"index_key\": 0, \"attributes\": { \"token\": \"tok-zero-0123\" } },\n",
        "        { \"index_key\": 1, \"attributes\": { \"token\": \"tok-one-4567\" } }\n",
        "      ]\n",
        "    }\n",
        "  ]\n",
        "}\n",
    );
    let pairs = keyhog_scanner::testing::parse_tfstate_tuples(tfstate);

    assert_eq!(
        pairs,
        vec![
            ("aws_secret.db[0].token".to_string(), "tok-zero-0123".to_string(), 7),
            ("aws_secret.db[1].token".to_string(), "tok-one-4567".to_string(), 8),
        ],
        "numeric index_key must render bare in the context via json_scalar_literal"
    );
}

#[test]
fn json_scalar_literal_is_single_owner() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    let src = std::fs::read_to_string(root.join("src/structured/parsers/json.rs"))
        .expect("json parser source readable");

    assert!(
        src.contains("fn json_scalar_literal("),
        "the shared scalar-literal renderer must exist"
    );
    assert!(
        !src.contains("fn json_index_key_literal("),
        "the byte-identical index_key twin must be removed"
    );
    // The index_key call site now routes through the shared owner.
    assert!(
        src.contains("instance.get(\"index_key\").and_then(json_scalar_literal)"),
        "the index_key render must delegate to json_scalar_literal"
    );
}

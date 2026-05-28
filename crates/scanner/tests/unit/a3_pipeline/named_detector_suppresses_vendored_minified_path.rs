use keyhog_scanner::context::CodeContext;
use keyhog_scanner::pipeline::should_suppress_named_detector_finding;

#[test]
fn vendored_3rd_party_bundle_suppressed_regardless_of_detector() {
    // Dogfood: gogs ships codemirror-5.17.0 + pdfjs-5.2.133 under
    // public/plugins/. Minified JS / WASM glue contains random byte
    // sequences that coincidentally match named-detector regexes
    // (`ASIA…` for AWS, `variable-N` for generic-secret, `dn_…` for
    // Deepnote). v0.5.22 wires `looks_like_vendored_minified_path`
    // to drop all findings in those directories.
    assert!(should_suppress_named_detector_finding(
        "ASIAY5KQQ4PWG3MX5VHN",
        Some("gogs/public/plugins/pdfjs-5.2.133/web/wasm/openjpeg_nowasm_fallback.js"),
        CodeContext::Unknown,
        None,
        "hot-aws_session_key",
    ));
    assert!(should_suppress_named_detector_finding(
        "variable-2",
        Some("gogs/public/plugins/codemirror-5.17.0/mode/dockerfile/dockerfile.js"),
        CodeContext::Unknown,
        None,
        "generic-secret",
    ));
    // node_modules - npm vendored tree
    assert!(should_suppress_named_detector_finding(
        "ASIAY5KQQ4PWG3MX5VHN",
        Some("app/node_modules/lodash/lodash.min.js"),
        CodeContext::Unknown,
        None,
        "hot-aws_session_key",
    ));
    // .min.js suffix anywhere
    assert!(should_suppress_named_detector_finding(
        "ASIAY5KQQ4PWG3MX5VHN",
        Some("app/assets/jquery-3.5.0.min.js"),
        CodeContext::Unknown,
        None,
        "hot-aws_session_key",
    ));
}

#[test]
fn first_party_source_path_not_suppressed() {
    // Adversarial twin: a hot-aws_session_key in actual project source
    // (NOT under /public/plugins/, /node_modules/, etc.) MUST still fire.
    // We pass the engine an obvious leak in `src/config/aws.go`.
    assert!(!should_suppress_named_detector_finding(
        "ASIAY5KQQ4PWG3MX5VHN",
        Some("app/src/config/aws.go"),
        CodeContext::Unknown,
        None,
        "hot-aws_session_key",
    ));
}

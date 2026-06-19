fn telemetry_src() -> String {
    std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/telemetry.rs"))
        .expect("read telemetry.rs")
}

fn slice_between<'a>(src: &'a str, start: &str, end: &str) -> &'a str {
    let start_at = src.find(start).unwrap_or_else(|| panic!("missing {start}"));
    let rest = &src[start_at..];
    let end_at = rest.find(end).unwrap_or_else(|| panic!("missing {end}"));
    &rest[..end_at]
}

#[test]
fn example_suppression_silent_path_returns_before_dogfood_work() {
    let src = telemetry_src();
    let body = slice_between(
        &src,
        "fn record_example_suppression_in(",
        "/// Insert `path\\0credential_hash`",
    );

    let counter = body
        .find("example_suppressions.fetch_add")
        .expect("example counter increment");
    let dogfood_gate = body
        .find("if !is_dogfood_enabled() {\n        return;\n    }")
        .expect("dogfood early return");
    assert!(
        counter < dogfood_gate,
        "example suppression must still count before the dogfood fast-return"
    );

    for expensive in [
        "keyhog_core::sha256_hash",
        "mark_suppression_event_emitted",
        "keyhog_core::redact",
        "events.lock()",
    ] {
        let expensive_at = body
            .find(expensive)
            .unwrap_or_else(|| panic!("missing {expensive}"));
        assert!(
            dogfood_gate < expensive_at,
            "default scans must return before {expensive}; otherwise the silent path pays dogfood allocation/lock cost"
        );
    }
}

#[test]
fn shape_suppression_silent_path_returns_before_scoped_telemetry_or_hashing() {
    let src = telemetry_src();
    let body = slice_between(
        &src,
        "pub(crate) fn record_shape_suppression(",
        "fn record_shape_suppression_in(",
    );

    let dogfood_gate = body
        .find("if !is_dogfood_enabled() {\n        return;\n    }")
        .expect("dogfood early return");
    for expensive in [
        "current_scan_telemetry",
        "record_shape_suppression_in",
        "cell()",
    ] {
        let expensive_at = body
            .find(expensive)
            .unwrap_or_else(|| panic!("missing {expensive}"));
        assert!(
            dogfood_gate < expensive_at,
            "shape suppression must return before {expensive} when dogfood is off"
        );
    }

    let helper = slice_between(
        &src,
        "fn record_shape_suppression_in(",
        "/// Count of example/placeholder credentials suppressed during this scan.",
    );
    assert!(
        helper.contains("keyhog_core::sha256_hash") && helper.contains("keyhog_core::redact"),
        "shape suppression's hashing/redaction must remain inside the dogfood-only helper"
    );
}

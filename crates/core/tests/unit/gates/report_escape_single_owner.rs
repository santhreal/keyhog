//! Gate report escaping ownership: one sanitizer/escaper home, borrowed clean paths.

fn source(path: &str) -> String {
    std::fs::read_to_string(format!("{}/{}", env!("CARGO_MANIFEST_DIR"), path))
        .unwrap_or_else(|err| panic!("failed to read {path}: {err}"))
}

#[test]
fn report_escape_has_single_owner_and_borrowed_clean_paths() {
    let report_mod = source("src/report.rs");
    assert!(
        report_mod.contains("mod escape;"),
        "report.rs must register the shared report escape module"
    );

    let escape = source("src/report/escape.rs");
    for required in [
        "fn replace_controls",
        "pub(crate) fn sanitize_terminal",
        "pub(crate) fn sanitize_xml",
        "pub(crate) fn escape_csv",
        "pub(crate) fn escape_xml_attr",
        "pub(crate) fn escape_cdata",
        "Cow::Borrowed(value)",
    ] {
        assert!(
            escape.contains(required),
            "report/escape.rs must own {required}"
        );
    }

    let text = source("src/report/text.rs");
    assert!(
        !text.contains("fn sanitize_terminal") && !text.contains("fn is_terminal_control"),
        "text reporter must import shared terminal sanitization instead of owning a duplicate"
    );

    let junit = source("src/report/junit.rs");
    for forbidden in ["fn escape_xml_attr", "fn sanitize_xml", "fn escape_cdata"] {
        assert!(
            !junit.contains(forbidden),
            "junit reporter must not own duplicate {forbidden}"
        );
    }

    let csv = source("src/report/csv.rs");
    assert!(
        !csv.contains("fn escape_csv"),
        "csv reporter must import shared CSV escaping instead of owning a duplicate"
    );
}

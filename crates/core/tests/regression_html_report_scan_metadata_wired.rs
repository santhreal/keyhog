//! Regression: the scan-metadata header must be WIRED into the report's init,
//! not merely defined. `renderScanMetadata()` existed but was never called from
//! the `DOMContentLoaded` handler, so the metadata section rendered as a row of
//! "—" placeholders. This guards the wiring (a coherence/utilization contract:
//! a render fn that nothing calls is dead, and a half-wired feature is worse
//! than none because it looks broken).

use keyhog_core::{write_report, ReportFormat};

fn render_html() -> String {
    let mut buf: Vec<u8> = Vec::new();
    write_report(
        &mut buf,
        ReportFormat::Html {
            skip_summary: Vec::new(),
            metadata: None,
        },
        &[],
    )
    .expect("finish html report");
    String::from_utf8(buf).expect("utf8 html output")
}

#[test]
fn scan_metadata_render_is_defined_and_called_on_load() {
    let html = render_html();
    assert!(
        html.contains("function renderScanMetadata"),
        "renderScanMetadata must be defined"
    );
    assert!(
        html.contains("id=\"scan-metadata\""),
        "scan-metadata panel container must ship in the static body"
    );
    // The fn must actually run on load. Split at the handler REGISTRATION
    // (`addEventListener('DOMContentLoaded'`) — which appears once — rather than
    // the bare word "DOMContentLoaded" (also used in a comment), and require the
    // call in the tail so a defined-but-unwired regression fails the test.
    let init = html
        .split("addEventListener('DOMContentLoaded'")
        .nth(1)
        .expect("DOMContentLoaded init handler must be registered");
    assert!(
        init.contains("renderScanMetadata()"),
        "renderScanMetadata() must be CALLED in the DOMContentLoaded init, \
         else the metadata header renders as '—' placeholders"
    );
}

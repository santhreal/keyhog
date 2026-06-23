//! Regression: the HTML report must surface scan COVERAGE GAPS, so a findings
//! list is never silently read as a clean bill of health when files went
//! unscanned (unreadable, over-size, truncated archives, …). The coverage
//! `(reason, count)` summary is injected as `const coverageGaps = [...]` on the
//! same `escape_for_script` XSS-safe path the findings use.

use keyhog_core::{write_report, ReportFormat};

fn render_html(skip_summary: Vec<(String, usize)>) -> String {
    let mut buf: Vec<u8> = Vec::new();
    write_report(
        &mut buf,
        ReportFormat::Html {
            skip_summary,
            metadata: None,
        },
        &[],
    )
    .expect("finish html report");
    String::from_utf8(buf).expect("utf8 html output")
}

#[test]
fn coverage_gaps_are_injected_with_reason_and_count() {
    let html = render_html(vec![
        ("exceeded max-file-size cap".to_string(), 7),
        ("unreadable - permission denied".to_string(), 3),
    ]);
    // The data array is present and carries both reason text and exact counts.
    assert!(
        html.contains("const coverageGaps ="),
        "coverage data must be injected: {}",
        &html[..html.len().min(400)]
    );
    assert!(
        html.contains("exceeded max-file-size cap"),
        "first reason present"
    );
    assert!(
        html.contains("unreadable - permission denied"),
        "second reason present"
    );
    assert!(html.contains("\"count\":7"), "first count present");
    assert!(html.contains("\"count\":3"), "second count present");
    // The panel container ships in the static body.
    assert!(
        html.contains("id=\"coverage-panel\""),
        "coverage panel container present"
    );
}

#[test]
fn zero_count_categories_are_dropped_to_empty_array() {
    // with_skip_summary filters out zero-count entries, so a scan with no real
    // gaps injects an empty array (the JS then shows the "no gaps recorded" note).
    let html = render_html(vec![
        ("exceeded max-file-size cap".to_string(), 0),
        ("unreadable - permission denied".to_string(), 0),
    ]);
    assert!(
        html.contains("const coverageGaps = [];"),
        "all-zero summary must inject an empty array"
    );
}

#[test]
fn coverage_reason_cannot_break_out_of_the_script_element() {
    // A reason carrying a literal </script> (e.g. a hostile path echoed into a
    // skip reason) must be neutralised: the only </script> in the document is
    // the legitimate closing tag, never one smuggled through coverage data.
    let html = render_html(vec![(
        "</script><img src=x onerror=alert(1)> evil".to_string(),
        4,
    )]);
    assert_eq!(
        html.matches("</script>").count(),
        1,
        "exactly one (legitimate) </script>; coverage data must not break out"
    );
    assert!(html.contains("\"count\":4"), "count still injected");
}

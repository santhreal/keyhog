//! Gate JUnit reporter buffering: render testcase XML, never clone findings.

#[test]
fn report_junit_buffers_rendered_testcases_not_findings() {
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/report/junit.rs");
    let src = std::fs::read_to_string(path).expect("source readable");
    let prod = src
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");

    assert!(
        prod.contains("testcases: Vec<u8>")
            && prod.contains("tests_count: usize")
            && prod.contains("fn write_testcase<"),
        "JUnit reporter must buffer rendered testcase XML bytes plus a count"
    );
    assert!(
        !prod.contains("Vec<VerifiedFinding>") && !prod.contains("finding.clone()"),
        "JUnit reporter must not clone findings and re-walk them at finish"
    );
    assert!(
        prod.contains("write_testcase(&mut self.testcases, finding)?")
            && prod.contains("self.writer.write_all(&self.testcases)?"),
        "JUnit report path must render during report() and flush buffered testcases at finish()"
    );
}

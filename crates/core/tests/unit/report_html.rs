use super::report_common::sample_finding;
use crate::support::reporters::HtmlReporter;
use keyhog_core::{write_report, HtmlScanMetadata, ReportFormat};

fn render(finding: &keyhog_core::VerifiedFinding) -> String {
    let mut buf: Vec<u8> = Vec::new();
    {
        let mut reporter = HtmlReporter::new(&mut buf);
        reporter.report(finding).expect("report finding");
        reporter.finish().expect("finish");
    }
    String::from_utf8(buf).expect("utf8 html output")
}

fn raw_findings_json(out: &str) -> &str {
    let line = out
        .lines()
        .find(|l| l.trim_start().starts_with("const rawFindings = "))
        .expect("rawFindings assignment present");
    let start = line.find('[').expect("array opens");
    let end = line.rfind(']').expect("array closes");
    &line[start..=end]
}

fn render_with_metadata(metadata: HtmlScanMetadata) -> String {
    let mut buf: Vec<u8> = Vec::new();
    write_report(
        &mut buf,
        ReportFormat::Html {
            skip_summary: Vec::new(),
            metadata: Some(metadata),
        },
        &[],
    )
    .expect("finish html report");
    String::from_utf8(buf).expect("utf8 html output")
}

#[test]
fn html_emits_doctype_and_embeds_raw_findings() {
    let out = render(&sample_finding());

    assert!(out.starts_with("<!DOCTYPE html>\n"), "missing DOCTYPE");
    assert!(out.contains("<html lang=\"en\" data-theme=\"keyhog\">"));
    assert!(out.contains("<title>KeyHog Secret Scan Report</title>"));
    assert!(out.contains("const rawFindings = "));
    assert!(out.trim_end().ends_with("</html>"));

    let json = raw_findings_json(&out);
    let parsed: Vec<keyhog_core::VerifiedFinding> =
        serde_json::from_str(json).expect("embedded rawFindings is valid JSON array");
    assert_eq!(parsed.len(), 1);
    let finding = &parsed[0];
    assert_eq!(finding.detector_id.as_ref(), "aws-access-key");
    assert_eq!(finding.severity, keyhog_core::Severity::High);
    assert_eq!(finding.credential_redacted.as_ref(), "AKIA...7XYA");
    assert_eq!(finding.verification, keyhog_core::VerificationResult::Live);
    assert_eq!(finding.confidence, Some(0.875));
}

#[test]
fn html_json_escapes_quotes_in_detector_name() {
    let out = render(&sample_finding());
    let json = raw_findings_json(&out);
    // Quotes stay JSON-escaped, AND `<`/`>` are now `\uXXXX`-escaped before the
    // JSON is inlined into the <script> raw-text block so an attacker-controlled
    // field can never emit a literal `</script>` (stored-XSS fix, C3/C6/C7). The
    // value still JSON.parses back to the exact original string in the browser.
    assert!(json.contains("AWS Key, \\\"prod\\\" \\u003ca&b\\u003e"));
    // The raw, unescaped angle brackets must NOT appear in the inlined script.
    assert!(!json.contains("<a&b>"));
    assert!(json.contains("\"severity\":\"high\""));
}

#[test]
fn html_report_has_accessibility_affordances() {
    let out = render(&sample_finding());

    assert!(out.contains("aria-label=\"Report theme\""));
    assert!(out.contains("aria-label=\"Use KeyHog theme\""));
    assert!(out.contains("aria-pressed=\"true\""));
    assert!(out.contains("aria-live=\"polite\""));
    assert!(out.contains("aria-atomic=\"true\""));
    assert!(out.contains("role=\"tablist\""));
    assert!(out.contains("role=\"tab\" aria-selected=\"true\""));
    assert!(out.contains("<th scope=\"col\">Detector</th>"));
    assert!(out.contains("<th scope=\"col\">Verification</th>"));
    assert!(out.contains("button:focus-visible"));
    assert!(out.contains("tbody tr:focus-visible"));
    assert!(out.contains("btn.setAttribute('aria-pressed', 'true')"));
    assert!(out.contains("tab.setAttribute('aria-selected', 'true')"));
    assert!(out.contains("resultCount.innerText = `Showing ${count} of ${total} findings.`"));
    assert!(out.contains("tr.tabIndex = 0"));
    assert!(out.contains("tr.setAttribute('role', 'button')"));
    assert!(out.contains("toggleDetailsFromKeyboard"));
}

/// Lock in the Santh-house-style premium surface so a future edit cannot
/// silently strip the redesign, the interactive affordances, or the
/// accessibility guard rails that ship with them.
#[test]
fn html_report_ships_premium_santh_surface() {
    let out = render(&sample_finding());

    // Santh house style: keyhog-yellow accent token + sharp/grid canvas.
    assert!(
        out.contains("--accent-primary: #ffd60a"),
        "keyhog yellow token"
    );
    assert!(
        out.contains("[data-theme=\"light\"]") && out.contains("[data-theme=\"matrix\"]"),
        "KEYHOG/LIGHT/MATRIX theme set"
    );

    // Risk-posture hero.
    assert!(
        out.contains("id=\"risk-verdict\"") && out.contains("renderRiskHero"),
        "risk-posture hero present and populated"
    );

    // Click-to-sort columns (progressive enhancement; markup stays static).
    assert!(
        out.contains("wireSortableHeaders") && out.contains("COLUMN_SORTERS"),
        "sortable columns wired"
    );

    // Custom motion, gated for accessibility, plus the debounced search and
    // copy-to-clipboard affordance.
    assert!(
        out.contains("@keyframes kh-rise") && out.contains("kh-scanline"),
        "custom entrance + scanline animations"
    );
    assert!(
        out.contains("prefers-reduced-motion: no-preference"),
        "motion gated behind reduced-motion"
    );
    assert!(
        out.contains("applyFiltersDebounced"),
        "search input is debounced"
    );
    assert!(
        out.contains("function copyFrom"),
        "copy-to-clipboard affordance"
    );
    assert!(
        out.contains("function animateCount"),
        "count-up stat animation"
    );
    assert!(
        out.contains("SEVERITY_BADGE_CLASSES") && out.contains("function verificationDotClass"),
        "scan-derived badge/dot classes must be closed maps"
    );
}

#[test]
fn html_report_does_not_interpolate_scan_data_into_class_names() {
    let out = render(&sample_finding());

    assert!(
        !out.contains("badge-${"),
        "severity classes must be selected from a closed map, not interpolated"
    );
    assert!(
        out.contains("const severityClass = severityBadgeClass(finding.severity);"),
        "severity class map is wired"
    );
    assert!(
        out.contains("let statusClass = verificationDotClass(finding.verification);"),
        "verification dot class map is wired"
    );
}

#[test]
fn html_report_summary_surfaces_not_checked_findings() {
    let out = render(&sample_finding());

    assert!(
        out.contains("id=\"cnt-not-checked\"") && out.contains(">Not checked<"),
        "summary metrics must include an explicit not-checked count"
    );
    assert!(
        out.contains("const notChecked = findings.filter(f => verificationIsUnattempted(f.verification)).length;"),
        "summary not-checked count must reuse the canonical verification predicate"
    );
    assert!(
        out.contains("activeStatusTab === 'unverifiable' && !verificationIsUnattempted(status)"),
        "not-checked filter tab must include skipped and unverifiable findings consistently"
    );
    assert!(
        out.contains("setStat('cnt-not-checked', notChecked, isInitial);"),
        "summary not-checked count must be wired into renderMetrics"
    );
}

#[test]
fn html_report_service_bars_and_badges_are_contrast_guarded() {
    let out = render(&sample_finding());

    assert!(
        out.contains("const SERVICE_BAR_COLORS = [")
            && out.contains("function serviceBarColor(rank)")
            && out
                .contains("item.style.setProperty('--service-bar-color', serviceBarColor(rank));"),
        "Top Services bars must use a closed palette instead of one flat accent or scan-derived CSS"
    );
    assert!(
        out.contains(".chart-bar-fill { height: 100%; background: var(--service-bar-color, var(--accent-primary)); }"),
        "service bar fill must consume the closed palette custom property"
    );
    assert!(
        !out.contains("background-color: var(--accent-primary);"),
        "Top Services bars must not regress to one flat accent color"
    );
    assert!(
        out.contains("--badge-critical-ink:")
            && out.contains("--badge-high-ink:")
            && out.contains("--badge-medium-ink:"),
        "filled heat badges need explicit per-theme ink tokens"
    );
    assert!(
        out.contains(".badge-critical    { color: var(--badge-critical-ink); background: var(--color-critical); border-color: var(--color-critical); }")
            && out.contains(".badge-high        { color: var(--badge-high-ink);     background: var(--color-high);     border-color: var(--color-high); }")
            && out.contains(".badge-medium      { color: var(--badge-medium-ink);   background: var(--color-medium);   border-color: var(--color-medium); }"),
        "critical/high/medium badges must be filled heat badges with explicit contrast text"
    );
}

#[test]
fn html_report_embeds_scan_metadata_panel() {
    let out = render_with_metadata(HtmlScanMetadata {
        keyhog_version: "1.2.3".to_string(),
        generated_at: "2026-06-23T12:00:01".to_string(),
        scan_started_at: "2026-06-23T12:00:00".to_string(),
        scan_finished_at: "2026-06-23T12:00:01".to_string(),
        duration_ms: 1234,
        targets: vec!["path:/tmp/repo".to_string()],
        source_chunks_scanned: 37,
        detector_count: 899,
    });

    assert!(out.contains("id=\"scan-metadata\""));
    assert!(out.contains("const scanMetadata = "));
    assert!(out.contains("\"keyhog_version\":\"1.2.3\""));
    assert!(out.contains("\"targets\":[\"path:\\u002ftmp\\u002frepo\"]"));
    assert!(out.contains("\"source_chunks_scanned\":37"));
    assert!(out.contains("\"detector_count\":899"));
    assert!(out.contains("renderScanMetadata"));
    assert!(out.contains("meta-source-chunks"));
    assert!(out.contains("@media print"));
}

#[test]
fn html_report_does_not_embed_plaintext_unmask_controls() {
    let out = render(&sample_finding());

    assert!(
        !out.contains("toggleMask"),
        "HTML report must not ship a dead or plaintext-revealing credential toggle"
    );
    assert!(
        !out.contains("data-plaintext"),
        "HTML report must not embed a plaintext credential copy"
    );
    assert!(
        !out.contains("Show secret"),
        "HTML report must not promise a plaintext reveal path"
    );
    assert!(
        out.contains("<span id=\"cred-text-${idx}\">${credRedacted}</span>"),
        "report script should render the redacted credential as static text"
    );
}

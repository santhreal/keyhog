//! Report-injection invariants for the shipped report writer
//! (`keyhog_core::write_report`) across EVERY `ReportFormat`. A scanned file
//! path, git author/commit, provider metadata value, and the redacted credential
//! are all attacker-influenced, so they can smuggle spreadsheet-formula
//! prefixes, JSON/XML metacharacters, and raw terminal escape sequences straight
//! into the operator's report. These tests render adversarial findings through
//! the REAL production path and pin the universal safety invariants:
//!
//!   * A, every format returns `Ok` and emits valid UTF-8 (no panic, no DoS,
//!     no lone surrogate) for arbitrary Unicode-scalar content.
//!   * B, the JSON / JSONL envelopes always parse (injection cannot break the
//!     document structure), for adversarial content.
//!   * C: CSV neutralizes EVERY spreadsheet formula-trigger prefix
//!     (`= + - @ TAB CR`) (the OWASP CSV-injection class (for arbitrary tails)).
//!   * D, the colour-free text report carries NO raw ESC byte and visibly
//!     replaces it with U+FFFD (terminal-escape-injection defang).
//!   * F (the structural formats (JSON/JSONL/CSV) are byte-deterministic).
//!   * G: GitHub-Actions annotations neutralize CR/LF so one finding is one
//!     workflow-command line (no forged `::command` injection).
//!   * H, the HTML report \uXXXX-escapes `<`/`>`/`/` so no finding field can
//!     break out of the `<script>` data block (XSS).
//!   * I, the GitLab SAST report stays valid JSON with one vulnerability per
//!     finding under injection.
//!   * J, the SARIF report stays valid structured JSON (version, `$schema`,
//!     `tool.driver`, one result per finding) under injection.
//!
//! Fixed-vector CSV coverage lives in `regression_csv_formula_injection`; this
//! file is the cross-format INVARIANT sweep. Assertions pin concrete bytes /
//! parse results, never a shape/`!is_empty` check.

use std::borrow::Cow;
use std::collections::HashMap;
use std::sync::Arc;

use keyhog_core::{
    write_report, MatchLocation, ReportFormat, Severity, VerificationResult, VerifiedFinding,
};
use proptest::prelude::*;

/// Every report format, with fixed field values so a format's output depends
/// only on the findings (not wall-clock / uuid): the two time-stamped formats
/// get constant timestamps, HTML gets no metadata. Text is included in both
/// colour modes.
fn all_formats() -> Vec<ReportFormat> {
    vec![
        ReportFormat::Text {
            color: false,
            example_suppressions: 0,
            dogfood_active: false,
        },
        ReportFormat::Text {
            color: true,
            example_suppressions: 2,
            dogfood_active: true,
        },
        ReportFormat::Json,
        ReportFormat::Jsonl,
        ReportFormat::Sarif {
            skip_summary: vec![],
        },
        ReportFormat::Csv,
        ReportFormat::GithubAnnotations,
        ReportFormat::GitlabSast {
            scan_started_at: "2020-01-01T00:00:00".to_string(),
            scan_finished_at: "2020-01-01T00:00:01".to_string(),
        },
        ReportFormat::Html {
            skip_summary: vec![],
            metadata: None,
        },
        ReportFormat::Junit,
    ]
}

fn render(format: ReportFormat, findings: &[VerifiedFinding]) -> Vec<u8> {
    let mut buf = Vec::new();
    write_report(&mut buf, format, findings).expect("write_report must not fail");
    buf
}

/// A stable label per format for failure messages (`ReportFormat` derives no
/// `Debug`).
fn format_name(f: &ReportFormat) -> &'static str {
    match f {
        ReportFormat::Text { .. } => "text",
        ReportFormat::Json => "json",
        ReportFormat::Jsonl => "jsonl",
        ReportFormat::Sarif { .. } => "sarif",
        ReportFormat::Csv => "csv",
        ReportFormat::GithubAnnotations => "github-annotations",
        ReportFormat::GitlabSast { .. } => "gitlab-sast",
        ReportFormat::Html { .. } => "html",
        ReportFormat::Junit => "junit",
    }
}

/// A fully benign finding used as the mutation base for each test.
fn benign_finding() -> VerifiedFinding {
    VerifiedFinding {
        detector_id: Arc::from("aws-access-key"),
        detector_name: Arc::from("AWS Key"),
        service: Arc::from("aws"),
        severity: Severity::High,
        credential_redacted: Cow::Borrowed("AKIA...7XYA"),
        credential_hash: [0xab; 32].into(),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from("config/app.env")),
            line: Some(1),
            offset: 0,
            commit: None,
            author: None,
            date: None,
        },
        verification: VerificationResult::Live,
        metadata: HashMap::new(),
        additional_locations: vec![],
        confidence: Some(0.5),
    }
}

/// A finding whose every attacker-influenced field carries `payload`.
fn adversarial_finding(payload: &str) -> VerifiedFinding {
    let mut metadata = HashMap::new();
    metadata.insert(format!("key{payload}"), format!("val{payload}"));
    VerifiedFinding {
        detector_id: Arc::from(format!("det{payload}").as_str()),
        detector_name: Arc::from(format!("Name {payload}").as_str()),
        service: Arc::from(format!("svc{payload}").as_str()),
        credential_redacted: Cow::Owned(format!("AKIA{payload}7X")),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from(format!("path/{payload}").as_str())),
            line: Some(1),
            offset: 0,
            commit: Some(Arc::from(format!("commit{payload}").as_str())),
            author: Some(Arc::from(format!("author{payload}").as_str())),
            date: Some(Arc::from(format!("2020{payload}").as_str())),
        },
        metadata,
        ..benign_finding()
    }
}

/// Strategy: arbitrary Unicode-scalar strings up to 48 chars, INCLUDING C0/C1
/// control characters, ESC, quotes, and format metacharacters, the worst case
/// for every reporter's escaping.
fn adversarial_text() -> impl Strategy<Value = String> {
    prop::collection::vec(any::<char>(), 0..48).prop_map(|v| v.into_iter().collect())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2_000))]

    /// A (no format panics or emits invalid UTF-8 on arbitrary content).
    #[test]
    fn every_format_is_panic_free_and_valid_utf8(payload in adversarial_text()) {
        let findings = [adversarial_finding(&payload)];
        for format in all_formats() {
            let mut buf = Vec::new();
            let label = format_name(&format);
            let r = write_report(&mut buf, format, &findings);
            prop_assert!(r.is_ok(), "write_report failed for {label}: {:?}", r.err());
            prop_assert!(
                String::from_utf8(buf).is_ok(),
                "format {label} emitted invalid UTF-8 for payload {payload:?}"
            );
        }
    }

    /// C: CSV guards every formula-trigger prefix, whatever the tail.
    #[test]
    fn csv_neutralizes_every_formula_trigger_prefix(
        trigger in prop::sample::select(vec!['=', '+', '-', '@', '\t', '\r']),
        rest in "[a-zA-Z0-9 ()|/]{0,24}",
    ) {
        let payload = format!("{trigger}{rest}");
        let mut f = benign_finding();
        f.location.file_path = Some(Arc::from(payload.as_str()));
        let out = String::from_utf8(render(ReportFormat::Csv, &[f])).unwrap();
        // The single-quote guard must sit immediately before the payload, bare
        // or inside an RFC-4180 quoted field (TAB/CR force quoting). `rest` has
        // no `,`/`"`, so the guarded run stays a contiguous substring.
        let guarded = format!("'{payload}");
        prop_assert!(
            out.contains(&guarded),
            "CSV did not guard formula-trigger payload {payload:?}: {out:?}"
        );
    }
}

/// B, the JSON and JSONL envelopes survive injection: the array parses and each
/// JSONL line parses, so no metacharacter can break out of the document.
#[test]
fn json_and_jsonl_envelopes_survive_injection() {
    let payloads = [
        "\"},{\"pwned\":1",  // JSON break-out attempt
        "]}\n",              // structural close attempt
        "\u{0}\u{1b}\t\r\n", // control chars
        "</script><svg/onload=alert(1)>",
        "😀\"quote\\backslash",
    ];
    // Distinct hashes so the per-finding count assertion is not confounded by any
    // hash-based dedup in a reporter (every finding must survive to the output).
    let findings: Vec<_> = payloads
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let mut f = adversarial_finding(p);
            f.credential_hash = [(i as u8).wrapping_add(1); 32].into();
            f
        })
        .collect();

    let json = render(ReportFormat::Json, &findings);
    let v: serde_json::Value =
        serde_json::from_slice(&json).expect("JSON report must parse despite injection");
    assert!(v.is_array(), "JSON report must be a top-level array");
    assert_eq!(
        v.as_array().unwrap().len(),
        findings.len(),
        "every finding must appear as one array element"
    );

    let jsonl = String::from_utf8(render(ReportFormat::Jsonl, &findings)).unwrap();
    let mut lines = 0usize;
    for line in jsonl.lines().filter(|l| !l.trim().is_empty()) {
        let _: serde_json::Value =
            serde_json::from_str(line).expect("each JSONL line must parse despite injection");
        lines += 1;
    }
    assert_eq!(lines, findings.len(), "one JSONL object per finding");
}

/// D, a colour-free text report never leaks a raw ESC byte; the sanitizer makes
/// the escape visible as U+FFFD rather than dropping it silently.
#[test]
fn color_free_text_report_has_no_raw_escape_byte() {
    // An ESC-laden payload placed in every SCANNED field (file path, commit,
    // author, date, metadata, redacted credential, all routed through
    // `sanitize_terminal`). Detector name/id/service come from detector defs,
    // not scanned content, so they stay benign here.
    let esc = "\u{1b}[31mHACK\u{1b}]0;title\u{7}\u{1b}[0m\u{9b}payload";
    let mut metadata = HashMap::new();
    metadata.insert(format!("key{esc}"), format!("val{esc}"));
    let f = VerifiedFinding {
        credential_redacted: Cow::Owned(format!("AK{esc}IA")),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from(format!("path/{esc}/f").as_str())),
            line: Some(1),
            offset: 0,
            commit: Some(Arc::from(format!("commit{esc}").as_str())),
            author: Some(Arc::from(format!("author{esc}").as_str())),
            date: Some(Arc::from(format!("2020{esc}").as_str())),
        },
        metadata,
        ..benign_finding()
    };
    let out = render(
        ReportFormat::Text {
            color: false,
            example_suppressions: 0,
            dogfood_active: false,
        },
        &[f],
    );
    assert!(
        !out.iter().any(|&b| b == 0x1b),
        "colour-free text report leaked a raw ESC byte, terminal-escape injection"
    );
    let s = String::from_utf8(out).unwrap();
    assert!(
        s.contains('\u{FFFD}'),
        "the terminal sanitizer must REPLACE the escape with U+FFFD, not drop it silently"
    );
}

/// F, the structural formats are byte-for-byte deterministic (rendering the
/// same findings twice yields identical bytes). Guards against nondeterministic
/// ordering or embedded entropy sneaking into a machine-consumed report.
#[test]
fn structural_formats_are_byte_deterministic() {
    let findings = [
        adversarial_finding("d1<>&\"'=@,\ttab"),
        adversarial_finding("d2\r\nnewlines"),
    ];
    assert_eq!(
        render(ReportFormat::Json, &findings),
        render(ReportFormat::Json, &findings),
        "Json must be byte-deterministic"
    );
    assert_eq!(
        render(ReportFormat::Jsonl, &findings),
        render(ReportFormat::Jsonl, &findings),
        "Jsonl must be byte-deterministic"
    );
    assert_eq!(
        render(ReportFormat::Csv, &findings),
        render(ReportFormat::Csv, &findings),
        "Csv must be byte-deterministic"
    );
}

/// G: GitHub-Actions workflow-command injection. Each finding renders to a
/// single `::error file=…,line=…,title=…::message` line terminated by a newline;
/// GitHub parses workflow commands line-by-line, so an attacker-controlled field
/// that smuggled a raw newline could start a SECOND forged command
/// (`::add-mask::`, `::set-output::`, …). The reporter neutralizes CR/LF
/// (sanitizing control chars to U+FFFD) and percent-encodes `%`/`:`/`,` in the
/// property list, so ONE finding must emit EXACTLY ONE line no matter how many
/// newlines, carriage returns, colons and commas its fields carry.
#[test]
fn github_annotations_encode_newlines_no_command_injection() {
    let nasty = "x\n::error::forged\r%25:,\n::add-mask::secret";
    let mut metadata = HashMap::new();
    metadata.insert(format!("k{nasty}"), format!("v{nasty}"));
    let f = VerifiedFinding {
        detector_name: Arc::from(format!("Name {nasty}").as_str()),
        credential_redacted: Cow::Owned(format!("AK{nasty}")),
        location: MatchLocation {
            source: Arc::from("filesystem"),
            file_path: Some(Arc::from(format!("path/{nasty}").as_str())),
            line: Some(7),
            offset: 0,
            commit: Some(Arc::from(format!("c{nasty}").as_str())),
            author: Some(Arc::from(format!("a{nasty}").as_str())),
            date: None,
        },
        metadata,
        ..benign_finding()
    };
    let out = String::from_utf8(render(ReportFormat::GithubAnnotations, &[f])).unwrap();
    // One finding = exactly one workflow-command line: a single trailing newline,
    // none embedded, no raw CR.
    assert_eq!(
        out.matches('\n').count(),
        1,
        "one finding must be exactly one annotation line: {out:?}"
    );
    assert!(
        out.ends_with('\n'),
        "the single newline must be the line terminator: {out:?}"
    );
    assert!(
        !out.contains('\r'),
        "raw CR must be percent-encoded, never emitted: {out:?}"
    );
    // The smuggled CR/LF survive only as the visible replacement char U+FFFD
    // (the reporter sanitizes control chars before percent-encoding), neutralized,
    // never dropped silently, and never as bytes that could start a new command.
    assert!(
        out.contains('\u{FFFD}'),
        "smuggled control chars must be neutralized to U+FFFD, not dropped: {out:?}"
    );
}

/// H: HTML report XSS. The self-contained HTML report inlines the findings as
/// JSON inside a `<script>` block; `escape_for_script` rewrites `<`, `>`, `/` to
/// `\uXXXX`, so no attacker-controlled field can close the script tag or inject
/// live markup. A unique injected `</script><kaboom …>` sentinel must never
/// appear raw in the output.
#[test]
fn html_report_escapes_script_breakout_for_xss() {
    let payload = "SENTINEL</script><kaboom onerror=alert(1)>";
    let f = adversarial_finding(payload);
    let out = String::from_utf8(render(
        ReportFormat::Html {
            skip_summary: vec![],
            metadata: None,
        },
        &[f],
    ))
    .unwrap();
    // The raw injected tag / script-close must NOT survive anywhere in the report.
    assert!(
        !out.contains("<kaboom"),
        "raw injected tag leaked into the HTML report. XSS"
    );
    assert!(
        !out.contains("</script><kaboom"),
        "script-breakout sequence survived into the HTML report. XSS"
    );
    // The finding data still round-trips (letters are untouched) but the `<` is
    // \uXXXX-escaped (proving it was neutralized, not dropped).
    assert!(
        out.contains("SENTINEL"),
        "finding data must still be present in escaped form"
    );
    assert!(
        out.contains("u003c") || out.contains("u003C"),
        "the injected `<` must be \\uXXXX-escaped inside the script payload"
    );
}

/// I: GitLab SAST report is a machine-consumed JSON document; injection must not
/// break its structure. It parses as valid JSON with a `vulnerabilities` array,
/// one element per finding, whatever the finding content.
#[test]
fn gitlab_sast_report_is_valid_json_under_injection() {
    let payloads = ["\"}]},{", "</x>", "\u{0}\n\r\t", "😀\\\"esc", "]}"];
    let findings: Vec<_> = payloads
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let mut f = adversarial_finding(p);
            f.credential_hash = [(i as u8).wrapping_add(1); 32].into();
            f
        })
        .collect();
    let out = render(
        ReportFormat::GitlabSast {
            scan_started_at: "2020-01-01T00:00:00".to_string(),
            scan_finished_at: "2020-01-01T00:00:01".to_string(),
        },
        &findings,
    );
    let v: serde_json::Value = serde_json::from_slice(&out)
        .expect("GitLab SAST report must be valid JSON under injection");
    assert!(
        v["vulnerabilities"].is_array(),
        "GitLab SAST report must carry a vulnerabilities array"
    );
    assert_eq!(
        v["vulnerabilities"].as_array().unwrap().len(),
        findings.len(),
        "one vulnerability per finding"
    );
}

/// J: SARIF is the format GitHub code-scanning consumes; a malformed SARIF
/// under injection breaks the security dashboard. It parses as valid JSON with
/// the 2.1.0 version, a `$schema`, a `tool.driver`, and one result per finding,
/// whatever the finding content.
#[test]
fn sarif_report_is_valid_structured_json_under_injection() {
    let payloads = ["\"}]},{", "</x>", "\u{0}\n\r\t", "😀\\\"esc", "]}"];
    let findings: Vec<_> = payloads
        .iter()
        .enumerate()
        .map(|(i, p)| {
            let mut f = adversarial_finding(p);
            f.credential_hash = [(i as u8).wrapping_add(1); 32].into();
            f
        })
        .collect();
    let out = render(
        ReportFormat::Sarif {
            skip_summary: vec![],
        },
        &findings,
    );
    let v: serde_json::Value =
        serde_json::from_slice(&out).expect("SARIF report must be valid JSON under injection");
    assert_eq!(v["version"], "2.1.0", "SARIF version must be 2.1.0");
    assert!(v["$schema"].is_string(), "SARIF must declare a $schema");
    let run = &v["runs"][0];
    assert!(
        run["tool"]["driver"].is_object(),
        "SARIF run must carry tool.driver"
    );
    assert!(
        run["results"].is_array(),
        "SARIF run must carry a results array"
    );
    assert_eq!(
        run["results"].as_array().unwrap().len(),
        findings.len(),
        "one SARIF result per finding"
    );
}

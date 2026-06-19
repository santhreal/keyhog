//! Lane 10 — verification-feature DOC↔BINARY coherence.
//!
//! docs/src/verification.md is the operator's contract for `keyhog scan
//! --verify`. A prior version of that doc made claims the binary never honored:
//! it printed a flat `src/...:14:12  CRITICAL  ...  verified-live` example line
//! (the real text reporter renders a bordered box and appends the verdict to the
//! `Confidence:` line as `(LIVE)`/`(dead)`), and it promised a dead-credential
//! severity downgrade that `into_finding` never applied. These black-box tests
//! drive the REAL `keyhog` binary and read the committed doc via `include_str!`
//! so the verification claims can never silently drift from behavior again.
//!
//! What is pinned here:
//!   * `--verify`, `--proxy`, `--insecure` are real, accepted flags (not exit-2).
//!   * `--help` documents exit 10 = "Live credentials found (requires --verify)".
//!   * the JSON `verification` field is the lowercase variant (`skipped` on an
//!     unverified scan), never the text-reporter labels.
//!   * verification.md no longer carries the fabricated `verified-live` /
//!     `verified-dead` text labels, and DOES show the real `(LIVE)` / `(dead)`
//!     `Confidence:`-line suffix the text reporter emits.
//!   * verification.md's severity table lists every real `VerificationResult`
//!     variant and states the canonical one-tier `dead`/`revoked` downgrade.
//!   * low-confidence `--verify` skips are surfaced on stderr and documented.

use std::path::PathBuf;
use std::process::Command;
use tempfile::TempDir;

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

/// A planted GitHub classic PAT shape (valid checksum-free format that the
/// embedded `github-classic-pat` detector fires on at CRITICAL). Split so this
/// test file is not itself a self-scan hit.
const PLANTED_GH: &str = concat!(
    "GITHUB_TOKEN=ghp_",
    "0123456789abcdefghijklmnopqrstuvwxyz1234\n"
);

const VERIFICATION_DOC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/src/verification.md"
));
const DETECTORS_DOC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/src/detectors.md"
));
const ENV_DOC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/src/reference/env.md"
));
const HTTP_WIRE_DOC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/src/http-wire.md"
));
const CLI_REF_DOC: &str = include_str!(concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../../docs/src/reference/cli.md"
));

fn run(args: &[&str]) -> (Option<i32>, String, String) {
    let out = Command::new(binary())
        .args(args)
        .output()
        .expect("spawn keyhog");
    (
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn scan_file(content: &str, extra: &[&str]) -> (Option<i32>, String, String) {
    let dir = TempDir::new().unwrap();
    let path = dir.path().join("planted.env");
    std::fs::write(&path, content).unwrap();
    // This doc-coherence test proves verification flag/output behavior, not
    // autoroute calibration. Use an explicit backend so the test stays
    // independent of the host's persisted fastest-correct routing cache.
    let mut args: Vec<&str> = vec!["scan", "--no-daemon", "--backend", "simd"];
    args.extend_from_slice(extra);
    let p = path.to_string_lossy().into_owned();
    args.push(&p);
    run(&args)
}

fn cli_source(rel: &str) -> String {
    std::fs::read_to_string(PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(rel))
        .unwrap_or_else(|error| panic!("read {rel}: {error}"))
}

/// The verification flags verification.md advertises must be real `scan` flags:
/// passing each on a clean file exits 0, never exit 2 (clap unknown-flag). This
/// pins that the documented `--verify` surface is wired, not vaporware.
#[test]
fn verify_proxy_insecure_flags_are_accepted() {
    // `--insecure` and `--proxy off` take no network; `--verify` on a clean file
    // finds nothing to verify, so it also stays offline and exits 0.
    for extra in [vec!["--verify"], vec!["--insecure"], vec!["--proxy", "off"]] {
        let (code, _o, e) = scan_file("clean prose, no secrets here\n", &extra);
        assert_eq!(
            code,
            Some(0),
            "`keyhog scan {extra:?}` on a clean file must exit 0 (the flag is a real, \
             documented `scan` flag in docs/src/verification.md); got {code:?}, stderr: {e}"
        );
    }
}

/// `--help` must document exit code 10 with the exact "Live credentials found"
/// meaning verification.md and first-scan.md rely on. Drift-proof: reads live
/// `--help`.
#[test]
fn help_documents_exit_10_live_credentials() {
    let (_c, help, _e) = run(&["--help"]);
    let line10 = help
        .lines()
        .find(|l| l.trim_start().starts_with("10"))
        .unwrap_or_else(|| panic!("`--help` has no exit-10 line:\n{help}"))
        .to_lowercase();
    assert!(
        line10.contains("live credential"),
        "`--help` exit-10 line must say \"Live credentials found\"; got {line10:?}"
    );
    assert!(
        line10.contains("--verify"),
        "`--help` exit-10 line must note it requires --verify; got {line10:?}"
    );
}

/// The JSON `verification` field for an UNVERIFIED finding is the lowercase
/// `VerificationResult` variant `skipped`, never a text-reporter label. This
/// drives a real scan and asserts the emitted bytes, matching the contract
/// verification.md now states explicitly.
#[test]
fn json_verification_field_is_skipped_not_text_label() {
    let (code, out, _e) = scan_file(PLANTED_GH, &["--format", "json"]);
    assert_eq!(
        code,
        Some(1),
        "planted GitHub PAT must exit 1 (finding, unverified)"
    );
    assert!(
        out.contains("\"verification\":\"skipped\"")
            || out.contains("\"verification\": \"skipped\""),
        "JSON `verification` for an unverified finding must be the lowercase variant \
         \"skipped\"; got: {out}"
    );
    assert!(
        !out.contains("verified-live") && !out.contains("verified-dead"),
        "JSON output must never carry the text-reporter labels verified-live/verified-dead. \
         Output: {out}"
    );
}

/// verification.md must not carry the FABRICATED `verified-live`/`verified-dead`
/// text labels anywhere (the real text reporter renders `(LIVE)`/`(dead)`), and
/// must show the real `Confidence:`-line verdict suffix. This pins the corrected
/// example so the doc cannot regress to an output shape the binary never emits.
#[test]
fn verification_doc_uses_real_text_reporter_labels() {
    assert!(
        !VERIFICATION_DOC.contains("verified-live")
            || VERIFICATION_DOC.contains("never the `verified-live`"),
        "verification.md still shows the fabricated `verified-live` text label as the \
         reporter output (the real text reporter emits `(LIVE)`)."
    );
    // The doc must demonstrate the REAL text-reporter verdict suffix.
    assert!(
        VERIFICATION_DOC.contains("(LIVE)"),
        "verification.md must show the real `(LIVE)` verdict the text reporter appends to \
         the `Confidence:` line."
    );
    assert!(
        VERIFICATION_DOC.contains("(dead)"),
        "verification.md must show the real `(dead)` verdict the text reporter appends to \
         the `Confidence:` line."
    );
    // The fabricated `(downgraded)` / `originally CRITICAL` annotations must be gone.
    assert!(
        !VERIFICATION_DOC.contains("originally CRITICAL"),
        "verification.md still shows the fabricated `originally CRITICAL` annotation; the \
         text reporter has no such field. The downgrade is shown by the box header alone."
    );
}

/// verification.md's severity table must reflect the REAL set of
/// `VerificationResult` variants and the wired one-tier downgrade for both
/// `dead` and `revoked`. Pins that the table lists `revoked` and `rate_limited`
/// (previously omitted) and states the canonical downgrade.
#[test]
fn verification_doc_severity_table_lists_real_variants() {
    for variant in [
        "`live`",
        "`dead`",
        "`revoked`",
        "`rate_limited`",
        "`skipped`",
    ] {
        assert!(
            VERIFICATION_DOC.contains(variant),
            "verification.md severity table must list the real VerificationResult variant \
             {variant}; it does not."
        );
    }
    assert!(
        VERIFICATION_DOC.contains("Downgrade one tier"),
        "verification.md must keep the canonical \"Downgrade one tier\" severity action."
    );
    assert!(
        VERIFICATION_DOC.contains("downgrade_one"),
        "verification.md must reference the canonical `Severity::downgrade_one` step so the \
         doc names the exact behavior the verifier wires."
    );
}

#[test]
fn verification_doc_discloses_low_confidence_verify_skips() {
    assert!(
        VERIFICATION_DOC.contains("## Low-confidence candidates"),
        "verification.md must document that --verify can leave low-confidence \
         findings unverified"
    );
    assert!(
        VERIFICATION_DOC.contains("verifier confidence floor")
            && VERIFICATION_DOC.contains("stderr warning")
            && VERIFICATION_DOC.contains("verification` field stays `skipped`"),
        "verification.md must disclose the stderr warning and JSON result for \
         low-confidence verify skips"
    );
}

#[test]
fn low_confidence_verify_skips_are_operator_visible() {
    let source = cli_source("src/orchestrator/postprocess.rs");
    let block = source
        .split("skipping low-confidence findings from verification")
        .nth(1)
        .expect("verify path must classify low-confidence verification skips");
    let block = block
        .split("let rate = self.args.verify_rate")
        .next()
        .unwrap_or(block);
    assert!(
        block.contains("eprintln!"),
        "`--verify` low-confidence skips must reach stderr, not only tracing"
    );
    assert!(
        block.contains("--verify skipped")
            && block.contains("verifier confidence floor")
            && block.contains("verification=skipped"),
        "the stderr warning must name the requested verify mode, the threshold \
         reason, and the machine-visible result"
    );
}

#[test]
fn oob_handshake_failure_is_operator_visible() {
    let source = cli_source("src/orchestrator/postprocess.rs");
    let block = source
        .split("OOB verification unavailable: collector handshake failed")
        .nth(1)
        .expect("verify-oob path must classify collector handshake failure");
    let block = block
        .split("let mut findings = verifier.verify_all")
        .next()
        .unwrap_or(block);
    assert!(
        block.contains("eprintln!"),
        "`--verify-oob` handshake failures must reach stderr, not only tracing"
    );
    assert!(
        block.contains("--verify-oob collector handshake failed")
            && block.contains("detectors that require OOB verification")
            && block.contains("verification errors"),
        "the stderr warning must name the requested OOB mode and explain the \
         partial-verification result"
    );
}

#[test]
fn verification_doc_discloses_oob_handshake_failures() {
    assert!(
        VERIFICATION_DOC.contains("## Out-of-band callbacks"),
        "verification.md must document --verify-oob callback behavior"
    );
    assert!(
        VERIFICATION_DOC.contains("collector handshake fails")
            && VERIFICATION_DOC.contains("stderr warning")
            && VERIFICATION_DOC.contains("verification errors"),
        "verification.md must disclose the operator-visible OOB handshake \
         failure contract"
    );
}

#[test]
fn detector_authoring_doc_uses_json_verification_variants() {
    assert!(
        !DETECTORS_DOC.contains("verification: \"verified-live\"")
            && !DETECTORS_DOC.contains("\"verified-dead\""),
        "docs/src/detectors.md must document JSON verification enum values, not stale \
         text labels: verified-live / verified-dead"
    );
    assert!(
        DETECTORS_DOC.contains("verification: \"live\"")
            && DETECTORS_DOC.contains("verification: \"dead\""),
        "docs/src/detectors.md must show the actual VerificationResult JSON values \
         `live` and `dead`"
    );
}

#[test]
fn docs_do_not_advertise_ambient_proxy_or_tls_env_controls() {
    let docs = [
        ("docs/src/verification.md", VERIFICATION_DOC),
        ("docs/src/reference/env.md", ENV_DOC),
        ("docs/src/http-wire.md", HTTP_WIRE_DOC),
        ("docs/src/reference/cli.md", CLI_REF_DOC),
    ];
    let stale_claims = [
        "Same as `HTTPS_PROXY` env var",
        "Set `KEYHOG_PROXY=off`",
        "KEYHOG_PROXY` env var",
        "KEYHOG_INSECURE_TLS=1",
        "Env: `KEYHOG_INSECURE_TLS=1`",
        "Order: explicit flag → KEYHOG_PROXY → standard env vars",
        "Order: explicit flag -> KEYHOG_PROXY -> standard env vars",
        "reqwest's default. Last resort.",
        "Routes verifier traffic through a proxy. `keyhog scan --proxy <URL>` overrides.",
        "If set, accept self-signed TLS certs on verifier traffic.",
    ];

    for (path, doc) in docs {
        for stale in stale_claims {
            assert!(
                !doc.contains(stale),
                "{path} still advertises the removed ambient verifier proxy/TLS contract: {stale:?}"
            );
        }
    }

    assert!(
        ENV_DOC.contains("deliberately does NOT read")
            && ENV_DOC.contains("HTTPS_PROXY")
            && ENV_DOC.contains("KEYHOG_INSECURE_TLS")
            && ENV_DOC.contains("No proxy or TLS environment variable participates"),
        "env reference must explicitly state ambient verifier proxy/TLS variables are ignored"
    );
    assert!(
        VERIFICATION_DOC.contains("ambient `HTTPS_PROXY`")
            && VERIFICATION_DOC.contains("variables are ignored")
            && VERIFICATION_DOC
                .contains("no environment variable can disable certificate verification"),
        "verification.md must state the explicit-only network policy"
    );
}

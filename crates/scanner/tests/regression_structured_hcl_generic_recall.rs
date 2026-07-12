//! Regression: structured HCL extraction must feed the generic keyword bridge.
//!
//! Terraform `variable "api_key" { default = "..." }` keeps the credential
//! keyword on the block header while the value lives on the `default` line.
//! The HCL preprocessor already synthesizes `api_key: <value>` lines for the
//! named detector path; the generic bridge must scan that same preprocessed
//! text and then report the original source line/offset.

mod support;
use support::paths::detector_dir;

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

fn scanner_with_floor(min_confidence: f64) -> CompiledScanner {
    let detectors = keyhog_core::load_detectors(&detector_dir()).expect("load detectors");
    CompiledScanner::compile(detectors)
        .expect("compile scanner")
        .with_config(ScannerConfig::default().min_confidence(min_confidence))
}

fn scan(scanner: &CompiledScanner, body: &str, path: &str) -> Vec<RawMatch> {
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some(path.into()),
            ..Default::default()
        },
    };
    scanner.clear_fragment_cache();
    scanner
        .scan_chunks_with_backend(std::slice::from_ref(&chunk), ScanBackend::CpuFallback)
        .into_iter()
        .flatten()
        .collect()
}

fn generic_api_key_hits<'a>(matches: &'a [RawMatch], credential: &str) -> Vec<&'a RawMatch> {
    matches
        .iter()
        .filter(|m| {
            m.detector_id.as_ref() == "generic-api-key" && m.credential.as_ref() == credential
        })
        .collect()
}

fn detector_hits<'a>(
    matches: &'a [RawMatch],
    detector_id: &str,
    credential: &str,
) -> Vec<&'a RawMatch> {
    matches
        .iter()
        .filter(|m| m.detector_id.as_ref() == detector_id && m.credential.as_ref() == credential)
        .collect()
}

#[test]
fn hcl_variable_default_generic_api_key_surfaces_with_source_line_and_offset() {
    let secret = "f1e2d3c4b5a69788776655443322110fedcba9876543210a";
    let body =
        format!("variable \"api_key\" {{\n  type    = string\n  default = \"{secret}\"\n}}\n");
    let scanner = scanner_with_floor(0.40);
    let matches = scan(&scanner, &body, "/repo/infra/variables.tf");
    let hits = generic_api_key_hits(&matches, secret);
    assert_eq!(
        hits.len(),
        1,
        "HCL synthetic api_key/value line must feed generic-api-key exactly once; matches={matches:#?}"
    );
    let hit = hits[0];
    assert_eq!(hit.location.line, Some(3));
    assert_eq!(
        hit.location.offset,
        body.find(secret).expect("secret offset")
    );
    assert!(
        hit.location.offset < body.len(),
        "structured synthetic offsets must be mapped back into the source file"
    );
}

#[test]
fn hcl_inline_variable_default_generic_api_key_surfaces_with_source_line_and_offset() {
    let secret = "f1e2d3c4b5a69788776655443322110fedcba9876543210a";
    let body = format!("variable \"api_key\" {{ default = \"{secret}\" }}\n");
    let scanner = scanner_with_floor(0.40);
    let matches = scan(&scanner, &body, "/repo/infra/inline.tf");
    let hits = generic_api_key_hits(&matches, secret);
    assert_eq!(
        hits.len(),
        1,
        "single-line HCL variable defaults must feed generic-api-key exactly once"
    );
    let hit = hits[0];
    assert_eq!(hit.location.line, Some(1));
    assert_eq!(
        hit.location.offset,
        body.find(secret).expect("secret offset")
    );
    assert!(
        hit.location.offset < body.len(),
        "inline structured synthetic offset must be mapped back into the source file"
    );
}

#[test]
fn mirror_shaped_hcl_base64_surfaces_at_default_floor() {
    let secret = "gD+iWXpmkfIoEZcJV55KwQf/z2VyN87XesmdPZbZgtVHuZhwAVaRPi";
    let body = format!(
        "variable \"api_key\" {{\n  type    = string\n  default = \"{secret}\"\n}}\n\nresource \"null_resource\" \"deploy\" {{}}\n"
    );
    let scanner = scanner_with_floor(0.40);
    let matches = scan(&scanner, &body, "/repo/pkg/core/consumer.tf");
    let hits = generic_api_key_hits(&matches, secret);
    assert_eq!(
        hits.len(),
        1,
        "mirror Terraform generic-high-entropy sample must surface through generic-api-key"
    );
    let hit = hits[0];
    assert_eq!(hit.location.line, Some(3));
    assert_eq!(
        hit.location.offset,
        body.find(secret).expect("secret offset")
    );
    assert!(
        hit.confidence.is_some_and(|confidence| confidence >= 0.40),
        "default-floor HCL generic hit must carry an honest emitted confidence"
    );
}

#[test]
fn hcl_structured_only_generic_password_reports_source_offset_not_append_offset() {
    let secret = "S4oxj2N-bVEi6ivQsrW3";
    let body =
        format!("variable \"db_password\" {{\n  type    = string\n  default = \"{secret}\"\n}}\n");
    let scanner = scanner_with_floor(0.40);
    let matches = scan(&scanner, &body, "/repo/infra/passwords.tf");
    let hits = detector_hits(&matches, "generic-password", secret);
    assert_eq!(
        hits.len(),
        1,
        "db_password structured append must feed generic-password exactly once; matches={matches:#?}"
    );
    let hit = hits[0];
    let source_offset = body.find(secret).expect("secret offset");
    assert_eq!(hit.location.line, Some(3));
    assert_eq!(
        hit.location.offset, source_offset,
        "structured-only generic-password hit must report the source value offset, not the appended synthetic line"
    );
    assert!(
        hit.location.offset < body.len(),
        "structured append offset {} must be inside source len {}",
        hit.location.offset,
        body.len()
    );
}

#[test]
fn structured_append_does_not_duplicate_raw_env_generic_hit() {
    let secret = "3f8a9c2e1b7d4f6a8c0e2d4f6a8b0c1e";
    let body = format!("API_KEY=\"{secret}\"\n");
    let scanner = scanner_with_floor(0.40);
    let matches = scan(&scanner, &body, "/repo/.env");
    let hits = generic_api_key_hits(&matches, secret);
    assert_eq!(
        hits.len(),
        1,
        "raw and structured .env views must collapse to one source-offset-stable finding"
    );
    assert_eq!(hits[0].location.line, Some(1));
    assert_eq!(
        hits[0].location.offset,
        body.find(secret).expect("secret offset")
    );
}

#[test]
fn hcl_low_signal_defaults_stay_quiet() {
    let body = r#"
variable "region" {
  type    = string
  default = "us-east-1"
}

resource "aws_iam_user" "service_account" {
  name = "app-service"
}
"#;
    let scanner = scanner_with_floor(0.0);
    let matches = scan(&scanner, body, "/repo/infra/variables.tf");
    assert!(
        matches
            .iter()
            .all(|m| !matches!(m.detector_id.as_ref(), "generic-secret" | "generic-api-key")),
        "HCL preprocessing must not turn ordinary Terraform defaults into generic secrets: {matches:#?}"
    );
}

//! Default filesystem scans must decode bounded subwindows of large source chunks.
//!
//! Filesystem readers emit 1 MiB windows while the default decode working-set
//! ceiling is 512 KiB. Rejecting the whole source window made encoded secrets in
//! its interior unreachable. The scanner must retain the smaller ceiling as a
//! memory bound and decode overlap-safe subwindows instead.

use base64::Engine;
use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::{CompiledScanner, ScannerConfig};
use std::path::PathBuf;

#[test]
fn default_decode_ceiling_recovers_an_encoded_midwindow_secret() {
    const SOURCE_WINDOW_SIZE: usize = 1024 * 1024;
    const SECRET_OFFSET: usize = 700 * 1024;
    let secret = "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";
    let encoded =
        base64::engine::general_purpose::STANDARD.encode(format!("token={secret}\n").as_bytes());

    let mut body = "filler line\n".repeat(SECRET_OFFSET / "filler line\n".len());
    body.push_str("TOKEN_B64=");
    let encoded_offset = body.len();
    body.push_str(&encoded);
    body.push('\n');
    body.extend(std::iter::repeat_n('x', SOURCE_WINDOW_SIZE - body.len()));
    assert_eq!(body.len(), SOURCE_WINDOW_SIZE);

    let mut detector_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    detector_dir.pop();
    detector_dir.pop();
    detector_dir.push("detectors");
    let scanner = CompiledScanner::compile(
        keyhog_core::load_detectors(&detector_dir).expect("load embedded detectors"),
    )
    .expect("compile scanner")
    .with_config(ScannerConfig::default());
    let chunk = Chunk {
        data: body.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("encoded/middle.txt".into()),
            ..Default::default()
        },
    };

    let findings = scanner.scan(&chunk).expect("scan large filesystem window");
    let finding = findings
        .iter()
        .find(|finding| {
            finding.detector_id.as_ref() == "github-classic-pat"
                && finding.credential.as_ref() == secret
        })
        .unwrap_or_else(|| {
            panic!("encoded midwindow GitHub token was not recovered: {findings:#?}")
        });
    assert_eq!(
        finding.location.offset,
        encoded_offset + "token=".len(),
        "decoded finding must retain the credential's source-relative offset"
    );
}

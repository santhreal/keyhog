//! R5-T-SCAN engine chunk boundary: twilio token split reassembled.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

#[test]
fn chunk_boundary_twilio_token_split_reassembled() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop();
    d.pop();
    d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d).expect("detectors"))
        .expect("compile");

    // Realistic cross-seam leak: the `twilio_auth_token=` keyword anchor and
    // the 32-hex value straddle the chunk boundary together. The detector is
    // context-required - a bare 32-hex is an MD5, not a Twilio token, so it
    // demands the Twilio `AccountSid` companion (AC + 32 hex) within 5 lines.
    // Real leaks carry the SID alongside the token (the SDK constructor takes
    // both), so the boundary buffer must reassemble the token AND see the SID.
    // The SID sits fully in chunk A; the auth-token hex straddles the seam.
    // The captured credential is the 32-hex auth-token group.
    let credential = "00000000000000000000000000000000";
    let block = format!(
        "TWILIO_ACCOUNT_SID=AC00000000000000000000000000000000\ntwilio_auth_token={credential}"
    );
    // Split inside the auth-token hex (the SID line is 53 bytes incl. newline,
    // `twilio_auth_token=` is 18 bytes, so the hex starts at byte 71).
    let split = 80;
    let pad = "z\n".repeat(4096);
    let mut data_a = pad.clone();
    data_a.push_str(&block[..split]);
    let len_a = data_a.len();
    let mut data_b = block[split..].to_string();
    data_b.push_str("\n");

    let chunk_a = Chunk {
        data: data_a.into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some("chunk-a.txt".into()),
            base_offset: 0,
            ..Default::default()
        },
    };
    let chunk_b = Chunk {
        data: data_b.into(),
        metadata: ChunkMetadata {
            source_type: "adversarial".into(),
            path: Some("chunk-a.txt".into()),
            base_offset: len_a,
            ..Default::default()
        },
    };

    let results = scanner.scan_coalesced(&[chunk_a, chunk_b]);
    let found = results.iter().flatten().any(|m| {
        m.detector_id.as_ref() == "twilio-auth-token" && m.credential.as_ref() == credential
    });
    assert!(
        found,
        "twilio-auth-token split across chunk seam must reassemble; matches={:?}",
        results
            .iter()
            .flatten()
            .map(|m| (
                m.detector_id.as_ref().to_string(),
                m.credential.as_ref().to_string()
            ))
            .collect::<Vec<_>>()
    );
}

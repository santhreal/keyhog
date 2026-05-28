//! R5-T-SCAN engine chunk boundary: discord bot token split.

use keyhog_core::{Chunk, ChunkMetadata};
use keyhog_scanner::CompiledScanner;
use std::path::PathBuf;

#[test]
fn chunk_boundary_discord_bot_split_reassembled() {
    let mut d = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    d.pop(); d.pop(); d.push("detectors");
    let scanner = CompiledScanner::compile(keyhog_core::load_detectors(&d).expect("detectors")).expect("compile");
    let secret = "MTAxMjM0NTY3ODkw.AbCdEf.GhIjKlMnOpQrStUvWxYz0123456789";
    let split = 15;
    let pad = "z\n".repeat(4096);
    let mut data_a = pad.clone(); data_a.push_str(&secret[..split]); let len_a = data_a.len();
    let mut data_b = secret[split..].to_string(); data_b.push_str("\n");
    let chunk_a = Chunk { data: data_a.into(), metadata: ChunkMetadata { source_type: "adversarial".into(), path: Some("discord.env".into()), base_offset: 0, ..Default::default() } };
    let chunk_b = Chunk { data: data_b.into(), metadata: ChunkMetadata { source_type: "adversarial".into(), path: Some("discord.env".into()), base_offset: len_a, ..Default::default() } };
    let results = scanner.scan_coalesced(&[chunk_a, chunk_b]);
    let found = results.iter().flatten().any(|m| m.detector_id.as_ref() == "discord-bot-token" && m.credential.as_ref() == secret);
    assert!(found, "discord-bot-token split across chunk seam must reassemble");
}

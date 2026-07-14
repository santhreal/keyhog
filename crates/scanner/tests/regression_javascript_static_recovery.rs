#![cfg(feature = "decode")]

use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::{CompiledScanner, ScanBackend, ScannerConfig};

const SECRET: &str = concat!("ghp_", "69121b4cdeeff121c88dffac1f9dbc2giIjE");

const XOR_LITERAL: &str = concat!(
    "const data = [177,109,7,171,232,62,227,128,231,103,67,151,186,98,183,212,",
    "176,52,69,197,189,63,234,214,176,99,22,151,239,97,235,214,180,102,69,147,",
    "183,78,184,247]; const key = [214,5,119,244,222,7,210,178]; ",
    "return String.fromCharCode(...data.map((b, i) => b ^ key[i % key.length]));",
);

const XOR_HEX_LITERAL: &str = concat!(
    "const data = [0xb1,0x6d,0x07,0xab,0xe8,0x3e,0xe3,0x80,0xe7,0x67,0x43,",
    "0x97,0xba,0x62,0xb7,0xd4,0xb0,0x34,0x45,0xc5,0xbd,0x3f,0xea,0xd6,",
    "0xb0,0x63,0x16,0x97,0xef,0x61,0xeb,0xd6,0xb4,0x66,0x45,0x93,0xb7,",
    "0x4e,0xb8,0xf7]; const key = [0xd6,0x05,0x77,0xf4,0xde,0x07,0xd2,0xb2]; ",
    "return String.fromCharCode(...data.map((b, i) => b ^ key[i % key.length]));",
);

const XOR_BASE64_ARRAYS: &str = concat!(
    "const _d = JSON.parse(Buffer.from(\"WzE3NywgMTA5LCA3LCAxNzEsIDIzMiwgNjIsIDIyNywg",
    "MTI4LCAyMzEsIDEwMywgNjcsIDE1MSwgMTg2LCA5OCwgMTgzLCAyMTIsIDE3NiwgNTIsIDY5LCAx",
    "OTcsIDE4OSwgNjMsIDIzNCwgMjE0LCAxNzYsIDk5LCAyMiwgMTUxLCAyMzksIDk3LCAyMzUsIDIx",
    "NCwgMTgwLCAxMDIsIDY5LCAxNDcsIDE4MywgNzgsIDE4NCwgMjQ3XQ==\", 'base64')",
    ".toString('utf8')); const _k = JSON.parse(Buffer.from(\"WzIxNCwgNSwgMTE5LCAyNDQs",
    "IDIyMiwgNywgMjEwLCAxNzhd\", 'base64').toString('utf8')); ",
    "return String.fromCharCode(..._d.map((b, i) => b ^ _k[i % _k.length]));",
);

const AES_BOUND_BUFFERS: &str = concat!(
    "const key = Buffer.from(\"75aa41b547fb2b20b1c35bf524115e077c7d5dd5c173271fe67c03c2d781192d\", 'hex'); ",
    "const iv = Buffer.from(\"667daed70df5f3b0c37d48833c330c1c\", 'hex'); ",
    "const payload = Buffer.from(\"X1VL9YbGVjOgjoQWE2fjtUL63C7dbUU9DXwze8i9Ejb9yqL5UEABmPYwofE18q5J\", 'base64'); ",
    "const decipher = crypto.createDecipheriv('aes-256-cbc', key, iv); ",
    "return Buffer.concat([decipher.update(payload), decipher.final()]).toString('utf8');",
);

const AES_JOINED_BUFFERS: &str = concat!(
    "const _key = [\"75aa41b547fb2b20b1c35bf524115e07\",",
    "\"7c7d5dd5c173271fe67c03c2d781192d\"].join(''); ",
    "const _payload = [\"X1VL9YbGVjOgjoQWE2fjtUL6\",",
    "\"3C7dbUU9DXwze8i9Ejb9yqL5UEABmPYwofE18q5J\"].join(''); ",
    "const _dec = crypto.createDecipheriv('aes-256-cbc', Buffer.from(_key, 'hex'), ",
    "Buffer.from(\"667daed70df5f3b0c37d48833c330c1c\", 'hex')); ",
    "return Buffer.concat([_dec.update(Buffer.from(_payload, 'base64')), ",
    "_dec.final()]).toString('utf8');",
);

const CRYPTOJS_PASSPHRASE: &str = concat!(
    "const CryptoJS = require(\"crypto-js\"); ",
    "function decryptAES(encryptedData, keyMaterial) { ",
    "const bytes = CryptoJS.AES.decrypt(encryptedData, keyMaterial); ",
    "return bytes.toString(CryptoJS.enc.Utf8); } ",
    "let secretKey = \"mySecretKey123\"; ",
    "let encryptedMessage = \"U2FsdGVkX18AESIzRFVmd4gAG90IBfANYeQRW2joYGicJIAQKVwf/Qhcc0SZhoi6oSIms0UnVPuMaiFkNHu2pw==\"; ",
    "let decryptedMessage = decryptAES(encryptedMessage, secretKey); ",
    "console.log(decryptedMessage);",
);

const CRYPTOJS_RENAMED: &str = concat!(
    "const jediw = require(\"crypto-js\"); ",
    "function vmmgm(encryptedData, hqlpz) { ",
    "const txfvq = jediw.AES.decrypt(encryptedData, hqlpz); ",
    "return txfvq.toString(jediw.enc.Utf8); } ",
    "let spipm = \"mySecretKey123\"; ",
    "let vbsqh = \"U2FsdGVkX18AESIzRFVmd4gAG90IBfANYeQRW2joYGicJIAQKVwf/Qhcc0SZhoi6oSIms0UnVPuMaiFkNHu2pw==\"; ",
    "let vzwod = vmmgm(vbsqh, spipm); console.log(vzwod);",
);

const ANCHORED_SECRET: &str = "X7qP2mN9vK4sR8tY5wC3fH6jL1zB0dE7uA9iQ";
const CRYPTOJS_ANCHORED_ASSIGNMENT: &str = concat!(
    "const CryptoJS = require(\"crypto-js\"); ",
    "function decryptAES(encryptedData, keyMaterial) { ",
    "const bytes = CryptoJS.AES.decrypt(encryptedData, keyMaterial); ",
    "return bytes.toString(CryptoJS.enc.Utf8); } ",
    "let secretKey = \"mySecretKey123\"; ",
    "let encryptedMessage = \"U2FsdGVkX18AESIzRFVmd7gI6FXxdUdNPWSM65ik+d83V+nCKTW7tVDRu4O8s0pkbE7ruGTUXT/as9OqTMXKMg==\"; ",
    "let api_key = decryptAES(encryptedMessage, secretKey);",
);

fn scanner(config: ScannerConfig) -> CompiledScanner {
    CompiledScanner::compile(keyhog_core::embedded_detector_specs().to_vec())
        .expect("compile embedded detector corpus")
        .with_config(config)
}

fn scan(scanner: &CompiledScanner, source: &str, backend: ScanBackend) -> Vec<RawMatch> {
    let chunk = Chunk {
        data: source.into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("recovery.js".into()),
            ..Default::default()
        },
    };
    scanner
        .scan_chunks_with_backend(&[chunk], backend)
        .into_iter()
        .flatten()
        .collect()
}

fn exact_target_found(matches: &[RawMatch]) -> bool {
    matches.iter().any(|matched| {
        matched.detector_id.as_ref() == "github-classic-pat"
            && matched.credential.as_ref() == SECRET
    })
}

fn credential_found(matches: &[RawMatch], credential: &str) -> bool {
    matches
        .iter()
        .any(|matched| matched.credential.as_ref() == credential)
}

#[test]
fn deep_scan_recovers_every_supported_static_program_shape() {
    let scanner = scanner(ScannerConfig::thorough());
    for source in [
        XOR_LITERAL,
        XOR_HEX_LITERAL,
        XOR_BASE64_ARRAYS,
        AES_BOUND_BUFFERS,
        AES_JOINED_BUFFERS,
        CRYPTOJS_PASSPHRASE,
        CRYPTOJS_RENAMED,
    ] {
        let matches = scan(&scanner, source, ScanBackend::CpuFallback);
        assert!(
            exact_target_found(&matches),
            "deep scan must recover the exact plaintext from {source:?}; got {matches:?}"
        );
    }
}

#[test]
fn cryptojs_recovery_preserves_assignment_anchor_for_unprefixed_secret() {
    let scanner = scanner(ScannerConfig::thorough());
    let matches = scan(
        &scanner,
        CRYPTOJS_ANCHORED_ASSIGNMENT,
        ScanBackend::CpuFallback,
    );
    assert!(
        credential_found(&matches, ANCHORED_SECRET),
        "the retained api_key assignment must detect the recovered unprefixed credential: {matches:?}"
    );
}

#[cfg(feature = "simd")]
#[test]
fn simd_scan_recovers_every_supported_static_program_shape() {
    let scanner = scanner(ScannerConfig::thorough());
    for source in [
        XOR_LITERAL,
        XOR_HEX_LITERAL,
        XOR_BASE64_ARRAYS,
        AES_BOUND_BUFFERS,
        AES_JOINED_BUFFERS,
        CRYPTOJS_PASSPHRASE,
        CRYPTOJS_RENAMED,
        CRYPTOJS_ANCHORED_ASSIGNMENT,
    ] {
        let mut cpu = scan(&scanner, source, ScanBackend::CpuFallback);
        let mut simd = scan(&scanner, source, ScanBackend::SimdCpu);
        cpu.sort();
        simd.sort();
        assert_eq!(
            simd, cpu,
            "SIMD and CPU static recovery must return identical findings for {source:?}"
        );
        assert!(
            exact_target_found(&simd) || credential_found(&simd, ANCHORED_SECRET),
            "SIMD route must preserve the recovered credential"
        );
    }
}

#[cfg(feature = "gpu")]
#[test]
fn cryptojs_static_recovery_has_exact_gpu_cpu_parity() {
    let scanner = scanner(ScannerConfig::thorough());
    for source in [
        CRYPTOJS_PASSPHRASE,
        CRYPTOJS_RENAMED,
        CRYPTOJS_ANCHORED_ASSIGNMENT,
    ] {
        let mut cpu = scan(&scanner, source, ScanBackend::CpuFallback);
        let mut gpu = scan(&scanner, source, ScanBackend::Gpu);
        cpu.sort();
        gpu.sort();
        assert_eq!(gpu, cpu, "CryptoJS recovery must be backend-neutral");
        assert!(
            exact_target_found(&gpu) || credential_found(&gpu, ANCHORED_SECRET),
            "GPU route must preserve the recovered credential"
        );
    }
}

#[test]
fn fast_scan_does_not_run_static_program_recovery() {
    let scanner = scanner(ScannerConfig::fast());
    for source in [XOR_LITERAL, AES_BOUND_BUFFERS, CRYPTOJS_PASSPHRASE] {
        let matches = scan(&scanner, source, ScanBackend::CpuFallback);
        assert!(
            !exact_target_found(&matches),
            "decode-disabled fast mode must not claim static recovery; got {matches:?}"
        );
    }
}

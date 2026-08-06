#![cfg(target_os = "linux")]

use keyhog_scanner::execution_pack::{
    compile_execution_pack, CompileSection, ExecutionPack, ExecutionPackBackend,
    ExecutionPackCompileInput, ExecutionPackIdentity, ExecutionPackPolicy,
    ExecutionPackSectionKind, ExecutionPackSigningKey,
};
use std::fs;
use std::path::Path;

const LARGE_PROGRAM_BYTES: usize = 32 * 1024 * 1024;

fn identity() -> ExecutionPackIdentity {
    ExecutionPackIdentity::new(
        [0x11; 32],
        [0x22; 32],
        [0x33; 32],
        [0x44; 32],
        [0x55; 32],
        [0x66; 32],
        ExecutionPackPolicy::Default,
        ExecutionPackBackend::Cpu,
    )
}

fn mapped_rss_kib(path: &Path) -> u64 {
    let canonical = path.canonicalize().expect("canonical pack path");
    let path = canonical.to_string_lossy();
    let smaps = fs::read_to_string("/proc/self/smaps").expect("read process smaps");
    let mut selected = false;
    let mut rss = 0_u64;
    for line in smaps.lines() {
        if line.contains(path.as_ref()) {
            selected = true;
        } else if selected && line.starts_with("Rss:") {
            rss += line
                .split_whitespace()
                .nth(1)
                .expect("Rss value")
                .parse::<u64>()
                .expect("numeric Rss value");
            selected = false;
        }
    }
    rss
}

/// WHY: authenticating a large native backend program must not leave every pack page resident while decoded scanner state is built; only a section the runtime actually touches may fault back into RSS.
#[test]
fn authenticated_pack_discards_validation_pages_before_lazy_section_access() {
    let backend_program = vec![0xA5; LARGE_PROGRAM_BYTES];
    let sections = [
        CompileSection {
            kind: ExecutionPackSectionKind::DetectorIr,
            alignment: 8,
            bytes: b"detector-ir",
        },
        CompileSection {
            kind: ExecutionPackSectionKind::LiteralIndex,
            alignment: 64,
            bytes: b"literal-index",
        },
        CompileSection {
            kind: ExecutionPackSectionKind::RegexPrograms,
            alignment: 64,
            bytes: b"regex-programs",
        },
        CompileSection {
            kind: ExecutionPackSectionKind::SuppressionPolicy,
            alignment: 8,
            bytes: b"suppression-policy",
        },
        CompileSection {
            kind: ExecutionPackSectionKind::BackendProgram,
            alignment: 4096,
            bytes: &backend_program,
        },
    ];
    let compiled = compile_execution_pack(ExecutionPackCompileInput {
        identity: identity(),
        sections: &sections,
    })
    .expect("compile large pack");
    let signing_key = ExecutionPackSigningKey::from_bytes([0x5A; 32]).expect("signing key");
    let signature = signing_key.sign(&compiled);
    let directory = tempfile::tempdir().expect("temporary pack directory");
    let pack_path = directory.path().join("large.khpack");
    let signature_path = directory.path().join("large.sig");
    fs::write(&pack_path, compiled.as_bytes()).expect("write pack");
    fs::write(
        &signature_path,
        signature.canonical_bytes().expect("encode signature"),
    )
    .expect("write signature");
    drop(compiled);
    drop(backend_program);

    let pack = ExecutionPack::open_authenticated(
        &pack_path,
        &signature_path,
        identity(),
        &signing_key,
    )
    .expect("open authenticated pack");
    let rss_after_auth = mapped_rss_kib(&pack_path);
    assert!(
        rss_after_auth < 2 * 1024,
        "authentication retained {rss_after_auth} KiB of a {LARGE_PROGRAM_BYTES}-byte pack"
    );

    let detector_ir = pack
        .section(ExecutionPackSectionKind::DetectorIr)
        .expect("detector IR section");
    std::hint::black_box(detector_ir[0]);
    let rss_after_small_section = mapped_rss_kib(&pack_path);
    assert!(
        rss_after_small_section < 2 * 1024,
        "one small section fault retained {rss_after_small_section} KiB"
    );

    let program = pack
        .section(ExecutionPackSectionKind::BackendProgram)
        .expect("backend program section");
    let checksum = program
        .chunks(4096)
        .fold(0_u64, |sum, page| sum.wrapping_add(u64::from(page[0])));
    std::hint::black_box(checksum);
    let rss_after_program = mapped_rss_kib(&pack_path);
    assert!(
        rss_after_program > (LARGE_PROGRAM_BYTES as u64 / 1024) / 2,
        "control walk faulted only {rss_after_program} KiB, so the RSS probe did not observe mapped pages"
    );
}

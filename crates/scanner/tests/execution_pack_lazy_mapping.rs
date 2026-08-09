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

fn mapped_metric_kib(path: &Path, metric: &str) -> u64 {
    let canonical = path.canonicalize().expect("canonical pack path");
    let path = canonical.to_string_lossy();
    let smaps = fs::read_to_string("/proc/self/smaps").expect("read process smaps");
    let mut selected = false;
    let mut total = 0_u64;
    for line in smaps.lines() {
        if line.contains(path.as_ref()) {
            selected = true;
        } else if selected && line.starts_with(metric) {
            total += line
                .split_whitespace()
                .nth(1)
                .expect("smaps metric value")
                .parse::<u64>()
                .expect("numeric smaps metric value");
            selected = false;
        }
    }
    total
}

fn mapped_rss_kib(path: &Path) -> u64 {
    mapped_metric_kib(path, "Rss:")
}

fn authenticated_pack(
    backend_program: &[u8],
    stem: &str,
) -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    ExecutionPackSigningKey,
) {
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
            bytes: backend_program,
        },
        CompileSection {
            kind: ExecutionPackSectionKind::DetectorPlan,
            alignment: 8,
            bytes: b"detector-plan",
        },
    ];
    let compiled = compile_execution_pack(ExecutionPackCompileInput {
        identity: identity(),
        sections: &sections,
    })
    .expect("compile execution pack");
    let signing_key = ExecutionPackSigningKey::from_bytes([0x5A; 32]).expect("signing key");
    let signature = signing_key.sign(&compiled);
    let directory = tempfile::tempdir().expect("temporary pack directory");
    let pack_path = directory.path().join(format!("{stem}.khpack"));
    let signature_path = directory.path().join(format!("{stem}.sig"));
    fs::write(&pack_path, compiled.as_bytes()).expect("write pack");
    fs::write(
        &signature_path,
        signature.canonical_bytes().expect("encode signature"),
    )
    .expect("write signature");
    (directory, pack_path, signature_path, signing_key)
}

fn large_authenticated_pack() -> (
    tempfile::TempDir,
    std::path::PathBuf,
    std::path::PathBuf,
    ExecutionPackSigningKey,
) {
    authenticated_pack(&vec![0xA5; LARGE_PROGRAM_BYTES], "large")
}

/// WHY: whole-pack release owns the trailing partial page; routing it through the
/// interior-slice trimmer leaves that page resident and retains every tiny pack.
#[test]
fn authenticated_pack_discards_trailing_partial_page() {
    let (_directory, pack_path, signature_path, signing_key) =
        authenticated_pack(b"backend-program", "partial-page");
    let page = usize::try_from(unsafe { libc::sysconf(libc::_SC_PAGESIZE) })
        .expect("positive host page size");
    let pack_len = usize::try_from(fs::metadata(&pack_path).expect("pack metadata").len())
        .expect("pack length fits usize");
    assert_ne!(
        pack_len % page,
        0,
        "control pack must end in a partial page"
    );

    let pack =
        ExecutionPack::open_authenticated(&pack_path, &signature_path, identity(), &signing_key)
            .expect("open authenticated pack");
    std::hint::black_box(&pack);
    assert_eq!(
        mapped_rss_kib(&pack_path),
        0,
        "authenticated whole-pack release must discard its trailing partial page"
    );
}

/// WHY: authenticating a large native backend program must not leave every pack page resident while decoded scanner state is built; only a section the runtime actually touches may fault back into RSS.
#[test]
fn authenticated_pack_discards_validation_pages_before_lazy_section_access() {
    let (_directory, pack_path, signature_path, signing_key) = large_authenticated_pack();

    let pack =
        ExecutionPack::open_authenticated(&pack_path, &signature_path, identity(), &signing_key)
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

/// WHY: separate KeyHog processes must charge one physical copy of immutable execution-pack pages; private heap hydration for the same serialized program multiplies fleet memory by process count.
#[test]
fn faulted_execution_pack_pages_are_shared_across_processes() {
    let (_directory, pack_path, signature_path, signing_key) = large_authenticated_pack();
    let pack =
        ExecutionPack::open_authenticated(&pack_path, &signature_path, identity(), &signing_key)
            .expect("open authenticated pack");
    let program = pack
        .section(ExecutionPackSectionKind::BackendProgram)
        .expect("backend program section");
    let pointer = program.as_ptr();
    let length = program.len();
    let mut child_ready = [0; 2];
    let mut child_release = [0; 2];
    assert_eq!(unsafe { libc::pipe(child_ready.as_mut_ptr()) }, 0);
    assert_eq!(unsafe { libc::pipe(child_release.as_mut_ptr()) }, 0);

    let child = unsafe { libc::fork() };
    assert!(
        child >= 0,
        "fork failed: {}",
        std::io::Error::last_os_error()
    );
    if child == 0 {
        unsafe {
            libc::close(child_ready[0]);
            libc::close(child_release[1]);
            let mut checksum = 0_u8;
            let mut offset = 0;
            while offset < length {
                checksum ^= std::ptr::read_volatile(pointer.add(offset));
                offset += 4096;
            }
            let ready = [checksum];
            if libc::write(child_ready[1], ready.as_ptr().cast(), 1) != 1 {
                libc::_exit(120);
            }
            let mut release = [0_u8];
            if libc::read(child_release[0], release.as_mut_ptr().cast(), 1) != 1 {
                libc::_exit(121);
            }
            libc::_exit(0);
        }
    }

    unsafe {
        libc::close(child_ready[1]);
        libc::close(child_release[0]);
    }
    let mut ready = [0_u8];
    assert_eq!(
        unsafe { libc::read(child_ready[0], ready.as_mut_ptr().cast(), 1) },
        1
    );
    let checksum = program
        .chunks(4096)
        .fold(0_u64, |sum, page| sum.wrapping_add(u64::from(page[0])));
    std::hint::black_box(checksum);
    let rss = mapped_metric_kib(&pack_path, "Rss:");
    let pss = mapped_metric_kib(&pack_path, "Pss:");
    assert!(
        rss > (LARGE_PROGRAM_BYTES as u64 / 1024) / 2,
        "parent faulted only {rss} KiB of the {LARGE_PROGRAM_BYTES}-byte pack"
    );
    assert!(
        pss < rss * 3 / 4,
        "pack PSS {pss} KiB is not shared across processes relative to {rss} KiB RSS"
    );
    assert_eq!(
        unsafe { libc::write(child_release[1], [1_u8].as_ptr().cast(), 1) },
        1
    );
    let mut status = 0;
    assert_eq!(unsafe { libc::waitpid(child, &mut status, 0) }, child);
    assert_eq!(status, 0, "child exited with wait status {status}");
    unsafe {
        libc::close(child_ready[0]);
        libc::close(child_release[1]);
    }
}

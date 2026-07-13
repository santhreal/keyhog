//! The archive-within-archive recursion cap must be ONE shared depth for every
//! container family.
//!
//! Tar, zip, and compressed-member extraction each used to hard-code their own
//! `MAX_*_DEPTH = 8`. Three independent copies of the same security constant are
//! a drift hazard: bump one (say to descend deeper into tar) and a zip nested in
//! a tar would refuse at a *different* depth than a tar nested in a tar, so the
//! partial-coverage drop would land at an inconsistent place across families.
//! The cap is now the single `MAX_NESTED_ARCHIVE_DEPTH` in `extract.rs`.
//!
//! This proves the contract behaviorally: an over-deep all-tar chain and an
//! over-deep all-zip chain BOTH fail closed with the depth-exceeded coverage
//! error naming the SAME canonical depth (8), and neither reaches the secret
//! buried below the cap. If the families ever drift back to separate constants,
//! the two messages stop agreeing and this test goes red.

use crate::support::split_chunk_results;
use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::io::{Cursor, Write};

/// The canonical cap mirrored from `extract.rs::MAX_NESTED_ARCHIVE_DEPTH`. The
/// assertions below check the error text references THIS exact number, so a
/// silent change to the real constant (without updating every family) is caught.
const EXPECTED_CAP: usize = 8;

/// Wrap `inner_bytes` as the sole entry of a new in-memory tar, named so the
/// extractor recognizes it as an embedded tar to recurse into.
fn wrap_in_tar(entry_name: &str, inner_bytes: &[u8]) -> Vec<u8> {
    let mut builder = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(inner_bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    builder
        .append_data(&mut header, entry_name, inner_bytes)
        .unwrap();
    builder.into_inner().unwrap()
}

/// Wrap `inner_bytes` as the sole STORED entry of a new in-memory zip.
fn wrap_in_zip(entry_name: &str, inner_bytes: &[u8]) -> Vec<u8> {
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    let options =
        zip::write::SimpleFileOptions::default().compression_method(zip::CompressionMethod::Stored);
    zip.start_file(entry_name, options).unwrap();
    zip.write_all(inner_bytes).unwrap();
    zip.finish().unwrap().into_inner()
}

/// Build a chain of `levels` nested archives around `secret`, each layer wrapped
/// by `wrap`, and return the outermost container bytes. `levels` is chosen well
/// past `EXPECTED_CAP` so the innermost secret sits below the depth cap.
fn build_over_deep_chain(
    levels: usize,
    inner_entry: &str,
    secret: &[u8],
    wrap: impl Fn(&str, &[u8]) -> Vec<u8>,
) -> Vec<u8> {
    // Innermost: a plain `.env` carrying the secret, wrapped once.
    let mut bytes = wrap("secret.env", secret);
    for _ in 1..levels {
        bytes = wrap(inner_entry, &bytes);
    }
    bytes
}

fn scan_outer(file_name: &str, outer_bytes: &[u8]) -> (Vec<String>, Vec<String>) {
    let dir = tempfile::tempdir().unwrap();
    std::fs::write(dir.path().join(file_name), outer_bytes).unwrap();
    let source = FilesystemSource::new(dir.path().to_path_buf());
    let rows: Vec<_> = source.chunks().collect();
    let (chunks, errors) = split_chunk_results(&rows);
    let bodies: Vec<String> = chunks.iter().map(|c| c.data.to_string()).collect();
    let error_texts: Vec<String> = errors.iter().map(|e| e.to_string()).collect();
    (bodies, error_texts)
}

#[test]
fn tar_chain_refuses_at_the_canonical_depth_and_never_reaches_the_secret() {
    // A secret token unique to this family so a cross-test leak can't satisfy it.
    let secret = b"GITHUB_TOKEN=ghp_tarDepthCapTokenAAAAAAAAAAAAAAAAAA00\n";
    // 12 levels > the cap (8); the secret is at level 12, well below the refusal.
    let outer = build_over_deep_chain(12, "inner.tar", secret, wrap_in_tar);

    let (bodies, errors) = scan_outer("deep.tar", &outer);

    let depth_error = errors
        .iter()
        .find(|e| e.contains("maximum nested archive depth") && e.contains("exceeded"));
    assert!(
        depth_error.is_some(),
        "over-deep tar chain must surface a depth-exceeded coverage error; got errors {errors:?}"
    );
    assert!(
        depth_error.unwrap().contains(&EXPECTED_CAP.to_string()),
        "tar depth-exceeded error must name the canonical cap {EXPECTED_CAP}; got {:?}",
        depth_error.unwrap()
    );
    assert!(
        !bodies.iter().any(|b| b.contains(concat!("gh", "p_tarDepthCapTokenAAAAAAAAAAAAAAAAAA00"))),
        "the secret buried below the depth cap must NOT be scanned (cap was bypassed); got {bodies:?}"
    );
}

#[test]
fn zip_chain_refuses_at_the_canonical_depth_and_never_reaches_the_secret() {
    let secret = b"GITHUB_TOKEN=ghp_zipDepthCapTokenBBBBBBBBBBBBBBBBBB00\n";
    let outer = build_over_deep_chain(12, "inner.zip", secret, wrap_in_zip);

    let (bodies, errors) = scan_outer("deep.zip", &outer);

    let depth_error = errors
        .iter()
        .find(|e| e.contains("maximum nested archive depth") && e.contains("exceeded"));
    assert!(
        depth_error.is_some(),
        "over-deep zip chain must surface a depth-exceeded coverage error; got errors {errors:?}"
    );
    assert!(
        depth_error.unwrap().contains(&EXPECTED_CAP.to_string()),
        "zip depth-exceeded error must name the canonical cap {EXPECTED_CAP}; got {:?}",
        depth_error.unwrap()
    );
    assert!(
        !bodies.iter().any(|b| b.contains(concat!("gh", "p_zipDepthCapTokenBBBBBBBBBBBBBBBBBB00"))),
        "the secret buried below the depth cap must NOT be scanned (cap was bypassed); got {bodies:?}"
    );
}

#[test]
fn tar_and_zip_families_refuse_at_the_same_depth() {
    // The whole point of the unification: both families cite the identical cap.
    // Extract the integer each family reports and assert they are equal, this is
    // what regresses the instant someone reintroduces a per-family constant.
    let tar_secret = b"GITHUB_TOKEN=ghp_tarParityTokenCCCCCCCCCCCCCCCCCC00\n";
    let zip_secret = b"GITHUB_TOKEN=ghp_zipParityTokenDDDDDDDDDDDDDDDDDD00\n";
    let tar_outer = build_over_deep_chain(12, "inner.tar", tar_secret, wrap_in_tar);
    let zip_outer = build_over_deep_chain(12, "inner.zip", zip_secret, wrap_in_zip);

    let (_, tar_errors) = scan_outer("deep.tar", &tar_outer);
    let (_, zip_errors) = scan_outer("deep.zip", &zip_outer);

    let tar_depth =
        extract_reported_depth(&tar_errors).expect("tar chain must report a depth-exceeded error");
    let zip_depth =
        extract_reported_depth(&zip_errors).expect("zip chain must report a depth-exceeded error");
    assert_eq!(
        tar_depth, zip_depth,
        "tar and zip must refuse at the SAME nesting depth (one shared constant); \
         tar reported {tar_depth}, zip reported {zip_depth}"
    );
    assert_eq!(
        tar_depth, EXPECTED_CAP,
        "the shared cap must be the canonical {EXPECTED_CAP}; got {tar_depth}"
    );
}

/// Pull the integer out of "...maximum nested archive depth N exceeded...".
fn extract_reported_depth(errors: &[String]) -> Option<usize> {
    let marker = "maximum nested archive depth ";
    for error in errors {
        if let Some(start) = error.find(marker) {
            let rest = &error[start + marker.len()..];
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(value) = digits.parse::<usize>() {
                return Some(value);
            }
        }
    }
    None
}

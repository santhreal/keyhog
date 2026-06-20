//! R5-T archive adversarial: nested tar respects extraction budget.

use super::support::collect_chunks;
use keyhog_sources::FilesystemSource;

#[test]
fn r5t_nested_tar_two_levels_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut inner = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_path("inner.env").expect("path");
    header.set_size(20);
    header.set_cksum();
    inner
        .append(&header, &b"TAIL=SHOULDNOTAPPEAR\n"[..])
        .expect("append");
    let inner_bytes = inner.into_inner().expect("inner tar");
    let mut outer = tar::Builder::new(Vec::new());
    let mut outer_header = tar::Header::new_gnu();
    outer_header.set_path("nested.tar").expect("path");
    outer_header.set_size(inner_bytes.len() as u64);
    outer_header.set_cksum();
    outer
        .append(&outer_header, &inner_bytes[..])
        .expect("append outer");
    std::fs::write(
        dir.path().join("nested.tar"),
        outer.into_inner().expect("outer"),
    )
    .expect("write");
    let bodies: Vec<String> =
        collect_chunks(&FilesystemSource::new(dir.path().to_path_buf()).with_max_file_size(64))
            .into_iter()
            .map(|c| c.data.to_string())
            .collect();
    assert!(
        !bodies.iter().any(|b| b.contains("SHOULDNOTAPPEAR")),
        "nested tar budget must block; got {bodies:?}"
    );
}

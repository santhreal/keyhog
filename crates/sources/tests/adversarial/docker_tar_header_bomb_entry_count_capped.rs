//! A docker layer built purely from zero-length tar entries must be refused by
//! the entry-COUNT cap.
//!
//! The `docker_tar_total_bytes` bomb guard sums each entry's `entry_size`, so a
//! directory / zero-length entry adds 0 to it on every iteration and the byte
//! guard never fires no matter how many entries arrive. Layers are gzip/zstd
//! streams, so a ~4 MB gzip expands into millions of tar headers (~229x), and
//! each surviving entry costs a filesystem syscall during unpack. Without a
//! count cap that is inode exhaustion and an effective hang from a tiny input.

#[cfg(feature = "docker")]
use keyhog_sources::testing::{SourceTestApi, TestApi};

/// One past `MAX_DOCKER_TAR_ENTRIES` in `src/docker/archive.rs`.
#[cfg(feature = "docker")]
const OVER_CAP_ENTRIES: usize = 500_001;

#[cfg(feature = "docker")]
#[test]
fn docker_tar_header_bomb_entry_count_capped() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layer_path = dir.path().join("layer.tar.gz");
    let destination = dir.path().join("out");
    std::fs::create_dir(&destination).expect("create destination");

    // Zero-length directory entries: every one contributes 0 to the cumulative
    // byte budget, so only a count cap can stop this.
    let file = std::fs::File::create(&layer_path).expect("create layer");
    let encoder = flate2::write::GzEncoder::new(file, flate2::Compression::default());
    let mut builder = tar::Builder::new(encoder);
    let mut header = tar::Header::new_gnu();
    header.set_path("d").expect("set path");
    header.set_size(0);
    header.set_entry_type(tar::EntryType::Directory);
    header.set_cksum();
    for _ in 0..OVER_CAP_ENTRIES {
        builder.append(&header, std::io::empty()).expect("append");
    }
    builder.finish().expect("finish tar");
    drop(builder);

    let error = TestApi
        .unpack_docker_layer_archive(&layer_path, &destination)
        .expect_err("a tar-header bomb must be refused, not walked to completion");

    let message = error.to_string();
    assert!(
        message.contains("entry cap") && message.contains("not scanned"),
        "the refusal must name the entry cap and the coverage gap, got {message:?}"
    );

    assert_eq!(
        std::fs::read_dir(&destination)
            .expect("read destination")
            .count(),
        0,
        "the bomb must be refused during validation, before anything is written to disk"
    );
}

/// A layer whose entry count sits under the cap still unpacks normally, so the
/// guard cannot be satisfied by refusing everything.
#[cfg(feature = "docker")]
#[test]
fn docker_tar_under_entry_cap_still_unpacks() {
    let dir = tempfile::tempdir().expect("tempdir");
    let layer_path = dir.path().join("layer.tar");
    let destination = dir.path().join("out");
    std::fs::create_dir(&destination).expect("create destination");

    let file = std::fs::File::create(&layer_path).expect("create layer");
    let mut builder = tar::Builder::new(file);
    let payload = b"AKIAIOSFODNN7EXAMPLE";
    let mut header = tar::Header::new_gnu();
    header.set_path("app/config.env").expect("set path");
    header.set_size(payload.len() as u64);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append(&header, payload.as_slice())
        .expect("append");
    builder.finish().expect("finish tar");

    TestApi
        .unpack_docker_layer_archive(&layer_path, &destination)
        .expect("a normal layer must still unpack");

    assert_eq!(
        std::fs::read(destination.join("app/config.env")).expect("unpacked file"),
        payload,
        "an under-cap layer must unpack its entries unchanged"
    );
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_tar_header_bomb_requires_docker_feature() {
    assert!(!cfg!(feature = "docker"));
}

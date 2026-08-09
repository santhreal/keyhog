//! Docker layer hard links must be ignored without resolving host paths.

#[cfg(feature = "docker")]
use keyhog_sources::testing::TestApi;

/// A real image hard link must not abort the layer or create an alias to data outside the extracted tree.
#[cfg(feature = "docker")]
#[test]
fn docker_tar_hardlink_entry_is_safely_ignored() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tar_path = dir.path().join("layer.tar");
    let file = std::fs::File::create(&tar_path).expect("create tar");
    let mut builder = tar::Builder::new(file);
    let mut header = tar::Header::new_gnu();
    header.set_path("usr/bin/tool").expect("set path");
    header.set_entry_type(tar::EntryType::Link);
    header.set_link_name("../../outside").expect("link");
    header.set_size(0);
    header.set_cksum();
    builder.append(&header, &[] as &[u8]).expect("append");
    builder.finish().expect("finish tar");
    let destination = dir.path().join("unpacked");
    std::fs::create_dir(&destination).expect("create destination");

    let errors = TestApi
        .unpack_docker_layer_archive(&tar_path, &destination)
        .expect("safe hard-link skip");

    assert!(errors.is_empty());
    assert!(!destination.join("usr/bin/tool").exists());
}

/// A build without Docker keeps the feature-gated adversarial test inert.
#[cfg(not(feature = "docker"))]
#[test]
fn docker_tar_hardlink_entry_is_safely_ignored() {
    assert!(!cfg!(feature = "docker"));
}

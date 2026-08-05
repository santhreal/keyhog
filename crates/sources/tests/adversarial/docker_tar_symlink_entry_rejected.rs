//! Docker layer symlinks must be ignored without following host targets.

#[cfg(feature = "docker")]
use keyhog_sources::testing::{TestApi};

/// A real image symlink must not abort the layer, materialize the link, or expose its absolute host target.
#[cfg(feature = "docker")]
#[test]
fn docker_tar_symlink_entry_is_safely_ignored() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tar_path = dir.path().join("layer.tar");
    let file = std::fs::File::create(&tar_path).expect("create tar");
    let mut builder = tar::Builder::new(file);
    let mut header = tar::Header::new_gnu();
    header.set_path("bin/arch").expect("set path");
    header.set_entry_type(tar::EntryType::Symlink);
    header.set_link_name("/etc/passwd").expect("link");
    header.set_size(0);
    header.set_cksum();
    builder.append(&header, &[] as &[u8]).expect("append");
    builder.finish().expect("finish tar");
    let destination = dir.path().join("unpacked");
    std::fs::create_dir(&destination).expect("create destination");

    let errors = TestApi
        .unpack_docker_layer_archive(&tar_path, &destination)
        .expect("safe symlink skip");

    assert!(errors.is_empty());
    assert!(!destination.join("bin/arch").exists());
}

/// A build without Docker keeps the feature-gated adversarial test inert.
#[cfg(not(feature = "docker"))]
#[test]
fn docker_tar_symlink_entry_is_safely_ignored() {
    assert!(!cfg!(feature = "docker"));
}

//! Many small docker tar entries must trip aggregate zip-bomb cap.

#[cfg(feature = "docker")]
#[test]
fn docker_tar_aggregate_many_entries_rejected() {
    let dir = tempfile::tempdir().expect("tempdir");
    let tar_path = dir.path().join("many.tar");
    let file = std::fs::File::create(&tar_path).expect("create tar");
    let mut builder = tar::Builder::new(file);
    for i in 0..5 {
        let payload = vec![b'Q'; 300];
        let mut header = tar::Header::new_gnu();
        header.set_path(format!("part{i}.bin")).expect("set path");
        header.set_size(300);
        header.set_entry_type(tar::EntryType::Regular);
        header.set_cksum();
        builder.append(&header, payload.as_slice()).expect("append");
    }
    builder.finish().expect("finish tar");

    let err = keyhog_sources::testing::validate_docker_tar_archive_with_total_cap(&tar_path, 1_000)
        .unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("cumulative size exceeds") && msg.contains("zip-bomb"), "got {msg:?}");
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_tar_aggregate_many_entries_rejected() {
    assert!(!cfg!(feature = "docker"));
}

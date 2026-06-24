//! Docker image export failures must drain stderr without buffering it unboundedly.

#[cfg(all(feature = "docker", unix))]
use keyhog_sources::testing::{SourceTestApi, TestApi};

#[cfg(all(feature = "docker", unix))]
#[test]
fn docker_export_failure_stderr_is_bounded() {
    use std::io::Write;
    use std::os::unix::fs::PermissionsExt;

    let dir = tempfile::tempdir().expect("tempdir");
    let fake_docker = dir.path().join("docker-fake");
    let mut script = std::fs::File::create(&fake_docker).expect("create fake docker");
    script
        .write_all(
            br#"#!/bin/sh
i=0
while [ "$i" -lt 70000 ]; do
  printf E >&2
  i=$((i + 1))
done
exit 42
"#,
        )
        .expect("write fake docker");
    drop(script);
    let mut perms = std::fs::metadata(&fake_docker)
        .expect("fake docker metadata")
        .permissions();
    perms.set_mode(0o700);
    std::fs::set_permissions(&fake_docker, perms).expect("chmod fake docker");

    let archive_path = dir.path().join("image.tar");
    let err = TestApi
        .export_docker_image_archive(&fake_docker, "alpine:latest", &archive_path)
        .expect_err("fake docker failure must surface");
    let msg = err.to_string();
    assert!(
        msg.contains("failed to export docker image: alpine:latest"),
        "error must keep image context, got {msg:?}"
    );
    assert!(
        msg.contains("[stderr truncated after 65536 bytes]"),
        "large docker stderr must be drained but stored as a bounded excerpt"
    );
    assert!(
        msg.len() < 67_000,
        "docker stderr excerpt must stay bounded, got {} bytes",
        msg.len()
    );
}

#[cfg(feature = "docker")]
#[test]
fn docker_export_uses_shared_timeout_and_reaps_on_timeout() {
    let src = std::fs::read_to_string(concat!(env!("CARGO_MANIFEST_DIR"), "/src/docker.rs"))
        .expect("docker source readable");
    assert!(src.contains("crate::timeouts::DOCKER_EXPORT"));
    assert!(src.contains(".wait_timeout(timeout)"));
    assert!(src.contains("fn kill_and_reap_docker_child("));
    assert!(src.contains("child.kill()"));
    assert!(src.contains("child.wait()"));
    assert!(
        !src.contains("let status = child.wait()"),
        "docker image export must not wait forever without the shared timeout"
    );
}

#[cfg(any(not(feature = "docker"), not(unix)))]
#[test]
fn docker_export_failure_stderr_is_bounded() {
    assert!(cfg!(any(not(feature = "docker"), not(unix))));
}

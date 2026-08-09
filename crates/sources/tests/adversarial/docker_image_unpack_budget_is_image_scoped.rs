//! `docker_tar_total_bytes` must bound the whole IMAGE, not each tar in it.
//!
//! The cap was enforced with a fresh accumulator per tar, so every layer got a
//! full allowance and nothing bounded their sum. Docker permits 127 layers, so
//! the 8 GiB default admitted roughly 1 TiB of unpacking per image while every
//! individual check passed and the operator had no knob that said otherwise.

#[cfg(feature = "docker")]
use keyhog_sources::testing::TestApi;

/// Build a layer tar holding one regular entry of exactly `payload_len` bytes.
#[cfg(feature = "docker")]
fn layer_tar(dir: &std::path::Path, name: &str, payload_len: usize) -> std::path::PathBuf {
    let path = dir.join(name);
    let file = std::fs::File::create(&path).expect("create layer tar");
    let mut builder = tar::Builder::new(file);
    let payload = vec![b'Q'; payload_len];
    let mut header = tar::Header::new_gnu();
    header.set_path("payload.bin").expect("set path");
    header.set_size(payload_len as u64);
    header.set_entry_type(tar::EntryType::Regular);
    header.set_cksum();
    builder
        .append(&header, payload.as_slice())
        .expect("append payload");
    builder.finish().expect("finish tar");
    path
}

#[cfg(feature = "docker")]
#[test]
fn docker_layer_tars_share_one_image_wide_unpack_budget() {
    let dir = tempfile::tempdir().expect("tempdir");
    const PAYLOAD: usize = 4096;

    let first = layer_tar(dir.path(), "layer1.tar", PAYLOAD);
    let second = layer_tar(dir.path(), "layer2.tar", PAYLOAD);
    let out_first = dir.path().join("out1");
    let out_second = dir.path().join("out2");
    std::fs::create_dir(&out_first).expect("create out1");
    std::fs::create_dir(&out_second).expect("create out2");

    // A budget big enough for ONE layer but not for both. Per-tar accounting
    // admitted both because each tar restarted the count at zero.
    let cap = (PAYLOAD as u64) + 512;

    let error = TestApi
        .unpack_docker_layers_with_shared_budget(
            &[
                (first.as_path(), out_first.as_path()),
                (second.as_path(), out_second.as_path()),
            ],
            cap,
        )
        .expect_err("the second layer must exhaust the image-wide budget");

    let message = error.to_string();
    assert!(
        message.contains("not scanned") || message.contains("zip-bomb"),
        "exhausting the image budget must surface a coverage gap, got {message:?}"
    );
    assert!(
        std::fs::read_dir(&out_first)
            .expect("read out1")
            .next()
            .is_some(),
        "the first layer must still unpack; only the layer that overruns the image budget is refused"
    );
}

/// A budget that comfortably covers every layer must let the whole image
/// through, so the guard cannot be satisfied by refusing multi-layer images.
#[cfg(feature = "docker")]
#[test]
fn docker_multi_layer_image_within_budget_still_unpacks() {
    let dir = tempfile::tempdir().expect("tempdir");
    const PAYLOAD: usize = 4096;

    let first = layer_tar(dir.path(), "layer1.tar", PAYLOAD);
    let second = layer_tar(dir.path(), "layer2.tar", PAYLOAD);
    let out_first = dir.path().join("out1");
    let out_second = dir.path().join("out2");
    std::fs::create_dir(&out_first).expect("create out1");
    std::fs::create_dir(&out_second).expect("create out2");

    let errors = TestApi
        .unpack_docker_layers_with_shared_budget(
            &[
                (first.as_path(), out_first.as_path()),
                (second.as_path(), out_second.as_path()),
            ],
            (PAYLOAD as u64) * 8,
        )
        .expect("an image inside its budget must unpack every layer");

    assert!(errors.is_empty(), "unexpected error rows: {errors:?}");
    for out in [&out_first, &out_second] {
        assert_eq!(
            std::fs::read(out.join("payload.bin"))
                .expect("unpacked payload")
                .len(),
            PAYLOAD,
            "every layer inside the image budget must unpack unchanged"
        );
    }
}

#[cfg(not(feature = "docker"))]
#[test]
fn docker_image_unpack_budget_requires_docker_feature() {
    assert!(!cfg!(feature = "docker"));
}

use std::{path::PathBuf, process::Command};

fn binary() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_keyhog"))
}

#[test]
fn zip64_duplicate_scan_gap_is_visible_to_operator() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("z64.zip");
    std::fs::write(&path, zip_with_zip64_eocd_sentinel("safe.txt", b"SAFE=1\n"))
        .expect("write zip64-sentinel archive");
    std::fs::write(dir.path().join("sibling.txt"), "SAFE_SIBLING=1\n")
        .expect("write sibling source");

    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--daemon=off",
            "--progress",
            "--format",
            "json",
        ])
        .arg(dir.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("spawn keyhog");

    assert!(
        output.status.success(),
        "zip64 duplicate-detection degrade with a readable sibling should complete; status={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("archive(s) scanned WITHOUT duplicate-entry detection"),
        "operator summary must name the duplicate-entry coverage gap; stderr={stderr}"
    );
    assert!(
        stderr.contains("duplicated/shadow entry hiding a secret may have been missed"),
        "summary must describe the evasion risk, not only a counter name; stderr={stderr}"
    );
}

#[test]
fn zip64_duplicate_scan_gap_is_visible_in_sarif_notifications() {
    let dir = tempfile::tempdir().expect("tempdir");
    let path = dir.path().join("z64.zip");
    std::fs::write(&path, zip_with_zip64_eocd_sentinel("safe.txt", b"SAFE=1\n"))
        .expect("write zip64-sentinel archive");
    std::fs::write(dir.path().join("sibling.txt"), "SAFE_SIBLING=1\n")
        .expect("write sibling source");

    let output = Command::new(binary())
        .args([
            "scan",
            "--backend",
            "simd",
            "--daemon=off",
            "--format",
            "sarif",
        ])
        .arg(dir.path())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .output()
        .expect("spawn keyhog");

    assert!(
        output.status.success(),
        "zip64 duplicate-detection degrade with a readable sibling should complete; status={:?} stderr={}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );

    let sarif: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("SARIF stdout must be JSON");
    let notifications = sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"]
        .as_array()
        .expect("duplicate-scan coverage gap must create SARIF notifications");
    assert!(
        notifications.iter().any(|notification| {
            notification["properties"]["reason"].as_str()
                == Some(
                    "archive duplicate-entry detection unavailable (zip64 or malformed central directory; shadow entries may be missed)",
                )
                && notification["properties"]["count"].as_u64() == Some(1)
        }),
        "SARIF notifications must include the duplicate-entry detection gap; sarif={sarif}"
    );
}

fn zip_with_zip64_eocd_sentinel(name: &str, data: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let name_bytes = name.as_bytes();
    let size = u32::try_from(data.len()).expect("small data");
    let name_len = u16::try_from(name_bytes.len()).expect("short name");
    let crc = crc32(data);

    let local_offset = u32::try_from(out.len()).expect("small offset");
    write_u32(&mut out, 0x0403_4b50);
    write_u16(&mut out, 20);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u32(&mut out, crc);
    write_u32(&mut out, size);
    write_u32(&mut out, size);
    write_u16(&mut out, name_len);
    write_u16(&mut out, 0);
    out.extend_from_slice(name_bytes);
    out.extend_from_slice(data);

    let central_offset = u32::try_from(out.len()).expect("small offset");
    write_u32(&mut out, 0x0201_4b50);
    write_u16(&mut out, 20);
    write_u16(&mut out, 20);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u32(&mut out, crc);
    write_u32(&mut out, size);
    write_u32(&mut out, size);
    write_u16(&mut out, name_len);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u32(&mut out, 0);
    write_u32(&mut out, local_offset);
    out.extend_from_slice(name_bytes);

    let central_size = u32::try_from(out.len())
        .expect("small zip")
        .checked_sub(central_offset)
        .expect("central size");

    write_u32(&mut out, 0x0605_4b50);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0);
    write_u16(&mut out, 0xFFFF);
    write_u16(&mut out, 0xFFFF);
    write_u32(&mut out, central_size);
    write_u32(&mut out, central_offset);
    write_u16(&mut out, 0);
    out
}

fn write_u16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn write_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xffff_ffffu32;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    !crc
}

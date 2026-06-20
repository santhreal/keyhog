//! M17 regression: the `.har` content path must honor the same
//! no-follow-symlink guard every other filesystem read uses.
//!
//! Before the fix the HAR branch read the file with symlink-following
//! `std::fs::read`. Via an explicit `--include` entry naming a `.har`
//! symlink (include paths are admitted with `Path::is_file()`, which
//! follows links), keyhog could be steered to read a sensitive target
//! (e.g. `creds.har -> ~/.aws/credentials`) and emit its bytes as
//! chunks - the exact link-swap class the archive branch's guard was
//! added to defend. The fix routes the HAR read through
//! `read_file_safe` -> `open_file_safe` (`O_NOFOLLOW` on Unix), so the
//! symlink target is never read.
//!
//! Observable through the public `Source::chunks()` API: the secret
//! sitting in the symlink target must NOT appear in any emitted chunk.

#![cfg(unix)]

use keyhog_core::Source;
use keyhog_sources::FilesystemSource;
use std::fs;
use std::os::unix::fs::symlink;

/// A real-looking HAR document whose request body carries a sentinel
/// "secret". If the no-follow guard were bypassed, this string would be
/// expanded into a HAR chunk and surface in the scan output.
const HAR_WITH_SECRET: &str = r#"{
  "log": {
    "version": "1.2",
    "creator": { "name": "test", "version": "1.0" },
    "entries": [
      {
        "request": {
          "method": "POST",
          "url": "https://api.example.com/v1/login",
          "httpVersion": "HTTP/1.1",
          "headers": [
            { "name": "Authorization", "value": "Bearer LEAKED_HAR_SENTINEL_TOKEN_8f3a91" }
          ],
          "queryString": [],
          "headersSize": -1,
          "bodySize": 0
        },
        "response": {
          "status": 200,
          "statusText": "OK",
          "httpVersion": "HTTP/1.1",
          "headers": [],
          "content": { "size": 0, "mimeType": "application/json", "text": "" },
          "headersSize": -1,
          "bodySize": 0
        }
      }
    ]
  }
}"#;

const SENTINEL: &str = "LEAKED_HAR_SENTINEL_TOKEN_8f3a91";

/// A `.har` symlink pointing at a secret-bearing target, surfaced onto the scan
/// set via `with_include_paths`, must be refused visibly before its target is
/// read.
#[test]
fn har_symlink_target_is_not_followed_via_include() {
    let dir = tempfile::tempdir().unwrap();

    // The "sensitive target" lives OUTSIDE any directory we walk; it is
    // only reachable through the symlink. Naming it without a `.har`
    // extension models a real `~/.aws/credentials`-style victim file.
    let target = dir.path().join("victim_credentials");
    fs::write(&target, HAR_WITH_SECRET).unwrap();

    // The bait: a `.har` symlink the attacker gets onto the include list.
    let bait = dir.path().join("creds.har");
    symlink(&target, &bait).unwrap();

    // Drive the public API with the symlink as an explicit include path. The
    // include-admission guard must reject the archive symlink before HAR
    // expansion can read the target bytes.
    let source =
        FilesystemSource::new(dir.path().to_path_buf()).with_include_paths(vec![bait.clone()]);
    let rows: Vec<_> = source.chunks().collect();
    assert_eq!(
        rows.len(),
        1,
        "archive symlink include must surface one source error"
    );
    let err = rows[0]
        .as_ref()
        .expect_err("archive symlink include must be refused");
    assert!(
        err.to_string().contains("archive symlink") && err.to_string().contains("refusing to scan"),
        "error should name the refused archive symlink include, got {err}"
    );
}

/// Control: a REAL (non-symlink) `.har` file with the same content IS
/// expanded and the sentinel surfaces - proving the negative test above
/// is gated by the symlink guard, not by HAR parsing being broken.
#[test]
fn real_har_file_is_expanded_and_secret_surfaces() {
    let dir = tempfile::tempdir().unwrap();
    let real = dir.path().join("capture.har");
    fs::write(&real, HAR_WITH_SECRET).unwrap();

    let source = FilesystemSource::new(dir.path().to_path_buf());
    let chunks: Vec<_> = source.chunks().collect::<Result<Vec<_>, _>>().unwrap();

    let found = chunks.iter().any(|c| c.data.contains(SENTINEL));
    assert!(
        found,
        "a real .har file should expand and surface its embedded secret; \
         got {} chunk(s) none containing the sentinel",
        chunks.len()
    );
}

use keyhog::testing::{CliTestApi as _, API};
use std::path::Path;

#[test]
fn allowlist_root_file_uses_parent() {
    let p = Path::new("/tmp/project/src/main.rs");
    assert_eq!(
        API.allowlist_root_for_test(p),
        Path::new("/tmp/project/src")
    );
}

use super::is_system_path;
use std::path::Path;

#[test]
fn rejects_filesystem_root_and_system_prefixes() {
    assert!(is_system_path(Path::new("/")));
    assert!(is_system_path(Path::new("/etc")));
    assert!(is_system_path(Path::new("/etc/passwd")));
    assert!(is_system_path(Path::new("/var/lib/foo")));
    assert!(is_system_path(Path::new("/credentials")));
}

#[test]
fn rejects_home_and_credential_stores() {
    let Ok(home) = std::env::var("HOME") else {
        eprintln!("skipping home-path checks: HOME unset");
        return;
    };
    assert!(is_system_path(Path::new(&home)));
    assert!(is_system_path(Path::new(&format!("{home}/.ssh"))));
    assert!(is_system_path(Path::new(&format!(
        "{home}/.aws/credentials"
    ))));
    assert!(is_system_path(Path::new(&format!("{home}/.gnupg"))));
    // Project trees under home remain allowed.
    assert!(!is_system_path(Path::new(&format!("{home}/src/keyhog"))));
}

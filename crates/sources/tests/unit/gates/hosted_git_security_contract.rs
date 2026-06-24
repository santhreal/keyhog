//! Gate hosted-Git clone credential and child-process safety contracts.

use std::path::Path;

fn source(path: impl AsRef<Path>) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

#[test]
fn hosted_git_windows_askpass_does_not_expand_raw_prompt_with_percent_vars() {
    let hosted_git = source("src/hosted_git.rs");
    assert!(
        hosted_git.contains("setlocal EnableExtensions EnableDelayedExpansion")
            && hosted_git.contains(r#"set \"prompt=%~1\""#)
            && hosted_git.contains(r#"echo(!prompt!| findstr /I /L /C:\"!origin!\""#)
            && hosted_git.contains(r#"echo(!prompt!| findstr /I /C:\"Username\""#),
        "Windows hosted Git askpass must classify prompts via delayed expansion, not raw percent-expanded prompt text"
    );
    assert!(
        !hosted_git.contains("setlocal EnableExtensions DisableDelayedExpansion")
            && !hosted_git.contains("echo(%prompt%|")
            && !hosted_git.contains("echo %1 | findstr"),
        "Windows hosted Git askpass must not feed raw %prompt%/%1 through cmd metacharacter parsing"
    );
}

#[test]
fn hosted_git_clone_origin_and_wait_cleanup_contracts_stay_wired() {
    let hosted_git = source("src/hosted_git.rs");
    assert!(
        hosted_git.contains("validate_clone_url_for_origin(")
            && hosted_git.contains("outside expected clone origin")
            && hosted_git.contains(r#""http.followRedirects=false""#)
            && hosted_git.contains(r#""credential.helper=""#),
        "hosted Git clone must bind forge-listed URLs to the expected origin and disable redirect/ambient credential paths"
    );

    let wait_start = hosted_git
        .find("fn wait_for_command_with_timeout(")
        .expect("wait_for_command_with_timeout present");
    let auth_start = hosted_git[wait_start..]
        .find("#[derive(Debug)]")
        .map(|offset| wait_start + offset)
        .expect("wait helper boundary present");
    let wait_block = &hosted_git[wait_start..auth_start];
    assert!(
        wait_block.contains("Err(error) =>")
            && wait_block.contains("kill_and_reap_child(&mut child)")
            && wait_block.contains("fn kill_and_reap_child(")
            && wait_block.contains("child.kill()")
            && wait_block.contains("child.wait()"),
        "hosted Git clone wait errors and timeouts must kill and reap the child before returning"
    );
    assert!(
        !wait_block.contains("child.try_wait().map_err(|e| e.to_string())?"),
        "hosted Git clone wait must not return directly from try_wait errors before child cleanup"
    );
}

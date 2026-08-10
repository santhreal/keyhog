//! Gate hosted-Git clone credential and child-process safety contracts.

use std::path::Path;

fn source(path: impl AsRef<Path>) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(path);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

/// The whole `hosted_git` module: parent file first, then every submodule in
/// sorted order.
///
/// These contracts name behavior that belongs to the module, not to one file.
/// Reading only `src/hosted_git.rs` meant that moving the child-process
/// lifetime into `src/hosted_git/process.rs` stopped covering the askpass and
/// kill-and-reap contracts while the gate still reported on the parent, which
/// is the failure a source-text gate exists to prevent. Reading the directory
/// keeps it pointed at the code wherever a later split puts it.
fn module_source() -> String {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("src/hosted_git");
    let mut children: Vec<_> = std::fs::read_dir(&dir)
        .unwrap_or_else(|error| panic!("read_dir {}: {error}", dir.display()))
        .map(|entry| {
            entry
                .unwrap_or_else(|error| panic!("read_dir {} entry: {error}", dir.display()))
                .path()
        })
        .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("rs"))
        .collect();
    assert!(
        !children.is_empty(),
        "src/hosted_git/ must hold the module's submodules; an empty listing means this gate is \
         reading the wrong path and every assertion below would pass vacuously"
    );
    children.sort();
    let mut parts = vec![source("src/hosted_git.rs")];
    parts.extend(children.into_iter().map(source));
    parts.join("\n")
}

fn without_line_comments(source: &str) -> String {
    source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n")
}

#[test]
fn hosted_git_windows_askpass_does_not_expand_raw_prompt_with_percent_vars() {
    let hosted_git = module_source();
    assert!(
        hosted_git.contains("setlocal EnableExtensions EnableDelayedExpansion")
            && hosted_git.contains(r#"set \"prompt=%~1\""#)
            && hosted_git.contains(r#"echo(!prompt!| findstr /I /L "#)
            && hosted_git.contains(r#"/C:\"://!origin!/\""#)
            && hosted_git.contains(r#"/C:\"@!origin!/\""#)
            && !hosted_git.contains(r#"/C:\"!origin!\""#)
            && hosted_git.contains(r#"echo(!prompt!| findstr /I /C:\"Username\""#),
        "Windows hosted Git askpass must classify prompts via delayed expansion and host-boundary findstr needles, not bare origin substring or raw percent-expanded prompt text"
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
    let hosted_git = module_source();
    assert!(
        hosted_git.contains("validate_clone_url_for_origin(")
            && hosted_git.contains("outside expected clone origin")
            && hosted_git.contains(r#""http.followRedirects=false""#)
            && hosted_git.contains(r#""credential.helper=""#),
        "hosted Git clone must bind forge-listed URLs to the expected origin and disable redirect/ambient credential paths"
    );
    assert!(
        hosted_git.contains(".stdout(Stdio::piped())")
            && hosted_git.contains(".stderr(Stdio::piped())")
            && hosted_git.contains("drain_hosted_git_stdout")
            && hosted_git.contains("crate::process_excerpt::drain_stderr_excerpt")
            && hosted_git.contains("hosted_git_stderr_suffix(&stderr)")
            && hosted_git.contains("sanitize_git_error_message(&output.stderr)"),
        "hosted Git clone must capture and drain child output so diagnostics are sanitized instead of inherited"
    );
    assert!(
        !hosted_git.contains(r#"$(dirname "$0")"#)
            && !hosted_git.contains("exec cat --")
            && !hosted_git.contains("cat -- \"$DIR/"),
        "Unix hosted Git askpass must use shell builtins instead of ambient PATH commands for credential files"
    );
    assert!(
        !hosted_git.contains("wait_with_output()"),
        "hosted Git clone must not poll try_wait while leaving piped stdout/stderr undrained for wait_with_output"
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

#[test]
fn hosted_git_scan_orchestrator_keeps_single_repo_worker_boundary() {
    let hosted_git = source("src/hosted_git.rs");
    let scan_start = hosted_git
        .find("pub(crate) fn stream_hosted_repos(")
        .expect("stream_hosted_repos present");
    let worker_start = hosted_git
        .find("fn scan_single_hosted_repo_into(")
        .expect("single hosted repo worker present");
    assert!(
        scan_start < worker_start,
        "scan_hosted_repos must appear before scan_single_hosted_repo for this bounded source contract"
    );
    let scan_block = &hosted_git[scan_start..worker_start];
    let scan_code = without_line_comments(scan_block);
    assert!(
        scan_code.contains("tempfile::tempdir()")
            && scan_code.contains("scan_single_hosted_repo_into("),
        "scan_hosted_repos should own temp-root setup, bounded fanout, worker dispatch, and merge only"
    );
    for forbidden in [
        "validate_repo_name(",
        "validate_display_path(",
        "validate_clone_url_for_origin(",
        "clone_repo(",
        "scan_repo(",
    ] {
        assert!(
            !scan_code.contains(forbidden),
            "scan_hosted_repos must not inline single-repo pipeline step {forbidden}"
        );
    }

    let worker_end = hosted_git[worker_start..]
        .find("fn repo_unreadable_error(")
        .map(|offset| worker_start + offset)
        .unwrap_or(hosted_git.len());
    let worker_block = &hosted_git[worker_start..worker_end];
    let worker_code = without_line_comments(worker_block);
    for required in [
        "validate_repo_name(",
        "validate_display_path(",
        "validate_clone_url_for_origin(",
        "clone_repo(",
    ] {
        assert!(
            worker_code.contains(required),
            "single hosted repo worker must own pipeline step {required}"
        );
    }
    let val_pos = worker_code
        .find("validate_clone_url_for_origin(")
        .expect("validate_clone_url_for_origin present");
    let clone_pos = worker_code.find("clone_repo(").expect("clone_repo present");
    let scan_pos = worker_code
        .find("scan_repo_into(")
        .or_else(|| worker_code.find("scan_repo("))
        .expect("scan_repo present");
    assert!(
        val_pos < clone_pos,
        "validation must precede clone_repo in worker"
    );
    assert!(
        clone_pos < scan_pos,
        "clone_repo must precede scan_repo in worker"
    );
}

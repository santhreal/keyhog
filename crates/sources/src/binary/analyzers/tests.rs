//! Behavioral coverage for analyzer process and result contracts.

use std::path::Path;

use super::ghidra::parse_decompiled_output;
use super::*;

#[cfg(unix)]
fn write_script(path: &Path, contents: &str) {
    use std::io::Write;

    let mut file = std::fs::File::create(path).expect("create fake analyzer");
    file.write_all(contents.as_bytes())
        .expect("write fake analyzer");
    file.sync_all().expect("sync fake analyzer");
    drop(file);
}

#[cfg(unix)]
fn script_analyzer(path: &Path) -> GhidraAnalyzer {
    GhidraAnalyzer::with_arguments("/bin/sh", [path.as_os_str().to_owned()])
}

#[cfg(target_os = "linux")]
fn process_is_running(pid: i32) -> bool {
    if let Ok(stat) = std::fs::read_to_string(format!("/proc/{pid}/stat")) {
        if stat
            .rsplit_once(") ")
            .is_some_and(|(_, rest)| rest.starts_with("Z "))
        {
            return false;
        }
    }

    // SAFETY: signal 0 performs existence and permission checking without sending a signal.
    let result = unsafe { libc::kill(pid, 0) };
    result == 0 || std::io::Error::last_os_error().raw_os_error() == Some(libc::EPERM)
}

#[cfg(target_os = "linux")]
fn process_stops_within(pid: i32, timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while process_is_running(pid) {
        if std::time::Instant::now() >= deadline {
            return false;
        }
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
    true
}

#[cfg(unix)]
#[test]
fn successful_process_returns_decompiled_and_literal_chunks_with_provenance() {
    let temp = tempfile::tempdir().expect("tempdir");
    let input = temp.path().join("fixture.bin");
    std::fs::write(&input, b"binary fixture").expect("write input");
    let executable = temp.path().join("fake-analyze-headless");
    write_script(
        &executable,
        r#"#!/bin/sh
while [ "$#" -gt 0 ]; do
    if [ "$1" = "-postScript" ]; then
        shift
        script="$1"
        break
    fi
    shift
done
output=$(sed -n 's/.*FileWriter("\([^"]*\)").*/\1/p' "$script")
printf '%s\n' 'const char *value = "fixture-decompiled-value";' > "$output"
"#,
    );

    let outcome = script_analyzer(&executable)
        .analyze(BinaryAnalysisRequest {
            path: &input,
            decompiled_bytes_limit: 4096,
            timeout: std::time::Duration::from_secs(1),
        })
        .expect("analysis succeeds");

    let BinaryAnalysisOutcome::Complete(chunks) = outcome else {
        panic!("successful analyzer process degraded")
    };
    assert_eq!(chunks.len(), 2);
    assert_eq!(
        chunks[0].data.as_ref(),
        "const char *value = \"fixture-decompiled-value\";\n"
    );
    assert_eq!(
        chunks[0].metadata.source_type.as_ref(),
        "binary:ghidra:decompiled"
    );
    assert_eq!(
        chunks[0].metadata.path.as_deref(),
        Some(crate::filesystem::display_path(&input).as_str())
    );
    assert_eq!(chunks[1].data.as_ref(), "fixture-decompiled-value");
    assert_eq!(
        chunks[1].metadata.source_type.as_ref(),
        "binary:ghidra:strings"
    );
    assert_eq!(chunks[1].metadata.path, chunks[0].metadata.path);
}

#[cfg(unix)]
#[test]
fn unsuccessful_process_returns_typed_sanitized_degradation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let input = temp.path().join("fixture.bin");
    std::fs::write(&input, b"binary fixture").expect("write input");
    let executable = temp.path().join("fake-analyze-headless");
    write_script(
        &executable,
        "#!/bin/sh\nprintf 'first\\nsecond\\033[31m' >&2\nexit 9\n",
    );

    let outcome = script_analyzer(&executable)
        .analyze(BinaryAnalysisRequest {
            path: &input,
            decompiled_bytes_limit: 4096,
            timeout: std::time::Duration::from_secs(1),
        })
        .expect("process failure is a degradation outcome");

    let BinaryAnalysisOutcome::Degraded(BinaryAnalysisDegradation::ToolFailure {
        reason,
        stderr_excerpt,
    }) = outcome
    else {
        panic!("expected typed tool failure")
    };
    assert!(
        reason.contains("exit status: 9"),
        "unexpected reason: {reason}"
    );
    assert_eq!(stderr_excerpt, "first second[31m");
}

#[test]
fn process_spawn_failure_remains_a_source_error() {
    let temp = tempfile::tempdir().expect("tempdir");
    let input = temp.path().join("fixture.bin");
    std::fs::write(&input, b"binary fixture").expect("write input");

    let error = GhidraAnalyzer::new(temp.path().join("missing-analyze-headless"))
        .analyze(BinaryAnalysisRequest {
            path: &input,
            decompiled_bytes_limit: 4096,
            timeout: std::time::Duration::from_secs(1),
        })
        .expect_err("spawn failure must remain an error");

    assert!(matches!(
        error,
        keyhog_core::SourceError::Io(error) if error.kind() == std::io::ErrorKind::NotFound
    ));
}

#[cfg(unix)]
#[test]
fn successful_exit_without_output_is_a_typed_degradation() {
    let temp = tempfile::tempdir().expect("tempdir");
    let input = temp.path().join("fixture.bin");
    std::fs::write(&input, b"binary fixture").expect("write input");
    let executable = temp.path().join("fake-analyze-headless");
    write_script(&executable, "#!/bin/sh\nexit 0\n");

    let outcome = script_analyzer(&executable)
        .analyze(BinaryAnalysisRequest {
            path: &input,
            decompiled_bytes_limit: 4096,
            timeout: std::time::Duration::from_secs(1),
        })
        .expect("missing output is a degradation outcome");

    let BinaryAnalysisOutcome::Degraded(BinaryAnalysisDegradation::ToolFailure {
        reason,
        stderr_excerpt,
    }) = outcome
    else {
        panic!("expected missing-output degradation")
    };
    assert!(reason.contains("produced no output"));
    assert!(stderr_excerpt.is_empty());
}

#[cfg(unix)]
#[test]
fn process_stderr_is_drained_but_excerpt_is_capped() {
    let temp = tempfile::tempdir().expect("tempdir");
    let input = temp.path().join("fixture.bin");
    std::fs::write(&input, b"binary fixture").expect("write input");
    let executable = temp.path().join("fake-analyze-headless");
    write_script(
        &executable,
        "#!/bin/sh\ni=0\nwhile [ \"$i\" -lt 5000 ]; do printf x >&2; i=$((i + 1)); done\nexit 4\n",
    );

    let outcome = script_analyzer(&executable)
        .analyze(BinaryAnalysisRequest {
            path: &input,
            decompiled_bytes_limit: 4096,
            timeout: std::time::Duration::from_secs(5),
        })
        .expect("process failure is a degradation outcome");

    let BinaryAnalysisOutcome::Degraded(BinaryAnalysisDegradation::ToolFailure {
        stderr_excerpt,
        ..
    }) = outcome
    else {
        panic!("expected typed tool failure")
    };
    assert_eq!(stderr_excerpt.len(), 4096);
    assert!(stderr_excerpt.bytes().all(|byte| byte == b'x'));
}

#[cfg(target_os = "linux")]
#[test]
fn timeout_kills_and_reaps_the_analyzer_process() {
    let temp = tempfile::tempdir().expect("tempdir");
    let input = temp.path().join("fixture.bin");
    let parent_pid_file = temp.path().join("analyzer.pid");
    let descendant_pid_file = temp.path().join("descendant.pid");
    std::fs::write(&input, b"binary fixture").expect("write input");
    let executable = temp.path().join("fake-analyze-headless");
    write_script(
        &executable,
        &format!(
            "#!/bin/sh\nprintf '%s' \"$$\" > '{}'\nsleep 60 &\ndescendant=$!\nprintf '%s' \"$descendant\" > '{}'\nwait \"$descendant\"\n",
            parent_pid_file.display(),
            descendant_pid_file.display()
        ),
    );

    let started = std::time::Instant::now();
    let outcome = script_analyzer(&executable)
        .analyze(BinaryAnalysisRequest {
            path: &input,
            decompiled_bytes_limit: 4096,
            timeout: std::time::Duration::from_secs(3),
        })
        .expect("timeout is a degradation outcome");

    assert!(
        started.elapsed() < std::time::Duration::from_secs(5),
        "timed out analyzer did not return promptly"
    );
    let BinaryAnalysisOutcome::Degraded(BinaryAnalysisDegradation::ToolFailure {
        reason,
        stderr_excerpt,
    }) = outcome
    else {
        panic!("expected timeout degradation")
    };
    assert!(reason.contains("Ghidra analysis timed out"));
    assert!(stderr_excerpt.is_empty());

    let parent_pid = std::fs::read_to_string(&parent_pid_file)
        .expect("analyzer recorded its pid")
        .parse::<i32>()
        .expect("valid analyzer pid");
    let descendant_pid = std::fs::read_to_string(&descendant_pid_file)
        .expect("analyzer recorded descendant pid")
        .parse::<i32>()
        .expect("valid descendant pid");
    assert!(
        process_stops_within(parent_pid, std::time::Duration::from_secs(2)),
        "timed out analyzer process was not reaped"
    );
    assert!(
        process_stops_within(descendant_pid, std::time::Duration::from_secs(2)),
        "timed out analyzer descendant survived process-group cleanup"
    );
}

#[test]
fn oversized_output_returns_typed_degradation_without_reading_contents() {
    let temp = tempfile::tempdir().expect("tempdir");
    let input = temp.path().join("fixture.bin");
    let output = temp.path().join("decompiled.c");
    std::fs::write(&input, b"binary fixture").expect("write input");
    std::fs::write(&output, b"0123456789").expect("write output");

    let outcome = parse_decompiled_output(
        &output,
        BinaryAnalysisRequest {
            path: &input,
            decompiled_bytes_limit: 9,
            timeout: std::time::Duration::from_secs(1),
        },
    )
    .expect("size rejection is a degradation outcome");

    assert!(matches!(
        outcome,
        BinaryAnalysisOutcome::Degraded(BinaryAnalysisDegradation::OutputTooLarge {
            actual_bytes: 10,
            limit_bytes: 9
        })
    ));
}

#[cfg(unix)]
#[test]
fn decompiler_output_symlink_is_rejected_by_safe_open() {
    use std::os::unix::fs::symlink;

    let temp = tempfile::tempdir().expect("tempdir");
    let input = temp.path().join("fixture.bin");
    let target = temp.path().join("target.c");
    let output = temp.path().join("decompiled.c");
    std::fs::write(&input, b"binary fixture").expect("write input");
    std::fs::write(&target, b"const char *value = \"off-target\";").expect("write target");
    symlink(&target, &output).expect("create output symlink");

    let error = parse_decompiled_output(
        &output,
        BinaryAnalysisRequest {
            path: &input,
            decompiled_bytes_limit: 4096,
            timeout: std::time::Duration::from_secs(1),
        },
    )
    .expect_err("safe-open must reject a symlinked analyzer output");

    assert!(matches!(error, keyhog_core::SourceError::Io(_)));
}

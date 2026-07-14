//! Ghidra headless process orchestration and decompiled-output parsing.

use std::ffi::OsString;
use std::io::{BufRead, Read};
use std::path::{Path, PathBuf};
use std::process::{Child, Command};

use keyhog_core::{Chunk, ChunkMetadata, SourceError};
use wait_timeout::ChildExt;

use super::{
    BinaryAnalysisDegradation, BinaryAnalysisOutcome, BinaryAnalysisRequest, BinaryAnalyzer,
};

const GHIDRA_STDERR_EXCERPT_BYTES: usize = 4096;

pub(in crate::binary) struct GhidraAnalyzer {
    executable: PathBuf,
    arguments: Vec<OsString>,
}

impl GhidraAnalyzer {
    pub(in crate::binary) fn new(executable: impl Into<PathBuf>) -> Self {
        Self::with_arguments(executable, std::iter::empty())
    }

    pub(super) fn with_arguments(
        executable: impl Into<PathBuf>,
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Self {
        Self {
            executable: executable.into(),
            arguments: arguments.into_iter().collect(),
        }
    }
}

impl BinaryAnalyzer for GhidraAnalyzer {
    fn analyze(
        &self,
        request: BinaryAnalysisRequest<'_>,
    ) -> Result<BinaryAnalysisOutcome, SourceError> {
        let tmp_dir = tempfile::tempdir().map_err(SourceError::Io)?;
        let project_dir = tmp_dir.path().join("ghidra_project");
        std::fs::create_dir_all(&project_dir).map_err(SourceError::Io)?;

        let script_path = tmp_dir.path().join("ExportDecompiled.java");
        let output_path = tmp_dir.path().join("decompiled.c");
        write_ghidra_script(&script_path, &output_path)?;

        let mut command = Command::new(&self.executable);
        command
            .args(&self.arguments)
            .arg(&project_dir)
            .arg("keyhog_analysis")
            .arg("-import")
            .arg(request.path)
            .arg("-postScript")
            .arg(&script_path)
            .arg("-deleteProject")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped());
        isolate_analyzer_process_tree(&mut command);
        let mut child = command.spawn().map_err(SourceError::Io)?;
        let stderr_capture = child.stderr.take().map(capture_ghidra_stderr_excerpt);
        let timeout = request.timeout;
        let status = match child.wait_timeout(timeout) {
            Ok(Some(status)) => Ok(status),
            Ok(None) => {
                let cleanup = kill_and_reap_ghidra_child(&mut child, "Ghidra timeout cleanup");
                let message = match cleanup {
                    Ok(()) => format!("Ghidra analysis timed out after {}s", timeout.as_secs()),
                    Err(cleanup_error) => format!(
                        "Ghidra analysis timed out after {}s; cleanup failed: {cleanup_error}",
                        timeout.as_secs()
                    ),
                };
                Err(std::io::Error::new(std::io::ErrorKind::TimedOut, message))
            }
            Err(error) => {
                let cleanup = kill_and_reap_ghidra_child(&mut child, "Ghidra wait-error cleanup");
                let message = match cleanup {
                    Ok(()) => format!("Ghidra process wait failed: {error}"),
                    Err(cleanup_error) => format!(
                        "Ghidra process wait failed: {error}; cleanup failed: {cleanup_error}"
                    ),
                };
                Err(std::io::Error::other(message))
            }
        };
        let stderr_excerpt = match stderr_capture {
            Some(handle) => match handle.join() {
                Ok(excerpt) => excerpt,
                Err(panic) => {
                    drop(panic);
                    eprintln!(
                        "keyhog: WARNING: internal Ghidra stderr capture failed; \
                         deep-analysis failure reporting will use process status only."
                    );
                    String::new()
                }
            },
            // Process status still makes the degradation visible when no pipe handle exists.
            None => String::new(),
        };

        match status {
            Ok(status) if status.success() && output_path.exists() => {
                parse_decompiled_output(&output_path, request)
            }
            other => {
                let reason = match &other {
                    Ok(status) => {
                        format!("exited unsuccessfully (status {status}) or produced no output")
                    }
                    Err(error) => error.to_string(),
                };
                Ok(BinaryAnalysisOutcome::Degraded(
                    BinaryAnalysisDegradation::ToolFailure {
                        reason,
                        stderr_excerpt,
                    },
                ))
            }
        }
    }
}

pub(super) fn parse_decompiled_output(
    output_path: &Path,
    request: BinaryAnalysisRequest<'_>,
) -> Result<BinaryAnalysisOutcome, SourceError> {
    // Safe-open first, then size the opened descriptor so path swaps cannot bypass the cap.
    let file = crate::filesystem::open_file_safe(output_path).map_err(SourceError::Io)?;
    let metadata = file.metadata().map_err(SourceError::Io)?;
    if metadata.len() > request.decompiled_bytes_limit {
        return Ok(BinaryAnalysisOutcome::Degraded(
            BinaryAnalysisDegradation::OutputTooLarge {
                actual_bytes: metadata.len(),
                limit_bytes: request.decompiled_bytes_limit,
            },
        ));
    }

    let reader = std::io::BufReader::new(file);
    let mut decompiled_text = String::new();
    let mut string_literals = Vec::new();

    for line in reader.lines() {
        let line = line.map_err(SourceError::Io)?;
        decompiled_text.push_str(&line);
        decompiled_text.push('\n');
        super::super::literals::extract_string_literals(&line, &mut string_literals);
    }

    let path = Some(crate::filesystem::display_path(request.path).into());
    let mut chunks = Vec::new();
    if !decompiled_text.is_empty() {
        chunks.push(Chunk {
            data: decompiled_text.into(),
            metadata: ChunkMetadata {
                base_offset: 0,
                base_line: 0,
                source_type: "binary:ghidra:decompiled".into(),
                path: path.clone(),
                commit: None,
                author: None,
                date: None,
                mtime_ns: None,
                size_bytes: None,
                decoded_span: None,
            },
        });
    }
    if !string_literals.is_empty() {
        chunks.push(Chunk {
            data: string_literals.join("\n").into(),
            metadata: ChunkMetadata {
                base_offset: 0,
                base_line: 0,
                source_type: "binary:ghidra:strings".into(),
                path,
                commit: None,
                author: None,
                date: None,
                mtime_ns: None,
                size_bytes: None,
                decoded_span: None,
            },
        });
    }

    Ok(BinaryAnalysisOutcome::Complete(chunks))
}

fn kill_and_reap_ghidra_child(child: &mut Child, context: &str) -> std::io::Result<()> {
    let kill_result = terminate_analyzer_process_tree(child);
    let wait_result = child.wait();
    match (kill_result, wait_result) {
        (Ok(()), Ok(_)) => Ok(()),
        (Err(kill_error), Ok(_))
            if matches!(
                kill_error.kind(),
                std::io::ErrorKind::InvalidInput | std::io::ErrorKind::NotFound
            ) =>
        {
            Ok(())
        }
        (Err(kill_error), Ok(status)) => Err(std::io::Error::other(format!(
            "{context}: failed to kill child before reap: {kill_error}; reap status: {status}"
        ))),
        (Ok(()), Err(wait_error)) => Err(std::io::Error::other(format!(
            "{context}: killed child but failed to reap it: {wait_error}"
        ))),
        (Err(kill_error), Err(wait_error)) => Err(std::io::Error::other(format!(
            "{context}: failed to kill child: {kill_error}; failed to reap child: {wait_error}"
        ))),
    }
}

#[cfg(unix)]
fn isolate_analyzer_process_tree(command: &mut Command) {
    use std::os::unix::process::CommandExt;

    command.process_group(0);
}

#[cfg(not(unix))]
fn isolate_analyzer_process_tree(_command: &mut Command) {}

#[cfg(unix)]
fn terminate_analyzer_process_tree(child: &mut Child) -> std::io::Result<()> {
    let process_group = match i32::try_from(child.id()) {
        Ok(process_group) if process_group > 1 => process_group,
        Ok(process_group) => {
            return kill_direct_after_group_failure(
                child,
                format!("refusing unsafe Ghidra process-group ID {process_group}"),
            );
        }
        Err(_) => {
            // LAW10: direct-child termination still runs and the returned error is loud and operator-visible when process-tree termination is incomplete.
            return kill_direct_after_group_failure(
                child,
                "Ghidra process ID does not fit the platform process-group type".into(),
            );
        }
    };
    // SAFETY: the negative, nonzero PID targets only the process group created at spawn.
    if unsafe { libc::kill(-process_group, libc::SIGKILL) } == 0 {
        return Ok(());
    }

    let group_error = std::io::Error::last_os_error();
    if group_error.raw_os_error() == Some(libc::ESRCH) {
        return child.kill();
    }
    kill_direct_after_group_failure(
        child,
        format!("failed to kill Ghidra process group {process_group}: {group_error}"),
    )
}

#[cfg(unix)]
fn kill_direct_after_group_failure(child: &mut Child, group_error: String) -> std::io::Result<()> {
    match child.kill() {
        Ok(()) => Err(std::io::Error::other(format!(
            "{group_error}; killed direct child only"
        ))),
        Err(child_error) => Err(std::io::Error::other(format!(
            "{group_error}; failed to kill direct child: {child_error}"
        ))),
    }
}

#[cfg(not(unix))]
fn terminate_analyzer_process_tree(child: &mut Child) -> std::io::Result<()> {
    child.kill()
}

fn capture_ghidra_stderr_excerpt(
    mut stderr: std::process::ChildStderr,
) -> std::thread::JoinHandle<String> {
    std::thread::spawn(move || {
        let mut captured = Vec::with_capacity(GHIDRA_STDERR_EXCERPT_BYTES);
        let mut buffer = [0_u8; 1024];
        loop {
            match stderr.read(&mut buffer) {
                Ok(0) => break,
                Ok(n) => {
                    let remaining = GHIDRA_STDERR_EXCERPT_BYTES.saturating_sub(captured.len());
                    if remaining > 0 {
                        captured.extend_from_slice(&buffer[..n.min(remaining)]);
                    }
                }
                Err(error) => {
                    let suffix = format!(" [stderr capture read failed: {error}]");
                    let remaining = GHIDRA_STDERR_EXCERPT_BYTES.saturating_sub(captured.len());
                    if remaining > 0 {
                        let bytes = suffix.as_bytes();
                        captured.extend_from_slice(&bytes[..bytes.len().min(remaining)]);
                    }
                    break;
                }
            }
        }
        sanitize_ghidra_stderr_excerpt(&captured)
    })
}

fn sanitize_ghidra_stderr_excerpt(bytes: &[u8]) -> String {
    let text = String::from_utf8_lossy(bytes);
    let mut out = String::new();
    let mut pending_space = false;
    for ch in text.chars() {
        if ch.is_whitespace() {
            pending_space = !out.is_empty();
            continue;
        }
        if pending_space {
            out.push(' ');
            pending_space = false;
        }
        if ch.is_control() {
            continue;
        }
        out.push(ch);
    }
    out
}

/// Search standard locations for Ghidra's `analyzeHeadless` script.
pub(in crate::binary) fn find_ghidra_headless() -> Option<PathBuf> {
    // Non-standard installs must enter through the configured trusted-bin boundary.
    if let Some(path) = keyhog_core::resolve_safe_bin("analyzeHeadless") {
        return Some(path);
    }

    for pattern in &[
        "/opt/ghidra*/support/analyzeHeadless",
        "/usr/share/ghidra/support/analyzeHeadless",
        "/usr/local/share/ghidra/support/analyzeHeadless",
    ] {
        let paths = match glob::glob(pattern) {
            Ok(paths) => paths,
            Err(error) => {
                tracing::warn!(
                    pattern,
                    %error,
                    "Ghidra discovery glob pattern failed; skipping pattern"
                );
                continue;
            }
        };
        for entry in paths {
            match entry {
                Ok(entry) => {
                    if entry.exists() {
                        return Some(entry);
                    }
                }
                Err(error) => {
                    tracing::warn!(
                        pattern,
                        %error,
                        "Ghidra discovery glob entry failed; skipping entry"
                    );
                }
            }
        }
    }

    None
}

/// Write a Ghidra postScript that runs analysis and exports decompiled C.
fn write_ghidra_script(script_path: &Path, output_path: &Path) -> Result<(), SourceError> {
    let script = format!(
        r#"// KeyHog Ghidra export script - runs full analysis then decompiles all functions.
// @category KeyHog
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import java.io.FileWriter;
import java.io.PrintWriter;

public class ExportDecompiled extends GhidraScript {{
    @Override
    public void run() throws Exception {{
        // Run full analysis first
        analyzeAll(currentProgram);

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        PrintWriter writer = new PrintWriter(new FileWriter("{output}"));

        // Export all string data from the program
        var dataIterator = currentProgram.getListing().getDefinedData(true);
        while (dataIterator.hasNext()) {{
            var data = dataIterator.next();
            if (data.hasStringValue()) {{
                writer.println("// DATA @ " + data.getAddress() + ": " + data.getValue());
            }}
        }}

        // Decompile all functions
        FunctionIterator funcs = currentProgram.getListing().getFunctions(true);
        while (funcs.hasNext()) {{
            Function func = funcs.next();
            DecompileResults results = decomp.decompileFunction(func, 30, monitor);
            if (results != null && results.decompileCompleted()) {{
                String decompiled = results.getDecompiledFunction().getC();
                if (decompiled != null) {{
                    writer.println("// FUNCTION: " + func.getName() + " @ " + func.getEntryPoint());
                    writer.println(decompiled);
                    writer.println();
                }}
            }}
        }}

        decomp.dispose();
        writer.close();
    }}
}}
"#,
        output = output_path
            .display()
            .to_string()
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    );

    std::fs::write(script_path, script).map_err(SourceError::Io)
}

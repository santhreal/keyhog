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
const GHIDRA_SCAN_CHUNK_BYTES: usize = crate::strings::BOUNDED_DERIVED_TEXT_CHUNK_BYTES;

pub(in crate::binary) struct GhidraAnalyzer {
    executable: PathBuf,
    arguments: Vec<OsString>,
    version: Option<String>,
}

impl GhidraAnalyzer {
    pub(in crate::binary) fn new(executable: impl Into<PathBuf>) -> Self {
        Self::with_arguments(executable, std::iter::empty())
    }

    pub(super) fn with_arguments(
        executable: impl Into<PathBuf>,
        arguments: impl IntoIterator<Item = OsString>,
    ) -> Self {
        let executable = executable.into();
        let version = probe_ghidra_version(&executable);
        Self {
            executable,
            arguments: arguments.into_iter().collect(),
            version,
        }
    }

    pub fn version(&self) -> Option<&str> {
        self.version.as_deref()
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
    let (file, metadata) =
        crate::filesystem::open_file_safe_with_metadata(output_path).map_err(SourceError::Io)?;
    if metadata.len() > request.decompiled_bytes_limit {
        return Ok(BinaryAnalysisOutcome::Degraded(
            BinaryAnalysisDegradation::OutputTooLarge {
                actual_bytes: metadata.len(),
                limit_bytes: request.decompiled_bytes_limit,
            },
        ));
    }

    let path: Option<std::sync::Arc<str>> =
        Some(crate::filesystem::display_path(request.path).into());
    let mut decompiled = GhidraChunkBuilder::new("binary:ghidra:decompiled", path.clone());
    let mut literals = GhidraChunkBuilder::new("binary:ghidra:strings", path);
    let mut line_literals = Vec::new();

    let read_limit = request.decompiled_bytes_limit.saturating_add(1);
    let mut reader = std::io::BufReader::new(file).take(read_limit);
    let mut total_read = 0_u64;
    let mut line = String::new();
    loop {
        line.clear();
        let read = reader.read_line(&mut line).map_err(SourceError::Io)?;
        if read == 0 {
            break;
        }
        total_read = total_read.saturating_add(read as u64);
        if total_read > request.decompiled_bytes_limit {
            return Ok(BinaryAnalysisOutcome::Degraded(
                BinaryAnalysisDegradation::OutputTooLarge {
                    actual_bytes: total_read,
                    limit_bytes: request.decompiled_bytes_limit,
                },
            ));
        }
        let line = line.strip_suffix('\n').unwrap_or(&line);
        let line = line.strip_suffix('\r').unwrap_or(line);
        decompiled.push_text(line);
        decompiled.push_text("\n");

        line_literals.clear();
        super::super::literals::extract_string_literals(line, &mut line_literals);
        for literal in &line_literals {
            literals.push_separated(literal);
        }
    }

    let mut chunks = decompiled.finish();
    chunks.extend(literals.finish());
    Ok(BinaryAnalysisOutcome::Complete(chunks))
}

struct GhidraChunkBuilder {
    chunks: Vec<Chunk>,
    buffer: String,
    base_offset: usize,
    base_line: usize,
    has_value: bool,
    source_type: &'static str,
    path: Option<std::sync::Arc<str>>,
}

impl GhidraChunkBuilder {
    fn new(source_type: &'static str, path: Option<std::sync::Arc<str>>) -> Self {
        Self {
            chunks: Vec::new(),
            buffer: String::with_capacity(GHIDRA_SCAN_CHUNK_BYTES),
            base_offset: 0,
            base_line: 0,
            has_value: false,
            source_type,
            path,
        }
    }

    fn push_separated(&mut self, value: &str) {
        if self.has_value {
            self.push_text("\n");
        }
        self.push_text(value);
        self.has_value = true;
    }

    fn push_text(&mut self, mut text: &str) {
        while !text.is_empty() {
            if self.buffer.len() == GHIDRA_SCAN_CHUNK_BYTES {
                self.flush();
            }
            let available = GHIDRA_SCAN_CHUNK_BYTES - self.buffer.len();
            let mut split = text.len().min(available);
            while split > 0 && !text.is_char_boundary(split) {
                split -= 1;
            }
            if split == 0 {
                self.flush();
                continue;
            }
            self.buffer.push_str(&text[..split]);
            text = &text[split..];
        }
    }

    fn flush(&mut self) {
        if self.buffer.is_empty() {
            return;
        }
        let bytes = self.buffer.len();
        let lines = self
            .buffer
            .as_bytes()
            .iter()
            .filter(|&&byte| byte == b'\n')
            .count();
        self.chunks.push(Chunk {
            data: std::mem::take(&mut self.buffer).into(),
            metadata: ChunkMetadata {
                base_offset: self.base_offset,
                base_line: self.base_line,
                source_type: keyhog_core::intern_source_type(self.source_type),
                path: self.path.clone(),
                commit: None,
                author: None,
                date: None,
                mtime_ns: None,
                size_bytes: None,
                decoded_span: None,
            },
        });
        self.base_offset += bytes;
        self.base_line += lines;
        self.buffer = String::with_capacity(GHIDRA_SCAN_CHUNK_BYTES);
    }

    fn finish(mut self) -> Vec<Chunk> {
        self.flush();
        self.chunks
    }
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

/// Probe Ghidra's installation directory for its version string (from `application.properties`).
pub(in crate::binary) fn probe_ghidra_version(executable: &Path) -> Option<String> {
    if let Ok(dir) = std::env::var("GHIDRA_INSTALL_DIR") {
        let prop = Path::new(&dir).join("Ghidra/application.properties");
        if let Some(v) = parse_ghidra_properties_version(&prop) {
            return Some(v);
        }
    }
    if let Some(parent) = executable.parent() {
        if let Some(root) = parent.parent() {
            let prop = root.join("Ghidra/application.properties");
            if let Some(v) = parse_ghidra_properties_version(&prop) {
                return Some(v);
            }
        }
    }
    None
}

fn parse_ghidra_properties_version(path: &Path) -> Option<String> {
    let content = std::fs::read_to_string(path).ok()?;
    let mut version = None;
    let mut release = None;
    for line in content.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("application.version=") {
            version = Some(rest.trim().to_string());
        } else if let Some(rest) = line.strip_prefix("application.release.name=") {
            release = Some(rest.trim().to_string());
        }
    }
    match (version, release) {
        (Some(v), Some(r)) if !r.is_empty() => Some(format!("{v} {r}")),
        (Some(v), _) => Some(v),
        _ => None,
    }
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

//! Source-of-truth receipts binding an Action finding count to exact report bytes.

use crate::args::{ActionReportFormat, ActionReportVerifyArgs, OutputFormat, ScanArgs};
use anyhow::{bail, Context, Result};
use keyhog_core::ScanCompletionStatus;
use sha2::{Digest, Sha256};
use std::fs::{self, File, OpenOptions};
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::process::ExitCode;

const SCHEMA: &str = "keyhog-action-report-v1";
const MAX_RECEIPT_BYTES: u64 = 1024;

pub(crate) fn validate_scan_paths(args: &ScanArgs) -> Result<()> {
    let Some(receipt) = args.action_receipt.as_ref() else {
        return Ok(());
    };
    let report = args
        .output
        .as_ref()
        .context("--action-receipt requires --output")?;
    match fs::symlink_metadata(receipt) {
        Ok(_) => bail!(
            "Action receipt destination must be absent before scan: {}",
            receipt.display()
        ),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => {
            return Err(error).with_context(|| {
                format!(
                    "inspecting Action receipt destination {}",
                    receipt.display()
                )
            })
        }
    }
    if canonical_destination(report)? == canonical_destination(receipt)? {
        bail!("Action report and receipt paths must be distinct");
    }
    Ok(())
}

pub(crate) fn write_scan_receipt(
    args: &ScanArgs,
    findings: usize,
    exit_code: u8,
    status: ScanCompletionStatus,
) -> Result<()> {
    let Some(receipt_path) = args.action_receipt.as_ref() else {
        return Ok(());
    };
    let report_path = args
        .output
        .as_ref()
        .context("--action-receipt requires --output")?;
    let format = action_format(&args.format)
        .context("--action-receipt supports only sarif, json, jsonl, or text reports")?;
    validate_semantics(findings, exit_code, status_token(status))?;
    // Receipt metadata assembly (report digest) and publication are Reporting-stage work.
    let _span = keyhog_profile::span(keyhog_profile::Stage::Reporting);
    let (report_bytes, report_sha256) = digest_regular(report_path)?;
    let body = format!(
        "schema={SCHEMA}\nformat={format}\nfindings={findings}\nreport-bytes={report_bytes}\nreport-sha256={report_sha256}\nscan-status={}\nexit-code={exit_code}\n",
        status_token(status)
    );
    write_receipt_noclobber(receipt_path, body.as_bytes()).with_context(|| {
        format!(
            "atomically creating Action receipt {}",
            receipt_path.display()
        )
    })
}

pub(crate) fn verify(args: ActionReportVerifyArgs) -> Result<ExitCode> {
    let mut receipt = open_regular(&args.receipt)?;
    reject_same_open_file(&receipt, &args.receipt, &args.report)?;
    let receipt_len = receipt.metadata()?.len();
    if receipt_len == 0 || receipt_len > MAX_RECEIPT_BYTES {
        bail!("Action receipt length {receipt_len} is outside 1..={MAX_RECEIPT_BYTES} bytes");
    }
    let mut body = String::with_capacity(receipt_len as usize);
    receipt
        .read_to_string(&mut body)
        .context("Action receipt must be strict UTF-8 text")?;
    if !body.is_ascii() {
        bail!("Action receipt must contain ASCII only");
    }
    let lines = body.lines().collect::<Vec<_>>();
    if lines.len() != 7 || !body.ends_with('\n') {
        bail!("Action receipt must contain exactly seven newline-terminated fields");
    }
    let schema = field(lines[0], "schema")?;
    let format = field(lines[1], "format")?;
    let findings = parse_decimal(field(lines[2], "findings")?, "findings")?;
    let expected_bytes = parse_decimal(field(lines[3], "report-bytes")?, "report-bytes")?;
    let expected_sha = field(lines[4], "report-sha256")?;
    let status = field(lines[5], "scan-status")?;
    let receipt_exit = parse_decimal(field(lines[6], "exit-code")?, "exit-code")?;
    if schema != SCHEMA {
        bail!("unsupported Action receipt schema {schema:?}");
    }
    if format != args.format.to_string() {
        bail!(
            "Action receipt format {format:?} contradicts requested {}",
            args.format
        );
    }
    if receipt_exit != usize::from(args.exit_code) {
        bail!(
            "Action receipt exit {receipt_exit} contradicts scanner exit {}",
            args.exit_code
        );
    }
    if expected_sha.len() != 64
        || !expected_sha
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        bail!("Action receipt report-sha256 must be exactly 64 lowercase hexadecimal characters");
    }
    validate_semantics(findings, args.exit_code, status)?;
    let (actual_bytes, actual_sha) = digest_regular(&args.report)?;
    if actual_bytes != expected_bytes as u64 {
        bail!("Action report length changed: receipt={expected_bytes}, actual={actual_bytes}");
    }
    if actual_sha != expected_sha {
        bail!("Action report SHA-256 changed after scan");
    }
    let parsed_findings = report_finding_count(&args.report, &args.format, findings)?;
    if parsed_findings != findings {
        bail!("Action report finding count {parsed_findings} contradicts receipt count {findings}");
    }
    println!("{findings}");
    Ok(ExitCode::SUCCESS)
}

fn report_finding_count(
    path: &Path,
    format: &ActionReportFormat,
    text_count: usize,
) -> Result<usize> {
    match format {
        ActionReportFormat::Json => {
            let value: serde_json::Value =
                serde_json::from_reader(BufReader::new(open_regular(path)?))
                    .context("parsing Action JSON report")?;
            value
                .as_array()
                .map(Vec::len)
                .context("Action JSON report must be a top-level findings array")
        }
        ActionReportFormat::Jsonl => {
            let mut count = 0usize;
            for line in BufReader::new(open_regular(path)?).lines() {
                let line = line.context("reading Action JSONL report")?;
                if line.trim().is_empty() {
                    continue;
                }
                let value: serde_json::Value =
                    serde_json::from_str(&line).context("parsing Action JSONL finding")?;
                if !value.is_object() {
                    bail!("Action JSONL report rows must be finding objects");
                }
                count = count
                    .checked_add(1)
                    .context("Action JSONL finding count overflow")?;
            }
            Ok(count)
        }
        ActionReportFormat::Sarif => {
            #[derive(serde::Deserialize)]
            struct Sarif {
                runs: Vec<Run>,
            }
            #[derive(serde::Deserialize)]
            struct Run {
                results: Vec<serde::de::IgnoredAny>,
            }

            let sarif: Sarif = serde_json::from_reader(BufReader::new(open_regular(path)?))
                .context("parsing Action SARIF report")?;
            sarif.runs.into_iter().try_fold(0usize, |total, run| {
                total
                    .checked_add(run.results.len())
                    .context("Action SARIF finding count overflow")
            })
        }
        ActionReportFormat::Text => Ok(text_count),
    }
}

fn field<'a>(line: &'a str, name: &str) -> Result<&'a str> {
    line.strip_prefix(name)
        .and_then(|value| value.strip_prefix('='))
        .filter(|value| !value.is_empty())
        .with_context(|| format!("Action receipt field {name} is missing, empty, or out of order"))
}

fn parse_decimal(value: &str, name: &str) -> Result<usize> {
    if !value.bytes().all(|byte| byte.is_ascii_digit()) {
        bail!("Action receipt field {name} must be canonical unsigned decimal");
    }
    if value.len() > 1 && value.starts_with('0') {
        bail!("Action receipt field {name} must not contain leading zeroes");
    }
    value
        .parse()
        .with_context(|| format!("Action receipt field {name} overflows"))
}

fn validate_semantics(findings: usize, exit_code: u8, status: &str) -> Result<()> {
    match (exit_code, status, findings) {
        (0 | 3, "success" | "complete_after_recovery" | "partial", _) => Ok(()),
        (1 | 10, "success" | "complete_after_recovery" | "partial", 1..) => Ok(()),
        // A fail-closed scan reports `failed` when a source failed outright and
        // `partial` when coverage merely has gaps (row 163). Both are valid here.
        (11 | 13, "partial" | "failed", _) => Ok(()),
        _ => bail!("Action receipt count/status/exit semantics contradict: findings={findings}, status={status}, exit={exit_code}"),
    }
}

fn status_token(status: ScanCompletionStatus) -> &'static str {
    match status {
        ScanCompletionStatus::Success => "success",
        ScanCompletionStatus::CompleteAfterRecovery => "complete_after_recovery",
        ScanCompletionStatus::Partial => "partial",
        ScanCompletionStatus::Cancelled => "cancelled",
        ScanCompletionStatus::Failed => "failed",
    }
}

fn action_format(format: &OutputFormat) -> Option<&'static str> {
    match format {
        OutputFormat::Sarif => Some("sarif"),
        OutputFormat::Json => Some("json"),
        OutputFormat::Jsonl => Some("jsonl"),
        OutputFormat::Text => Some("text"),
        _ => None,
    }
}

fn write_receipt_noclobber(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new(".")); // LAW10: intended path default, a basename-only destination is relative to the current directory.
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    use std::io::Write as _;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map(drop)
        .map_err(|error| error.error)
}

fn open_regular(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true);

    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        options.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    let file = options
        .open(path)
        .with_context(|| format!("opening Action file {}", path.display()))?;
    if !file.metadata()?.file_type().is_file() {
        bail!(
            "Action file must be a regular, non-symlink file: {}",
            path.display()
        );
    }
    Ok(file)
}

fn canonical_destination(path: &Path) -> Result<std::path::PathBuf> {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()?.join(path)
    };
    let parent = absolute.parent().context("Action path has no parent")?;
    let name = absolute
        .file_name()
        .context("Action path has no file name")?;
    Ok(parent
        .canonicalize()
        .with_context(|| format!("canonicalizing Action path parent {}", parent.display()))?
        .join(name))
}

fn reject_same_open_file(receipt: &File, _receipt_path: &Path, report_path: &Path) -> Result<()> {
    let report = open_regular(report_path)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        let receipt_meta = receipt.metadata()?;
        let report_meta = report.metadata()?;
        if receipt_meta.dev() == report_meta.dev() && receipt_meta.ino() == report_meta.ino() {
            bail!("Action report and receipt resolve to the same file");
        }
    }
    #[cfg(not(unix))]
    if canonical_destination(_receipt_path)? == canonical_destination(report_path)? {
        bail!("Action report and receipt resolve to the same file");
    }
    Ok(())
}

fn digest_regular(path: &Path) -> Result<(u64, String)> {
    let mut file = open_regular(path)?;
    let mut hasher = Sha256::new();
    let mut bytes = 0u64;
    let mut buffer = [0u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        bytes = bytes
            .checked_add(read as u64)
            .context("Action report length overflow")?;
        hasher.update(&buffer[..read]);
    }
    Ok((bytes, keyhog_core::hex_encode(hasher.finalize())))
}

# Embedding KeyHog

Call KeyHog from your own code instead of shelling out to it, or hand its
output to another tool.

## As a library (Rust)

Add to `Cargo.toml`:

```toml
[dependencies]
keyhog-core = "0.5"        # detector specs + Chunk/ChunkMetadata
keyhog-scanner = "0.5"     # CompiledScanner
```

(Detectors ship inside `keyhog-core` as a static-embedded TOML
corpus; there is no separate `keyhog-detectors` crate.)

Minimal scan:

```rust,ignore
use keyhog_core::{Chunk, ChunkMetadata, RawMatch};
use keyhog_scanner::CompiledScanner;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Built-in embedded detectors - no disk I/O, fail-closed on corrupt bundled TOML.
    let specs = keyhog_core::load_embedded_detectors_or_fail()?;
    // …or load from a directory of TOMLs:
    // let specs = load_detectors(std::path::Path::new("detectors"))?;

    let scanner = CompiledScanner::compile(specs)?;

    let bytes = std::fs::read("config.yaml")?;
    let chunk = Chunk {
        data: String::from_utf8_lossy(&bytes).into_owned().into(),
        metadata: ChunkMetadata {
            source_type: "filesystem".into(),
            path: Some("config.yaml".into()),
            ..Default::default()
        },
    };
    let matches = scanner.scan(&chunk)?;
    for m in &matches {
        println!(
            "{}:{} (detector {})",
            m.location.file_path.as_deref().unwrap_or("<memory>"),
            m.location.line.unwrap_or(0),
            m.detector_id
        );
    }
    // RawMatch stays in process; this projection is safe to serialize or report.
    let _report_safe: Vec<_> = matches.iter().map(RawMatch::to_redacted).collect();
    Ok(())
}
```

For directory-tree / git / docker walking, drive `keyhog-sources`
or shell out to the CLI - `CompiledScanner` is one chunk at a time
by design.

The no-backend `scan` and `scan_coalesced` methods are deterministic portable
CPU calls. Explicit `scan_with_backend` and `scan_coalesced_with_backend` calls
return typed `ScanError` values when a selected backend cannot initialize or
finish. They never terminate the embedding process and never substitute a
different engine. You can probe startup eligibility with `warm_backend`; the
CLI owns the separate mapping from terminal scanner errors to process exit
status.

Successful calls return `Vec<RawMatch>` inside the typed `Result`. `Credential`,
`SensitiveString`, raw or deduplicated matches, and source `Chunk` values can
contain plaintext or encoded secret bytes and therefore refuse implicit serde
output. Convert raw matches with `RawMatch::to_redacted`, or emit the
verification pipeline's `VerifiedFinding`, before JSON, logging, disk, or
network output. Only a protected private protocol should explicitly reveal
secret bytes.

For finer-grained control of individual detector features:

```toml
[dependencies]
keyhog-scanner = { version = "0.5", default-features = false, features = ["ml", "decode", "entropy"] }
```

## Embedded in another CLI

Shell out:

```rust,ignore
use std::process::Command;
let out = Command::new("keyhog")
    .args(["scan", "--format", "jsonl-envelope", "--min-confidence", "0.4", "."])
    .output()?;
if !matches!(out.status.code(), Some(0 | 1)) {
    return Err(std::io::Error::other(format!(
        "keyhog did not complete the requested scan: {}",
        String::from_utf8_lossy(&out.stderr)
    )).into());
}
for line in out.stdout.split(|b| *b == b'\n') {
    if line.is_empty() { continue; }
    let record: serde_json::Value = serde_json::from_slice(line)?;
    if matches!(record.get("record_type").and_then(|v| v.as_str()), Some("header" | "summary")) {
        continue;
    }
    let finding = record;
    // ... do whatever
}
```

Or invoke the scan subcommand directly from a wrapper script:

```bash
keyhog scan /path/to/project --format jsonl-envelope --min-confidence 0.4
```

## SARIF for GitHub Code Scanning

The composite Action is the safest way to create, upload, and retain SARIF:

```yaml
- uses: santhreal/keyhog@v0
  with:
    format: sarif
    upload-sarif: 'true'
    fail-on-findings: 'true'
```

Grant `security-events: write` as shown in the
[GitHub Action guide](../github-action.md#scan-a-repository). The Action uploads before it
enforces findings, keeps a workflow artifact, and makes only a fork pull
request's restricted-token upload advisory. Trusted upload failures fail the
job.

For another SARIF consumer, write the file directly:

```bash
keyhog scan . --format sarif --output keyhog.sarif
```

The command exits `1` when a finding blocks the active evidence policy and `10`
on a verified-live finding. Arrange report publication in an always-run or post
step, then restore the exact scan status. KeyHog tags findings with CWE-798 and
OWASP A07:2021.

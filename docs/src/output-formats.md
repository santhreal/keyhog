# Output formats

KeyHog's `--format` flag takes one of eleven values: `text` (default),
`json`, `json-envelope`, `jsonl`, `jsonl-envelope`, `sarif`, `csv`,
`github-annotations`, `gitlab-sast`, `html`, and `junit`. Pick the one that fits the consumer. `csv` emits a
spreadsheet-importable row per finding, `github-annotations` emits
GitHub Actions workflow-command annotations, `gitlab-sast` emits a
GitLab SAST security report, `html` emits a
self-contained report page, and `junit` emits a JUnit XML test-report
(one `<testcase>` per finding) for CI systems that ingest JUnit.

Every renderer receives the same completed scan report. Its common metadata
(version, timestamps, duration, targets, source bytes, source chunks, and detector count) is
owned by the core `ScanReport` model, so an output format cannot accidentally
invent a second scan clock or target list. Formats keep their established
schemas: HTML displays the full metadata panel, GitLab SAST projects the scan
times required by its schema, and finding-only formats preserve their stable
finding shape. Metadata-bearing JSON, JSONL, and HTML artifacts also include
`resolved_scan`: a versioned object with the selected `preset`, sorted
`effective` detection values, and an `overrides` list. This is the authoritative
machine-diffable record of what `default`, `fast`, `deep`, or `precision` meant
for that run; it includes compatible refinements such as
`--deep --decode-depth 3`, rather than requiring consumers to infer behavior
from CLI text or stderr.

Metadata-bearing formats expose `scan_status` as `success`,
`complete_after_recovery`, `partial`, `cancelled`, or `failed`.
`complete_after_recovery` is a successful complete scan, but it proves that a
visible backend fault occurred and every affected byte was recovered. Any
source or scanner coverage gap overrides it to `partial`; recovery never masks
incomplete input.

Every finding also carries `companions_redacted`, a sorted JSON object of
nearby credential or context values captured by the detector. Companion values
are redacted at the same boundary as the primary credential, so plaintext
never enters verification results or reports. JSON, JSONL, and HTML expose the
object directly; SARIF exposes `companions_redacted.<name>` result properties;
CSV, JUnit, GitLab SAST, and GitHub annotations use a deterministic redacted
summary. An empty object means the detector did not produce companion evidence,
not that companion matching was disabled.

`entropy` is an optional Shannon bits-per-byte measurement. It is present only
when the detection path measured entropy; an omitted field means that path did
not produce entropy evidence. JSON, JSONL, and HTML expose it as a numeric
field; SARIF exposes it as a result property; text, JUnit, GitLab SAST, and
GitHub annotations render it only when measured. It is independent of
`confidence`, which combines entropy with detector, context, shape, and
verification evidence.

## `--format text` (default)

Human-readable boxes. Best for terminal use, pre-commit hook output,
and screenshots. Colors auto-detect TTY; pipe through `cat` (or set
`NO_COLOR=1`) to disable.

```text
  ┌    CRITICAL ─── Stripe Secret Key
  │ Secret:     sk_l...p7dc
  │ Location:   src/config/staging.env:14
  │ Confidence: ■■■■■■ 100%
  │ Action:     Roll the exposed Stripe secret key in the Dashboard, update production consumers, then delete the old key.
  │ Docs:       https://docs.stripe.com/keys#roll-api-key
  └─────────────────────────────────────────────

  ━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1 secret found · 1 unverified
```

Each finding is a severity-colored box: the header carries the severity
and detector name, then `Secret:` (the credential redacted to its first
and last few characters), `Location:` (`file:line:offset`), a
`Confidence:` bar, and an `Action:`/`Docs:` remediation hint. Verified
runs add the liveness state and commit/author rows when known. The
`Results` footer joins the counts with ` · `.

## `--format json`

Legacy JSON array retained for compatibility with existing consumers. Every
finding has all required documented fields present; optional fields are omitted
only when their value is unavailable. Use `--format json-envelope` for a
versioned root object with schema identity and scan metadata.

```sh
keyhog scan . --format json | jq '.[].detector_id' | sort | uniq -c
```

That sample command dedups findings by detector, which is the most
common "what kinds of leaks do I have" question.

## `--format json-envelope`

Versioned JSON envelope. The root object contains `schema_version` and
`findings`, plus optional scan-wide `metadata` and the `coverage_gap_summary`
array. Each gap preserves the canonical reason and count used by SARIF/HTML,
including when there are no findings. A reader must reject an
unsupported `schema_version.major`; a newer minor under a supported major is
additive and may be accepted. See [Your first scan](./first-scan.md#json-output)
for the complete schema. Metadata includes the binary Git identity, detector-set
digest, effective-config digest when available, a stable non-secret `scan_id`,
targets, timing, and counters including the exact source bytes and chunks
consumed by the scanner. The top-level `scan_status` is one of `success`,
`complete_after_recovery`, `partial`, `cancelled`, or `failed`; readers must
preserve the explicit terminal state in detached artifacts. The `scan_id` lets
independently stored metadata-bearing JSON, JSONL, and HTML projections be
joined without exposing secrets. Reports
from older KeyHog versions may omit it; the HTML projection displays that state
as `not recorded` rather than inventing an identifier. `resolved_scan` is
omitted only for library-created reports that have no resolved CLI scan policy.

## `--format csv`

CSV emits one row per finding. CLI scan output begins with one metadata comment
(`# keyhog.scan.metadata=<JSON>`) before the header. It records a schema
version, terminal `scan_status`, and the complete `coverage_gap_summary`, so a
zero-finding partial scan cannot be mistaken for a clean scan. CSV consumers
should ignore comment lines before parsing the RFC 4180 header and data rows.
The library-compatible `ReportFormat::Csv` renderer omits this preamble;
the `write_csv_coverage_report` entrypoint emits it explicitly.

The `companions_redacted`, `remediation`,
`metadata`, and `additional_locations` columns contain deterministic JSON
objects or arrays. Metadata keys are sorted before serialization, and duplicate
locations retain their complete source, path, line, offset, commit, author, and
date fields. `entropy` is a numeric bits-per-byte column; it is empty when the
detection path did not measure entropy. Every textual cell is escaped with RFC 4180 quoting plus
spreadsheet-formula neutralization. An unavailable confidence score remains an
empty cell; remediation is still emitted so a CSV artifact never loses the
canonical action guidance.

### Finding-field losslessness

Use the versioned envelope formats when a downstream system needs the complete
finding model. The other formats are deliberate projections:

| Format | Finding fields retained | Scan-wide state |
| --- | --- | --- |
| `json-envelope` / `jsonl-envelope` | Every `VerifiedFinding` field, including metadata, remediation, and duplicate locations | `scan_status` and `coverage_gap_summary` |
| `csv` | All 20 documented columns, with metadata and duplicate locations encoded as JSON | Metadata preamble before the header |
| `sarif` | Detector identity, redacted credential/hash, verification, confidence, entropy, metadata, companions, primary and additional locations | Run properties and coverage notifications |
| `html` | Complete redacted findings plus the full report metadata object | Status and coverage panel |
| `junit` | Human-readable detector, service, severity, location, hash, verification, confidence, entropy, and companions in CDATA | Suite properties |
| `gitlab-sast` | GitLab schema fields plus redacted credential/hash, service, companions, and entropy details | Schema-native `scan.status` plus `scan.keyhog_scan_status` |
| `github-annotations` | Redacted detector, location, severity, and verification message | Coverage warning annotation when partial |

Fields not listed for a projection are intentionally unavailable in that
format; they must not be inferred from stderr or the process exit code.

## `--format sarif`

[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
- Static Analysis Results Interchange Format. GitHub Code Scanning,
GitLab Security Dashboard, and most IDE security plugins consume this.

```sh
keyhog scan . --format sarif > keyhog-results.sarif
```

Upload to GitHub:

```yaml
# .github/workflows/secrets.yml
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: keyhog-results.sarif
```

Findings show up in the **Security → Code scanning** tab with the
detector ID as the rule, file path + line as the location, and the
redacted credential as the message.

## `--format github-annotations`

GitHub Actions workflow commands - one annotation line per finding.
Use this when you want findings to appear inline in the Actions log
without uploading SARIF:

```sh
keyhog scan . --format github-annotations
```

Critical and high findings render as `error` annotations, medium and
low as `warning`, and info as `notice`. Each annotation carries the file,
line, title, detector, service, redacted credential, verification state,
and confidence when available. The plaintext credential is not emitted.
When source coverage is incomplete, the formatter also emits one terminal
`::warning` notice with deterministic reason/count pairs, so the GitHub job log
shows the incomplete state even when there are no findings. CLI output always
also emits `::notice title=keyhog scan::scan status: success|partial|cancelled|failed`; the
legacy library-only `ReportFormat::GithubAnnotations` variant remains finding-
only for compatibility.

SARIF carries the same terminal state in `runs[0].properties["keyhog.scan.status"]`;
coverage gaps remain detailed in `invocations[].toolExecutionNotifications`.

## `--format gitlab-sast`

GitLab SAST security-report JSON. Use it with `artifacts:reports:sast`
when GitLab should ingest KeyHog findings into the pipeline Security tab:

```yaml
keyhog:
  script:
    - keyhog scan . --format gitlab-sast --output gl-sast-report.json
  artifacts:
    reports:
      sast: gl-sast-report.json
```

GitLab SAST reports require every finding to have a file path and a
one-based line number. If a non-file source cannot be represented in that
schema, KeyHog fails the report with an error instead of fabricating a
location. Use `json` or `sarif` for mixed file and non-file sources.

The `scan.start_time` and `scan.end_time` values come from the same report
metadata used by HTML. This keeps CI artifacts and the human report aligned
when a daemon or a long-running scan finishes at a different time than the
reporting step began. If source coverage gaps occur, KeyHog emits the
schema-supported `scan.status: "failure"`; a complete scan emits
`scan.status: "success"`. Because GitLab's schema has no distinct cancelled or
failed values, the nested `scan.keyhog_scan_status` extension preserves
KeyHog's exact `success|partial|cancelled|failed` state for detached-artifact
consumers.

## `--format html`

HTML is a self-contained interactive report. In addition to findings and
coverage gaps, its metadata panel shows the terminal scan status, producing
KeyHog version, scan interval, duration, redacted targets, source bytes and
chunks, and detector count. The
metadata is descriptive only; it never changes finding or exit-code semantics.

## `--format junit`

JUnit XML contains one failing testcase per finding. The suite always contains
`keyhog.scan.status` (`success`, `partial`, `cancelled`, or `failed`), and partial scans add one
`keyhog.coverage_gap` property per reason/count pair. CI consumers can reject a
partial artifact without scraping stderr.

## `--format jsonl`

Legacy newline-delimited JSON retained for compatibility: one finding object
per line and no header. Use `--format jsonl-envelope` when the stream needs a
schema identity and explicit concatenation boundaries.

## `--format jsonl-envelope`

Versioned newline-delimited JSON. The first line is a `record_type: "header"`
object carrying the same `schema_version` major contract as
`--format json-envelope` (JSONL has its own additive minor revision) and
optional scan metadata; every following line is one finding object. The final
line is a `record_type: "summary"` object with transport
`status: "complete"`, a `scan_status` of `success` or `partial`, the exact
finding count, and the coverage-gap summary.
An empty scan still emits both header and summary. A stream without the final
summary is interrupted and must not be treated as complete; concatenated
streams are split at the next header. Importers must validate both records
before accepting the stream. This is better than `--format json-envelope` for
streaming consumers that want to start processing before the scan finishes:

```sh
keyhog scan /huge/monorepo --format jsonl-envelope \
  | while read line; do
      echo "$line" | jq -r 'select(.record_type == null) | .location.file_path'
    done
```

## Combining with `--verify`

`--verify` calls each detector's verification endpoint to confirm the
credential is live. Live credentials keep their severity; dead ones get
downgraded one tier. The output format doesn't change - the
`verification` field of each finding becomes `"live"` or `"dead"`
instead of `"skipped"`. (The JSON value is the lowercase
`VerificationResult` variant - `"live"`, `"dead"`, `"revoked"`,
`"rate_limited"`, `"unverifiable"`, `"skipped"`, or an `{"error": "..."}`
object - not the `verified-live`/`verified-dead` labels the *text*
reporter prints.)

```sh
keyhog scan . --verify --format json-envelope \
  | jq '.findings[] | select(.verification == "live")'
```

## Findings-only output

On an interactive terminal `keyhog scan` shows a banner, a live progress
ticker, and a completion summary on stderr. Most of the time you do not need to
silence it: the banner and ticker are printed only when stderr is a TTY (they
never appear in a pipe, a file, or CI logs), and the structured formats
(`json`, `json-envelope`, `jsonl`, `jsonl-envelope`, `sarif`, `csv`,
`github-annotations`, `gitlab-sast`, `junit`) carry structured findings and
format-specific coverage metadata, with no banner or footer prose. So a CI script
that wants machine output just selects a structured format:

```sh
keyhog scan . --format json
```

The `text` format does print a footer summary (counts + any skip
summary) to stdout alongside the findings; if you want findings only,
choose `json`/`json-envelope`/`jsonl`/`jsonl-envelope`/`sarif`/`csv`/`github-annotations`/`gitlab-sast` instead. The
interactive banner is TTY-gated and never reaches a pipe or a file. Exit code
semantics are unchanged by the format choice (see
[exit codes](./reference/exit-codes.md)).

When you do want to silence the interactive chrome on a TTY (for example a
local run whose stderr you are capturing), pass `--quiet`. It suppresses the
banner, the progress ticker, and the "Scan complete" summary, but still prints
coverage `FAIL`/`WARN` lines and fatal errors so a quiet scan can never be
mistaken for a clean one. Use `--no-color` to drop ANSI styling regardless of
whether output is a TTY (the [`NO_COLOR`](./reference/env.md) convention is also
honored).

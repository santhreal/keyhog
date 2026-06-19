# Output formats

KeyHog's `--format` flag takes one of nine values: `text` (default),
`json`, `jsonl`, `sarif`, `csv`, `github-annotations`, `gitlab-sast`,
`html`, and `junit`. Pick the one that fits the consumer. `csv` emits a
spreadsheet-importable row per finding, `github-annotations` emits
GitHub Actions workflow-command annotations, `gitlab-sast` emits a
GitLab SAST security report, `html` emits a
self-contained report page, and `junit` emits a JUnit XML test-report
(one `<testcase>` per finding) for CI systems that ingest JUnit.

## `--format text` (default)

Human-readable table. Best for terminal use, pre-commit hook output,
and screenshots. Colors auto-detect TTY; pipe through `cat` (or set
`NO_COLOR=1`) to disable.

```text
src/config/staging.env:14:12  HIGH  stripe-secret-key
                              sk_live_4eC39H…Tcd3Hc (redacted)
                              entropy 5.21 │ confidence 0.999 │ unverified
```

The columns are `file:line:offset`, severity, detector ID. The second
line is the redacted credential. The third is metadata.

## `--format json`

Stable-schema JSON array. Every finding has every documented field
present. See [Your first scan](./first-scan.md#json-output) for the
schema.

```sh
keyhog scan . --format json | jq '.[] | .detector_id' | sort | uniq -c
```

That sample command dedups findings by detector, which is the most
common "what kinds of leaks do I have" question.

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

## `--format jsonl`

Newline-delimited JSON - one finding per line, no outer array. Better
than `--format json` for streaming consumers that want to start
processing before the scan finishes:

```sh
keyhog scan /huge/monorepo --format jsonl \
  | while read line; do
      echo "$line" | jq -r '.location.file_path'
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
keyhog scan . --verify --format json \
  | jq '.[] | select(.verification == "live")'
```

## Findings-only output

`keyhog scan` has no `--quiet` flag. You don't need one: the banner is
printed only when stderr is a TTY (it never appears in a pipe, a file,
or CI logs), and the structured formats (`json`, `jsonl`, `sarif`,
`csv`, `github-annotations`, `gitlab-sast`, `junit`) carry findings only,
with no banner or footer prose. So a CI script that wants machine output just selects a
structured format:

```sh
keyhog scan . --format json
```

The `text` format does print a footer summary (counts + any skip
summary) to stdout alongside the findings; if you want findings only,
choose `json`/`jsonl`/`sarif`/`csv`/`github-annotations`/`gitlab-sast` instead. The
animated banner is the only TTY-gated piece and never reaches a pipe or
a file. Exit code semantics are unchanged by the format choice (see
[exit codes](./reference/exit-codes.md)).

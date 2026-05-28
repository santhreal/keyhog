# Output formats

KeyHog speaks four formats. Pick the one that fits the consumer.

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
`verification` field of each finding becomes `"verified-live"` or
`"verified-dead"` instead of `"skipped"`.

```sh
keyhog scan . --verify --format json \
  | jq '.[] | select(.verification == "verified-live")'
```

## Quiet mode

`--quiet` suppresses the header banner and the footer summary. Output
is findings-only, which is what CI scripts usually want:

```sh
keyhog scan . --quiet --format json
```

Exit code semantics are unchanged.

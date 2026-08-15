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
(version, timestamps, duration, targets, source bytes, source chunks, and
detector count) is owned by the core `ScanReport` model, so an output format
cannot accidentally invent a second scan clock or target list. Each format
retains its owned projection: HTML displays the full metadata panel, GitLab
SAST projects the scan times required by its schema, and finding-only formats
omit scan-wide state. JSON-envelope, JSONL-envelope, and HTML artifacts also
include a versioned `resolved_scan` object with the selected `preset`, sorted
`effective` detection values, and an `overrides` list. This is the authoritative
machine-diffable record of what `default`, `fast`, `deep`, or `precision` meant
for that run; it includes compatible refinements such as
`--deep --decode-depth 3`, rather than requiring consumers to infer behavior
from CLI text or stderr.

Metadata-bearing formats expose `scan_status` as `success`,
`complete_after_recovery`, `partial`, `cancelled`, or `failed`.
`complete_after_recovery` is a successful complete scan, but it proves that a
visible fault in an authenticated selected backend occurred and every affected
byte was recovered. Invalid autoroute state selects no backend and records
`partial`. Any source or scanner coverage gap overrides recovery; incomplete
input never reports clean.

The composite Action output named `scan-status` is a different, normalized
wrapper receipt: `success`, `partial`, `cancelled`, or `failed`.
`complete_after_recovery` remains `success` there because the process completed
with ordinary clean/findings semantics. Consumers that must distinguish healthy
completion from recovery must inspect a metadata-bearing report (for the
Action's SARIF default, the KeyHog run properties), not the wrapper output.

After a selected accelerated backend faults, the recovery backend is the
confidence-separated fastest remaining measured-correct peer for the same
workload and runtime class. When no trustworthy route can be selected, no
recovery backend is substituted: the affected input remains unscanned and the
report records partial coverage.

Authenticated-backend fault recovery is structured in every metadata-bearing
artifact. JSON-envelope, JSONL-envelope, HTML, and the CSV preamble carry
`backend_recoveries`; SARIF uses
`runs[].properties["keyhog.backend.recoveries"]`; GitLab SAST uses
`scan.keyhog_backend_recoveries`; JUnit adds `keyhog.backend.recovery` suite
properties; GitHub annotations emit a warning with recovered bytes and the
repair command. Plain `json` and `jsonl` remain finding-only and receive the
same recovery warning on stderr as text.
Each metadata projection retains the failed backend, recovery backend,
recovered byte count, and `keyhog calibrate-autoroute` remediation.

Every finding also carries `companions_redacted`, a sorted JSON object of
nearby credential or context values captured by the detector. Companion values
are redacted at the same boundary as the primary credential, so plaintext
never enters verification results or reports. JSON, JSONL, and HTML expose the
object directly; SARIF exposes `companions_redacted.<name>` result properties;
CSV, JUnit, GitLab SAST, and GitHub annotations use a deterministic redacted
summary. An empty object means the detector did not produce companion evidence,
not that companion matching was disabled.

Every finding format exposes the exact canonical evidence tier and reason code.
`confirmed` identifies intrinsic or live proof, `likely` identifies strong
vendor-specific shape in a credential-bearing role, and `review` identifies a
candidate that needs human judgment. The optional `evidence_score` supplements
that verdict when the detection path measured a score; it never replaces the
tier or reason.

`entropy` is an optional Shannon bits-per-byte measurement. It is present only
when the detection path measured entropy; an omitted field means that path did
not produce entropy evidence. JSON, JSONL, and HTML expose it as a numeric
field; SARIF exposes it as a result property; text, JUnit, GitLab SAST, and
GitHub annotations render it only when measured. It is independent of the
optional `evidence_score`.

## `--format text` (default)

Human-readable boxes. Best for terminal use, pre-commit hook output,
and screenshots. Colors auto-detect TTY; pipe through `cat` (or set
`NO_COLOR=1`) to disable.

```text
  ┌    CRITICAL ─── Stripe Secret Key
  │ Secret:     sk_l...p7dc
  │ Location:   src/config/.env.staging:14
  │ Evidence:   likely/vendor-pattern  ■■■■■■ 100%
  │ Action:     Roll the exposed Stripe secret key in the Dashboard, update production consumers, then delete the old key.
  │ Docs:       https://docs.stripe.com/keys#roll-api-key
  └─────────────────────────────────────────────

  ━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1 secret found · 1 unverified
```

Each finding is a severity-colored box: the header carries the severity and
detector name, then `Secret:` (the credential redacted to its first and last
few characters), `Location:` (`file:line:offset`), `Evidence:` with the exact
tier/reason and optional score bar, and an `Action:`/`Docs:` remediation hint.
Verified runs add the liveness state and commit/author rows when known. The
`Results` footer joins the counts with ` · `.

## `--format json`

Bare JSON array for simple pipelines. Every finding has all required documented
fields present; optional fields are omitted only when their value is
unavailable. Use `--format json-envelope` for a versioned root object with
schema identity and scan metadata.

The following is one complete finding object. The values are synthetic. The
credential is already redacted, and the hash is a non-secret example value.

```json
{
  "detector_id": "stripe-secret-key",
  "detector_name": "Stripe Secret Key",
  "service": "stripe",
  "severity": "critical",
  "credential_redacted": "sk_l...p7dc",
  "credential_hash": "0000000000000000000000000000000000000000000000000000000000000000",
  "companions_redacted": {},
  "location": {
    "source": "filesystem",
    "file_path": "src/config/.env.staging",
    "line": 14,
    "offset": 218,
    "commit": null,
    "author": null,
    "date": null
  },
  "verification": "skipped",
  "metadata": {},
  "additional_locations": [],
  "evidence": {
    "tier": "likely",
    "reason_code": "vendor-pattern",
    "provenance": {
      "schema_version": 1,
      "detector_digest": "0123456789abcdef",
      "pattern_index": 0,
      "candidate_channel": "pattern",
      "source_role": "environment-assignment-value",
      "context_class": "vendor-pattern"
    }
  },
  "evidence_score": 1.0,
  "remediation": {
    "action": "Roll the exposed Stripe secret key in the Dashboard, update production consumers, then delete the old key.",
    "revoke_url": "https://docs.stripe.com/keys#roll-api-key",
    "docs_url": "https://docs.stripe.com/keys"
  }
}
```

Optional fields such as `entropy` are absent when they were not measured.
Location members are present and use `null` when the value is unknown. A
verification transport failure is encoded as an externally tagged object, for
example `"verification":{"error":"timeout: the endpoint did not respond within the verification deadline. Fix: raise the verification timeout with --timeout, or check network egress / proxy reachability to the credential's host"}`.

`evidence.provenance` is secret-safe. The detector-corpus digest and pattern
ordinal bind the exact detector pattern. The candidate channel, source role,
and context class bind the evidence used before optional live verification.
Unsupported scanner context retains its producer identity and uses the
`unsupported-context` context class. Caller-created findings use the
`unattributed` channel with no detector digest or pattern ordinal.

Do not enable `--show-secrets` when stdout or `--output` is retained by CI,
uploaded as an artifact, or sent to another process. That option deliberately
replaces `credential_redacted` with plaintext. `credential_hash` is safe from
accidental plaintext disclosure, but it is a stable SHA-256 correlation value.
Treat every report as security-sensitive data.

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
consumed by the scanner. `backend_recoveries` records bounded, non-secret
failed-backend, recovery-backend, range, chunk, byte, reason, and repair-command
aggregates whenever an automatic route completes exact recovery. The top-level `scan_status` is one of `success`,
`complete_after_recovery`, `partial`, `cancelled`, or `failed`; readers must
preserve the explicit terminal state in detached artifacts. The `scan_id` lets
independently stored JSON-envelope, JSONL-envelope, and HTML projections be
joined without exposing secrets. Reports
from older KeyHog versions may omit it; the HTML projection displays that state
as `not recorded` rather than inventing an identifier. `resolved_scan` is
omitted only for library-created reports that have no resolved CLI scan policy.

### Cross-file correlation

Report schema 2.0 carries an optional `correlations` array after `findings`. It
is present only when the scan ran with `--correlate`; without the flag the key
is absent, not empty, and the rest of the report is unchanged. Correlation
never adds, drops, reorders, or edits a finding, so a `--correlate` run and a
default run produce the same `findings` array.

Each entry joins several findings into one credential risk:

| Field | Meaning |
| --- | --- |
| `kind` | `value_reuse` (one credential digest at several file paths, crossing detector boundaries) or `split_composite` (a provider credential whose halves are separate detectors placed in different files of one directory) |
| `severity` | Strongest member severity, raised to the composite's declared severity when the policy declares a higher one |
| `evidence_score` | Strongest member evidence score lifted by the policy bonus, clamped to the configured ceiling |
| `strongest_member_evidence_score` | What the best single member scored before the lift, so the added evidence is auditable |
| `scope` | Directory the composite parts share; absent for `value_reuse`, which is scan-wide |
| `members` | Contributing findings with `detector_id`, `credential_hash`, `role`, optional `evidence_score`, and the locations inside the scope |
| `locations` | Union of every member location, sorted by path then line |
| `impact` | What the correlation means operationally |

`value_reuse` is not the same as `additional_locations`. Per-detector dedup
folds repeats of ONE detector into a finding's `additional_locations`; it never
crosses detectors, so one value matched as two different detector ids in two
files stays two unrelated findings until correlation joins them.

Which providers have composite halves is Tier-B data in
`crates/core/data/credential-correlation.toml`, not a hardcoded list. A
composite is reported only when a directory holds exactly one candidate
credential for each required part and no single file holds them all: an
ambiguous directory yields nothing rather than a guess, and a pair that already
shares a file is left to the detector's own companion match.

```sh
keyhog scan . --correlate --format json-envelope \
  | jq '.correlations[] | {kind, severity, evidence_score, title, files: .file_count}'
```

`--format text` renders the same groups as a `Correlated credentials` block
above the results summary. Every other format is untouched by the flag.

### Status and process exit are separate contracts

Machine consumers must read the status carried by a metadata-bearing artifact.
Do not derive scan completeness from the process exit code:

| Reported result | Process exit |
| --- | --- |
| No finding blocks the active evidence policy and input is complete | `0` |
| At least one finding blocks, with no finding verified `live` | `1` |
| At least one reported finding verified `live` | `10` |
| No finding blocks and input coverage is incomplete | `13` |

A scanner panic exits `11`, a required or explicitly selected GPU that is
unavailable exits `12`, and Ctrl-C exits `130`. Blocking and live findings take
precedence over an input-coverage failure in process-exit selection. A partial
scan with such findings can therefore exit `1` or `10`. Its envelope still says
`"scan_status":"partial"`. This is why detached consumers must inspect
`scan_status` and `coverage_gap_summary`.

Legacy `json` and `jsonl` contain findings only. They cannot distinguish a
complete zero-finding scan from an incomplete one. Use `json-envelope`,
`jsonl-envelope`, SARIF, CSV with its CLI preamble, GitLab SAST, or JUnit when
that distinction controls a gate.

### `scan_status` alone is not a gate

Scanning any ordinary repository reports `"scan_status":"partial"`, because the
default walker prunes `.git/` and `node_modules/` during discovery and counts
each pruned directory once as a coverage gap. Branch on the `coverage_gap_summary` reasons rather than on
the status.

A scan that read nothing is a third case. `--exclude-paths '**'`, a
`.keyhogignore` containing `path:**`, and an empty stdin stream all read zero
source bytes. That now exits `13` and carries a `scan covered nothing` gap row,
and the text report says so instead of `No secrets detected`. Assert it anyway
in any gate whose input path can change, because the assertion is cheap and it
names the problem in the job log:

```sh
keyhog scan . --format json-envelope --output keyhog.json
jq -e '.metadata.source_bytes_scanned > 0' keyhog.json
```

That command exits `1` when the scan read nothing.

[Tell a real clean from a skipped input](./reference/coverage-truth.md) owns
the complete rule, including what each counter means and the shipped cases
where a clean scan is wrong.

## `--format csv`

CSV emits one row per finding. CLI scan output begins with one schema-2 metadata comment
(`# keyhog.scan.metadata=<JSON>`) before the header. It records a schema
version, terminal `scan_status`, `backend_recoveries`, and the complete
`coverage_gap_summary`, so a
zero-finding partial scan cannot be mistaken for a clean scan. CSV consumers
should ignore comment lines before parsing the RFC 4180 header and data rows.
The library-compatible `ReportFormat::Csv` renderer omits this preamble;
the `write_csv_coverage_report` entrypoint emits it explicitly.

The `companions_redacted`, `remediation`,
`metadata`, and `additional_locations` columns contain deterministic JSON
objects or arrays. Metadata keys are sorted before serialization, and duplicate
locations retain their complete source, path, line, offset, commit, author, and
date fields. `evidence_tier` and `evidence_reason_code` are required textual
columns. `evidence_score` and `entropy` are numeric columns that remain empty
when the detection path did not measure them. Every textual cell is escaped
with RFC 4180 quoting plus spreadsheet-formula neutralization; remediation is
still emitted so a CSV artifact never loses the canonical action guidance.

### Finding-field losslessness

Use the versioned envelope formats when a downstream system needs the complete
finding model. The other formats are deliberate projections:

| Format | Finding fields retained | Scan-wide state |
| --- | --- | --- |
| `json` / `jsonl` | Every `VerifiedFinding` field, including evidence, metadata, remediation, and duplicate locations | None |
| `json-envelope` / `jsonl-envelope` | Every `VerifiedFinding` field, including evidence, metadata, remediation, and duplicate locations | `scan_status` and `coverage_gap_summary` |
| `csv` | All 22 documented columns, with metadata and duplicate locations encoded as JSON | Metadata preamble before the header |
| `sarif` | Detector identity, redacted credential/hash, verification, evidence tier/reason, optional evidence score and entropy, metadata, companions, primary and additional locations | Run properties and coverage notifications |
| `html` | Complete redacted findings plus the full report metadata object | Status and coverage panel |
| `junit` | Human-readable detector, service, severity, location, hash, verification, evidence tier/reason, optional evidence score, entropy, and companions in CDATA | Suite properties |
| `gitlab-sast` | GitLab schema fields plus redacted credential/hash, service, evidence tier/reason, optional evidence score, companions, and entropy details | Schema-native `scan.status` plus `scan.keyhog_scan_status` |
| `github-annotations` | Redacted detector, location, severity, verification, evidence tier/reason, and optional evidence score | Coverage warning annotation when partial |
| `text` | Human-readable detector, severity, redacted credential, location, exact evidence tier/reason, optional evidence score, verification, and remediation | Coverage warnings and result summary |

Fields not listed for a projection are intentionally unavailable in that
format; they must not be inferred from stderr or the process exit code.

## `--format sarif`

[SARIF 2.1.0](https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html)
is the preferred format for GitHub Code Scanning and SARIF-aware IDEs.

```sh
keyhog scan . --format sarif --output keyhog-results.sarif
status=$?
test "$status" -eq 0 -o "$status" -eq 1 -o "$status" -eq 10
```

The file remains available when blocking or live findings make KeyHog exit `1`
or `10`. Do not write a command chain that uploads the file only after an
exit-zero scan.

The important machine fields have this shape. The values are synthetic and the
message contains only the redacted credential:

```json
{
  "version": "2.1.0",
  "runs": [{
    "results": [{
      "ruleId": "stripe-secret-key",
      "level": "error",
      "message": {"text": "stripe secret detected: sk_l...p7dc"},
      "locations": [{
        "physicalLocation": {
          "artifactLocation": {"uri": "src/config/.env.staging"},
          "region": {"startLine": 14, "charOffset": 218}
        }
      }],
      "properties": {
        "verification": "skipped",
        "evidence_tier": "likely",
        "evidence_reason_code": "vendor-pattern",
        "evidence_provenance": {
          "schema_version": 1,
          "detector_digest": "0123456789abcdef",
          "pattern_index": 0,
          "candidate_channel": "pattern",
          "source_role": "environment-assignment-value",
          "context_class": "vendor-pattern"
        },
        "evidence_score": 1.0,
        "cwe": "CWE-798",
        "owasp": "A07:2021",
        "remediation.action": "Roll the exposed Stripe secret key in the Dashboard, update production consumers, then delete the old key."
      }
    }],
    "properties": {
      "keyhog.scan.status": "success",
      "keyhog.backend.recoveries": []
    }
  }]
}
```

The full document also contains `$schema`, `tool.driver`, rules, taxonomies,
optional fixes, and partial fingerprints. Consume those fields from the file
rather than treating the abbreviated example as a complete SARIF document.
`runs[0].properties["keyhog.scan.status"]` carries the terminal state. When
coverage gaps exist, SARIF includes `invocations[0]`,
`executionSuccessful` is `false`, and the exact reasons appear in
`toolExecutionNotifications`. Consumers must still read `keyhog.scan.status`
because a cancelled or failed artifact is allowed to have no coverage
notification.

Upload to GitHub even when the scan found credentials:

```yaml
- name: Scan
  id: keyhog
  continue-on-error: true
  run: keyhog scan . --format sarif --output keyhog-results.sarif

- uses: github/codeql-action/upload-sarif@dd903d2e4f5405488e5ef1422510ee31c8b32357 # v3
  if: always() && hashFiles('keyhog-results.sarif') != ''
  with:
    sarif_file: keyhog-results.sarif

- name: Enforce KeyHog result
  if: always()
  env:
    KEYHOG_OUTCOME: ${{ steps.keyhog.outcome }}
  run: test "$KEYHOG_OUTCOME" = success
```

The final step fails for any nonzero KeyHog exit. If your policy permits
unverified findings but rejects live credentials, capture the numeric exit in a
wrapper instead of using the GitHub step outcome.

## `--format github-annotations`

GitHub Actions workflow commands emit one annotation line per finding.
Use this when you want findings to appear inline in the Actions log
without uploading SARIF:

```sh
keyhog scan . --format github-annotations
```

Critical and high findings render as `error` annotations, medium and low as
`warning`, and info as `notice`. Each annotation carries the file, line, title,
detector, service, redacted credential, verification state, exact evidence
tier and reason code, and optional evidence score. The plaintext credential is
not emitted.
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
`status: "complete"`, a `scan_status` of `success`,
`complete_after_recovery`, `partial`, `cancelled`, or `failed`, the exact
finding count, and the coverage-gap summary.
An empty scan still emits both header and summary. A stream without the final
summary is interrupted and must not be treated as complete; concatenated
streams are split at the next header. Importers must validate both records
before accepting the stream. This is better than `--format json-envelope` for
streaming consumers that want to start processing before the scan finishes.

Retain the stream while you consume it, so you can check the summary the rule
above requires:

```sh
keyhog scan /huge/monorepo --format jsonl-envelope \
  | tee keyhog.jsonl \
  | jq -r 'select(.record_type == null) | .location.file_path'

jq -e 'select(.record_type == "summary")
       | .scan_status == "success" or .scan_status == "complete_after_recovery"' \
  keyhog.jsonl
```

The second command exits nonzero when the summary is missing or reports an
incomplete scan: `jq -e` returns `4` when the summary record is absent
entirely, and `1` when it is present but the status is not one of those two. A
consumer that reads only the finding lines and stops cannot tell a finished
scan from a truncated one, because the finding records look identical in both.

## Combining with `--verify`

`--verify` sends eligible findings to the detector's declared verification
endpoint. A `live` result keeps its severity. A `dead` or `revoked` result
downgrades it by one tier. The machine value is one of `"live"`, `"dead"`,
`"revoked"`, `"rate_limited"`, `"unverifiable"`, `"skipped"`, or an
`{"error":"..."}` object.

```sh
set +e
keyhog scan . --verify --format json-envelope --output keyhog-results.json
status=$?
set -e

jq -e '.scan_status == "success" or
       .scan_status == "complete_after_recovery"' keyhog-results.json
jq '.findings[] | select(.verification == "live")' keyhog-results.json
test "$status" -ne 10
```

The first `jq` rejects incomplete input. The second emits only live findings.
The final command enforces the documented live-credential exit while permitting
exit `1`. Select `default` or `paranoid` evidence policy to control which
non-live finding tiers produce exit `1`.

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

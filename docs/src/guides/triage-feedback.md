# Triage and feedback interchange

`keyhog triage` imports a versioned redacted finding envelope and emits two
distinct, secret-safe artifacts: runtime suppressions for the scanner and
feedback observations for pattern training.

```sh
keyhog triage \
  --input envelope.json \
  --suppressions suppressions.json \
  --pattern-feedback pattern-feedback.json
```

## Purpose and separation of concerns

Scanning at scale produces findings that need operator review. Once reviewed,
decisions diverge into two operational tracks:

1. **Runtime suppressions** (`--suppressions`): Scoped rules that prevent the
   scanner from reporting a reviewed finding in future runs.
2. **Pattern feedback** (`--pattern-feedback`): Validated true-positive and
   false-positive observations consumed by model retraining and detector tuning
   loops.

The two outputs have different lifecycles and scopes. A runtime suppression
applies to a specific finding, path, or repository. A pattern feedback record
informs detector and model weights across the entire detector corpus. Keeping
the outputs in separate files ensures that model training data cannot
accidentally act as an unreviewed runtime bypass.

## Input envelope format

The input file is a versioned JSON envelope containing reviewed finding records.
Every record carries cryptographic digests and provenance metadata; no
plaintext credentials, context snippets, or raw file paths are accepted.

```json
{
  "version": 1,
  "detector_digest": "0123456789abcdef",
  "records": [
    {
      "finding_hash": "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "detector_id": "stripe-secret-key",
      "provenance": {
        "schema_version": 1,
        "detector_digest": "0123456789abcdef",
        "pattern_index": 0,
        "candidate_channel": "pattern",
        "source_role": "environment-assignment-value",
        "context_class": "vendor-pattern"
      },
      "context_digest": "blake3:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
      "disposition": "dismissed",
      "reason": "false-positive",
      "scope": {
        "path": {
          "path_hash": "blake3:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        }
      }
    }
  ]
}
```

### Required envelope fields

| Field | Type | Description |
|---|---|---|
| `version` | `u32` | Envelope format version (must be `1`). |
| `detector_digest` | `string` | 16-character lowercase hexadecimal digest of the active detector corpus. Must match the running binary's embedded corpus. |
| `records` | `array` | List of reviewed finding records. |

### Record fields

| Field | Type | Description |
|---|---|---|
| `finding_hash` | `string` | Prefixed `blake3:<64-hex>` hash of the finding. |
| `detector_id` | `string` | Stable identifier of the detector that fired. |
| `provenance` | `object` | Secret-safe pattern and source-role provenance from the scan report. |
| `provenance.schema_version` | `u32` | Provenance schema version (must be `1`). |
| `provenance.detector_digest` | `string` | 16-hex detector digest matching the envelope root. |
| `provenance.pattern_index` | `u32 \| null` | 0-indexed pattern ordinal within the detector TOML, or `null` for entropy/generic channels. |
| `provenance.candidate_channel` | `string` | Channel that created the candidate: `pattern`, `entropy`, `companion`, `static-recovery`, or `unattributed`. |
| `provenance.source_role` | `string` | Semantic source role where the secret was matched (e.g. `environment-assignment-value`, `code-literal`, `standalone-token`). |
| `provenance.context_class` | `string` | Context classification (e.g. `vendor-pattern`, `weak-anchor`, `generic-assignment`, `standalone-token`, `unsupported-context`). |
| `context_digest` | `string` | Prefixed `blake3:<64-hex>` digest of the surrounding context window. |
| `disposition` | `string` | Review disposition: `dismissed`. |
| `reason` | `string` | Typed reason: `false-positive`, `test-fixture`, `accepted-risk`, `mitigated`. |
| `scope` | `object` | Scoping rule for the suppression. |

### Scopes

Each record specifies exactly one scope variant:

| Scope | JSON structure | Behavior |
|---|---|---|
| `exact` | `{"exact": {}}` | Suppresses only this exact finding hash. |
| `path` | `{"path": {"path_hash": "blake3:<64-hex>"}}` | Suppresses findings with this detector and pattern at the specified path hash. |
| `repository` | `{"repository": {"repository_hash": "blake3:<64-hex>"}}` | Suppresses findings with this detector and pattern across the specified repository hash. |
| `pattern-feedback-only` | `{"pattern_feedback_only": {}}` | Emits a training feedback record only. Never creates a runtime suppression. |

## Generated outputs

### Runtime suppressions (`--suppressions`)

Runtime suppressions contain only reviewed dismissal records for `exact`, `path`,
and `repository` scopes. Records with `pattern-feedback-only` scope are excluded.

```json
{
  "version": 1,
  "detector_digest": "0123456789abcdef",
  "suppressions": [
    {
      "finding_hash": "blake3:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
      "detector_id": "stripe-secret-key",
      "provenance": {
        "schema_version": 1,
        "detector_digest": "0123456789abcdef",
        "pattern_index": 0,
        "candidate_channel": "pattern",
        "source_role": "environment-assignment-value",
        "context_class": "vendor-pattern"
      },
      "scope": {
        "path": {
          "path_hash": "blake3:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
        }
      },
      "reason": "false-positive"
    }
  ]
}
```

### Pattern feedback (`--pattern-feedback`)

Pattern feedback contains training observations from all valid records, including
those scoped as `pattern-feedback-only`.

```json
{
  "version": 1,
  "detector_digest": "0123456789abcdef",
  "feedback": [
    {
      "detector_id": "stripe-secret-key",
      "provenance": {
        "schema_version": 1,
        "detector_digest": "0123456789abcdef",
        "pattern_index": 0,
        "candidate_channel": "pattern",
        "source_role": "environment-assignment-value",
        "context_class": "vendor-pattern"
      },
      "context_digest": "blake3:fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210",
      "reason": "false-positive",
      "source_role": "environment-assignment-value"
    }
  ]
}
```

## Security and isolation guarantees

The triage subsystem is built to operate safely on untrusted feedback artifacts:

- **No secret leakage:** Plaintext credentials, unredacted tokens, and raw
  context strings are never accepted, stored, or emitted. All finding and
  context identities are cryptographic digests.
- **No path leakage:** File paths and repository URLs are replaced with BLAKE3
  hashes before interchange.
- **Corpus digest binding:** The envelope's `detector_digest` must match the
  running binary's compiled detector corpus. Stale or cross-version envelopes are
  rejected before processing.
- **Descriptor-relative I/O (Unix):** All file operations use
  descriptor-relative system calls (`openat`, `unlinkat`) with `O_NOFOLLOW` and
  `O_CREAT | O_EXCL` flags. This prevents symbolic link traversal and time-of-check
  to time-of-use (TOCTOU) race conditions.
- **Destination collision prevention:** `--input`, `--suppressions`, and
  `--pattern-feedback` paths must all be distinct. Existing output files are
  refused to prevent accidental overwrites.
- **Bounded resource consumption:** Input size is capped at 16 MiB
  (`MAX_TRIAGE_INPUT_BYTES`); output files are capped at 32 MiB
  (`MAX_TRIAGE_OUTPUT_BYTES`).
- **Platform fail-closed:** On Windows or platforms lacking safe
  descriptor-relative directory I/O, `keyhog triage` exits with an explicit
  error without reading or writing files.

# keyhog CLI SPEC

`keyhog` is the command-line entry point for the KeyHog workspace. It loads detector specifications, configures source readers and scanner settings, applies allowlists and baselines, and emits findings.

## Guarantees

- CLI output is selected by the requested output mode.
- Operational progress goes to stderr.
- Scanner, source, verifier, and baseline behavior is configured from explicit CLI options and config files.
- Exit status distinguishes clean scans, findings, user errors, and system errors.
- `keyhog triage` accepts only the current bounded redacted envelope with the 16-hex active detector digest and authoritative scanner pattern index, candidate channel, source role, and context class, then creates distinct versioned runtime-suppression and pattern-feedback artifacts without plaintext credential, context, or path fields.

## Boundaries

The CLI orchestrates library crates and keeps scanning logic in `keyhog-scanner`, source enumeration in `keyhog-sources`, and live checks in `keyhog-verifier`.

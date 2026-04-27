# keyhog CLI SPEC

`keyhog` is the command-line entry point for the Keyhog workspace. It loads detector specifications, configures source readers and scanner settings, applies allowlists and baselines, and emits findings.

## Guarantees

- CLI output is selected by the requested output mode.
- Operational progress goes to stderr.
- Scanner, source, verifier, and baseline behavior is configured from explicit CLI options and config files.
- Exit status distinguishes clean scans, findings, user errors, and system errors.

## Boundaries

The CLI orchestrates library crates and keeps scanning logic in `keyhog-scanner`, source enumeration in `keyhog-sources`, and live checks in `keyhog-verifier`.

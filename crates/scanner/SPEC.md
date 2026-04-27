# keyhog-scanner SPEC

`keyhog-scanner` compiles detector specifications into executable matchers and scans text chunks for credential candidates. It combines literal prefiltering, regex fallback, entropy scoring, decode-through scanning, context scoring, and optional acceleration features.

## Guarantees

- Scanner input is bounded by configured chunk, decode, and match limits.
- Decode-through scanning tracks seen decoded payloads to prevent repeated expansion.
- Findings preserve detector identity, source location, severity, confidence, and credential hash.
- Optional acceleration backends must preserve the same match semantics as the default scanner path.

## Boundaries

This crate consumes `keyhog-core` types and does not enumerate files, git history, cloud sources, or verify live credentials.

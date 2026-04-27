# keyhog-sources SPEC

`keyhog-sources` turns input locations into bounded `Chunk` streams for the scanner. It supports filesystem, archive, git, web, Docker, GitHub, Slack, and S3 inputs behind feature flags.

## Guarantees

- Source readers enforce size bounds before returning chunks.
- Filesystem reads avoid symlink following by default.
- Built-in exclusions skip generated dependency and build artifacts.
- Remote-source features are opt-in through Cargo features and CLI flags.

## Boundaries

This crate does not detect secrets or verify credentials. It only yields input chunks and metadata for `keyhog-scanner`.

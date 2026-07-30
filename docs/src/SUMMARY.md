# Summary

[Introduction](./introduction.md)
[Choose a scanning workflow](./capabilities.md)

# Getting started

- [Install](./install.md)
- [Your first scan](./first-scan.md)
- [Read and export findings](./output-formats.md)
- [Recipes](./recipes.md)

# Repository gates

- [Pre-commit secret scanning](./workflows/precommit.md)
- [GitHub Action secret scanning](./workflows/github-action.md)
- [CI secret scanning](./workflows/ci.md)
- [Scan Git history and recover hidden credentials](./guides/deep-recovery.md)

# Large inventories

- [Mass repository and cloud inventory scanning](./guides/mass-scanning.md)
- [GitHub collaboration scans](./workflows/github-collaboration.md)
- [System-wide credential triage](./guides/system-wide-triage.md)
- [Archives and compressed sources](./source-archives.md)
- [HTTP and wire captures](./http-wire.md)

# Performance and backend selection

- [CPU, Hyperscan, GPU, and automatic routing](./backends.md)
- [Autoroute calibration](./reference/autoroute-calibration.md)
- [Daemon and warm scans](./workflows/daemon.md)

# Detection policy and trust

- [How detection works](./detection.md)
- [Detectors and custom corpora](./detectors.md)
- [Suppressions and baselines](./suppressions.md)
- [Credential verification](./verification.md)
- [Confidence calibration](./reference/confidence-calibration.md)
- [Hardening and data handling](./hardening.md)
- [Security](./security.md)

# Reference

- [CLI reference](./reference/cli.md)
- [Configuration and precedence](./reference/configuration.md)
- [Environment variables](./reference/env.md)
- [Exit codes](./reference/exit-codes.md)
- [`.keyhogignore.toml`](./reference/keyhogignore-toml.md)
- [Out-of-band verification](./reference/oob-verification.md)
- [VYRE integration](./reference/vyre-integration.md)
- [Other integrations](./workflows/integrations.md)

# Internals and project

- [Architecture](./architecture.md)
- [Contributing](./contributing.md)
- [Prepare and publish a release](./releasing.md)
- [Changelog](./changelog.md)

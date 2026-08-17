# Summary

[Introduction](./introduction.md)
[Choose a scanning workflow](./capabilities.md)
[Pick your input shape](./workloads.md)

# Getting started

- [Install](./install.md)
- [Your first scan](./first-scan.md)
- [Read and export findings](./output-formats.md)
- [Source and endpoint recipes](./recipes.md)

# Repository gates

- [Perpetual repository and filesystem guard](./workflows/guard.md)
- [Pre-commit secret scanning](./workflows/precommit.md)
- [GitHub Action secret scanning](./workflows/github-action.md)
- [CI secret scanning](./workflows/ci.md)
- [Scan Git history and recover hidden credentials](./guides/deep-recovery.md)
# Input shapes

- [File shapes and sizes](./guides/file-shapes.md)
- [Container images and OCI layers](./guides/container-images.md)
- [Standard input and pipelines](./guides/stdin-and-pipelines.md)
- [Watch mode](./guides/watch-mode.md)

# Inventory, endpoint, and host scans

- [Mass repository and cloud scanning](./guides/mass-scanning.md)
- [GPU-backed daemon file queues](./workflows/daemon.md)
- [GitHub collaboration scans](./workflows/github-collaboration.md)
- [System-wide credential triage](./guides/system-wide-triage.md)
- [Archives and compressed sources](./source-archives.md)
- [HTTP endpoints and wire captures](./http-wire.md)

# Performance, worker sizing, and routing

- [CPU, Hyperscan, GPU, and automatic routing](./backends.md)
- [Performance evidence and comparison](./performance-evidence.md)
- [Autoroute calibration](./reference/autoroute-calibration.md)

# Detection policy and trust

- [How detection works](./detection.md)
- [Detectors and custom corpora](./detectors.md)
- [Write a detector](./guides/authoring-detectors.md)
- [Suppressions and baselines](./suppressions.md)
- [Triage and feedback interchange](./guides/triage-feedback.md)
- [Credential verification](./verification.md)
- [Access targets](./guides/access-targets.md)
- [Confidence calibration](./reference/confidence-calibration.md)
- [Hardening and data handling](./hardening.md)
- [Security](./security.md)

# Reference

- [CLI reference](./reference/cli.md)
- [Configuration and precedence](./reference/configuration.md)
- [Environment variables](./reference/env.md)
- [Exit codes](./reference/exit-codes.md)
- [`.keyhogignore.toml`](./reference/keyhogignore-toml.md)
- [Tell a real clean from a skipped input](./reference/coverage-truth.md)
- [Out-of-band verification](./reference/oob-verification.md)
- [Other integrations](./workflows/integrations.md)
  - [Git hook managers](./workflows/integrations/git-hooks.md)
  - [CI systems](./workflows/integrations/ci-systems.md)
  - [Embedding KeyHog](./workflows/integrations/embedding.md)
  - [Alerts and notifications](./workflows/integrations/alerts.md)
- [VYRE integration](./reference/vyre-integration.md)

# Internals and project

- [Architecture](./architecture.md)
- [Contributing](./contributing.md)
- [Releases](./releasing.md)
- [Changelog](./changelog.md)

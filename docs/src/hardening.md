# Hardening and data handling

A secret scanner reads credentials into memory. This chapter states which
process protections KeyHog applies, which commands can use the network, and
where the guarantees stop. For vulnerability reporting, see the
[security policy](./security.md).

## Start with the boundary

A normal local scan does not send findings, filenames, or telemetry away from
the host:

```sh
keyhog scan . --daemon=off
```

Filesystem, local Git, archive extraction, decoding, detection, suppression,
and reporting remain local. Network access begins only when you select an
operation that needs it.

| Operation | Why it can use the network |
|---|---|
| `scan --url`, `--github-org`, `--github-collaboration`, `--gitlab-group`, `--bitbucket-workspace`, `--s3-bucket`, `--gcs-bucket`, or `--azure-container-url` | Reads the remote source you named. |
| `scan --verify` | Sends credential-derived requests for detectors that have a live verification plan. Out-of-band verification can also wait for callbacks. |

The detector corpus and detector-owned validators are local. Offline validators
such as checksum or payload-shape checks do not contact the service.

## In-process scan hardening

The one-shot `scan` orchestrator and `scan-system` apply process protections
before reading scan input:

- On Linux, `prctl(PR_SET_DUMPABLE, 0)` disables ordinary core dumps,
  same-user `ptrace` attachment, and same-user `/proc/<pid>/mem` access.
- On macOS, `ptrace(PT_DENY_ATTACH, ...)` denies debugger attachment.
- On Windows, KeyHog does not currently wire WER dump suppression or an
  equivalent debugger-denial policy. The scan records that hardening gap.

These protections are best effort during a normal scan. A failure is logged and
the scan continues. They are not applied merely because another subcommand was
invoked. In particular, `watch` and the long-lived daemon do not pass through
the one-shot scan hardening call.

Do not treat these controls as protection from a privileged host
administrator. Run KeyHog inside the same host trust boundary as the data it
scans.

## Lockdown mode

`--lockdown` is a Linux-only, fail-closed mode for `scan` and `scan-system`.
Run it only after granting enough locked-memory allowance for the process:

```sh
keyhog scan . --daemon=off --lockdown
```

For `scan`, lockdown:

- calls `mlockall(MCL_CURRENT | MCL_FUTURE)` so current and future process
  pages stay resident;
- sets `RLIMIT_CORE` to zero and checks `/proc/self/coredump_filter`; it fails
  only if the dump limit cannot be set and the filter still permits a dump;
- checks the default KeyHog cache root and any selected incremental-cache path
  for persistence artifacts that could contain past scan state;
- allows validated `KHHS` Hyperscan pattern-database shards because they contain
  compiled detector automata, not findings or credentials;
- disables incremental cache use with a warning;
- refuses `--verify` and `--show-secrets`;
- refuses `--fast`, `--no-default-excludes`, `--no-unicode-norm`,
  `--no-decode`, `--no-entropy`, and `--no-ml`.

The daemon route is not eligible for a lockdown scan. `scan-system --lockdown`
also refuses `--include-network`. On macOS and Windows, memory locking for this
mode is not implemented, so lockdown fails rather than claiming a no-swap
guarantee.

## Credentials in memory and reports

Reported credential bytes are stored in the `Credential` type and zeroized when
that buffer is dropped. This protects that owned buffer. It is not a claim that
every temporary source or decoder allocation has never held the same bytes.

Reports redact credentials by default. `--show-secrets` explicitly requests
plaintext output and is rejected by lockdown. Treat any plaintext terminal,
pipe, or report file as secret-bearing data.

## Binary replacement

KeyHog has no self-update path. There is no signed binary-asset release
channel: automatic releases publish crates.io packages only, and no workflow
builds, signs, or uploads release binaries.

Update with `cargo install --locked --force keyhog`; see
[Install](./install.md). `install.sh` and `install.ps1` install a bundle you
already hold, with `--from-file`, and never fetch one.

## Related operator references

- [Environment variables](./reference/env.md) lists every direct production
  environment read and the platform directory variables that affect paths.
- [Exit codes](./reference/exit-codes.md) explains how hardening and other setup
  failures reach automation.
- [Daemon and warm scans](./workflows/daemon.md) documents the separate daemon
  process and its eligibility boundary.

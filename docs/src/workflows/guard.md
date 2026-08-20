# Perpetual repository and filesystem guard

The guard is a daemon-resident runtime that registers Git repositories and
filesystem trees as guarded roots. It maintains an in-memory clean Git object
attestation index and filesystem event tracking, enabling sub-second pre-commit
scanning on staged changes without cold-start detector compilation or redundant
file I/O.

Guard requires the Unix-domain daemon transport. On Windows, `keyhog guard`
exits with an unsupported-platform error; use `keyhog scan <path>` in process.

The guard supplements staged and working-tree scans. It does not replace them.
A commit is allowed only after the exact staged-object transaction proves the
staged content is clean.

## Three-step quickstart

1. Register the repository:
   ```sh
   keyhog guard add /path/to/repo
   ```
   Registers the repository with the guard daemon and installs the managed pre-commit hook at `.git/hooks/pre-commit`.

2. Start the daemon (if not already running):
   ```sh
   keyhog guard up
   ```
   Ensures the background daemon process is active and ready to handle scan requests. One daemon process serves all registered repositories.

3. Stage changes and commit:
   ```sh
   git add <files>
   git commit -m "commit message"
   ```
   The pre-commit hook runs `keyhog scan --git-staged` against the daemon, verifies staged object IDs against cached attestations, and blocks the commit if credentials are detected.

## Core mental model

1. **One-command registration (`keyhog guard add <path>`)**: Indexes the target
   repository into daemon memory once and establishes clean baseline attestations.
2. **Fast staged commit gating (`keyhog scan --git-staged`)**: Pre-commit
   hooks query the active guard daemon. The daemon verifies only changed staged
   blob OIDs against in-memory attestations, skipping unchanged clean payloads.
3. **Full lifecycle control**: List active roots with `keyhog guard list`, check
   memory and attestation metrics with `keyhog guard status <path>`, and free
   daemon memory immediately with `keyhog guard remove <path>` when finished
   working on a project.

## Lifecycle commands

| Command | Purpose |
|---|---|
| `keyhog guard up [--backend <name>]` | Start or ensure the background guard daemon is running and ready. Reconciles registered roots loaded from durable store. |
| `keyhog guard down` | Stop the background guard daemon cleanly. Persisted root registrations and durable indexes remain on disk. |
| `keyhog guard add <path> [--mode repo]` | Register a repository or tree for continuous guard protection. Performs initial baseline reconciliation and installs hook before returning. |
| `keyhog guard list` | Enumerate all registered guard roots, their active states, and terminal sequences. Reads durable store when daemon is offline. |
| `keyhog guard feed [--root <path>] [--limit <N>]` | Inspect continuous state machine transitions and event log with causal attribution across roots. |
| `keyhog guard status [<path>] [--format human|json]` | Print detailed metrics for a guarded root (including policy digest and recent transitions) or summarize all registered roots when path is omitted. Works offline via durable store. |
| `keyhog guard remove <path>` | Stop guarding a repository and drop its in-memory index and attestation cache to immediately free daemon memory and CPU. |
| `keyhog guard reconcile <path>` | Force a full baseline reconciliation after intentional policy updates or mass branch operations. |
| `keyhog guard rebuild <path>` | Delete and recreate the durable guard store for a root after corruption or irrecoverable state. |

## Detailed walkthrough

### 1. Start the daemon

```sh
keyhog guard up
```

`guard up` ensures the daemon is active in the background, compiles the active
934-detector corpus once, and stays resident in memory. One daemon process serves
all guarded repositories and scan requests.
### 2. Register a repository

```sh
keyhog guard add /path/to/repo --mode repo
```

- `--mode repo` (default): Uses Git object IDs (OIDs) for exact immutable
  staged-content identification, and automatically installs the managed
  pre-commit hook at `.git/hooks/pre-commit` (best-effort; skipped if a foreign
  hook already exists, or if `--no-hook` is passed).
- `--mode filesystem`: Uses file content hashes without Git OIDs.

The command waits for initial baseline reconciliation to complete before
returning:

```text
OK guard: root /path/to/repo registered (state stopped, sequence 1)
OK guard: reconciliation complete, root is current
```

### 3. Check guarded status

Inspect in-memory metrics, cache efficiency, and policy binding:

```sh
keyhog guard status /path/to/repo
```

Human-readable output:

```text
root:           /path/to/repo
mode:           repo
state:          current
sequence:       2
accepted seq:   2
completed seq:  2
pending events: 0
files scanned:  142
bytes scanned:  1849204
cache hits:     0
cache misses:   142
findings:       0
coverage gaps:  0
initial recon:  2026-08-17T00:15:00Z
last recon:     2026-08-17T00:15:00Z
residency:      resident
backend route:  gpu-cuda-region-presence
build digest:   1a2b3c4d5e6f7a8b
detector:       934-dc43f6629978321b
suppression:    0000000000000000
config:         18cc6ed841bf6dfe
autoroute:      calibrated
store schema:   1
```

Structured JSON output for monitoring and scripts:

```sh
keyhog guard status /path/to/repo --format json
```

### 4. Run instant staged commit scans

Inside the guarded repository, run:

```sh
keyhog scan --git-staged
```

The command connects to the guard daemon via Unix domain socket, checks the
staged Git blob OIDs against in-memory attestations, and returns in milliseconds.

- **Clean commit outcome**:

```text
  No secrets detected in the scanned files.
```

- **Blocked commit outcome**:

```text
  ┌    CRITICAL ─── OpenAI API Key
  │ Secret:     sk-9...M8vZ
  │ Location:   client.ts:4
  │ Evidence:   likely/vendor-pattern  ■■■■■■ 100%
  │ Entropy:    5.383 bits/byte
  │ Action:     Revoke immediately at the provider, rotate dependent credentials, and audit recent usage.
  └─────────────────────────────────────────────

  ━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  1 secret found · 1 unverified
  ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
```

### 5. List all guarded repositories

Check which repositories are currently guarded:

```sh
keyhog guard list
```

Output:

```text
OK 2 guard roots registered
  /path/to/repo-a  current  seq=14
  /path/to/repo-b  current  seq=3
```

### 6. Free resources when finished
When you finish working on a project, remove it from the guard to immediately
reclaim daemon memory and watcher resources:

```sh
keyhog guard remove /path/to/repo
```

`guard remove` unregisters the root from the daemon and removes any KeyHog-owned
pre-commit hook by default (pass `--keep-hook` to preserve the hook).
You can re-add the repository at any time with `keyhog guard add /path/to/repo`.

## Pre-commit hook integration

### Standalone Git hook

Create or update `.git/hooks/pre-commit` in your repository:

```bash
#!/usr/bin/env bash
set -euo pipefail

# Run staged scan against guard daemon (falls back to in-process if daemon is off)
keyhog scan --git-staged
```

Make the script executable:

```sh
chmod +x .git/hooks/pre-commit
```

### `pre-commit` framework

Add the following to `.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/santhreal/keyhog
    rev: v0.5.80
    hooks:
      - id: keyhog
        stages: [pre-commit]
```

## Bypassing checks and suppressing test fixtures

### Emergency single-commit bypass

To bypass the pre-commit hook for a single urgent commit:

```sh
git commit --no-verify -m "urgent fix"
```

This bypasses local Git hooks. Use it sparingly.

### Suppressing intentional test fixtures and false positives

When committing intentional test fixtures, mock data, or vendor example keys:

1. **Suppress by credential hash (`.keyhogignore`)**:
   Add the SHA-256 hash of the value to `.keyhogignore`:
   ```text
   hash:5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8
   ```
2. **Scoped suppression (`.keyhogignore.toml`)**:
   Target the exact detector and file path in `.keyhogignore.toml`:
   ```toml
   [[suppress]]
   detector = "stripe-secret-key"
   path_eq = "tests/fixtures/mock_stripe.env"
   reason = "reviewed synthetic test fixture"
   ```
3. **Inline source directive**:
   Append `// keyhog:ignore detector=<detector-id>` or
   `# keyhog:ignore detector=<detector-id>` directly to the source line.
   Without `detector=`, the directive suppresses every finding on that line.
After committing the suppression rule, run `keyhog guard reconcile <path>` if you
need to update the in-memory baseline immediately.

## Guard state machine

Every guarded root operates within a 7-state machine owned by `GuardRootState`:

| From State | Event / Trigger | Target State | Description |
|---|---|---|---|
| `stopped` | `ReconciliationStarted` | `indexing` | Baseline reconciliation begins. |
| `indexing` | `ReconciliationClean` | `current` | Baseline scan completed with zero blocking findings. |
| `indexing` | `ReconciliationFindings` | `blocked` | Baseline scan detected blocking secrets. |
| `indexing` | `ReconciliationDegraded` / `CoverageLost` | `degraded` | Incomplete coverage during reconciliation. |
| `indexing` | `PolicyChanged` | `stale-policy` | Detector corpus, suppressions, or config changed during scan. |
| `current` | `EventAccepted` | `dirty` | Filesystem change accepted; pending events await scan. |
| `current` | `CoverageLost` | `degraded` | Filesystem watcher overflow or read error. |
| `current` | `PolicyChanged` | `stale-policy` | Detector corpus, suppressions, or config modified. |
| `blocked` | `EventAccepted` | `dirty` | Filesystem change accepted in blocked repository. |
| `blocked` | `CoverageLost` | `degraded` | Coverage lost while blocked. |
| `blocked` | `PolicyChanged` | `stale-policy` | Policy modified while blocked. |
| `dirty` | `EventsClean` | `current` | Changed files scanned cleanly; all findings resolved. |
| `dirty` | `EventsFindings` | `blocked` | Changed files contain blocking secrets. |
| `dirty` | `EventsDegraded` / `CoverageLost` | `degraded` | Incomplete coverage during incremental scan. |
| `dirty` | `PolicyChanged` | `stale-policy` | Policy modified while processing dirty events. |
| `degraded` | `RepairStarted` | `indexing` | Manual `keyhog guard reconcile` or `rebuild` triggered. |
| `stale-policy` | `RepairStarted` | `indexing` | Manual `keyhog guard reconcile` or `rebuild` triggered. |
| *any state* | `Stopped` | `stopped` | Root unregistered with `keyhog guard remove` or daemon shutdown. |
### Process exit codes

`keyhog guard status` and `keyhog scan --git-staged` enforce strict exit semantics:

| Exit Code | Condition |
|---|---|
| `0` | Root is `current`, or staged scan contains zero blocking secrets under the active policy. |
| `1` | Root is `blocked`, or staged scan contains a finding that blocks the evidence policy. |
| `13` | Root is `dirty`, `stopped`, `indexing`, `degraded`, or `stale-policy` (incomplete proof of cleanliness). |

## How clean attestations work

When KeyHog scans a staged Git blob and detects zero unsuppressed secrets, it
records a clean attestation record keyed by four immutable elements:

1. **Blob Git OID**: The SHA-1 or SHA-256 object hash of the staged blob.
2. **Byte Length**: The exact byte length of the blob payload.
3. **Policy Identity Digest**: The 32-byte digest of the active detector corpus,
   suppression rules, and scanner configuration.
4. **Sorted Source-Path Set**: The hashed set of all sorted staged source paths
   mapped to that blob.

Future commit transactions matching all four elements skip payload re-scanning
and return an instant cache hit. If a file is renamed, moved across source roles,
or an alias is added, the attestation is invalidated. Persisted policy identity
records contain no plaintext staged paths.
## Guard configuration

The guard runtime resolves settings from the `[guard]` table in `.keyhog.toml`:

```toml
[guard]
# Periodic scrub interval for `current` roots (e.g. "5m", "24h").
# Default: disabled.
# scrub_interval = "5m"

# Durable redb state database path (default: disabled, ephemeral memory).
# state_path = "~/.local/state/keyhog/guard.redb"

# Memory budget ceiling for hot clean attestation index (default: "64MB").
# hot_index_memory = "64MB"

# Maximum queued filesystem events per root before degraded status (default: 8192).
# max_pending_events_per_root = 8192

# Maximum total queued filesystem events across all roots (default: 65536).
# max_pending_events_total = 65536

# Event coalescing window before applying state transitions (default: "100ms").
# coalesce_window = "100ms"

# Scanner residency mode: "warm" (keep loaded) or "idle-unload" (unload after idle timeout).
# scanner_residency = "warm"

# Scanner idle timeout before reporting `idle-unload` residency (default: "5m").
# scanner_idle_timeout = "5m"
# Maximum files scanned during one subtree reconciliation (default: 10000).
# subtree_max_files = 10000

# Maximum directory depth during subtree reconciliation (default: 64).
# subtree_max_depth = 64
```

| Setting | Type | Default | Description |
|---|---|---|---|
| `scrub_interval` | string | disabled | Periodic re-scan interval for `current` roots (e.g. `5m`, `24h`). Catches changes that filesystem events missed. |
| `state_path` | string | disabled | Durable guard state path (e.g. `~/.local/state/keyhog/guard.redb`). Persists root records and attestations across daemon restarts. Ignored in lockdown mode (guard operates in ephemeral memory). |
| `hot_index_memory` | string | 64MB | Hot clean attestation index memory budget (e.g. `64MB`). |
| `max_pending_events_per_root` | integer | 8192 | Maximum queued filesystem events per root before degraded status. |
| `max_pending_events_total` | integer | 65536 | Maximum total queued filesystem events across all roots before degraded status. |
| `coalesce_window` | string | 100ms | Event coalescing window before applying state transitions. |
| `scanner_residency` | string | warm | Scanner residency mode (`warm` or `idle-unload`). |
| `scanner_idle_timeout` | string | 5m | Scanner idle-unload timeout. After this duration without guard activity, residency reports `idle-unload`. |
| `subtree_max_files` | integer | 10000 | Maximum files for one subtree reconciliation. |
| `subtree_max_depth` | integer | 64 | Maximum depth for one subtree reconciliation. |

## Durable state persistence

By default, guard state is held in daemon memory. To persist root registrations
and clean attestations across daemon restarts, configure `state_path` in
`.keyhog.toml`:

```toml
[guard]
state_path = "~/.local/state/keyhog/guard.redb"
```

The durable store uses a high-performance redb database with owner-only (0600)
file permissions, enforces 0700 permissions on its parent directory, and rejects
symlinked state paths.
On daemon restart, persisted roots load in the `stopped` state. Running
`keyhog guard reconcile /path/to/repo` re-verifies the repository and transitions
it back to `current`.

In lockdown mode (`[lockdown] require = true`), durable persistence is
disabled and the guard operates strictly in ephemeral memory.

## Periodic scrubbing

Configure `scrub_interval` in `.keyhog.toml` to periodically re-verify `current`
repositories:

```toml
[guard]
scrub_interval = "24h"
```

Scrubbing detects modifications made outside standard kernel filesystem events (such as
NFS mounts, container volume mutations, or out-of-band Git object manipulation).

### Unauthoritative filesystems

When registering a root, KeyHog automatically probes the backing filesystem type.
Local filesystems (such as `ext4`, `btrfs`, `xfs`, `apfs`, and `ntfs`) generate kernel change
events reliably and are classified as authoritative.

Network filesystems (`nfs`, `cifs`/`smb`, `9p`, `afs`, `ceph`), userspace/virtual filesystems
(`fuse`, `overlay`), and unrecognized filesystem types do not reliably generate real-time local
kernel notifications. When an unauthoritative filesystem is registered and no operator
`scrub_interval` is configured, KeyHog enforces a default 60-second periodic scrub interval
to guarantee that remote modifications are caught.

When the scrub interval elapses, each `current` root automatically transitions to
`dirty` for re-reconciliation.
## Recovering corrupted roots

If a repository's durable state becomes corrupt or desynchronized, rebuild it:

```sh
keyhog guard rebuild /path/to/repo
```

`rebuild` clears the root's durable database entries, re-registers the root, and
triggers a clean baseline reconciliation.

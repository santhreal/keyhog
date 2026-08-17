# Perpetual repository and filesystem guard

The guard is a daemon-resident runtime that registers Git repositories and
filesystem trees as guarded roots. It maintains in-memory Merkle trees and clean
Git object attestations, enabling sub-millisecond pre-commit scanning on staged
changes without cold-start detector compilation or redundant file I/O.

Guard requires the Unix-domain daemon transport. On Windows, `keyhog guard`
exits with an unsupported-platform error; use `keyhog scan <path>` in process.

The guard supplements staged and working-tree scans. It does not replace them.
A commit is allowed only after the exact staged-object transaction proves the
staged content is clean.

## Core mental model

1. **One-command registration (`keyhog guard add <path>`)**: Indexes the target
   repository into daemon memory once and establishes clean baseline attestations.
2. **Sub-millisecond commit gating (`keyhog scan --git-staged`)**: Pre-commit
   hooks query the active guard daemon. The daemon verifies only changed staged
   blob OIDs against in-memory attestations, completing scans in milliseconds.
3. **Full lifecycle control**: List active roots with `keyhog guard list`, check
   memory and attestation metrics with `keyhog guard status <path>`, and free
   daemon memory immediately with `keyhog guard remove <path>` when finished
   working on a project.

## Lifecycle commands

| Command | Purpose |
|---|---|
| `keyhog guard add <path> [--mode repo]` | Register a repository or tree for continuous guard protection. Performs initial baseline reconciliation before returning. |
| `keyhog guard list` | Enumerate all registered guard roots, their active states, and terminal sequences. |
| `keyhog guard status <path> [--format human\|json]` | Print detailed metrics for a guarded root: state, cache hits/misses, files/bytes scanned, residency, and policy digest. |
| `keyhog guard remove <path>` | Stop guarding a repository and drop its in-memory index and attestation cache to immediately free daemon memory and CPU. |
| `keyhog guard reconcile <path>` | Force a full baseline reconciliation after intentional policy updates or mass branch operations. |
| `keyhog guard rebuild <path>` | Delete and recreate the durable guard store for a root after corruption or irrecoverable state. |

## Quick start

### 1. Start the daemon

```sh
keyhog daemon start --backend auto
```

The daemon compiles the active 926-detector corpus once and stays resident in
memory. One daemon process serves all guarded repositories and scan requests.

### 2. Register a repository

```sh
keyhog guard add /path/to/repo --mode repo
```

- `--mode repo` (default): Uses Git object IDs (OIDs) for exact immutable
  staged-content identification.
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
detector:       926-174c093ae73b
suppression:    0000000000000000
config:         18cc6ed841bf6dfe
autoroute:      calibrated
store schema:   2
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
━━━ Results ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
0 secrets found · Clean staged commit (1.8ms)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
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
Guarded roots:
  /path/to/repo-a  current  seq=14
  /path/to/repo-b  current  seq=3
```

### 6. Free resources when finished

When you finish working on a project, remove it from the guard to immediately
reclaim daemon memory and watcher resources:

```sh
keyhog guard remove /path/to/repo
```

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
    rev: v0.5.79
    hooks:
      - id: keyhog
        stages: [pre-commit]
```

Install the hook:

```sh
pre-commit install
```

## Guard state machine

Every guarded root operates within a 7-state machine:

```text
                  ┌──────────────┐
                  │   stopped    │
                  └──────┬───────┘
                         │ reconcile
                         ▼
                  ┌──────────────┐
                  │   indexing   │
                  └──────┬───────┘
                         │
        ┌────────────────┼────────────────┐
        ▼                ▼                ▼
 ┌──────────────┐ ┌──────────────┐ ┌──────────────┐
 │   current    │ │   blocked    │ │   degraded   │
 └──────┬───────┘ └──────────────┘ └──────────────┘
        │ fs event       │                │
        ▼                │ policy change  │
 ┌──────────────┐        │                │
 │    dirty     │◄───────┴────────────────┘
 └──────┬───────┘
        │ reconcile
        ▼
 ┌──────────────┐
 │ stale-policy │
 └──────────────┘
```

| State | Definition |
|---|---|
| `stopped` | The root is registered in the daemon registry but not actively watching or scanning. |
| `indexing` | Baseline reconciliation is running in the background. |
| `current` | Baseline scan completed cleanly. Coverage is 100% complete and no finding blocks the active policy. |
| `dirty` | Filesystem changes occurred and have not yet been reconciled against the baseline. |
| `blocked` | A likely or confirmed secret was detected in the root baseline. The root is blocked. |
| `degraded` | Scanner coverage was incomplete (for example, inaccessible files or failed reads). |
| `stale-policy` | Daemon detector corpus, suppression rules, or configuration changed since the baseline was computed. Existing attestations are invalidated. |

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
2. **Hash Algorithm**: The Git object format algorithm in use.
3. **Policy Identity Digest**: A 16-hex hash of the active 926 detector corpus,
   suppression rules, and scanner configuration.
4. **Sorted Source-Path Set**: The canonical file path within the repository.

Future commit transactions matching all four elements skip payload re-scanning
and return an instant cache hit. If a file is renamed, moved across source roles,
or the detector corpus is updated, the attestation is invalidated.

## Durable state persistence

By default, guard state is held in daemon memory. To persist root registrations
and clean attestations across daemon restarts, configure `state_path` in
`.keyhog.toml`:

```toml
[guard]
state_path = "~/.local/state/keyhog/guard.redb"
```

The durable store uses a high-performance redb database with owner-only (0600)
file permissions.

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

Scrubbing detects modifications made outside standard filesystem events (such as
NFS mounts, container volume mutations, or out-of-band Git object manipulation).
When the interval elapses, each `current` root automatically transitions to
`indexing` for a full reconciliation.

## Recovering corrupted roots

If a repository's durable state becomes corrupt or desynchronized, rebuild it:

```sh
keyhog guard rebuild /path/to/repo
```

`rebuild` clears the root's durable database entries, re-registers the root, and
triggers a clean baseline reconciliation.

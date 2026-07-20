# System-wide credential triage

`keyhog scan-system` audits a whole machine in one command. It enumerates
every mounted drive, auto-discovers every git repository on the way, and runs
the same scan and git-history pipeline that `keyhog scan --git-history` runs,
against each. It exists for the moments when the question is not "does this
repo leak" but "does anything on this host leak".

```sh
sudo keyhog scan-system --space 50G                   # default 50 GiB ceiling
sudo keyhog scan-system --space 1T --include-network  # also walk NFS / SMB / sshfs
sudo keyhog scan-system --space 10G --no-git-history  # skip historical blobs
```

Run it with enough privilege to read the trees you care about. Without `sudo`
it silently cannot enter another user's home directory, which is the opposite
of what a triage sweep wants.

## What it walks

The command discovers targets, it is not handed a path. It enumerates every
mounted filesystem and skips the pseudo-filesystems that never hold source:
`/proc`, `/sys`, `tmpfs`, `nsfs`, `fuse.snapfuse`, and their kin. Network
mounts (NFS, SMB, sshfs) are skipped by default because they are usually slow
and shared; `--include-network` opts them in.

On the way through each filesystem it auto-discovers every git repository:
ordinary worktrees, bare repositories, and submodules. Each one is scanned
through the full pipeline, and unless you pass `--no-git-history` its history
is walked too, so a credential committed and later deleted still surfaces.

## The space ceiling is a hard limit

`--space <N>` (default `50G`) caps the total bytes scanned. It is not a
suggestion: the sweep stops when it reaches the ceiling so a run on an
unfamiliar host cannot accidentally exhaust a CI runner or an incident
responder's laptop. Sizes take `K`/`M`/`G`/`T` suffixes (`--space 1T`). Raise
it deliberately when you know the host is large; lower it when you want a fast
first pass.

## Why `.gitignore` is ignored by default

A normal scan honors `.gitignore`. `scan-system` does not, and that is the
security-correct default: an attacker or a careless developer who stashes a
leaked key will often `.gitignore` it precisely so tooling stops looking. A
triage sweep that respected those rules would be blind to the exact files most
worth finding. Pass `--respect-gitignore` only when you are auditing your own
hygiene rather than hunting for hidden secrets.

## When to reach for it

- **Incident response.** A host is suspected compromised; you need to know what
  credentials are recoverable from it before rotating.
- **Inherited infrastructure.** An M&A handover or a decommissioned server whose
  history nobody remembers.
- **Quarterly laptop sweeps.** A recurring audit of developer machines where
  secrets accumulate in dotfiles, old clones, and forgotten branches.

## Pairing with lockdown

When the host holding the secrets is the same host running the scan, add
`--lockdown` so credentials never reach swap or a core dump while the sweep
runs. Lockdown forbids `--include-network` (a network sweep from a locked-down
host defeats the point), so pick one posture per run. See the
[CLI reference](../reference/cli.md#keyhog-scan-system) for the full flag list
and the exit-code contract.

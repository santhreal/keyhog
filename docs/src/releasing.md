# Prepare and publish a release

You can preview or publish a complete KeyHog release with one script. The script
runs locally by default. You can point the same command at a prepared SSH host
when benchmark hardware, signing keys, or build caches live elsewhere.

## Choose an operation

| Need | Command and effect |
|---|---|
| Validate a local release plan | Run `python3 -B scripts/release.py "$NEXT_VERSION"`. The preview is read-only. |
| Validate on the benchmark and signing host | Add `--ssh USER@HOST --remote-dir /absolute/keyhog/path`. Neither checkout changes. |
| Publish from the current host | Add `--publish`. The command may create generated evidence and release commits, then update `main`, the signed tag, and downstream publication. |
| Publish on the prepared SSH host | Add `--ssh USER@HOST --remote-dir /absolute/keyhog/path --publish`. The remote checkout and public release surfaces may change. The local checkout stays unchanged. |
| Continue an interrupted publication | Add `--publish --resume` to the same local or SSH command. Only incomplete phases run. Existing tags are verified and never replaced. |
| Diagnose one lower-level phase | Run the commands under [Run individual preparation commands](#run-individual-preparation-commands). The named local phase may change. Do not use lower-level commands as the publication path. |

Set `NEXT_VERSION` to the reviewed next stable SemVer without a `v` prefix.
The script rejects placeholders, prerelease suffixes, and versions that do not
advance the workspace.

Preview the next release locally:

```sh
NEXT_VERSION=X.Y.Z
python3 -B scripts/release.py "$NEXT_VERSION"
```

The preview is read-only. It verifies the clean `main` checkout, generated star
chart, change fragments, version transition, lockfile packages, public version
pins, and release-note structure. It then prints every publication phase.

Publish only after you review that preview:

```sh
python3 -B scripts/release.py "$NEXT_VERSION" --publish
```

`--publish` is the explicit irreversible boundary. It permits commits, pushes,
a signed tag, GitHub release publication, container publication, Pages
deployment, and the serial crates.io publisher.

## Write the release notes first

Create one `.toml` file under `changes/` for each operator-visible change. Use a
lowercase, hyphenated file name:

```toml
category = "Fixed"
summary = "Preserve the receipt-bound report when a workspace path changes."
crates = ["cli"]
```

Each fragment has three fields:

| Field | Value |
|---|---|
| `category` | One of `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, or `Security` |
| `summary` | One concrete, single-line statement without a Markdown bullet prefix |
| `crates` | One or more owners: `cli`, `core`, `scanner`, `sources`, or `verifier` |

Commit the fragments before you run the release command. The root release notes
contain every fragment. Each crate changelog receives only the fragments that
name that crate.

The release chain publishes all five crates with exact internal dependency pins.
The complete fragment set must therefore name every crate at least once. Add a
release-chain fragment when a crate changes only because its exact dependency
or publication identity moves with the other packages. Empty and placeholder
crate changelogs fail closed.

## Run on an SSH host

Pass one SSH target and one absolute repository path:

```sh
python3 -B scripts/release.py "$NEXT_VERSION" \
  --ssh release-builder@example.com \
  --remote-dir /srv/keyhog \
  --publish
```

The local script opens one foreground SSH process, enters the requested remote
directory, and executes the same checked-in `scripts/release.py`. It forwards
the version, date, publication, benchmark, Rust, resume, and watch choices. It
does not copy the repository, signing key, or credentials.

Use `--ssh-port 2222` for a non-default port. Use
`--identity-file /path/to/key` when SSH does not select the correct identity.
The SSH target accepts only a host or `user@host`. It does not accept an
arbitrary shell command. The remote directory must be absolute. These
restrictions keep user input from becoming shell syntax.

Prepare the remote host before you publish. It needs:

- a clean `main` checkout whose `origin` is `https://github.com/santhreal/keyhog.git`
- the benchmark corpora and required competitor binaries
- Rust, Python, mdBook, Hyperscan, GPU dependencies, `gh`, and GPG
- the authorized GitHub account with stable actor ID `64453045`
- the authorized OpenPGP release secret key configured as `user.signingkey`
- the persistent Cargo target directory used by the host

The crates.io token remains in GitHub Actions. The local or SSH host never needs
to read it.

## What the command runs

The publishing command owns five ordered phases.

### 1. Prepare changelogs and versions

The script applies the deterministic release transaction. It updates:

- the workspace version and four exact internal dependency pins
- the five KeyHog packages in `Cargo.lock`
- canonical Action, installer, CLI, and documentation version examples
- the root changelog and GitHub release-note section
- all five crate changelogs

It preserves historical benchmark versions. It consumes the committed change
fragments and commits only the paths owned by this transaction.

### 2. Refresh measured evidence

The script builds one `release-fast` KeyHog candidate after version preparation.
It regenerates the mirror corpus results, canonical competitor comparison,
leaderboard, CPU and GPU matrix, cache and daemon measurements, hardware scaling
tables, README panels, and the repository-owned star chart. It runs the report
freshness gate and commits only `README.md`, `benchmarks/reports/`, and the
generated star SVG. Unexpected source or configuration changes stop the release
before staging.

Benchmark generation is fail-closed. A missing competitor, corpus, accelerator,
or output contract is a failed release prerequisite. The script does not invent
a fallback result. Because generation writes reports while later panels are
still being measured, the snapshot truthfully records a developer-dirty source
classification. Executable and detector digests remain bound in the evidence.
The executable digest identifies the final versioned candidate used for the
measurement. Committing that evidence creates one child commit and changes the
Git hash embedded in the next build. The pre-tag gate accepts this unavoidable
digest difference only when every intervening path is generated evidence.
Any source, manifest, configuration, fixture, or other path change rejects the
measurement as stale.

Choose the benchmark path by intent:

| Intent | Command | Evidence contract |
|---|---|---|
| Publish a release | `scripts/release.py "$NEXT_VERSION" --publish` | Prepares the version, then builds one candidate and refreshes every committed benchmark surface. |
| Check committed competitor and README evidence | `make -C benchmarks report-check` | Reads existing snapshots and fails on stale generated bytes. It does not measure. |
| Remeasure all README panels during investigation | `make -C benchmarks readme-matrix KEYHOG_BIN=/absolute/path/to/keyhog` | Measures route, preset, cache, daemon, worker, reader, storage, size, and partition panels. |
| Isolate host scaling | `make -C benchmarks readme-scaling KEYHOG_BIN=/absolute/path/to/keyhog` | Measures the configured host and storage identities without refreshing competitor results. |

The release path is the only command that orders version preparation, benchmark
refresh, generated commit ownership, gates, signing, and publication.
`--skip-benchmarks` is a visible diagnostic override for an already measured
and reviewed resume. It is not a faster normal release mode.

### 3. Prove the pre-tag candidate

The script runs `scripts/prerelease.sh --pre-tag`. This mode builds the candidate
and runs benchmark, differential, GPU crossover, coherence, package, and Rust
gates. It then runs the complete mdBook build, link validation, Pages metadata
generation, star-viewer check, and source prevention suite.

The signed-bundle install smoke cannot exist before the signed tag. The
immutable GitHub release workflow owns that proof. It downloads the staged
candidate, verifies signatures and checksums, installs it, runs `doctor`, scans
a planted credential, checks secret redaction, and uninstalls it before public
release publication.

### 4. Push one signed source identity

The script pushes `main`, creates one annotated OpenPGP-signed tag, verifies the
signature against the configured primary-key fingerprint, and only then pushes
that exact tag. Resume applies the same signature and fingerprint check to an
existing local or remote tag. An unsigned tag, a valid signature from another
key, or a lightweight tag fails closed.

A star-history commit that races the push is rebased only when the remote change
touches `metrics/stars.json` or `metrics/stars.svg`. Any other remote change
stops publication for review.

The signed tag triggers tag-specific CI and `.github/workflows/release.yml`.
That workflow binds the successful CI verdict to the exact tag commit, builds
platform assets, signs payloads, generates SBOMs and attestations, publishes the
container, exercises the installed product, publishes the GitHub release, calls
the serial crates.io publisher, and moves the floating Action major tag only
after publication succeeds.

### 5. Watch every publication lane

The command waits for the exact release workflow and Pages workflow associated
with the release commit. It exits nonzero if either workflow fails. A successful
release workflow includes all five crates.io publication jobs. The final check
requires the exact canonical tag URL, a publication timestamp, and a public,
non-draft, non-prerelease GitHub release.

Use `--no-watch` only when another operator will watch the exact runs. It does
not change publication behavior.

## Resume an interrupted release

Use the same command with `--resume`:

```sh
python3 -B scripts/release.py "$NEXT_VERSION" --publish --resume
```

Resume accepts either clean local release commits ahead of `origin/main`, an
already prepared workspace version, a local signed tag that still needs to be
pushed, or the exact remote signed annotated tag. Before tag creation, a normal
resume refreshes benchmark evidence against the prepared version and reruns the
pre-tag proofs. After tag creation, resume retains the immutable tagged evidence.
It verifies the existing tag's commit, OpenPGP signature, and configured primary-key fingerprint.
It never moves or replaces a release tag.

If final-version benchmark evidence was already committed before an
interruption, add `--skip-benchmarks` to retain that checked evidence:

```sh
python3 -B scripts/release.py "$NEXT_VERSION" \
  --publish --resume --skip-benchmarks
```

`--skip-benchmarks` and `--skip-rust` are diagnostic recovery overrides. They
are not the normal release path. The command records them in terminal output,
and the GitHub release still requires its complete immutable CI and publication
contracts.

## Run individual preparation commands

The lower-level commands remain available for investigation:

```sh
make release-check VERSION="$NEXT_VERSION"
make release-prepare VERSION="$NEXT_VERSION"
scripts/prerelease.sh --pre-tag
make docs-build
```

Use them to isolate a failing phase. Use `scripts/release.py` for the actual
release so benchmark evidence, changelogs, pushes, signing, GitHub publication,
Pages, and crates.io stay in one ordered workflow.

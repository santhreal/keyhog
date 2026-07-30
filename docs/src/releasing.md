# Prepare and publish a release

You can preview or publish a complete KeyHog release with one script. The script
runs locally by default. You can point the same command at a prepared SSH host
when benchmark hardware, signing keys, or build caches live elsewhere.

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

### 1. Refresh measured evidence

The script builds one `release-fast` KeyHog candidate. It regenerates the mirror
corpus results, canonical competitor comparison, leaderboard, CPU and GPU
matrix, cache and daemon measurements, hardware scaling tables, README panels,
and the repository-owned star chart. It runs the report freshness gate and
commits only `README.md`, `benchmarks/reports/`, and the generated star SVG.
Unexpected source or configuration changes stop the release before staging.

Benchmark generation is fail-closed. A missing competitor, corpus, accelerator,
or output contract is a failed release prerequisite. The script does not invent
a fallback result. Because generation writes reports while later panels are
still being measured, the snapshot truthfully records a developer-dirty source
classification. Executable and detector digests remain bound in the evidence.

### 2. Prepare changelogs and versions

The script applies the deterministic release transaction. It updates:

- the workspace version and four exact internal dependency pins
- the five KeyHog packages in `Cargo.lock`
- canonical Action, installer, CLI, and documentation version examples
- the root changelog and GitHub release-note section
- all five crate changelogs

It preserves historical benchmark versions. It consumes the committed change
fragments and commits only the paths owned by this transaction.

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

The script pushes `main`, creates one annotated OpenPGP-signed tag, and pushes
that exact tag. A star-history commit that races the push is rebased only when
the remote change touches `metrics/stars.json` or `metrics/stars.svg`. Any other
remote change stops publication for review.

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
requires a public, non-draft, non-prerelease GitHub release with the exact tag.

Use `--no-watch` only when another operator will watch the exact runs. It does
not change publication behavior.

## Resume an interrupted release

Use the same command with `--resume`:

```sh
python3 -B scripts/release.py "$NEXT_VERSION" --publish --resume
```

Resume accepts either clean local release commits ahead of `origin/main`, an
already prepared workspace version, a local signed tag that still needs to be
pushed, or the exact remote annotated tag. It verifies that every existing tag
resolves to the current release commit. It never moves or replaces a release
tag.

If benchmark evidence was already committed before an interruption, add
`--skip-benchmarks` to retain that checked evidence:

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

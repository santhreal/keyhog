# Prepare and publish a release

You prepare one release from small change fragments. The preparer updates the
workspace version, exact internal dependency pins, lockfile packages, public
version examples, root changelog, and five crate changelogs as one validated
transaction.

For example, add `changes/action-receipts.toml`:

```toml
category = "Fixed"
summary = "Preserve the receipt-bound report when a workspace path changes."
crates = ["cli"]
```

Then preview the next release:

```sh
NEXT_VERSION=X.Y.Z
make release-check VERSION="$NEXT_VERSION"
```

The preview is read-only. It validates every fragment and computes every file
that the release would change. It rejects an empty release, a stale version,
unknown fields, duplicate summaries, unknown crate ownership, missing lockfile
packages, and stale public version pins.

## Write a change fragment

Create one `.toml` file under `changes/` for each operator-visible change. Use a
lowercase, hyphenated file name. The file has three fields:

| Field | Value |
|---|---|
| `category` | One of `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, or `Security` |
| `summary` | One concrete, single-line statement without a Markdown bullet prefix |
| `crates` | One or more owners: `cli`, `core`, `scanner`, `sources`, or `verifier` |

List every crate whose published behavior or API changed. The root release
notes contain every fragment. Each crate changelog receives only the fragments
that name that crate.

The release chain publishes all five crates with exact internal pins. The
complete fragment set must therefore name every crate at least once. Add one
release-chain fragment when a crate changes only because its exact dependencies
or publication identity move with the other packages. The preparer rejects an
empty crate changelog instead of inventing a placeholder note.

Use a summary that explains the result to an operator. Do not describe file
moves, test counts, or implementation mechanics unless those facts change the
published contract.

## Preview the release transaction

Run the preview before you apply it:

```sh
make release-check VERSION="$NEXT_VERSION" DATE=2026-07-28
```

`DATE` is optional and defaults to the current UTC date. The command runs the
release automation regression suites and validates the complete transformation
without writing files. GitHub also runs the same read-only transaction each day
and whenever release automation or a change fragment changes. If there are no
fragments, the scheduled job reports that there is no pending candidate.

The preview never invents a version. You choose the next Semantic Versioning
number. The preparer accepts stable `MAJOR.MINOR.PATCH` versions and requires the
new version to be greater than the workspace version.

## Apply and review the candidate

Apply the exact transaction you previewed:

```sh
make release-prepare VERSION="$NEXT_VERSION" DATE=2026-07-28
```

The command writes all validated outputs and consumes the fragment files. It
preserves generated benchmark evidence, including measurements from older
KeyHog versions. Review the resulting diff. In particular, check the release
notes, crate ownership, public version examples, and release date.

Run the local prerelease gate against the signed candidate bundle when you have
one:

```sh
scripts/prerelease.sh \
  --release-candidate /path/to/keyhog-linux-x86_64
```

The gate builds the candidate, checks benchmark and documentation coherence,
runs the release test lanes, installs the signed bundle, scans a planted
credential, and uninstalls it. A source binary is not a substitute for the
signed release bundle.

## Publish from one signed tag

Commit the reviewed candidate on `main`. Create an annotated, signed tag for the
same commit, then push that tag. The tag name is the prepared version with a `v`
prefix, such as `v<next-version>`.

The release workflow performs publication from that immutable tag. It requires
the exact successful CI verdict, builds and signs platform assets, generates
SBOMs and attestations, exercises the installed product, publishes the GitHub
release and container image, publishes the crate chain, and moves maintained
Action tags only after the required proofs pass.

A maintainer signs the tag. Automation does not manufacture or bypass this
approval. Manual workflow recovery must run from the same signed tag and passes
the same identity checks.

## Update documentation

Run the complete documentation command when public behavior or guidance
changes:

```sh
make docs-build
```

This command validates generated README benchmark panels, Action and workflow
boundaries, documentation truth, mdBook examples, internal links, canonical
page metadata, `sitemap.xml`, and `robots.txt`. GitHub Pages runs the same build
for pull requests and deploys only from `main`.

The generated discovery metadata uses
`https://santhreal.github.io/keyhog/` as the canonical site root. Each guide has
one canonical URL, Open Graph metadata, a social-card summary, and structured
software-project context. The sitemap excludes mdBook utility pages such as the
print view and error page.

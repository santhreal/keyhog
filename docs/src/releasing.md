# Releases

A successful `main` CI run publishes KeyHog automatically. You do not choose a version or sign a release.

## Release a push

Push your change to `main`. The `CI` workflow must finish successfully. The automatic release workflow then:

1. increments the workspace patch version;
2. generates the root and crate changelogs;
3. updates `Cargo.toml`, `Cargo.lock`, all changelogs, and operator-facing version pins;
4. commits the generated files and creates a lightweight version tag;
5. dispatches the publish job for that tag;
6. publishes all six crates to crates.io in dependency order; and
7. creates the GitHub Release for that tag from its changelog section.

For example, a successful push at `1.2.3` produces `1.2.4`.

Step 5 exists because a tag pushed with the workflow token raises no `push` event. `workflow_dispatch` is one of the two events the workflow token can start, so the bump job dispatches the publish itself. A tag you push by hand publishes through the `push` trigger instead.

The workflow does not run for pull requests, failed CI runs, or cancelled CI runs. It does not build release assets, signatures, attestations, or SBOMs. The GitHub Release carries changelog notes only.

## Write a changelog fragment

Fragments are optional. Without one, the workflow uses the successful push commit subject for every crate.

Use a fragment when different crates need a precise note:

```toml
category = "Changed"
summary = "Use one allocation for each decoded candidate batch."
crates = ["core", "scanner"]
```

Save the file under `changes/` with a lowercase kebab-case name and a `.toml` extension. A fragment contains exactly `category`, `summary`, and `crates`.

Valid categories are:

- `Added`
- `Changed`
- `Deprecated`
- `Removed`
- `Fixed`
- `Security`

`Performance` and `Documentation` are accepted as aliases of `Changed` so existing notes publish under the Keep a Changelog heading.

Valid crate names are `cli`, `core`, `profile`, `scanner`, `sources`, and `verifier`. The release commit consumes the fragment. Any crate not covered by a fragment receives the push commit subject.

## Configure crates.io trusted publishing

Each published package is configured on crates.io with a trusted publisher for
this repository's `release.yml` workflow, with no environment. crates.io rejects
`workflow_run` JWTs, so publishing runs under the `push` (tag) or
`workflow_dispatch` trigger. The workflow requests `id-token: write` and uses
`rust-lang/crates-io-auth-action` first; it falls back to the
`CARGO_REGISTRY_TOKEN` repository secret only if that exchange fails.

The trusted publisher must be authorized for all six packages, in publication
order:

1. `keyhog-profile`
2. `keyhog-core`
3. `keyhog-verifier`
4. `keyhog-sources`
5. `keyhog-scanner`
6. `keyhog`

The repository workflow token also needs `contents: write`. It uses that
permission only for the generated release commit and lightweight version tag.

## Recover a failed upload

Rerun the failed `Automatic crates.io release` workflow. The workflow recognizes an existing generated release commit whose parent is the successful CI commit. It reuses that version. `scripts/publish.sh` skips versions already visible on crates.io and resumes at the first missing package.

If a newer `main` push supersedes the successful commit before the release begins, the older workflow exits. The newer successful CI run releases the combined state.

## Check release automation

Run the focused checks locally:

```sh
make release-check
```

The command validates patch increments, generated changelogs, version ownership, and workflow triggers. It does not commit, tag, push, or publish.

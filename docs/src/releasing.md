# Releases

A successful `main` CI run publishes KeyHog automatically. You do not choose a version or sign a release.

## Release a push

Push your change to `main`. The `CI` workflow must finish successfully. The automatic release workflow then:

1. increments the workspace patch version;
2. generates the root and crate changelogs;
3. updates `Cargo.toml`, `Cargo.lock`, all changelogs, and operator-facing version pins;
4. commits the generated files and creates a lightweight version tag; and
5. publishes all five crates to crates.io in dependency order.

For example, a successful push at `1.2.3` produces `1.2.4`.

The workflow does not run for pull requests, failed CI runs, cancelled CI runs, tags, or manual dispatches. It does not build GitHub release assets. It does not create signatures, attestations, SBOMs, or a GitHub Release.

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

Valid crate names are `cli`, `core`, `scanner`, `sources`, and `verifier`. The release commit consumes the fragment. Any crate not covered by a fragment receives the push commit subject.

## Configure crates.io

Set the repository Actions secret `CARGO_REGISTRY_TOKEN`. The token must publish these crates:

1. `keyhog-core`
2. `keyhog-verifier`
3. `keyhog-sources`
4. `keyhog-scanner`
5. `keyhog`

The repository workflow token also needs `contents: write`. It uses that permission only for the generated release commit and lightweight version tag.

## Recover a failed upload

Rerun the failed `Automatic crates.io release` workflow. The workflow recognizes an existing generated release commit whose parent is the successful CI commit. It reuses that version. `scripts/publish.sh` skips versions already visible on crates.io and resumes at the first missing package.

If a newer `main` push supersedes the successful commit before the release begins, the older workflow exits. The newer successful CI run releases the combined state.

## Check release automation

Run the focused checks locally:

```sh
make release-check
```

The command validates patch increments, generated changelogs, version ownership, and workflow triggers. It does not commit, tag, push, or publish.

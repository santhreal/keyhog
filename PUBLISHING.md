# Publishing KeyHog

KeyHog publishes one patch release for every successful `main` push. You do not prepare, sign, or dispatch a release manually.

## Configure the repository

Add one Actions secret named `CARGO_REGISTRY_TOKEN`. Use a crates.io token that can publish these packages:

1. `keyhog-core`
2. `keyhog-verifier`
3. `keyhog-sources`
4. `keyhog-scanner`
5. `keyhog`

The automatic workflow needs `contents: write` so it can commit the generated version and changelogs to `main`.

## Publish a change

Push the change to `main`. The `CI` workflow runs first. If CI fails or is cancelled, nothing is published.

After CI succeeds, `.github/workflows/release.yml` performs this transaction:

1. Read the workspace version from `Cargo.toml`.
2. Increment the patch component. For example, `1.2.3` becomes `1.2.4`.
3. Consume the TOML files under `changes/`.
4. Use the push commit subject as the changelog note for any crate that has no authored fragment.
5. Update `Cargo.toml`, `Cargo.lock`, all changelogs, and operator-facing version pins.
6. Commit the generated files as `release: vX.Y.Z` and create a lightweight `vX.Y.Z` tag.
7. Push the commit and tag with the workflow token.
8. Run `scripts/publish.sh`, which publishes the six crates in dependency order.

The workflow does not create signed tags, signatures, attestations, SBOMs, release assets, or a GitHub Release.

## Add an optional change fragment

A fragment gives you a more precise changelog than the commit subject.

```toml
category = "Changed"
summary = "Reduce allocations in the scanner hot path."
crates = ["core", "scanner"]
```

Save it as `changes/<short-name>.toml`. Valid categories are `Added`, `Changed`, `Deprecated`, `Removed`, `Fixed`, and `Security`. `Performance` and `Documentation` are accepted as aliases of `Changed`. The automatic release consumes the fragment after CI succeeds. Crates not named by a fragment receive the push commit subject.

## Recover a failed publication

Rerun the failed `Automatic crates.io release` workflow. If the generated release commit already exists, the workflow reuses its version and resumes `scripts/publish.sh`. The publisher skips package versions already visible on crates.io.

A newer successful `main` push supersedes an older CI result. The newer result creates the next release.

## Check the release code locally

Run the focused suite:

```sh
make release-check
```

This checks patch calculation, changelog generation, version updates, and the workflow trigger contract. It does not publish.

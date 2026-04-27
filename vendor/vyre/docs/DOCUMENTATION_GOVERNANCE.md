# Documentation governance

This file defines which vyre documents are authoritative when plans,
archives, generated docs, and internal notes disagree.

## Precedence

1. [`VISION.md`](../VISION.md) and [`docs/THESIS.md`](THESIS.md) define
   the long-term product and architecture direction.
2. [`RELEASE.md`](../RELEASE.md) defines the release procedure.
3. [`audits/LEGENDARY_GATE.md`](../audits/LEGENDARY_GATE.md) is the
   active release gate and execution backlog.
4. Generated and frozen-contract docs are authoritative only for the
   artifacts they are derived from:
   - [`docs/generated/`](generated/) is regenerated from live inventory.
   - [`docs/catalog/`](catalog/) is regenerated from op registries.
   - [`docs/frozen-traits/`](frozen-traits/) is checked by the frozen
     trait gate.
5. Other files under [`docs/`](.) are reference material. They must not
   override the files above.
6. Files under [`.internals/`](../.internals/) are maintainer working
   notes unless explicitly linked from a higher-precedence document.
7. Files under [`.internals/archive/`](../.internals/archive/) and
   [`.internals/audits/from-docs-audits/`](../.internals/audits/from-docs-audits/)
   are historical imports. They preserve evidence and prior reasoning,
   but they are not plans of record.

When two documents conflict, the higher item in this list wins. Fix the
lower-precedence document by adding a supersession note or updating its
claim; do not delete the historical content just to remove the conflict.

## Plan names

Only `audits/LEGENDARY_GATE.md` may call itself the active release gate.
Older files named `MASTER_PLAN.md`, `MASTER_PLAN_LEGENDARY.md`, or
`V7_*_PLAN.md` are archived or superseded unless
`audits/LEGENDARY_GATE.md` explicitly delegates a section to them.

## Audit backlog and the no-TODO rule

LAW 1 and LAW 9 still ban TODO/FIXME/stub markers in shipped source
code. Audit documents may contain those words when they are recording a
finding, a grep target, or an unresolved backlog item. That text is not
permission to leave TODOs in Rust, scripts, generated source, or shipped
user-facing docs.

## Generated, frozen, and CI-coupled docs

Do not hand-edit generated or frozen-contract files as a way to make CI
green. If a generated inventory, catalog, or frozen snapshot is wrong,
fix the source artifact or generator, regenerate the document, and keep
the checker coupled to the file. If a checker is intentionally changed,
the document it protects must link that checker so future edits know the
enforcement path.

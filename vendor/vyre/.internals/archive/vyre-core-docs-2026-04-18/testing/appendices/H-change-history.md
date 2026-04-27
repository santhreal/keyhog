# Appendix H — Change history

This appendix records material changes to the book.
Stylistic fixes, typo corrections, and minor rewording are
not tracked here; they appear in git history. This appendix
tracks architectural decisions and chapter additions —
changes that affect what the book says, not how it says it.

The change history is append-only. Entries are not edited
after they are written. If a past entry becomes stale
because of a later change, a new entry is added that
supersedes it; the old entry stays in place as a record of
what was believed at the time.

The book aspires to be stable. Entries here should be rare.
A long gap between entries is a good sign; it means the
book's architecture is holding.

---

## 2026-04-12 — Initial book

The book is first written as a complete 60-chapter
treatment of testing in vyre, replacing the earlier short
`docs/testing.md` stub. Organized as eleven parts plus
eight appendices.

**Rationale:** vyre's testing discipline needed a
reference document that could scale with the project.
Previous documentation was scattered across short notes
and inline comments in source. The new book consolidates
the discipline in one place and establishes the patterns
contributors are expected to follow.

**Scope:**
- Part I (Foundations): introduction, failure modes, the
  fifteen invariants.
- Part II (Vocabulary): terms, oracles, mutations,
  archetypes.
- Part III (Categories): the nine-plus directory layout
  of `vyre/tests/` and per-category chapters for each.
- Part IV (Worked example): complete walkthrough for
  BinOp::Add.
- Part V (Writing): decision tree, templates, naming,
  helpers, oracles in practice.
- Part VI (Anti-patterns): tautology, kitchen sink,
  doesn't crash, hidden helpers, seedless proptest,
  test smells.
- Part VII (Discipline): review checklist, daily audit,
  seed discipline, regression rule, flakiness, suite
  performance.
- Part VIII (Advanced): property generators, differential
  fuzzing, mutation at scale, concurrency, floating-point,
  cross-backend.
- Part IX (Running): local workflow, continuous
  integration, debugging failures, debugging flakes.
- Part X (vyre-conform integration): two-tier suite,
  generator supersession, never-replaced categories,
  contribution flow.
- Part XI (Meta): testing as design, testing the testers,
  post-mortem discipline, the long game.
- Appendices A-H: glossary, invariants catalog, mutations
  reference, archetypes reference, command reference,
  review checklist, examples index, change history.

**Key architectural decisions recorded:**
- The oracle hierarchy (Law, SpecTable, ReferenceInterp,
  CpuReference, Composition, ExternalCorpus, Property) is
  permanent.
- The ten-plus test categories are permanent.
- Regression tests are never deleted.
- The mutation gate is the quality floor.
- The daily audit is non-optional.
- The two-tier (hand-written + generated) suite model is
  the scaling strategy.
- Seed discipline is strict: every proptest has fixed
  seed and committed regression corpus.
- Flakes are P1 findings that block merges.

**Contributors:** This book is co-authored by the vyre
project maintainers and is a synthesis of the practices
developed during vyre's initial development. Specific
authorship is in git history; the book is a collective
document.

---

## Future entries

As this book is updated over time, future entries will
follow the format above:

- **Date.**
- **One-line summary.**
- **Rationale.**
- **Scope of change.**
- **Key decisions recorded (if any).**

The intent is that a reader ten years from now can read
this appendix and understand what the book has said over
time, even if specific chapters have been rewritten.
Historical entries preserve the earlier viewpoints for
context.

When a future maintainer adds an entry, they should be
specific: what changed, why, and what downstream
consequences to expect. Vague entries lose value.

---

## End of book

This is the last page of the last appendix. The book is
complete.

If you have read this far, you have read the whole thing.
Thank you. The book's purpose is served if you now
understand the discipline well enough to teach it to
someone else. Go do that.

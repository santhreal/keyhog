# The vyre Testing Book

This book is the complete and authoritative guide to testing vyre. It is
written to last: the architecture it describes is a permanent decision,
not a checkpoint in an evolving design. When vyre ships a conformance
certificate to a backend vendor, the certificate is valid because this
book describes the discipline that made it valid. When a contributor adds
a primitive operation ten years from now, the test they write belongs to
the categories this book defines, obeys the oracle rules this book
enforces, and survives the mutation gate this book mandates. If this book
changes, it is because vyre's testing architecture itself has changed —
which should happen roughly never.

## Preface

### Why this book exists

vyre's value to the world is not what it does today. vyre's value is that
a `Program` written against its specification produces byte-identical
results on every conformant backend, today and for every future version,
forever. That is the contract. Without that contract, vyre is one more
GPU compute framework in a graveyard of frameworks that could not
guarantee their own semantics. With that contract, vyre is infrastructure
— the kind of thing NVIDIA pays engineers to support because the cost of
not supporting it is higher than the cost of contributing.

The contract is only real if the test suite is strong enough to enforce
it. A specification without a conformance test is a wish. A conformance
test without adversarial rigor is a ritual. A test suite without
discipline is theater. vyre cannot afford any of these. Every
determinism violation, every backend disagreement, every lowering bug,
every missed validation rule is a failure of the contract. The test
suite exists to prevent those failures, and this book exists to teach you
how to write tests that actually prevent them.

The standard we measure ourselves against is not other GPU compute
frameworks. It is SQLite, which ships with 590 times more test code than
source code and catches crashes before they reach a user. It is the
Linux kernel, which runs kselftest, syzkaller, KASAN, KCSAN, and lockdep
on every commit and treats a single crash as a P0 bug. It is LLVM,
whose test infrastructure is the reason compiler backends can be written
by vendors without central coordination. These projects are the way
they are because their tests are first-class engineering artifacts. A
sloppy test in SQLite is a crisis, not a nit. A flaky test in Linux is
reverted, not documented. This book exists so that every test in vyre
carries that same weight.

### What this book is not

This book is not a tutorial on testing in general. It assumes you know
what a unit test is, how `#[test]` works in Rust, and what `cargo test`
does. If you are new to Rust testing, read the Rust Book's testing
chapter first.

This book is not vyre's reference manual. It does not explain what
`ir::Program` looks like or how `lower::wgsl` works internally — those
questions are answered by the IR and lowering docs. This book answers a
different question: given that those subsystems exist, how do we prove
they are correct, and how do we prove they stay correct forever.

This book is not a style guide for Rust code. vyre's conventions doc
handles that. When this book and the conventions doc disagree about code
style, the conventions doc wins. When they disagree about tests, this
book wins.

### Who this book is for

Every vyre contributor, human or agent. Every backend implementor. Every
reviewer. Every engineer who receives a bug report against vyre and has
to decide whether the bug is in vyre or in the user's program. Every
company evaluating vyre for production use who wants to know whether the
conformance guarantees are real.

If you are about to write your first test for vyre, this book teaches
you how to write one that meets the bar. If you have written thousands,
this book is the place you return when a test feels wrong but you cannot
say why. If you are reviewing a pull request, this book is the authority
you cite when you reject a test that passes but does not actually verify
anything.

### A note on tone

vyre's documentation is opinionated on purpose. We tell you what to do,
we explain why, and we tell you what not to do. We do not hedge. If a
rule in this book seems wrong in a specific case, you almost certainly
misunderstand the rule or the case. In the rare case where the rule is
actually wrong, the correct response is a pull request against this book
before you write the offending test. We would rather debate the rule
than quietly erode it.

The tone is inherited from the rest of vyre's docs, which are inherited
from projects we respect. The Linux kernel's coding style does not
apologize for existing. The LLVM coding standard does not begin with
"please consider." The SQLite documentation tells you what SQLite does
and what it does not do. This book is written in the same voice because
the subject matter deserves it.

## Table of contents

### Part I — Why testing vyre is hard

1. [Introduction](introduction.md) — vyre's promise to its users, why that
   promise is hard to keep, and what a test suite has to prove for the
   promise to be real.
2. [A tour of what can go wrong](a-tour-of-what-can-go-wrong.md) — the
   failure modes vyre's test suite must prevent. Miscompilation,
   nondeterminism, backend drift, composition bugs, validation gaps,
   float nondeterminism, regression. Each failure mode is a class of bug
   the suite is specifically designed to catch.
3. [The promises](the-promises.md) — vyre's fifteen invariants, expressed
   as promises to users rather than as tabulated rules. These are the
   things the suite proves. Every test ultimately exists to keep one of
   these promises.

### Part II — The language of testing in vyre

4. [Vocabulary](vocabulary.md) — what we mean by "test," "oracle,"
   "property," "mutation," "archetype," "determinism," and the other
   terms of art used throughout the book. Every term defined here has a
   single precise meaning across the entire vyre project.
5. [Oracles](oracles.md) — the oracle hierarchy, from strongest to
   weakest. When to use each, why tests never derive their expected
   output from the code under test, and how oracle selection is
   mechanical rather than judgmental.
6. [Mutations and the adversarial mindset](mutations.md) — what a
   mutation is, how mutation testing grades a test suite, and why "my
   test passes on correct code" is not the same as "my test catches
   wrong code." The chapter that teaches you to write tests that are
   worth writing.
7. [Archetypes — the shapes of bad inputs](archetypes.md) — the
   catalog of input shapes that expose bugs. Identity pairs, overflow
   boundaries, bit-pattern alternations, resource bombs, diamond
   dataflows, off-by-one indices. You do not have to invent adversarial
   inputs from scratch. The archetype catalog is the inventory.

### Part III — The test suite architecture

8. [Architecture](architecture.md) — the directory layout of
   `vyre/tests/`, what each category is for, and the rationale behind
   each boundary. The reference chapter you will open most often.
9. [Unit tests](categories/unit.md) — fast isolated tests with no
   cross-module dependencies. Why we prefer inline `#[cfg(test)]`
   modules and when to reach for the `tests/unit/` directory instead.
10. [Integration tests](categories/integration.md) — tests that exercise
    the complete `ir::Program` → validate → lower → dispatch path. The
    bulk of hand-written correctness coverage.
11. [Validation tests](categories/validation.md) — the V001–V020 suite.
    One test per rule, independently triggerable, must-reject and
    must-accept pairs.
12. [Lowering tests](categories/lowering.md) — covering every `Expr`,
    `Node`, `BinOp`, `UnOp`, `AtomicOp`, and `BufferAccess` variant.
    Includes the enum-exhaustiveness meta-test that refuses to compile
    when a new variant is added without coverage.
13. [Wire format tests](categories/wire_format.md) — wire format ↔ IR conversion,
    round-trip identity, opcode coverage.
14. [Adversarial tests](categories/adversarial.md) — hostile inputs,
    resource bombs, malformed IR, malformed wire-format bytes, OOM and fault
    injection. The category where "graceful rejection, no panic" is the
    whole assertion.
15. [Property tests](categories/property.md) — proptest-based
    invariants, generator discipline, seed reproducibility, and how to
    write a generator that actually exercises the shape of
    `ir::Program` rather than its flat surface.
16. [Backend tests](categories/backend.md) — cross-backend equivalence,
    determinism across runs, the skip rule when only one backend is
    registered.
17. [Regression tests](categories/regression.md) — permanent
    reproducers for fixed bugs. The one category where a test, once
    committed, is never deleted.
18. [Benchmarks](categories/benchmarks.md) — criterion-based performance
    gates and the regression policy. Benchmarks are not correctness
    tests and do not substitute for them.
19. [Support utilities](categories/support.md) — what belongs in
    `tests/support/` and what does not. The rule that helpers exist to
    reduce boilerplate, not to obscure test intent.

### Part IV — A worked example: testing BinOp::Add

This part walks through the design and construction of the complete
test set for `BinOp::Add` end to end. It is the chapter you will copy
from when you add your first primitive op. Every decision is
explained; every test is justified.

20. [Starting with intent](worked-example/01-intent.md) — what does
    `Add` mean, and what must be true about it?
21. [The first test](worked-example/02-first-test.md) — writing
    `test_add_identity_zero_spec_table` line by line, explaining every
    decision.
22. [Building out the suite](worked-example/03-building-out.md) — the
    rest of the canonical add test set, and why each test exists.
23. [Catching a deliberate bug](worked-example/04-catching-a-bug.md)
    — injecting an off-by-one into the implementation and watching the
    suite fire.
24. [Running the mutation gate](worked-example/05-mutation-gate.md) —
    iterating tests until the gate reports zero survivors, and what to
    do when a mutation refuses to die.

### Part V — Writing tests

25. [The decision tree](writing/decision-tree.md) — the nine questions
    that place any new test in the correct category. When you are about
    to write a test and do not know where it goes, answer these in
    order.
26. [Templates](writing/templates.md) — canonical skeletons for the
    most common test shapes. Copy, fill in, commit.
27. [Naming](writing/naming.md) — the `test_<subject>_<property>`
    convention, why consistency is load-bearing, and the naming rules
    that make `cargo test <substring>` useful.
28. [Support utilities](writing/support-utilities.md) — writing helpers
    that clarify rather than obscure. The tests that read as one
    statement with no indirection, even when the helper is necessary.
29. [Oracles in practice](writing/oracles-in-practice.md) — picking the
    right oracle for the test you are writing, with worked examples
    across every category.

### Part VI — What not to write

30. [Anti-patterns](anti-patterns/README.md) — the shapes that look
    like tests but are not. Each anti-pattern has its own chapter.
31. [The tautology test](anti-patterns/tautology.md)
32. [The kitchen sink test](anti-patterns/kitchen-sink.md)
33. [The "doesn't crash" test](anti-patterns/doesnt-crash.md)
34. [The hidden-helper test](anti-patterns/hidden-helpers.md)
35. [The seedless proptest](anti-patterns/seedless-proptest.md)
36. [Test smells](anti-patterns/test-smells.md) — the subtler warning
    signs that appear before a test becomes an outright anti-pattern.
    What to look for and what to do.

### Part VII — Discipline

37. [The review checklist](discipline/review-checklist.md) — the
    eleven items a reviewer enforces on every PR that touches a test.
    No exceptions.
38. [The daily audit](discipline/daily-audit.md) — read ten random
    committed tests every day, delete any that fail the checklist. The
    calibration loop that keeps the suite honest.
39. [Seed discipline](discipline/seed-discipline.md) — proptest seed
    management, regression corpus handling, making CI failures
    reproducible a year later.
40. [The regression rule](discipline/regression-rule.md) — once a file
    lands in `tests/regression/`, it never leaves. When such a file
    starts failing, the bug has returned. Fix the code, not the test.
41. [Flakiness](discipline/flakiness.md) — the most corrosive failure
    mode of a test suite. How to detect a flake, how to eliminate it,
    and why "flake tolerance" is the beginning of the end.
42. [Suite performance](discipline/suite-performance.md) — a slow
    suite does not get run. The rules for keeping the suite fast
    enough that running it before every commit is reflex.

### Part VIII — Advanced topics

43. [Property-based testing for GPU IR](advanced/property-generators.md)
    — writing generators that produce valid `ir::Program` values with
    enough structure to exercise real bugs. Shrinking, coverage-guided
    generation, and the traps of naive random input.
44. [Differential fuzzing](advanced/differential-fuzzing.md) — vyre
    against itself, vyre against its reference interpreter, vyre
    against upstream GPU compute implementations. The most powerful
    bug-finding technique for cross-backend semantics.
45. [Mutation testing at scale](advanced/mutation-at-scale.md) —
    scoping `cargo-mutants`, interpreting surviving mutations as
    findings, the cache discipline that keeps mutation runs under ten
    seconds per op.
46. [Concurrency and ordering](advanced/concurrency-and-ordering.md) —
    atomics, barriers, memory ordering, and the stress tests that
    catch ordering bugs the compiler and hardware cooperate to hide.
47. [Floating-point](advanced/floating-point.md) — testing strict IEEE
    754 paths, ULP-bounded approximate tracks, and the rules that
    prevent float semantics from silently drifting across backends.
48. [Cross-backend equivalence in practice](advanced/cross-backend.md)
    — the hard cases: platform-specific rounding, atomic ordering
    differences, workgroup size variation, and how the suite catches
    divergences before users do.

### Part IX — Running the suite

49. [Local workflow](running/local-workflow.md) — `cargo test`, `cargo
    test --ignored`, `cargo bench`, `cargo fuzz run`, and how to run
    just the tests relevant to your change.
50. [Continuous integration](running/continuous-integration.md) — what
    CI runs on every commit, what runs on release, what runs nightly,
    and how failures are triaged.
51. [Debugging failures](running/debugging-failures.md) — when a test
    fails in your PR: read the failure, find the minimal reproducer,
    decide whether the code or the test is wrong, fix.
52. [Debugging flakes](running/debugging-flakes.md) — the harder
    triage. How to tell a flake from a real bug, how to make a flake
    reproduce, and why you do not "just re-run CI."

### Part X — Integration with vyre-conform

53. [The two-tier suite](vyre-conform/two-tier-suite.md) — how vyre's
    hand-written suite and vyre-conform's generated suite fit together
    as a single coherent test corpus.
54. [When the generator supersedes you](vyre-conform/generator-supersession.md)
    — the rule for migrating an op's hand-written tests to the
    generated suite, and the proof standard that must be met first.
55. [What the generator will never replace](vyre-conform/never-replaced.md)
    — regression reproducers, category-specific adversarial tests,
    property invariants, benchmarks. The chapters that remain
    hand-written forever.
56. [Contribution flow](vyre-conform/contribution-flow.md) — the path a
    test takes from proposal to committed artifact, whether the author
    is human, agent, or mixed.

### Part XI — Meta

57. [Testing as design](meta/testing-as-design.md) — how writing tests
    first shapes the code you write next. Not a religious argument
    about TDD; a practical observation that the ops with the best
    tests are the ops that were designed alongside their tests.
58. [Testing the testers](meta/testing-the-testers.md) — how we know
    our tests are good. Mutation score, coverage score, the audit
    rate, and the meta-tests that catch classes of test bugs.
59. [Post-mortem discipline](meta/post-mortem-discipline.md) — when a
    bug reaches production, the test suite failed. Every post-mortem
    adds at least one mutation operator or archetype. The catalog
    grows with the project.
60. [The long game](meta/the-long-game.md) — the closing chapter. Why
    this book exists and what we expect of it in five, ten, twenty
    years.

### Appendices

- [A. Glossary](appendices/A-glossary.md) — every term used in this
  book, cross-referenced to vyre's main glossary.
- [B. Invariants catalog](appendices/B-invariants-catalog.md) — the
  fifteen invariants in full, with test-family references.
- [C. Mutation operator reference](appendices/C-mutation-operators.md)
  — the complete mutation catalog used by the mutation gate.
- [D. Archetype reference](appendices/D-archetypes.md) — the complete
  archetype catalog.
- [E. Command reference](appendices/E-command-reference.md) — every
  `cargo` command relevant to testing, with flags and when to use
  each.
- [F. Review checklist](appendices/F-review-checklist.md) — the
  enforceable eleven-item checklist, printable.
- [G. Examples index](appendices/G-examples-index.md) — every worked
  example in the book, cross-referenced by topic and category.
- [H. Change history](appendices/H-change-history.md) — when each
  chapter was last revised and why. The architectural decisions
  recorded here are permanent; the revisions that matter are ones
  that refine explanation, not ones that change the rules.

## How to read this book

If you are about to write your first vyre test, read Part I, Part II,
the relevant chapter from Part III, and Part IV. That is roughly fifty
pages and will take an afternoon. You will emerge knowing exactly what
to do.

If you are experienced with vyre and you want to know where a specific
kind of test belongs, go directly to [the decision tree](writing/decision-tree.md).
It answers the question in under a minute.

If you are reviewing a pull request that touches tests, [the review
checklist](discipline/review-checklist.md) is the authority that
decides whether the PR merges.

If you are debugging a failing test in your own PR, start with
[debugging failures](running/debugging-failures.md). If the failure
seems to depend on timing or thread count, continue to [debugging
flakes](running/debugging-flakes.md).

If you are writing a new backend and want to know what conformance
means, Part VII and [cross-backend equivalence in practice](advanced/cross-backend.md)
are the chapters you need. Part X explains how your backend
interacts with vyre-conform.

## Reading this book as an agent

Agents contributing to vyre read this book for the same reason humans
do: to understand what a correct test looks like. The book is written
to be readable by agents without special accommodation. The anti-patterns
in Part VI are specifically the shapes agents produce most often when
asked for tests without context, which is why the book treats them with
the severity it does.

An agent reading this book should pay particular attention to
[oracles](oracles.md), [anti-patterns](anti-patterns/README.md), and
[the review checklist](discipline/review-checklist.md). Those chapters
encode the gates the agent's output will be judged against.

## Cross-references

Every chapter in this book links to the specific vyre sources and
invariants it depends on. Every invariant mentioned is defined in
[Appendix B](appendices/B-invariants-catalog.md) and cross-referenced
throughout. Every term is defined in [Appendix A](appendices/A-glossary.md)
or in vyre's main glossary. When this book talks about a specific
module, it uses `crate::path::to::module` notation, and you can navigate
directly.

If you find a broken cross-reference, file it as a bug against this
book.

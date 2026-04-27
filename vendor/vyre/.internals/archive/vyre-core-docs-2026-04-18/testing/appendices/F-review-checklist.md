# Appendix F — Review checklist

The printable eleven-item review checklist for tests in
vyre. Reviewers use this list when evaluating PRs that add
or modify tests. Contributors use it for self-review before
submitting.

For the full explanation of each item, see
[review-checklist.md](../discipline/review-checklist.md).

---

**1. The test is in the correct category.**

Run the [decision tree](../writing/decision-tree.md) and
confirm the test's location matches.

- [ ] The test is in the correct directory.
- [ ] The category matches the test's subject and
  property.

**2. The test has a doc comment stating its oracle.**

Every test has a doc comment on the test function.

- [ ] The comment has at least two lines.
- [ ] The comment identifies the property being verified.
- [ ] The comment declares the oracle.

**3. The oracle is the strongest applicable.**

Check the oracle hierarchy. If a stronger oracle applies,
the test must use it.

- [ ] The declared oracle is in the hierarchy.
- [ ] No stronger oracle applies.

**4. The expected value comes from the oracle, not the
code.**

The expected value in the assertion must be independent of
the code under test.

- [ ] The expected is a literal, a spec table lookup, a
  law, or an independent implementation's result.
- [ ] The expected is not derived from calling the function
  being tested.

**5. The test has a specific subject and property.**

- [ ] The test name follows `test_<subject>_<property>[_<oracle>]`.
- [ ] The subject is clear from the name and/or the
  doc comment.
- [ ] The property is specific enough to distinguish
  correct from broken behavior.

**6. The test has one clear assertion.**

- [ ] The test verifies one property (kitchen sink tests
  are rejected).
- [ ] If the test has multiple assertions, they are on the
  same observed value and test the same property.

**7. Helpers clarify, do not obscure.**

- [ ] The reader can understand what is being tested
  from the test body.
- [ ] Helpers have descriptive names.
- [ ] No configuration objects hide the inputs or
  expected values.

**8. Proptest has fixed seed and committed regression
corpus.**

Applies only to property tests.

- [ ] `ProptestConfig` is explicit with cases, shrinks, and
  failure persistence.
- [ ] The regression corpus file is committed.

**9. The test name follows the convention.**

- [ ] The name uses `test_` prefix (or `regression_` for
  regression tests, `bench_` for benchmarks).
- [ ] The name is descriptive.
- [ ] The name matches the pattern
  `test_<subject>_<property>[_<oracle>]`.

**10. The test is not a known anti-pattern.**

Review against Part VI. If the test matches any
anti-pattern, the PR is sent back.

- [ ] Not a tautology test.
- [ ] Not a kitchen sink test.
- [ ] Not a "doesn't crash" test (unless in adversarial
  category).
- [ ] Not a hidden helper test.
- [ ] Not a seedless proptest.
- [ ] No test smells significant enough to warrant fixing.

**11. The test has a sensible failure message.**

- [ ] The default `assert_eq!` message is acceptable for
  simple cases.
- [ ] Loops or iterations have explicit failure messages.
- [ ] Multi-step tests have messages that identify which
  step failed.

---

## Action on the checklist

- **All items pass:** the test is accepted on the
  discipline axis. The reviewer may still have non-test
  feedback.
- **Any item fails:** the PR is sent back with a specific
  citation of which item failed and a link to the relevant
  chapter. The contributor fixes and re-submits.

## The checklist at a glance

1. Correct category
2. Oracle declared in doc comment
3. Strongest applicable oracle
4. Expected value from oracle, not code
5. Specific subject and property
6. One clear assertion
7. Helpers clarify, not obscure
8. Proptest has fixed seed and committed corpus
9. Naming convention
10. Not a known anti-pattern
11. Sensible failure message

Print this list. Post it where reviewers can see it. Use it
every time.

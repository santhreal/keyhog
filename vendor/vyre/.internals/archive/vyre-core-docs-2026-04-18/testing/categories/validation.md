# Validation tests

## The validator is vyre's contract

vyre's validation pass is the contract between vyre and its
consumers. The consumer calls `validate(&program)`. If the
validator returns an empty error list, the consumer knows the
Program is well-formed, can be lowered safely, can be dispatched
without panic, and will produce meaningful output. If the
validator returns errors, the consumer knows exactly which rules
were violated and can report the problem to the user.

This contract is load-bearing. Everything downstream of validation
assumes its input has been validated. The lowering does not
defensively re-check whether buffers have unique names; it
assumes validation caught that. The dispatcher does not verify
the Program has no out-of-range indices; it assumes validation
caught that. If validation fails to catch a class of error, the
downstream code crashes, corrupts data, or produces undefined
behavior — and from the user's perspective, vyre is broken.

The validation test category exists specifically to prove the
validator is complete and sound. Complete means every rule that
should fire does fire when violated. Sound means the validator
does not fire when it should not. Together these two properties
are invariants I5 (soundness) and I6 (completeness), and the
validation test category is the primary defense for both.

## The rule set

vyre's validator checks rules V001 through V020. Each rule targets
a specific class of malformed Program:

| Rule | Checks |
|---|---|
| V001 | Duplicate buffer names |
| V002 | Duplicate buffer binding slots |
| V003 | Reserved buffer names |
| V004 | Invalid buffer element counts |
| V005 | Mismatch between buffer convention and access mode |
| V006 | References to undeclared buffers |
| V007 | Type mismatches in binary operations |
| V008 | Variable shadowing |
| V009 | Loop variable immutability |
| V010 | Barriers under divergent control flow |
| V011 | Cast type compatibility |
| V012 | If-condition type is boolean |
| V013 | Atomic element type validity |
| V014 | Workgroup buffer size bounds |
| V015 | Out-of-range constant values |
| V016 | Maximum nesting depth exceeded |
| V017 | Maximum node count exceeded |
| V018 | Invalid opcode use in composition |
| V019 | Unreachable code after return |
| V020 | Invalid storage class combinations |

The exact rule list evolves as vyre grows. New rules are added
when a class of malformed Program is identified that the existing
rules cannot catch. Rules are rarely removed; when they are, the
removal is a deprecation with a migration path, not a silent
deletion.

Each rule has an entry in the `ValidationRule` enum, a
corresponding implementation in `src/ir/validate/`, and at least
two test cases in `tests/integration/validation/`: a must-reject
case and a must-accept case.

## The must-reject / must-accept pattern

Every validation test comes in a pair. The must-reject case
constructs a Program that violates exactly one rule and asserts
the validator returns exactly that error. The must-accept case
constructs the same Program with the violation removed and
asserts the validator returns no errors.

```rust
/// V001 must-reject: two buffers with the same name.
/// Oracle: V-rule definition in src/ir/validate/buffers.rs.
#[test]
fn test_v001_rejects_duplicate_buffer_name() {
    let mut program = Program::empty();
    program.buffers.push(BufferDecl::new("foo", DataType::U32, 16));
    program.buffers.push(BufferDecl::new("foo", DataType::U32, 32));
    program.entry = Node::Return;

    let errors = validate(&program);

    assert_eq!(
        errors.len(), 1,
        "expected exactly one error, got {:?}", errors,
    );
    assert_eq!(errors[0].rule, ValidationRule::V001);
}

/// V001 must-accept: distinct buffer names.
/// Oracle: V-rule definition in src/ir/validate/buffers.rs.
#[test]
fn test_v001_accepts_distinct_buffer_names() {
    let mut program = Program::empty();
    program.buffers.push(BufferDecl::new("foo", DataType::U32, 16));
    program.buffers.push(BufferDecl::new("bar", DataType::U32, 32));
    program.entry = Node::Return;

    let errors = validate(&program);

    assert!(errors.is_empty(), "expected no errors, got {:?}", errors);
}
```

The two tests together pin down the rule's behavior on both
sides of the boundary. The must-reject case proves the rule
fires when it should; the must-accept case proves it does not
fire when it should not. Either test alone is incomplete.

## The separability requirement

Invariant I6 says every validation rule must be independently
triggerable: for each rule, there must exist a Program that
violates exactly that rule and no other. This is the separability
requirement, and it matters because rules that cannot be
triggered in isolation are either redundant or coupled.

A redundant rule is one whose violations always also violate
another rule. The redundant rule adds no information; removing
it would not change what the validator catches. Redundant rules
are technical debt and are removed when discovered.

A coupled rule is one that fires together with another rule
because the two rules have overlapping trigger conditions. A
coupled rule may or may not be removable — sometimes the overlap
is meaningful, sometimes it indicates a rule-design mistake.
Either way, the coupling is worth knowing about.

The separability requirement is enforced by a meta-test:

```rust
/// Separability: every V-rule is independently triggerable.
/// Oracle: I6 (validation completeness).
#[test]
fn test_every_v_rule_has_a_must_reject_test() {
    let rules = ValidationRule::all();
    let tested: Vec<ValidationRule> = collect_tested_rules();

    let missing: Vec<_> = rules.iter()
        .filter(|r| !tested.contains(r))
        .collect();

    assert!(
        missing.is_empty(),
        "rules without must-reject tests: {:?}",
        missing,
    );
}

/// Separability: every must-reject test triggers exactly one rule.
/// Oracle: I6 (validation completeness).
#[test]
fn test_must_reject_tests_are_separable() {
    for test_case in iter_must_reject_test_cases() {
        let program = test_case.build();
        let errors = validate(&program);
        assert_eq!(
            errors.len(), 1,
            "test {} should trigger exactly one rule, got {:?}",
            test_case.name, errors,
        );
    }
}
```

The first meta-test enumerates the `ValidationRule` enum at
runtime (via a helper that uses `strum` or a manual enumeration)
and compares it to the set of rules that have at least one
must-reject test in the suite. Any rule without a must-reject test
is a finding: either the rule is untested or the rule is not
independently triggerable.

The second meta-test iterates every must-reject test case and
asserts each triggers exactly one rule. A test case that triggers
two rules means those two rules are coupled in a way that this
test does not disentangle. The fix is either to refine the test
case (construct a Program that violates only one of the two rules)
or to report the coupling as a finding and investigate whether it
indicates a rule-design problem.

## The grouping in `validation/`

Validation tests are grouped by rule family for readability:

```
tests/integration/validation/
├── buffers.rs       V001-V005: buffer declarations
├── types.rs         V006, V007, V011, V012, V013: type rules
├── control.rs       V008, V009, V010, V016, V019: control flow
├── limits.rs        V015, V017: size and range limits
├── storage.rs       V020: storage class rules
├── composition.rs   V018: composition-level rules
└── separability.rs  the meta-tests
```

The grouping is not load-bearing — it is a convenience for
readers. The separability test iterates the whole
`tests/integration/validation/` tree, so adding a new rule test
to any file is caught automatically as long as the test follows
the naming convention.

## Naming convention

Validation tests follow a strict naming convention so the meta-test
can find them and so readers can navigate:

- `test_v<NNN>_rejects_<scenario>` for must-reject tests.
- `test_v<NNN>_accepts_<scenario>` for must-accept tests.

`<NNN>` is the three-digit rule number with leading zeros. `<scenario>`
is a short description of the specific case the test exercises.
For rules that have multiple scenarios (a common case), multiple
must-reject tests with different `<scenario>` suffixes are
allowed and encouraged.

Examples:

- `test_v001_rejects_duplicate_buffer_name`
- `test_v001_accepts_distinct_buffer_names`
- `test_v010_rejects_barrier_under_if_branch`
- `test_v010_rejects_barrier_under_while_loop`
- `test_v010_accepts_barrier_in_uniform_block`
- `test_v017_rejects_program_with_ten_thousand_and_one_nodes`
- `test_v017_accepts_program_with_ten_thousand_nodes`

## What validation tests do not cover

Validation tests are narrowly scoped. They test the validator
and nothing else. They do not test what the validator should be
checking for; that is a rule-design question answered in vyre's
IR docs. They do not test what happens when a validated program
runs; that is covered by integration tests for the pipeline. They
do not test the validator's performance; that is covered by
benchmarks.

A validation test's one job is: given this Program, does the
validator return this error list? Nothing else.

## The validation soundness property test

Invariant I5 (validation soundness) is the claim that every
validated Program is safe to lower. Validation tests in this
category verify specific rules, but they do not verify the
property that *every* validated Program is safe. That property is
verified by a proptest in `tests/property/validation_soundness.rs`:

```rust
proptest! {
    #![proptest_config(ProptestConfig {
        cases: 10_000,
        ..ProptestConfig::default()
    })]

    /// Validation soundness: every validated Program can be lowered
    /// without panic, UB, or unbounded allocation.
    /// Oracle: I5.
    #[test]
    fn validated_programs_lower_safely(program in arb_program()) {
        let errors = validate(&program);
        if errors.is_empty() {
            // Lowering must not panic on any validated Program.
            let result = std::panic::catch_unwind(|| {
                wgsl::lower(&program)
            });
            prop_assert!(result.is_ok(), "lowering panicked on validated program");
        }
    }
}
```

The proptest generates arbitrary (valid and invalid) Programs,
validates them, and for those that pass validation, asserts that
lowering does not panic. If any validated Program causes
lowering to panic, the test fails, the proptest shrinks the input
to a minimal case, and the failing case becomes a regression in
`tests/regression/` once the underlying bug is fixed.

Property-based soundness tests and specific-rule tests are
complementary. The specific-rule tests pin down individual rule
behavior. The soundness proptest covers the overall contract.
Both are needed.

## When a new validation rule is added

Adding a new validation rule to vyre requires six artifacts, in
this order:

1. The rule's definition in `src/ir/validate/` — the code that
   actually checks the condition.
2. A new `ValidationRule` enum variant.
3. A must-reject test in `tests/integration/validation/` for the
   appropriate rule family file.
4. A must-accept test in the same file.
5. An entry in the rule table in this chapter (or in
   `docs/ir/validation.md`, depending on where the authoritative
   table lives).
6. An update to the separability meta-test, which is automatic if
   the meta-test uses enum enumeration.

If any of these six is missing, the rule is incomplete and the
PR is rejected. The enum enumeration in the meta-test is
load-bearing: it is how the suite catches additions that forget
test coverage.

## When a validation rule is removed

Removing a rule is rare and requires:

1. Justification that the rule is redundant (its violations are
   caught by another rule) or that the condition it checks is no
   longer a violation (the spec changed).
2. A deprecation warning on the rule for at least one release
   cycle before removal.
3. A migration note in the changelog explaining what replaced
   the rule.
4. Removal of the must-reject and must-accept tests.
5. Preservation of any Programs that depended on the old rule
   still being validated — they must still pass or must be
   flagged with a different rule.

I13 (userspace stability) means rule removals must not break
existing Programs. If an existing Program relied on the removed
rule to catch a mistake, that mistake must now be caught by a
different rule, or the rule removal is a breaking change and
must be rejected.

## Summary

Validation tests verify the validator. Every rule has at least a
must-reject and a must-accept test. Every rule is independently
triggerable, enforced by the separability meta-test. The overall
contract (I5 soundness) is enforced by a proptest. New rules
require six artifacts. Removed rules require migration.

Next: [Lowering tests](lowering.md).
